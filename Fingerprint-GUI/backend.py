# backend.py
import subprocess
import os
import json
import hashlib
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 导入Protobuf生成的代码
import fingerprint_pb2 as pb


# 帮助函数
def get_canonical_representation_py(item: pb.FingerprintItem) -> bytes:
    data = (f"{item.name}{item.value}{item.raw_value.decode('latin-1', errors='ignore')}"
            f"{item.status}{item.timestamp.seconds}"
            f"{item.provenance.source}{item.provenance.method}{item.provenance.tool_version}").encode('utf-8')
    return data


def sha256_py(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# 权重定义
FINGERPRINT_WEIGHTS = {
    "mainboard.serial_number": 100, "disk.*.serial_number": 80, "tee.sgx_quote": 90,
    "cpu.vendor_id": 50, "cpu.brand_string": 50, "gpu.*.description": 40,
    "benchmark.cpu_integer_score": 20, "benchmark.cpu_float_score": 20,
    "benchmark.gpu_render_hash": 30, "os.install_id": 25, "os.hostname": 5
}


def get_weight(item_name: str) -> int:
    for key, weight in FINGERPRINT_WEIGHTS.items():
        if key.endswith('*') and item_name.startswith(key[:-1]):
            return weight
        if key == item_name:
            return weight
    return 10


class Backend:
    def __init__(self, validator_exe_path="..\\Fingerprint-CPP\\build\\Release\\FingerprintCLI.exe"):
        self.validator_path = validator_exe_path
        self.c_validator_exists = os.path.exists(validator_exe_path)
        if not self.c_validator_exists:
            print(f"[警告] C++校验程序未在路径 '{validator_exe_path}' 找到。部分验证功能将受限。")

    def run_c_validation(self, fingerprint_path: str, pub_key_path: str) -> dict:
        if not self.c_validator_exists:
            return {"success": False, "output": "C++校验程序未配置，跳过此验证步骤。"}

        command = [self.validator_path, "validate", fingerprint_path, pub_key_path]
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            result = subprocess.run(
                command, capture_output=True, text=True, check=True,
                encoding='utf-8', startupinfo=startupinfo
            )
            passed = "校验流程结束" in result.stdout and "失败" not in result.stdout
            return {"success": passed, "output": result.stdout}
        except FileNotFoundError:
            return {"success": False, "output": f"错误: 无法执行C++校验程序，请检查路径: {self.validator_path}"}
        except subprocess.CalledProcessError as e:
            return {"success": False, "output": f"C++校验程序返回错误:\n{e.stdout}\n{e.stderr}"}
        except Exception as e:
            return {"success": False, "output": f"执行C++校验程序时发生未知错误: {e}"}

    def parse_fingerprint_file(self, fingerprint_path: str) -> pb.DeviceFingerprintReport | None:
        report = pb.DeviceFingerprintReport()
        try:
            with open(fingerprint_path, "rb") as f:
                report.ParseFromString(f.read())
            return report
        except Exception:
            return None

    def verify_all_items_py(self, report: pb.DeviceFingerprintReport, public_key_path: str) -> dict:
        results = {}
        try:
            with open(public_key_path, "rb") as f:
                public_key = f.read()
            # 修正: 兼容新旧API，使用 hasattr 判断
            if hasattr(oqs, 'Signature'):
                sig = oqs.Signature("Dilithium3")
            else:
                sig = oqs.sig.Sig("Dilithium3")

            for i, item in enumerate(report.all_items):
                item_id = f"{item.name}_{i}"
                canonical_data = get_canonical_representation_py(item)
                data_hash = sha256_py(canonical_data)
                is_valid = sig.verify(data_hash, item.item_signature.signature_data, public_key)
                results[item_id] = (is_valid, "签名有效" if is_valid else "签名无效!")
        except Exception as e:
            return {"error": str(e)}
        return results

    def compare_reports(self, report1: pb.DeviceFingerprintReport, report2: pb.DeviceFingerprintReport) -> dict:
        items1 = {item.name: item for item in report1.all_items if item.status == pb.SUCCESS}
        items2 = {item.name: item for item in report2.all_items if item.status == pb.SUCCESS}
        all_names = set(items1.keys()) | set(items2.keys())

        achieved, max_score = 0, 0
        details = []

        for name in sorted(list(all_names)):
            item1, item2 = items1.get(name), items2.get(name)
            weight = get_weight(name)

            if item1 and item2:
                max_score += weight
                is_match = False
                if name.startswith("benchmark."):
                    try:
                        v1, v2 = float(item1.value), float(item2.value)
                        if max(v1, v2) > 0 and abs(v1 - v2) / max(v1, v2) < 0.05:
                            is_match = True
                    except (ValueError, ZeroDivisionError):
                        is_match = False
                elif item1.value == item2.value and item1.raw_value == item2.raw_value:
                    is_match = True

                if is_match:
                    achieved += weight
                    details.append({"name": name, "status": "匹配", "val1": item1.value, "val2": item2.value})
                else:
                    details.append({"name": name, "status": "不匹配", "val1": item1.value, "val2": item2.value})
            elif item1:
                details.append({"name": name, "status": "仅文件1存在", "val1": item1.value, "val2": "N/A"})
            elif item2:
                details.append({"name": name, "status": "仅文件2存在", "val1": "N/A", "val2": item2.value})

        score = (achieved / max_score * 100) if max_score > 0 else 0
        return {"score": score, "details": details}

    def generate_pqc_keys(self, kem_alg: str, sig_alg: str, base_path: str):
        try:
            # 修正: 兼容新旧API，使用 hasattr 判断
            if hasattr(oqs, 'KeyEncapsulation'):
                kem = oqs.KeyEncapsulation(kem_alg)
            else:
                kem = oqs.kem.Kem(kem_alg)
            pk_kem, sk_kem = kem.generate_keypair(), kem.export_secret_key()

            if hasattr(oqs, 'Signature'):
                sig = oqs.Signature(sig_alg)
            else:
                sig = oqs.sig.Sig(sig_alg)
            pk_sig, sk_sig = sig.generate_keypair(), sig.export_secret_key()

            with open(os.path.join(base_path, "kem_public.key"), "wb") as f:
                f.write(pk_kem)
            with open(os.path.join(base_path, "kem_private.key"), "wb") as f:
                f.write(sk_kem)
            with open(os.path.join(base_path, "sig_public.key"), "wb") as f:
                f.write(pk_sig)
            with open(os.path.join(base_path, "sig_private.key"), "wb") as f:
                f.write(sk_sig)

            return True, f"成功生成密钥于: {base_path}"
        except Exception as e:
            return False, f"密钥生成失败: {e}"

    def encrypt_config_file(self, config_json_str: str, kem_pub_key_path: str, output_path: str):
        try:
            with open(kem_pub_key_path, "rb") as f:
                public_key = f.read()

            if hasattr(oqs, 'KeyEncapsulation'):
                kem = oqs.KeyEncapsulation("Kyber768")
                ciphertext, shared_secret = kem.encap_secret(public_key)
            else:
                kem = oqs.kem.Kem("Kyber768")
                ciphertext, shared_secret = kem.encap_secret(public_key)

            config_data_bytes = config_json_str.encode('utf-8')
            aesgcm = AESGCM(shared_secret)
            nonce = os.urandom(12)
            encrypted_config = aesgcm.encrypt(nonce, config_data_bytes, None)

            final_payload = ciphertext + nonce + encrypted_config

            with open(output_path, "wb") as f:
                f.write(final_payload)
            return True, f"成功加密配置文件到: {output_path}"
        except Exception as e:
            return False, f"加密失败: {e}"

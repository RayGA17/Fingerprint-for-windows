# config_handler.py
import json
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ConfigHandler:
    def __init__(self, kem_alg="Kyber768"):
        self.kem_algorithm = kem_alg
        self.config = None

    def load_and_decrypt(self, private_key_path: str, encrypted_config_path: str) -> bool:
        try:
            with open(private_key_path, "rb") as f:
                private_key = f.read()
            with open(encrypted_config_path, "rb") as f:
                full_payload = f.read()

            with oqs.KeyEncapsulation(self.kem_algorithm) as kem:
                len_enc_key = kem.details['length_ciphertext']

                # 从载荷末尾分离出封装的（加密的）主密钥
                encapsulated_master_key = full_payload[-len_enc_key:]
                # 使用PQC私钥解封装主密钥
                master_key = kem.decap_secret(encapsulated_master_key, private_key)

                # 从载荷开头分离出nonce和加密的配置数据
                nonce = full_payload[:12]
                encrypted_config = full_payload[12:-len_enc_key]

                # 使用解密出的主密钥通过AES-GCM解密配置
                aesgcm = AESGCM(master_key)
                decrypted_bytes = aesgcm.decrypt(nonce, encrypted_config, None)
                self.config = json.loads(decrypted_bytes)
                print("[+] 配置文件解密成功。")
                return True
        except FileNotFoundError as e:
            print(f"错误: 文件未找到 - {e}")
            return False
        except Exception as e:
            print(f"错误: 解密配置文件失败 - {e}")
            return False

# fingerprint_cli.py
import argparse
import uuid
import time
import os

# 导入所有模块
from config_handler import ConfigHandler
from crypto_handler import CryptoHandler
from tpm_handler import TpmHandler
import fingerprint_pb2 as pb

from fetchers.cpu_fetcher import CpuFetcher
from fetchers.smbios_fetcher import SmbiosFetcher
from fetchers.disk_fetcher import DiskFetcher
from fetchers.gpu_fetcher import GpuFetcher
from fetchers.os_benchmark_fetcher import OsBenchmarkFetcher
from fetchers.tee_fetcher import TeeFetcher

# 版本号
TOOL_VERSION = "1.0.0-python"


def get_canonical_representation(item: pb.FingerprintItem) -> bytes:
    data = (f"{item.name}{item.value}{item.raw_value.decode('latin-1', errors='ignore')}"
            f"{item.status}{item.timestamp.seconds}"
            f"{item.provenance.source}{item.provenance.method}{item.provenance.tool_version}").encode('utf-8')
    return data


def run_extraction(config, output_path, signer_key_path):
    print("[1/4] 正在提取硬件和软件指纹...")
    report = pb.DeviceFingerprintReport()

    # 填充元数据
    report.metadata.report_id = str(uuid.uuid4())
    report.metadata.client_program_version = TOOL_VERSION
    report.metadata.creation_timestamp.seconds = int(time.time())

    # 初始化并运行所有采集器
    fetchers = [
        CpuFetcher(), SmbiosFetcher(), DiskFetcher(), GpuFetcher(),
        OsBenchmarkFetcher(), TeeFetcher()
    ]

    for fetcher in fetchers:
        try:
            for name, value, method in fetcher.fetch():
                item = report.all_items.add()
                item.name = name
                item.value = str(value)  # 确保所有值为字符串
                item.status = pb.SUCCESS
                item.provenance.source = "WMI/psutil"  # Python版本的主要来源
                item.provenance.method = method
                item.provenance.tool_version = TOOL_VERSION
        except Exception as e:
            print(f"采集器 {type(fetcher).__name__} 运行失败: {e}")

    print(f"[2/4] 正在执行个体签名... 共 {len(report.all_items)} 项")
    crypto = CryptoHandler("Dilithium3")
    try:
        with open(signer_key_path, "rb") as f:
            signer_sk = f.read()
    except FileNotFoundError:
        print(f"错误: 签名私钥未找到: {signer_key_path}")
        return

    leaf_hashes = []
    for item in report.all_items:
        item.timestamp.seconds = int(time.time())
        canonical_data = get_canonical_representation(item)
        item_hash = crypto.sha256(canonical_data)
        leaf_hashes.append(item_hash)

        signature = crypto.sign(item_hash, signer_sk)
        item.item_signature.algorithm = crypto.sig_algorithm
        item.item_signature.signature_data = signature

    print("[3/4] 正在构建Merkle树并尝试TPM聚合签名...")
    merkle_root = crypto.build_merkle_tree(leaf_hashes)
    report.merkle_root_hash = merkle_root

    # TPM签名
    tpm = TpmHandler()
    tpm_data_to_sign = report.metadata.SerializeToString() + report.merkle_root_hash
    tpm_hash = crypto.sha256(tpm_data_to_sign)
    signed_ok, tpm_sig = tpm.sign_with_tpm(tpm_hash)
    if signed_ok:
        report.aggregate_tpm_signature.algorithm = "TPM-RSA-PKCS1-SHA256"  # 示例
        report.aggregate_tpm_signature.signature_data = tpm_sig
    else:
        report.aggregate_tpm_signature.algorithm = "TPM-UNAVAILABLE"

    print("[4/4] 正在序列化报告到文件...")
    try:
        with open(output_path, "wb") as f:
            f.write(report.SerializeToString())
        print(f"成功: 指纹报告已写入 {output_path}")
    except IOError as e:
        print(f"错误: 写入文件失败: {e}")


def run_validation(fingerprint_path, signer_pub_key_path):
    print(f"\n--- 开始校验: {fingerprint_path} ---")
    report = pb.DeviceFingerprintReport()
    try:
        with open(fingerprint_path, "rb") as f:
            report.ParseFromString(f.read())
    except (IOError, DecodeError) as e:
        print(f"失败: 无法读取或解析指纹文件: {e}")
        return

    crypto = CryptoHandler("Dilithium3")

    print("[1/2] 验证Merkle树...")
    leaf_hashes = []
    for item in report.all_items:
        leaf_hashes.append(crypto.sha256(get_canonical_representation(item)))

    calculated_root = crypto.build_merkle_tree(leaf_hashes)
    if calculated_root == report.merkle_root_hash:
        print("  [+] 成功: Merkle树完整性校验通过。")
    else:
        print("  [-] 失败: Merkle树不匹配！报告内容可能被篡改。")
        return

    print("[2/2] 验证个体签名...")
    try:
        with open(signer_pub_key_path, "rb") as f:
            signer_pk = f.read()
    except FileNotFoundError:
        print(f"失败: 无法读取用于验证的公钥: {signer_pub_key_path}")
        return

    invalid_count = 0
    for i, item in enumerate(report.all_items):
        if not crypto.verify(leaf_hashes[i], item.item_signature.signature_data, signer_pk):
            invalid_count += 1
            print(f"  [-] 警告: 项 '{item.name}' 的签名无效！")

    if invalid_count == 0:
        print(f"  [+] 成功: 所有 {len(report.all_items)} 个体签名均有效。")
    else:
        print(f"  [-] 警告: 发现 {invalid_count} 个无效签名。")

    print("\n--- 校验流程结束 ---")


def main():
    parser = argparse.ArgumentParser(description="Python设备指纹工具 (v1.0.0)")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    extract_parser = subparsers.add_parser("extract", help="提取当前设备的指纹")
    extract_parser.add_argument("config_enc", help="加密的配置文件路径")
    extract_parser.add_argument("pqc_priv_key", help="用于解密配置的PQC私钥")
    extract_parser.add_argument("signer_priv_key", help="用于签名的Dilithium私钥")
    extract_parser.add_argument("output", help="输出的指纹文件路径 (.bin)")

    validate_parser = subparsers.add_parser("validate", help="校验一个指纹文件")
    validate_parser.add_argument("input", help="输入的指纹文件路径 (.bin)")
    validate_parser.add_argument("signer_pub_key", help="用于验证签名的Dilithium公钥")

    args = parser.parse_args()

    if args.mode == "extract":
        conf_handler = ConfigHandler()
        if not conf_handler.load_and_decrypt(args.pqc_priv_key, args.config_enc):
            return
        run_extraction(conf_handler.config, args.output, args.signer_priv_key)
    elif args.mode == "validate":
        run_validation(args.input, args.signer_pub_key)


if __name__ == "__main__":
    main()

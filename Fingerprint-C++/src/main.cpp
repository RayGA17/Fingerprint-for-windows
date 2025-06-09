// src/main.cpp
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <sstream>

#include "pqc_config_handler.hpp"
#include "crypto_handler.hpp"
#include "tpm_handler.hpp"
#include "cpu_fetcher.hpp"
#include "smbios_fetcher.hpp"
#include "disk_fetcher.hpp"
#include "gpu_fetcher.hpp"
#include "os_benchmark_fetcher.hpp"
#include "sgx_fetcher.hpp"

#include "proto_gen/fingerprint.pb.h"

// 全局帮助函数
std::vector<uint8_t> readFileToBytes(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) return {};
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void fill_item(DeviceFingerprint::FingerprintItem* item, const std::string& name, const std::string& value, const std::string& method, const std::string& source) {
    item->set_name(name);
    item->set_value(value);
    item->set_status(DeviceFingerprint::ItemStatus::SUCCESS);
    item->mutable_provenance()->set_source(source);
    item->mutable_provenance()->set_method(method);
    // 时间戳等稍后统一填充
}

std::string getCanonicalRepresentation(const DeviceFingerprint::FingerprintItem& item) {
    std::stringstream ss;
    ss << item.name() << item.value() << item.raw_value()
       << item.status() << item.timestamp().seconds()
       << item.provenance().source() << item.provenance().method();
    return ss.str();
}

void run_extraction(const json& config, const std::string& output_path) {
    DeviceFingerprint::DeviceFingerprintReport report;
    std::cout << "[1/4] 正在提取硬件和软件指纹..." << std::endl;
    CpuFetcher::fetch(&report);
    SmbiosFetcher::fetch(&report);
    DiskFetcher::fetch(&report);
    GpuFetcher::fetch(&report);
    OsBenchmarkFetcher::fetch(&report);
    SgxFetcher::fetch(&report);

    std::cout << "[2/4] 正在执行个体签名..." << std::endl;
    CryptoHandler crypto("Dilithium3");
    auto sk = readFileToBytes(config["crypto_keys"]["item_signer_private_key_path"]);
    if (sk.empty()) { std::cerr << "错误: 无法读取签名私钥。" << std::endl; return; }
    
    std::vector<std::vector<uint8_t>> leaf_hashes;
    for (auto& item : *report.mutable_all_items()) {
        auto now = std::chrono::system_clock::now();
        item.mutable_timestamp()->set_seconds(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
        auto canonical_data = getCanonicalRepresentation(item);
        auto item_hash = crypto.sha256(canonical_data);
        leaf_hashes.push_back(item_hash);
        crypto.sign(item_hash, sk, item.mutable_item_signature());
    }

    std::cout << "[3/4] 正在构建Merkle树并执行TPM聚合签名..." << std::endl;
    auto merkle_root = crypto.buildMerkleTree(leaf_hashes);
    report.set_merkle_root_hash(merkle_root.data(), merkle_root.size());

    std::string tpm_data;
    tpm_data.append(report.metadata().SerializeAsString());
    tpm_data.append(report.merkle_root_hash());
    auto tpm_hash = crypto.sha256(tpm_data);
    
    TpmHandler tpm(L"Fingerprint_Key");
    if (tpm.initializeKey()) {
        tpm.sign(tpm_hash, report.mutable_aggregate_tpm_signature());
    }

    std::cout << "[4/4] 正在序列化报告到文件..." << std::endl;
    std::fstream output(output_path, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!report.SerializeToOstream(&output)) {
        std::cerr << "错误: 写入文件失败。" << std::endl;
    } else {
        std::cout << "成功: 指纹报告已写入 " << output_path << std::endl;
    }
}

void run_validation(const std::string& fingerprint_path, const std::string& item_pub_key_path) {
    std::cout << "\n--- 开始校验: " << fingerprint_path << " ---" << std::endl;
    DeviceFingerprint::DeviceFingerprintReport report;
    std::fstream input(fingerprint_path, std::ios::in | std::ios::binary);
    if (!report.ParseFromIstream(&input)) { std::cerr << "失败: 无法解析文件。" << std::endl; return; }
    
    std::cout << "[1/3] 验证TPM聚合签名... (模拟成功)" << std::endl;
    
    std::cout << "[2/3] 验证Merkle树..." << std::endl;
    CryptoHandler crypto("Dilithium3");
    std::vector<std::vector<uint8_t>> leaf_hashes;
    for (const auto& item : report.all_items()) {
        leaf_hashes.push_back(crypto.sha256(getCanonicalRepresentation(item)));
    }
    auto calculated_root = crypto.buildMerkleTree(leaf_hashes);
    if (std::string(calculated_root.begin(), calculated_root.end()) == report.merkle_root_hash()) {
        std::cout << "  [+] 成功: Merkle树完整性校验通过。" << std::endl;
    } else {
        std::cout << "  [-] 失败: Merkle树不匹配！" << std::endl; return;
    }

    std::cout << "[3/3] 验证个体签名..." << std::endl;
    auto pk = readFileToBytes(item_pub_key_path);
    if (pk.empty()) { std::cerr << "失败: 无法读取公钥。" << std::endl; return; }
    int invalid_count = 0;
    for (size_t i = 0; i < report.all_items_size(); ++i) {
        if (!crypto.verify(leaf_hashes[i], report.all_items(i).item_signature(), pk)) {
            invalid_count++;
        }
    }
    if(invalid_count == 0) std::cout << "  [+] 成功: 所有个体签名均有效。" << std::endl;
    else std::cout << "  [-] 失败: 发现 " << invalid_count << " 个无效签名。" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "用法:\n"
                  << "  提取: FingerprintCLI.exe extract <config.enc> <pqc_private.key> <signer_private.key> <output.bin>\n"
                  << "  校验: FingerprintCLI.exe validate <input.bin> <signer_public.key>\n";
        return 1;
    }

    std::string mode = argv[1];
    if (mode == "extract" && argc == 6) {
        PQCConfigHandler conf("Kyber768");
        if (!conf.loadAndDecrypt(argv[3], argv[2])) return 1;
        auto mod_conf = conf.getConfig();
        mod_conf["crypto_keys"]["item_signer_private_key_path"] = argv[4];
        run_extraction(mod_conf, argv[5]);
    } else if (mode == "validate" && argc == 4) {
        run_validation(argv[2], argv[3]);
    } else {
        std::cerr << "无效参数。" << std::endl; return 1;
    }
    google::protobuf::ShutdownProtobufLibrary();
    return 0;
}

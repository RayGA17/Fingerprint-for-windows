// src/pqc_config_handler.cpp
#include "pqc_config_handler.hpp"
#include <fstream>
#include <iostream>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

PQCConfigHandler::PQCConfigHandler(const std::string& kem_alg) : kem_algorithm(kem_alg) {}

const json& PQCConfigHandler::getConfig() const { return config_json; }

std::vector<uint8_t> PQCConfigHandler::readFile(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) { return {}; }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

bool PQCConfigHandler::loadAndDecrypt(const std::string& private_key_path, const std::string& encrypted_config_path) {
    OQS_KEM *kem = OQS_KEM_new(kem_algorithm.c_str());
    if (!kem) { std::cerr << "错误: 不支持的KEM算法: " << kem_algorithm << std::endl; return false; }

    auto private_key = readFile(private_key_path);
    auto full_payload = readFile(encrypted_config_path);

    if (private_key.empty() || full_payload.empty()) { std::cerr << "错误: 无法读取私钥或加密配置。" << std::endl; OQS_KEM_free(kem); return false; }
    if (full_payload.size() <= kem->length_ciphertext + 12 + 16) { std::cerr << "错误: 加密文件格式无效。" << std::endl; OQS_KEM_free(kem); return false; }

    size_t encapsulated_key_pos = full_payload.size() - kem->length_ciphertext;
    std::vector<uint8_t> encapsulated_master_key(full_payload.begin() + encapsulated_key_pos, full_payload.end());
    
    std::vector<uint8_t> master_key(kem->length_shared_secret);
    if (OQS_KEM_decap(kem, master_key.data(), encapsulated_master_key.data(), private_key.data()) != OQS_SUCCESS) {
        std::cerr << "错误: PQC主密钥解封装失败。" << std::endl; OQS_KEM_free(kem); return false;
    }
    OQS_KEM_free(kem);

    const unsigned char* nonce = full_payload.data();
    size_t encrypted_data_len = encapsulated_key_pos - 12;
    const unsigned char* encrypted_data = full_payload.data() + 12;
    std::vector<unsigned char> decrypted_data(encrypted_data_len);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key.data(), nonce);
    int outlen;
    EVP_DecryptUpdate(ctx, decrypted_data.data(), &outlen, encrypted_data, encrypted_data_len - 16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)(encrypted_data + encrypted_data_len - 16));

    if (EVP_DecryptFinal_ex(ctx, decrypted_data.data() + outlen, &outlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx); std::cerr << "错误: AES-GCM解密失败 (Tag验证失败)。" << std::endl; return false;
    }
    EVP_CIPHER_CTX_free(ctx);

    try {
        config_json = json::parse(decrypted_data);
    } catch (const json::parse_error& e) {
        std::cerr << "错误: 解析JSON配置失败: " << e.what() << std::endl; return false;
    }
    return true;
}

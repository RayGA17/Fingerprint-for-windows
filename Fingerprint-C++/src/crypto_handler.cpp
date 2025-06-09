// src/crypto_handler.cpp
#include "crypto_handler.hpp"
#include <openssl/evp.h>
#include <stdexcept>

CryptoHandler::CryptoHandler(const std::string& sig_alg) : signature_algorithm(sig_alg) {
    sig_handler = OQS_SIG_new(signature_algorithm.c_str());
    if (!sig_handler) { throw std::runtime_error("不支持的签名算法: " + sig_alg); }
}

CryptoHandler::~CryptoHandler() { if (sig_handler) { OQS_SIG_free(sig_handler); } }

std::vector<uint8_t> CryptoHandler::sha256(const std::string& data) const {
    std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
    unsigned int len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data.c_str(), data.length());
    EVP_DigestFinal_ex(ctx, hash.data(), &len);
    EVP_MD_CTX_free(ctx);
    hash.resize(len);
    return hash;
}

bool CryptoHandler::sign(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sk, DeviceFingerprint::Signature* p) const {
    std::vector<uint8_t> sig(sig_handler->length_signature);
    size_t sig_len;
    if (OQS_SIG_sign(sig_handler, sig.data(), &sig_len, data.data(), data.size(), sk.data()) != OQS_SUCCESS) return false;
    sig.resize(sig_len);
    p->set_algorithm(signature_algorithm);
    p->set_signature_data(sig.data(), sig.size());
    return true;
}

bool CryptoHandler::verify(const std::vector<uint8_t>& data, const DeviceFingerprint::Signature& p, const std::vector<uint8_t>& pk) const {
    if (p.algorithm() != signature_algorithm) return false;
    std::string sig_data = p.signature_data();
    return OQS_SIG_verify(sig_handler, data.data(), data.size(), (uint8_t*)sig_data.c_str(), sig_data.size(), pk.data()) == OQS_SUCCESS;
}

std::vector<uint8_t> CryptoHandler::buildMerkleTree(const std::vector<std::vector<uint8_t>>& leaves) const {
    if (leaves.empty()) return {};
    if (leaves.size() == 1) return leaves[0];
    auto level = leaves;
    while (level.size() > 1) {
        if (level.size() % 2 != 0) level.push_back(level.back());
        std::vector<std::vector<uint8_t>> next_level;
        for (size_t i = 0; i < level.size(); i += 2) {
            std::string combined = std::string(level[i].begin(), level[i].end()) + std::string(level[i+1].begin(), level[i+1].end());
            next_level.push_back(sha256(combined));
        }
        level = next_level;
    }
    return level[0];
}

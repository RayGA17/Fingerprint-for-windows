// src/crypto_handler.hpp
#ifndef CRYPTO_HANDLER_HPP
#define CRYPTO_HANDLER_HPP

#include <string>
#include <vector>
#include <memory>
#include <oqs/oqs.h>
#include "fingerprint.pb.h"

class CryptoHandler {
public:
    CryptoHandler(const std::string& sig_alg);
    ~CryptoHandler();
    std::vector<uint8_t> sha256(const std::string& data) const;
    bool sign(const std::vector<uint8_t>& data, const std::vector<uint8_t>& private_key, DeviceFingerprint::Signature* proto) const;
    bool verify(const std::vector<uint8_t>& data, const DeviceFingerprint::Signature& proto, const std::vector<uint8_t>& public_key) const;
    std::vector<uint8_t> buildMerkleTree(const std::vector<std::vector<uint8_t>>& leaves) const;
private:
    std::string signature_algorithm;
    OQS_SIG* sig_handler = nullptr;
};
#endif

// src/pqc_config_handler.hpp
#ifndef PQC_CONFIG_HANDLER_HPP
#define PQC_CONFIG_HANDLER_HPP

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class PQCConfigHandler {
public:
    PQCConfigHandler(const std::string& kem_alg);
    bool loadAndDecrypt(const std::string& private_key_path, const std::string& encrypted_config_path);
    const json& getConfig() const;
private:
    std::string kem_algorithm;
    json config_json;
    static std::vector<uint8_t> readFile(const std::string& file_path);
};
#endif
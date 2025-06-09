// src/tpm_handler.hpp
#ifndef TPM_HANDLER_HPP
#define TPM_HANDLER_HPP

#include <string>
#include <vector>
#include "fingerprint.pb.h"

class TpmHandler {
public:
    TpmHandler(const std::wstring& key_name);
    bool initializeKey();
    bool sign(const std::vector<uint8_t>& data_to_sign, DeviceFingerprint::Signature* signature_proto);
    // 验证功能将在服务端实现，此处暂不提供
private:
    std::wstring key_name_ws;
    bool key_exists = false;
};
#endif
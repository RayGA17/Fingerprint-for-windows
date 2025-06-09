// src/tpm_handler.cpp
#include "tpm_handler.hpp"
#include <Windows.h>
#include <ncrypt.h>
#include <iostream>

#pragma comment(lib, "ncrypt.lib")

TpmHandler::TpmHandler(const std::wstring& key_name) : key_name_ws(key_name) {}

bool TpmHandler::initializeKey() {
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    SECURITY_STATUS status;

    if (FAILED(status = NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0))) {
        std::wcerr << L"错误: 无法打开TPM提供程序。错误码: 0x" << std::hex << status << std::endl;
        return false;
    }

    status = NCryptOpenKey(hProv, &hKey, key_name_ws.c_str(), 0, 0);
    if (status == NTE_KEY_NOT_FOUND) {
        if (FAILED(status = NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, key_name_ws.c_str(), 0, 0))) {
            std::wcerr << L"错误: 无法创建TPM密钥。错误码: 0x" << std::hex << status << std::endl;
        } else if (FAILED(status = NCryptFinalizeKey(hKey, 0))) {
            std::wcerr << L"错误: 无法完成TPM密钥创建。错误码: 0x" << std::hex << status << std::endl;
        }
    }

    if (SUCCEEDED(status)) key_exists = true;
    else std::wcerr << L"错误: 无法初始化TPM密钥。错误码: 0x" << std::hex << status << std::endl;

    if (hKey) NCryptFreeObject(hKey);
    if (hProv) NCryptFreeObject(hProv);
    return key_exists;
}

bool TpmHandler::sign(const std::vector<uint8_t>& data_to_sign, DeviceFingerprint::Signature* signature_proto) {
    if (!key_exists) return false;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbSignature = 0;
    std::vector<BYTE> signature_buffer;
    SECURITY_STATUS status;

    if (FAILED(NCryptOpenStorageProvider(&hProv, MS_PLATFORM_CRYPTO_PROVIDER, 0)) ||
        FAILED(NCryptOpenKey(hProv, &hKey, key_name_ws.c_str(), 0, 0))) {
        if(hProv) NCryptFreeObject(hProv);
        return false;
    }

    BCRYPT_PKCS1_PADDING_INFO paddingInfo = { BCRYPT_SHA256_ALGORITHM };

    status = NCryptSignHash(hKey, &paddingInfo, (PBYTE)data_to_sign.data(), data_to_sign.size(), NULL, 0, &cbSignature, NCRYPT_PAD_PKCS1_FLAG);
    if (SUCCEEDED(status)) {
        signature_buffer.resize(cbSignature);
        status = NCryptSignHash(hKey, &paddingInfo, (PBYTE)data_to_sign.data(), data_to_sign.size(), signature_buffer.data(), cbSignature, &cbSignature, NCRYPT_PAD_PKCS1_FLAG);
    }
    
    if (SUCCEEDED(status)) {
        signature_proto->set_algorithm("TPM-RSA-PKCS1-SHA256");
        signature_proto->set_signature_data(signature_buffer.data(), cbSignature);
    }

    if (hKey) NCryptFreeObject(hKey);
    if (hProv) NCryptFreeObject(hProv);
    return SUCCEEDED(status);
}

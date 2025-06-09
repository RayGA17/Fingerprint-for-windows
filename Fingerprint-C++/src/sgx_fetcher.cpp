// src/sgx_fetcher.cpp
#include "sgx_fetcher.hpp"
#include <string>

void fill_item(DeviceFingerprint::FingerprintItem* item, const std::string& name, const std::string& value, const std::string& method, const std::string& source);

void SgxFetcher::fetch(DeviceFingerprint::DeviceFingerprintReport* report) {
    // 这是一个占位符实现。实际的SGX集成需要Intel SGX SDK
    // 并创建一个独立的Enclave项目。此处仅报告SGX不可用。
    auto* item = report->add_all_items();
    item->set_name("tee.sgx_quote");
    item->set_status(DeviceFingerprint::ItemStatus::TEE_UNAVAILABLE);
    item->set_status_message("SGX SDK/environment not configured for this build.");
    item->mutable_provenance()->set_source("Intel SGX");
    item->mutable_provenance()->set_method("Remote Attestation Quote");
}

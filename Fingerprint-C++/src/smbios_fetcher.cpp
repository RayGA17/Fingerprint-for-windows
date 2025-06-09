// src/smbios_fetcher.cpp
#include "smbios_fetcher.hpp"
#include <Windows.h>
#include <vector>
#include <string>

void fill_item(DeviceFingerprint::FingerprintItem* item, const std::string& name, const std::string& value, const std::string& method, const std::string& source);

void fill_smbios_item(DeviceFingerprint::FingerprintItem* item, const std::string& name, const std::string& value, const std::string& method) {
    if (value.empty() || value.find("To be filled") != std::string::npos || value.find("None") != std::string::npos) {
        item->set_status(DeviceFingerprint::ItemStatus::NOT_FOUND);
        item->set_status_message("Firmware reports non-actual value");
    } else {
        item->set_status(DeviceFingerprint::ItemStatus::SUCCESS);
        item->set_value(value);
    }
    item->set_name(name);
    item->mutable_provenance()->set_source("SMBIOS");
    item->mutable_provenance()->set_method(method);
}

const char* SmbiosFetcher::getStringFromTable(const SMBIOSHeader* h, uint8_t idx) {
    if (idx == 0) return "Not Specified";
    const char* p = reinterpret_cast<const char*>(h) + h->Length;
    for (uint8_t i = 1; i < idx; ++i) p += strlen(p) + 1;
    return p;
}

void SmbiosFetcher::fetch(DeviceFingerprint::DeviceFingerprintReport* report) {
    DWORD size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (size == 0) return;
    std::vector<BYTE> buf(size);
    GetSystemFirmwareTable('RSMB', 0, buf.data(), size);
    
    const BYTE* table_data = buf.data() + 8;
    const DWORD table_size = size - 8;
    const BYTE* end = table_data + table_size;
    const SMBIOSHeader* h = reinterpret_cast<const SMBIOSHeader*>(table_data);

    while (reinterpret_cast<const BYTE*>(h) < end && h->Type != 127) {
        if (h->Type == 2) {
            const auto* t2 = reinterpret_cast<const SMBIOS_Type2*>(h);
            fill_smbios_item(report->add_all_items(), "mainboard.serial_number", getStringFromTable(h, t2->SerialNumber), "Type 2");
        }
        const BYTE* next = reinterpret_cast<const BYTE*>(h) + h->Length;
        while (next < end && (*next != 0 || *(next + 1) != 0)) next++;
        h = reinterpret_cast<const SMBIOSHeader*>(next + 2);
    }
}

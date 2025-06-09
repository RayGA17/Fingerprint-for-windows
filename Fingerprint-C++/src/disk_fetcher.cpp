// src/disk_fetcher.cpp
#include "disk_fetcher.hpp"
#include <Windows.h>
#include <string>
#include <vector>
#include <algorithm>

void fill_item(DeviceFingerprint::FingerprintItem* item, const std::string& name, const std::string& value, const std::string& method, const std::string& source);

std::string clean_device_string(char* str) {
    std::string s(str);
    s.erase(s.find_last_not_of(" \n\r\t") + 1);
    s.erase(0, s.find_first_not_of(" \n\r\t"));
    return s;
}

void DiskFetcher::fetch(DeviceFingerprint::DeviceFingerprintReport* report) {
    for (int i = 0; i < 16; ++i) {
        HANDLE h = CreateFileW((L"\\\\.\\PhysicalDrive" + std::to_wstring(i)).c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        
        std::vector<char> buf(1024);
        STORAGE_PROPERTY_QUERY q = {StorageDeviceProperty, PropertyStandardQuery};
        DWORD read = 0;
        
        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), buf.data(), buf.size(), &read, NULL)) {
            auto* d = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buf.data());
            std::string prefix = "disk" + std::to_string(i);
            if (d->SerialNumberOffset) fill_item(report->add_all_items(), prefix + ".serial_number", clean_device_string(buf.data() + d->SerialNumberOffset), "IOCTL_STORAGE_QUERY_PROPERTY", "DeviceIoControl");
        }
        CloseHandle(h);
    }
}

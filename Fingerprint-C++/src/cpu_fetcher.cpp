// src/cpu_fetcher.cpp
#include "cpu_fetcher.hpp"
#include <vector>
#include <string>
#include <array>
#include <algorithm>
#include <intrin.h>

// 帮助函数声明，定义在main.cpp
void fill_item(DeviceFingerprint::FingerprintItem* item, const std::string& name, const std::string& value, const std::string& method, const std::string& source = "CPUID");

void CpuFetcher::fetch(DeviceFingerprint::DeviceFingerprintReport* report) {
    std::array<int, 4> regs;
    
    __cpuid(regs.data(), 0);
    std::string vendor;
    vendor.append(reinterpret_cast<char*>(&regs[1]), 4);
    vendor.append(reinterpret_cast<char*>(&regs[3]), 4);
    vendor.append(reinterpret_cast<char*>(&regs[2]), 4);
    fill_item(report->add_all_items(), "cpu.vendor_id", vendor, "Leaf 0");

    std::string brand;
    for (unsigned int i = 0x80000002; i <= 0x80000004; ++i) {
        __cpuidex(regs.data(), i, 0);
        brand.append(reinterpret_cast<char*>(regs.data()), 16);
    }
    brand.erase(std::find(brand.begin(), brand.end(), '\0'), brand.end());
    fill_item(report->add_all_items(), "cpu.brand_string", brand, "Leaves 0x80000002-4");

    __cpuid(regs.data(), 1);
    if (regs[2] & (1 << 28)) fill_item(report->add_all_items(), "cpu.feature", "AVX", "Leaf 1, ECX");
    if (regs[2] & (1 << 25)) fill_item(report->add_all_items(), "cpu.feature", "AES-NI", "Leaf 1, ECX");
}


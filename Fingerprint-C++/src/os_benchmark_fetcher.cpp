// src/os_benchmark_fetcher.cpp
#include "os_benchmark_fetcher.hpp"
#include <Windows.h>
#include <string>

void fill_item(DeviceFingerprint::FingerprintItem* item, const std::string& name, const std::string& value, const std::string& method, const std::string& source);

void OsBenchmarkFetcher::fetch(DeviceFingerprint::DeviceFingerprintReport* report) {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        fill_item(report->add_all_items(), "os.hostname", std::string(computerName), "GetComputerNameA", "Kernel32");
    }

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    volatile long long r = 0;
    for (long long i = 0; i < 200000000; ++i) r += i;
    QueryPerformanceCounter(&end);
    double duration = static_cast<double>(end.QuadPart - start.QuadPart) / freq.QuadPart;
    fill_item(report->add_all_items(), "benchmark.cpu_integer_score", std::to_string(1.0 / duration), "Integer Loop", "PerformanceCounter");
}
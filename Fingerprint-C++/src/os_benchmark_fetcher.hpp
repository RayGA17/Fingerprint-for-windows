// src/os_benchmark_fetcher.hpp
#ifndef OS_BENCHMARK_FETCHER_HPP
#define OS_BENCHMARK_FETCHER_HPP
#include "fingerprint.pb.h"
class OsBenchmarkFetcher { public: static void fetch(DeviceFingerprint::DeviceFingerprintReport* report); };
#endif
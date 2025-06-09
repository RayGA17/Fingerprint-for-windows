// src/cpu_fetcher.hpp
#ifndef CPU_FETCHER_HPP
#define CPU_FETCHER_HPP

#include "fingerprint.pb.h"

class CpuFetcher {
public:
    static void fetch(DeviceFingerprint::DeviceFingerprintReport* report);
};
#endif

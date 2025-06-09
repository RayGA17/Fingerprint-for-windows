// src/gpu_fetcher.hpp
#ifndef GPU_FETCHER_HPP
#define GPU_FETCHER_HPP
#include "fingerprint.pb.h"
class GpuFetcher { public: static void fetch(DeviceFingerprint::DeviceFingerprintReport* report); };
#endif

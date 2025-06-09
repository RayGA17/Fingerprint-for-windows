// src/disk_fetcher.hpp
#ifndef DISK_FETCHER_HPP
#define DISK_FETCHER_HPP
#include "fingerprint.pb.h"
class DiskFetcher { public: static void fetch(DeviceFingerprint::DeviceFingerprintReport* report); };
#endif

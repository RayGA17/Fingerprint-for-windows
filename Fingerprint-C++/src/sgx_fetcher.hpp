// src/sgx_fetcher.hpp
#ifndef SGX_FETCHER_HPP
#define SGX_FETCHER_HPP
#include "fingerprint.pb.h"
class SgxFetcher { public: static void fetch(DeviceFingerprint::DeviceFingerprintReport* report); };
#endif

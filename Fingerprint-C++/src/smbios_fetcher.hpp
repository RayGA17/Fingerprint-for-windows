// src/smbios_fetcher.hpp
#ifndef SMBIOS_FETCHER_HPP
#define SMBIOS_FETCHER_HPP

#include "fingerprint.pb.h"
#include <cstdint>

#pragma pack(push, 1)
struct SMBIOSHeader { uint8_t Type; uint8_t Length; uint16_t Handle; };
struct SMBIOS_Type2 { SMBIOSHeader Header; uint8_t Manufacturer; uint8_t Product; uint8_t Version; uint8_t SerialNumber; };
#pragma pack(pop)

class SmbiosFetcher {
public:
    static void fetch(DeviceFingerprint::DeviceFingerprintReport* report);
private:
    static const char* getStringFromTable(const SMBIOSHeader* header, uint8_t string_index);
};
#endif

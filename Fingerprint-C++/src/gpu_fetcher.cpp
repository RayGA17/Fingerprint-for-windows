// src/gpu_fetcher.cpp
#include "gpu_fetcher.hpp"
#include <Windows.h>
#include <dxgi1_4.h>
#include <string>

void fill_item(DeviceFingerprint::FingerprintItem* item, const std::string& name, const std::string& value, const std::string& method, const std::string& source);

void GpuFetcher::fetch(DeviceFingerprint::DeviceFingerprintReport* report) {
    IDXGIFactory4* factory;
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory4), (void**)&factory))) return;
    
    IDXGIAdapter1* adapter;
    for (UINT i = 0; factory->EnumAdapters1(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
        DXGI_ADAPTER_DESC1 desc;
        adapter->GetDesc1(&desc);
        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) { adapter->Release(); continue; }
        
        std::wstring wdesc(desc.Description);
        int size = WideCharToMultiByte(CP_UTF8, 0, &wdesc[0], (int)wdesc.size(), NULL, 0, NULL, NULL);
        std::string desc_str(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wdesc[0], (int)wdesc.size(), &desc_str[0], size, NULL, NULL);

        fill_item(report->add_all_items(), "gpu" + std::to_string(i) + ".description", desc_str, "GetDesc1", "DXGI");
        adapter->Release();
    }
    factory->Release();
}


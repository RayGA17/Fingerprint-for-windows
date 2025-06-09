# fetchers/cpu_fetcher.py
import wmi

class CpuFetcher:
    def __init__(self):
        try:
            self.w = wmi.WMI()
        except Exception as e:
            self.w = None
            print(f"警告: WMI初始化失败，CPU信息将无法获取。错误: {e}")

    def fetch(self):
        if not self.w:
            return []
        items = []
        try:
            cpu = self.w.Win32_Processor()[0]
            items.append(("cpu.brand_string", cpu.Name.strip(), "WMI.Win32_Processor.Name"))
            items.append(("cpu.vendor_id", cpu.Manufacturer.strip(), "WMI.Win32_Processor.Manufacturer"))
            items.append(("cpu.core_count", str(cpu.NumberOfCores), "WMI.Win32_Processor.NumberOfCores"))
            items.append(("cpu.logical_processor_count", str(cpu.NumberOfLogicalProcessors), "WMI.Win32_Processor.NumberOfLogicalProcessors"))
            items.append(("cpu.l2_cache_size_kb", str(cpu.L2CacheSize), "WMI.Win32_Processor.L2CacheSize"))
            items.append(("cpu.l3_cache_size_kb", str(cpu.L3CacheSize), "WMI.Win32_Processor.L3CacheSize"))
        except Exception as e:
            print(f"获取CPU信息失败: {e}")
        return items

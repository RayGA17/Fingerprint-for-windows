# fetchers/gpu_fetcher.py
import wmi

class GpuFetcher:
    def __init__(self):
        try:
            self.w = wmi.WMI()
        except Exception as e:
            self.w = None
            print(f"警告: WMI初始化失败，GPU信息将无法获取。错误: {e}")

    def fetch(self):
        if not self.w:
            return []
        items = []
        try:
            for i, gpu in enumerate(self.w.Win32_VideoController()):
                prefix = f"gpu.{i}"
                if gpu.Description:
                    items.append((f"{prefix}.description", gpu.Description.strip(), "WMI.Win32_VideoController.Description"))
                if gpu.AdapterRAM:
                    ram_mb = gpu.AdapterRAM // (1024 * 1024)
                    items.append((f"{prefix}.adapter_ram_mb", str(ram_mb), "WMI.Win32_VideoController.AdapterRAM"))
                if gpu.DriverVersion:
                    items.append((f"{prefix}.driver_version", gpu.DriverVersion.strip(), "WMI.Win32_VideoController.DriverVersion"))
                if gpu.VideoProcessor:
                    items.append((f"{prefix}.video_processor", gpu.VideoProcessor.strip(), "WMI.Win32_VideoController.VideoProcessor"))
        except Exception as e:
            print(f"获取GPU信息失败: {e}")
        return items

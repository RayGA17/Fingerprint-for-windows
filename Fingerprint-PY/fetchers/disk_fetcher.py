# fetchers/disk_fetcher.py
import wmi

class DiskFetcher:
    def __init__(self):
        try:
            self.w = wmi.WMI()
        except Exception as e:
            self.w = None
            print(f"警告: WMI初始化失败，磁盘信息将无法获取。错误: {e}")

    def fetch(self):
        if not self.w:
            return []
        items = []
        try:
            for i, disk in enumerate(self.w.Win32_DiskDrive()):
                prefix = f"disk.{i}"
                if disk.SerialNumber:
                    items.append((f"{prefix}.serial_number", disk.SerialNumber.strip(), "WMI.Win32_DiskDrive.SerialNumber"))
                if disk.Model:
                    items.append((f"{prefix}.model", disk.Model.strip(), "WMI.Win32_DiskDrive.Model"))
                if disk.FirmwareRevision:
                     items.append((f"{prefix}.firmware", disk.FirmwareRevision.strip(), "WMI.Win32_DiskDrive.FirmwareRevision"))
                if disk.Size:
                    size_gb = int(disk.Size) // (1024**3)
                    items.append((f"{prefix}.size_gb", str(size_gb), "WMI.Win32_DiskDrive.Size"))
        except Exception as e:
            print(f"获取磁盘信息失败: {e}")
        return items

# fetchers/smbios_fetcher.py
import wmi


class SmbiosFetcher:
    def __init__(self):
        try:
            self.w = wmi.WMI()
        except Exception as e:
            self.w = None
            print(f"警告: WMI初始化失败，SMBIOS信息将无法获取。错误: {e}")

    def fetch(self):
        if not self.w:
            return []
        items = []
        try:
            board = self.w.Win32_BaseBoard()[0]
            items.append(("mainboard.serial_number", board.SerialNumber.strip(), "WMI.Win32_BaseBoard.SerialNumber"))
            items.append(("mainboard.product", board.Product.strip(), "WMI.Win32_BaseBoard.Product"))
            items.append(("mainboard.manufacturer", board.Manufacturer.strip(), "WMI.Win32_BaseBoard.Manufacturer"))

            bios = self.w.Win32_BIOS()[0]
            items.append(("bios.version", bios.Version.strip(), "WMI.Win32_BIOS.Version"))
            items.append(("bios.manufacturer", bios.Manufacturer.strip(), "WMI.Win32_BIOS.Manufacturer"))
        except Exception as e:
            print(f"获取SMBIOS信息失败: {e}")
        return items

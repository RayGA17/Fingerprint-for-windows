# fetchers/os_benchmark_fetcher.py
import wmi
import psutil
import time
import platform
import getpass


class OsBenchmarkFetcher:
    def __init__(self):
        try:
            self.w = wmi.WMI()
        except Exception as e:
            self.w = None
            print(f"警告: WMI初始化失败，OS信息将受影响。错误: {e}")

    def fetch(self):
        items = []

        # --- OS Info ---
        try:
            items.append(("os.platform", platform.platform(), "platform.platform"))
            items.append(("os.hostname", platform.node(), "platform.node"))
            items.append(("os.user", getpass.getuser(), "getpass.getuser"))
            if self.w:
                os_info = self.w.Win32_OperatingSystem()[0]
                items.append(("os.name", os_info.Caption.strip(), "WMI.Win32_OperatingSystem.Caption"))
                items.append(("os.version", os_info.Version, "WMI.Win32_OperatingSystem.Version"))
                items.append(("os.install_date", os_info.InstallDate, "WMI.Win32_OperatingSystem.InstallDate"))
        except Exception as e:
            print(f"获取OS信息失败: {e}")

        # --- Benchmark ---
        try:
            # 整数运算基准
            start_time = time.perf_counter()
            result = 0
            # 注意: Python的循环性能远低于C++，因此循环次数减少
            for i in range(20_000_000):
                result += (i * 5 - i * 2) // 3
            end_time = time.perf_counter()
            duration = end_time - start_time
            score = 1.0 / duration if duration > 0 else 0
            items.append(("benchmark.cpu_integer_score", f"{score:.4f}", "Integer Loop"))

            # 浮点运算基准
            start_time = time.perf_counter()
            f_result = 0.0
            for i in range(10_000_000):
                f_result += float(i) * 1.234 - float(i) * 0.123
            end_time = time.perf_counter()
            duration = end_time - start_time
            score = 1.0 / duration if duration > 0 else 0
            items.append(("benchmark.cpu_float_score", f"{score:.4f}", "Float Loop"))
        except Exception as e:
            print(f"执行基准测试失败: {e}")

        return items
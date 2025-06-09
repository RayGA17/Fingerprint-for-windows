# main_gui.py
import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QFileDialog, QMessageBox)
from PyQt6.QtGui import QIcon, QPalette, QColor
from PyQt6.QtCore import Qt

# 导入所有模块
from backend import Backend
from ui.analysis_tab import AnalysisTab
from ui.comparison_tab import ComparisonTab
from ui.config_tab import ConfigTab


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("设备指纹分析与管理平台 v1.0.1")
        self.setGeometry(100, 100, 1300, 900)
        # 您需要创建一个assets/icon.png文件
        if os.path.exists("assets/icon.png"):
            self.setWindowIcon(QIcon("assets/icon.png"))

        try:
            self.backend = Backend()
        except Exception as e:
            QMessageBox.critical(self, "严重错误", f"后端初始化失败: {e}")
            sys.exit(1)

        # 创建并设置主Tab控件
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.analysis_tab = AnalysisTab()
        self.comparison_tab = ComparisonTab(self.backend)
        self.config_tab = ConfigTab(self.backend)

        self.tabs.addTab(self.analysis_tab, "单文件分析")
        self.tabs.addTab(self.comparison_tab, "双文件比对")
        self.tabs.addTab(self.config_tab, "配置与密钥生成")

        self.init_interactions()

    def init_interactions(self):
        self.analysis_tab.load_button.clicked.connect(self.load_for_analysis)
        self.comparison_tab.btn_load1.clicked.connect(lambda: self.load_for_comparison(1))
        self.comparison_tab.btn_load2.clicked.connect(lambda: self.load_for_comparison(2))

    def load_for_analysis(self):
        fp_path, _ = QFileDialog.getOpenFileName(self, "选择指纹文件", "", "指纹文件 (*.bin)")
        if not fp_path: return
        pub_key_path, _ = QFileDialog.getOpenFileName(self, "选择签名公钥 (sig_public.key)", "", "*.key")
        if not pub_key_path: return

        self.analysis_tab.text_browser.setText(f"正在分析 {os.path.basename(fp_path)}...")
        QApplication.processEvents()

        c_val_result = self.backend.run_c_validation(fp_path, pub_key_path)
        report_data = self.backend.parse_fingerprint_file(fp_path)

        if not report_data:
            self.analysis_tab.update_status({"success": False, "output": "无法解析Protobuf文件"}, {})
            self.analysis_tab.tree.clear()
            return

        py_val_results = self.backend.verify_all_items_py(report_data, pub_key_path)

        self.analysis_tab.update_status(c_val_result, py_val_results)
        self.analysis_tab.populate_tree(report_data, py_val_results)
        self.analysis_tab.text_browser.setText(c_val_result['output'])

    def load_for_comparison(self, file_num):
        fp_path, _ = QFileDialog.getOpenFileName(self, f"为比对加载文件 {file_num}", "", "*.bin")
        if not fp_path: return
        report = self.backend.parse_fingerprint_file(fp_path)
        if not report:
            QMessageBox.warning(self, "错误", "无法解析此指纹文件。")
            return

        if file_num == 1:
            self.comparison_tab.report1 = report
            self.comparison_tab.lbl_file1.setText(f"文件1: {os.path.basename(fp_path)}")
        else:
            self.comparison_tab.report2 = report
            self.comparison_tab.lbl_file2.setText(f"文件2: {os.path.basename(fp_path)}")

        self.comparison_tab.update_comparison_view()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    # 暗色主题 (可选)
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
    palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    app.setPalette(palette)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())

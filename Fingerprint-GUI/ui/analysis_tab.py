# ui/analysis_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QTreeWidget, QTreeWidgetItem, QGroupBox, QHeaderView, QTextBrowser)
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import Qt
import fingerprint_pb2 as pb

# 将枚举值映射到可读的字符串
STATUS_MAP = {
    pb.SUCCESS: "成功", pb.NOT_SUPPORTED: "不支持", pb.PERMISSION_DENIED: "无权限", pb.API_ERROR: "API错误",
    pb.TIMEOUT: "超时", pb.NOT_FOUND: "未找到", pb.TEE_UNAVAILABLE: "TEE不可用", pb.UNKNOWN_ERROR: "未知错误"
}
STATUS_COLOR_MAP = {
    pb.SUCCESS: QColor("#d4edda"), pb.NOT_SUPPORTED: QColor("#e2e3e5"), pb.PERMISSION_DENIED: QColor("#fff3cd"),
    pb.API_ERROR: QColor("#f8d7da"), pb.TIMEOUT: QColor("#fff3cd"), pb.NOT_FOUND: QColor("#fff3cd"),
    pb.TEE_UNAVAILABLE: QColor("#e2d9f3"), pb.UNKNOWN_ERROR: QColor("#f8d7da")
}


class AnalysisTab(QWidget):
    def __init__(self):
        super().__init__()
        self.main_layout = QVBoxLayout(self)
        self.init_ui()

    def init_ui(self):
        self.load_button = QPushButton("加载指纹文件进行分析 (.bin)")
        self.main_layout.addWidget(self.load_button)

        status_box = QGroupBox("加密验证摘要")
        status_layout = QHBoxLayout()
        self.lbl_tpm = QLabel("TPM聚合签名: ❓")
        self.lbl_merkle = QLabel("Merkle树完整性: ❓")
        self.lbl_items = QLabel("个体签名: ❓")
        for lbl in [self.lbl_tpm, self.lbl_merkle, self.lbl_items]:
            lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            status_layout.addWidget(lbl)
        status_box.setLayout(status_layout)
        self.main_layout.addWidget(status_box)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(6)
        self.tree.setHeaderLabels(["名称", "值", "状态", "来源", "方法", "签名状态"])
        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.main_layout.addWidget(self.tree)

        self.text_browser = QTextBrowser()
        self.text_browser.setFontFamily("Consolas")
        self.text_browser.setPlaceholderText("C++校验程序的详细输出将显示在这里...")
        self.text_browser.setMaximumHeight(150)
        self.main_layout.addWidget(self.text_browser)

    def update_status(self, c_val_result: dict, item_statuses: dict):
        # TPM状态
        if "TPM聚合签名成功" in c_val_result.get('output', '') or "TPM聚合签名有效" in c_val_result.get('output', ''):
            self.lbl_tpm.setText("✅ TPM聚合签名: 有效")
            self.lbl_tpm.setStyleSheet("color: lightgreen;")
        else:
            self.lbl_tpm.setText("❌ TPM聚合签名: 无效或未找到")
            self.lbl_tpm.setStyleSheet("color: red;")

        # Merkle状态
        if "Merkle树完整性校验通过" in c_val_result.get('output', '') or "Merkle树根匹配" in c_val_result.get('output',
                                                                                                              ''):
            self.lbl_merkle.setText("✅ Merkle树完整性: 匹配")
            self.lbl_merkle.setStyleSheet("color: lightgreen;")
        else:
            self.lbl_merkle.setText("❌ Merkle树完整性: 不匹配")
            self.lbl_merkle.setStyleSheet("color: red;")

        # 个体签名状态
        if "error" in item_statuses:
            self.lbl_items.setText(f"❌ 个体签名: 验证出错 - {item_statuses['error']}")
            self.lbl_items.setStyleSheet("color: red;")
        elif item_statuses:
            all_valid = all(status[0] for status in item_statuses.values())
            if all_valid:
                self.lbl_items.setText(f"✅ 个体签名: 全部有效 ({len(item_statuses)})")
                self.lbl_items.setStyleSheet("color: lightgreen;")
            else:
                invalid_count = sum(1 for status in item_statuses.values() if not status[0])
                self.lbl_items.setText(f"❌ 个体签名: {invalid_count}个无效")
                self.lbl_items.setStyleSheet("color: red;")
        else:
            self.lbl_items.setText("❓ 个体签名: 未验证")
            self.lbl_items.setStyleSheet("")

    def populate_tree(self, report_data: pb.DeviceFingerprintReport, item_statuses: dict):
        self.tree.clear()
        grouped_items = {}
        for i, item in enumerate(report_data.all_items):
            source = item.provenance.source or "Unknown"
            if source not in grouped_items: grouped_items[source] = []
            grouped_items[source].append((item, i))

        for source, items in grouped_items.items():
            parent = QTreeWidgetItem(self.tree, [f"{source} ({len(items)}项)"])
            parent.setFont(0, QFont("Segoe UI", 9, QFont.Weight.Bold))
            for item, i in items:
                item_id = f"{item.name}_{i}"
                sig_status = item_statuses.get(item_id, (False, "未验证"))

                value_text = item.value or item.raw_value.hex()
                child = QTreeWidgetItem(parent, [
                    item.name, value_text[:200] + ('...' if len(value_text) > 200 else ''),
                    STATUS_MAP.get(item.status, "未知"), item.provenance.source,
                    item.provenance.method, sig_status[1]
                ])
                child.setBackground(2, STATUS_COLOR_MAP.get(item.status, QColor("white")))
                child.setForeground(5, QColor("lightgreen") if sig_status[0] else QColor("red"))
        self.tree.expandAll()

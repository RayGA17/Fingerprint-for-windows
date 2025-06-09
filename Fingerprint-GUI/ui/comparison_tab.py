# ui/comparison_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QTreeWidget, QTreeWidgetItem, QGroupBox, QHeaderView)
from PyQt6.QtGui import QFont, QColor


class ComparisonTab(QWidget):
    def __init__(self, backend_logic):
        super().__init__()
        self.backend = backend_logic
        self.report1 = None
        self.report2 = None
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)

        control_box = QGroupBox("控制与结果")
        control_layout = QHBoxLayout()
        self.btn_load1 = QPushButton("加载文件 1 (.bin)")
        self.btn_load2 = QPushButton("加载文件 2 (.bin)")
        self.lbl_file1 = QLabel("文件1: 未加载")
        self.lbl_file2 = QLabel("文件2: 未加载")
        self.lbl_score = QLabel("相似度: --%")
        self.lbl_score.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        control_layout.addWidget(self.btn_load1)
        control_layout.addWidget(self.lbl_file1, 1)
        control_layout.addWidget(self.btn_load2)
        control_layout.addWidget(self.lbl_file2, 1)
        control_layout.addStretch()
        control_layout.addWidget(self.lbl_score)
        control_box.setLayout(control_layout)
        main_layout.addWidget(control_box)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(["指纹项", "文件 1 的值", "文件 2 的值"])
        header = self.tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        main_layout.addWidget(self.tree)

    def update_comparison_view(self):
        if not self.report1 or not self.report2:
            return

        result = self.backend.compare_reports(self.report1, self.report2)

        score = result.get('score', 0)
        self.lbl_score.setText(f"相似度: {score:.2f}%")
        if score > 85:
            self.lbl_score.setStyleSheet("color: lightgreen;")
        elif score > 60:
            self.lbl_score.setStyleSheet("color: orange;")
        else:
            self.lbl_score.setStyleSheet("color: red;")

        self.tree.clear()
        for detail in result.get('details', []):
            item = QTreeWidgetItem(self.tree)
            item.setText(0, detail['name'])
            item.setText(1, detail['val1'][:100])
            item.setText(2, detail['val2'][:100])

            status = detail['status']
            if status == "匹配":
                item.setBackground(0, QColor("#196F3D"))
                item.setForeground(0, QColor("white"))
            elif status == "不匹配":
                item.setBackground(0, QColor("#922B21"))
                item.setForeground(0, QColor("white"))
            else:
                item.setBackground(0, QColor("#424949"))
                item.setForeground(0, QColor("lightgray"))

        self.tree.expandAll()
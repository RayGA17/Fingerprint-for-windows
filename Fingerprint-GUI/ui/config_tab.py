# ui/config_tab.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QTextEdit,
                             QGroupBox, QFileDialog, QMessageBox, QLabel)
import json
import os


class ConfigTab(QWidget):
    def __init__(self, backend_logic):
        super().__init__()
        self.backend = backend_logic
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)

        key_box = QGroupBox("1. 生成PQC密钥对")
        key_layout = QVBoxLayout()
        self.btn_gen_keys = QPushButton("选择目录并生成所有密钥")
        self.btn_gen_keys.clicked.connect(self.generate_keys)
        key_layout.addWidget(QLabel("这将生成用于加密配置的Kyber密钥对和用于签名的Dilithium密钥对。"))
        key_layout.addWidget(self.btn_gen_keys)
        key_box.setLayout(key_layout)

        config_box = QGroupBox("2. 编辑并加密配置文件")
        config_layout = QVBoxLayout()
        self.txt_config = QTextEdit()
        self.txt_config.setFontFamily("Consolas")
        self.txt_config.setPlaceholderText("在此处粘贴或编辑JSON配置...")
        self.load_template()

        btn_encrypt = QPushButton("加密此配置")
        btn_encrypt.clicked.connect(self.encrypt_config)

        config_layout.addWidget(self.txt_config)
        config_layout.addWidget(btn_encrypt)
        config_box.setLayout(config_layout)

        main_layout.addWidget(key_box)
        main_layout.addWidget(config_box)
        main_layout.addStretch()

    def load_template(self):
        template = {
            "client_id": "client-001",
            "fingerprint_options": {
                "extract_cpu_details": True,
                "extract_smbios": True,
                "run_gpu_benchmark": False
            },
            "crypto_keys": {
                "item_signer_private_key_path": "C:/path/to/sig_private.key"
            }
        }
        self.txt_config.setText(json.dumps(template, indent=2))

    def generate_keys(self):
        dir_path = QFileDialog.getExistingDirectory(self, "选择保存密钥的目录")
        if not dir_path: return

        success, msg = self.backend.generate_pqc_keys("Kyber768", "Dilithium3", dir_path)
        QMessageBox.information(self, "密钥生成结果", msg)

    def encrypt_config(self):
        kem_pub_key_path, _ = QFileDialog.getOpenFileName(self, "选择用于加密的KEM公钥 (kem_public.key)", "", "*.key")
        if not kem_pub_key_path: return

        output_path, _ = QFileDialog.getSaveFileName(self, "保存加密配置文件为 (config.enc)", "", "*.enc")
        if not output_path: return

        config_str = self.txt_config.toPlainText()
        try:
            json.loads(config_str)
        except json.JSONDecodeError as e:
            QMessageBox.critical(self, "JSON错误", f"配置文件不是有效的JSON格式:\n{e}")
            return

        success, msg = self.backend.encrypt_config_file(config_str, kem_pub_key_path, output_path)
        QMessageBox.information(self, "加密结果", msg)
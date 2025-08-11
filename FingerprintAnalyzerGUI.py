import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import json
import base64
import hashlib
import struct
import threading
import time
import concurrent.futures
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ecdsa import VerifyingKey, NIST256p, BadSignatureError


# --- Core Processing Logic (與前一版相同) ---
class FingerprintProcessor:
    """
    處理所有後端邏輯，包括解密、驗證、可信度評估和相似度比較。
    """

    def __init__(self):
        # 【安全性強化】在真實應用中，此金鑰應從 HSM 或安全金鑰庫中載入
        self.rsa_private_key = self._load_private_key()
        if not self.rsa_private_key:
            print("CRITICAL: RSA Private Key could not be loaded.")

    def _load_private_key(self):
        # 此處僅為演示，實際應替換為安全的金鑰載入機制
        RSA_PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCc1rnT/RxWCzwl
z4OK0jEe6UQFJHsKKIxJctZ3bq4yaECGyIRm/Jy1/l6eODAMQ5fLQ8CmR+WF0nNJ
BL14RqqA/te/YiX+Pe7YFpTDAhYRxje+finDXPVS7wE+U1qkUQVS6Ck9eS12S1YX
C3UJWcxmieN5E/CE4qB9pSeHJFcZeQpdeU8yKs9M9xBFprfjwdtNwds4Pn71wH4M
a04ajeqdFlTWf2JFmd2bN4bY8jCFzhJpTOnuRccq+Z+VIUmLKAw7cNlLVAyzw/FX
0QzWGc5AhYtL5jqWkTZGo3YTivLKWwmVObAJiWHjdqSagSjAjt3KMUZsqabFm1Tv
y1kPRStbAgMBAAECggEAJPOAH55cHTeTabMc4kmIUiiSIoYISQnpl2prdgMJHo4q
WbcHXr44a7Zs82j4hQMt0bF6Q5Lf1CoTiEoKG7rGdBLWoNwOaHqN+bJERTeKHJDv
VD2kOEd/8xSlXdpEmj8OeoyBHt8cY2j3dQF5hwT1n9jv03hrq9s7Ba8yA2h/7tuT
sgwkwADEuiiYeEA7F6SDTIr5clNEqrv+v7pqd9qIJaW6qxA84u3V3RnlVYoLe97h
8HHunfbJ9ulcgUJPJ/iMww98OFhYoRvJ2jy6TM9l+dNocSlgemJ002iPcIWZ+85G
u/A6yReD5ZhVQAtoo19spNQJ3f1U5niAR0Q157ZssQKBgQDMbkeIZBuG1F69AxfB
R4yXictXDFWAOChBxIjKHwVak7kYY7at9hz+W+0LmkYkG+hEw3+Gy0obbeHEsHzm
D+e/yJuWBS1KmqPM++uPbu14Wsm9AUE5pjqbZTvr0bzNhFbpJToy0mvhzVCtmsCf
lpM36mcB2LtrLEVCBne/pXqq8QKBgQDEZw1jKHXqlt1FJRWm1rVC87/nFvufYcou
rGOAwNluM9w3I1O1wiqZLqHbn8YFM+7Gr+BreD8CwzbJN5PG7jp96Zkhr6wZ+MFB
skrVRnMgXapTiKXJ9LmIdE2agP121LjjFJpEEVmNbnCoxxaMc05W2+yLF1atzcE7
rTmdrO8DCwKBgAExC12yJ67rgfncEMFhp2IivXquabkrmqB3gsyaza8veT65JhFx
g82/v2v35DzFpN7xvMaOXMo4I76/wJqesR0fEDkZop/yss25EjBt1xiCfvaJEVZC
r8jEGEtRl6YjBVaqjuJI87QHPFcmtcS4XfdPeHY8SytewLCX1Q7a6hIhAoGAFbrd
JVJtsXXdp2/R9HKe/XhgjB3j2x+DsiRKog00QVgljkgvU9XWxrn9GIKV8y9qxLri
1qEoP5L/tcWbaRAkkpfM5Ig+P2VhZHZohy5TQIp8dN+SkESuXmWXzHdnE8W3axB1
fQB6awaEGnhki0earEuK4VzEr1grgAHLdSGUFD8CgYBElCHksaMA9fvWjGm8xPo1
uqhbFUfVeEe/8i/RT9Vvj+/e8WqyhJ7iJLfcrmkJkeN1Qxi3QYWOQwF9aUsVKwXb
YYl6QYbu/GctyqrSIOSQ7QOoRe9XSfVzycQ8C6vRI3WsMVYyLLM3Fo/g44WJwC5V
QAscjCsxpuS0ZnQOGN+yxg==
-----END PRIVATE KEY-----"""
        try:
            return serialization.load_pem_private_key(RSA_PRIVATE_KEY_PEM.encode(), password=None,
                                                      backend=default_backend())
        except Exception:
            return None

    def _aes_decrypt(self, nonce, ciphertext, tag, key):
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _sha256(self, data):
        return hashlib.sha256(data).digest()

    def _build_merkle_tree(self, leaves):
        if not leaves: return None
        level = leaves
        while len(level) > 1:
            if len(level) % 2 == 1: level.append(level[-1])
            level = [self._sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        return level[0]

    def load_and_decrypt_fpt(self, file_path):
        if not self.rsa_private_key: return None, None, "RSA private key not loaded."
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                if len(header) < 16: return None, None, "Invalid file header."
                version, algo_id, data_len = struct.unpack('!4s4sQ', header)
                if version != b'FPT1' or algo_id != b'AESG': return None, None, "Unsupported file format."

                encrypted_aes_key_b64 = f.read(344)
                nonce_data = f.read(12)
                tag_data = f.read(16)
                encrypted_data = f.read()  # Read the rest
                encrypted_data = encrypted_data[:data_len]  # Truncate to expected length

            aes_key = self.rsa_private_key.decrypt(
                base64.b64decode(encrypted_aes_key_b64),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            data_json = self._aes_decrypt(nonce_data, encrypted_data, tag_data, aes_key)
            fingerprint_data = json.loads(data_json.decode('utf-8'))

            decrypted_items = {}
            for item in fingerprint_data['signed_items']:
                name = self._aes_decrypt(base64.b64decode(item['nonce']), base64.b64decode(item['encrypted_name']),
                                         base64.b64decode(item['tag']), aes_key).decode('utf-8')
                value_raw = self._aes_decrypt(base64.b64decode(item['nonce_value']),
                                              base64.b64decode(item['encrypted_value']),
                                              base64.b64decode(item['tag_value']), aes_key)
                try:
                    value = json.loads(value_raw.decode('utf-8'))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    value = value_raw.decode('utf-8', 'replace')
                decrypted_items[name] = value

            fingerprint_data['decrypted_items'] = decrypted_items
            return fingerprint_data, aes_key, "Success"
        except Exception as e:
            return None, None, str(e)

    def verify_single_fingerprint(self, fingerprint_data, aes_key):
        logs = []
        try:
            ecdsa_pk = VerifyingKey.from_string(base64.b64decode(fingerprint_data['public_keys']['ecdsa_pk']),
                                                curve=NIST256p, hashfunc=hashlib.sha256)
            logs.append(("SUCCESS", "ECDSA public key loaded."))

            leaf_hashes = []
            for item in fingerprint_data['signed_items']:
                name = self._aes_decrypt(base64.b64decode(item['nonce']), base64.b64decode(item['encrypted_name']),
                                         base64.b64decode(item['tag']), aes_key)
                value = self._aes_decrypt(base64.b64decode(item['nonce_value']),
                                          base64.b64decode(item['encrypted_value']),
                                          base64.b64decode(item['tag_value']), aes_key)
                salt, rsa_enc_sig = base64.b64decode(item['salt']), base64.b64decode(
                    item['rsa_encrypted_ecdsa_signature'])
                decrypted_sig = self.rsa_private_key.decrypt(rsa_enc_sig,
                                                             padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                          algorithm=hashes.SHA256(), label=None))
                salted_data = salt + name + value
                ecdsa_pk.verify(decrypted_sig, salted_data)
                leaf_hashes.append(self._sha256(salted_data))
            logs.append(("SUCCESS", "All item signatures verified."))

            expected_merkle_root = base64.b64decode(fingerprint_data['merkle_root'])
            computed_merkle_root = self._build_merkle_tree(leaf_hashes)
            if computed_merkle_root != expected_merkle_root: raise ValueError("Merkle root mismatch")
            logs.append(("SUCCESS", "Merkle Tree root is valid."))

            metadata_json = self._aes_decrypt(base64.b64decode(fingerprint_data['metadata']['nonce']),
                                              base64.b64decode(fingerprint_data['metadata']['encrypted_metadata']),
                                              base64.b64decode(fingerprint_data['metadata']['tag']), aes_key)
            salted_report = base64.b64decode(
                fingerprint_data['metadata']['salt']) + metadata_json + expected_merkle_root
            report_hash = self._sha256(salted_report)
            ecdsa_pk.verify(base64.b64decode(fingerprint_data['ecdsa_report_signature']), report_hash)
            logs.append(("SUCCESS", "Overall report signature is valid."))

        except Exception as e:
            logs.append(("ERROR", f"Verification failed: {e}"))
        return logs

    def calculate_credibility(self, fingerprint_data, verification_logs):
        score = 100
        reasons = []
        if any("ERROR" in log[0] for log in verification_logs):
            return 0, "Verification failed, not credible."

        vm_status = fingerprint_data['decrypted_items'].get('virtualization.status', '')
        if 'detected' in vm_status.lower():
            score -= 40
            reasons.append(f"VM detected ({vm_status})")

        missing_count = sum(1 for key in ['mainboard.serial_number', 'bios.serial_number', 'disk.0.serial_number'] if
                            fingerprint_data['decrypted_items'].get(key, 'unknown').lower() == 'unknown')
        if missing_count > 0:
            score -= missing_count * 15
            reasons.append(f"{missing_count} critical S/N missing")

        return max(0, score), "; ".join(reasons) or "High credibility"

    def compare_fingerprints(self, target_data, db_data, features_to_compare, tolerance=0.05):
        target_items, db_items = target_data['decrypted_items'], db_data['decrypted_items']
        total_score, max_score = 0.0, 0.0
        for feature in features_to_compare:
            if feature not in target_items or feature not in db_items: continue
            max_score += 1
            target_val, db_val = target_items[feature], db_items[feature]
            if target_val is None or db_val is None or (
                    isinstance(target_val, str) and 'unknown' in target_val.lower()): continue

            try:
                if 'benchmark' in feature and isinstance(target_val, (float, int)):
                    if float(target_val) > 0 and abs(float(target_val) - float(db_val)) / float(
                            target_val) <= tolerance:
                        total_score += 1
                elif 'cpu.features' in feature:
                    set1, set2 = set(str(target_val).split(',')), set(str(db_val).split(','))
                    if not set1 or not set2: continue
                    total_score += len(set1.intersection(set2)) / len(set1.union(set2))
                elif str(target_val) == str(db_val):
                    total_score += 1
            except (ValueError, TypeError):
                continue  # Skip if type conversion fails
        return (total_score / max_score * 100) if max_score > 0 else 0


# --- GUI Application ---
class CombinedAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Fingerprint Analyzer & Comparator")
        self.root.geometry("1400x900")
        ctk.set_appearance_mode("Dark")

        self.processor = FingerprintProcessor()
        self.target_fpt_path, self.db_dir_path = "", ""
        self.target_fpt_data, self.target_aes_key = None, None

        self.features_list = [
            "cpu.brand_string", "cpu.core_count", "mainboard.serial_number", "bios.serial_number",
            "disk.0.serial_number", "gpu.0.description", "network.mac_hash", "benchmark.cpu_integer_score",
            "benchmark.cpu_float_score", "cpu.features"
        ]
        self.feature_vars = {f: tk.BooleanVar(value=True) for f in self.features_list}

        self._create_widgets()

    def _create_widgets(self):
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        # Top-level Tab View
        self.tab_view = ctk.CTkTabview(self.root, corner_radius=10, anchor="w")
        self.tab_view.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.tab_view.add("Single File Analysis")
        self.tab_view.add("Batch Comparison")
        self.tab_view.set("Single File Analysis")  # Set default tab

        self._create_single_analysis_tab(self.tab_view.tab("Single File Analysis"))
        self._create_batch_comparison_tab(self.tab_view.tab("Batch Comparison"))

    def _create_single_analysis_tab(self, tab):
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        # --- Controls and Credibility Display ---
        top_frame = ctk.CTkFrame(tab, fg_color="transparent")
        top_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        top_frame.grid_columnconfigure(1, weight=1)

        self.single_load_button = ctk.CTkButton(top_frame, text="Load and Analyze Single File",
                                                command=self._start_single_analysis)
        self.single_load_button.grid(row=0, column=0, padx=(0, 20))

        # --- NEW: Credibility Score Display ---
        credibility_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        credibility_frame.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(credibility_frame, text="Credibility Score:", font=ctk.CTkFont(size=14, weight="bold")).pack(
            side="left")
        self.credibility_score_label = ctk.CTkLabel(credibility_frame, text=" N/A",
                                                    font=ctk.CTkFont(size=14, weight="bold"),
                                                    text_color="#a0a0a0")
        self.credibility_score_label.pack(side="left", padx=5)

        # --- Results Display ---
        results_frame = ctk.CTkFrame(tab)
        results_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_rowconfigure(0, weight=1)

        paned_window = tk.PanedWindow(results_frame, orient=tk.VERTICAL, sashrelief=tk.RAISED, bg="#2b2b2b")
        paned_window.pack(fill="both", expand=True)

        tree_frame = ctk.CTkFrame(paned_window, fg_color="transparent")
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        style.map('Treeview', background=[('selected', '#1f6aa5')])
        self.single_details_tree = ttk.Treeview(tree_frame, columns=("Name", "Value"), show="headings")
        self.single_details_tree.heading("Name", text="Item Name", anchor='w')
        self.single_details_tree.heading("Value", text="Item Value", anchor='w')
        self.single_details_tree.pack(fill="both", expand=True)
        paned_window.add(tree_frame, minsize=200)

        log_frame = ctk.CTkFrame(paned_window, fg_color="transparent")
        self.single_log_text = ctk.CTkTextbox(log_frame, state="disabled", font=("Courier New", 12))
        self.single_log_text.pack(fill="both", expand=True)
        paned_window.add(log_frame, minsize=100)

    def _create_batch_comparison_tab(self, tab):
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(1, weight=1)  # Allow right frame to expand vertically

        # --- Left Control Frame ---
        left_frame = ctk.CTkFrame(tab, width=280, corner_radius=10)
        left_frame.grid(row=0, column=0, rowspan=2, padx=10, pady=10, sticky="ns")
        left_frame.grid_propagate(False)

        # File Selection
        ctk.CTkLabel(left_frame, text="1. Select Files", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10,
                                                                                                        padx=10,
                                                                                                        anchor="w")
        self.target_button = ctk.CTkButton(left_frame, text="Select Target Fingerprint",
                                           command=self._select_target_file)
        self.target_button.pack(fill="x", padx=10)
        self.target_label = ctk.CTkLabel(left_frame, text="No target selected", wraplength=260, fg_color="#333",
                                         corner_radius=5, pady=5)
        self.target_label.pack(fill="x", padx=10, pady=(5, 10))
        self.db_button = ctk.CTkButton(left_frame, text="Select Fingerprint Directory",
                                       command=self._select_db_directory)
        self.db_button.pack(fill="x", padx=10)
        self.db_label = ctk.CTkLabel(left_frame, text="No directory selected", wraplength=260, fg_color="#333",
                                     corner_radius=5, pady=5)
        self.db_label.pack(fill="x", padx=10, pady=(5, 20))

        # Comparison Settings
        ctk.CTkLabel(left_frame, text="2. Comparison Settings", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10,
                                                                                                               padx=10,
                                                                                                               anchor="w")
        feature_frame = ctk.CTkScrollableFrame(left_frame, label_text="Features to Compare")
        feature_frame.pack(fill="x", expand=True, padx=10)
        for feature in self.features_list:
            ctk.CTkCheckBox(feature_frame, text=feature, variable=self.feature_vars[feature]).pack(anchor="w", padx=10,
                                                                                                   pady=2)
        ctk.CTkLabel(left_frame, text="Similarity Threshold (%)").pack(pady=(10, 0))
        self.threshold_slider = ctk.CTkSlider(left_frame, from_=0, to=100)
        self.threshold_slider.set(75)
        self.threshold_slider.pack(fill="x", padx=10, pady=5)

        # Action Button
        self.run_button = ctk.CTkButton(left_frame, text="Start Comparison", font=ctk.CTkFont(size=14, weight="bold"),
                                        command=self._start_comparison, state="disabled")
        self.run_button.pack(pady=20, padx=10, ipady=5)

        # --- Right Results Area ---
        # --- NEW: Progress Bar ---
        self.progress_bar = ctk.CTkProgressBar(tab)
        self.progress_bar.grid(row=0, column=1, padx=(0, 10), pady=(10, 5), sticky="ew")
        self.progress_bar.set(0)

        # --- NEW: Tabbed Results View ---
        results_tab_view = ctk.CTkTabview(tab, corner_radius=10)
        results_tab_view.grid(row=1, column=1, padx=(0, 10), pady=(5, 10), sticky="nsew")
        results_tab_view.add("High Similarity Matches")
        results_tab_view.add("All Results")

        # High Similarity Tree
        self.similar_results_tree = ttk.Treeview(results_tab_view.tab("High Similarity Matches"),
                                                 columns=("File", "Similarity", "Credibility", "Reason"),
                                                 show="headings")
        self.similar_results_tree.heading("File", text="File Path", anchor='w')
        self.similar_results_tree.heading("Similarity", text="Similarity (%)", anchor='w')
        self.similar_results_tree.heading("Credibility", text="Credibility (%)", anchor='w')
        self.similar_results_tree.heading("Reason", text="Credibility Notes", anchor='w')
        self.similar_results_tree.pack(fill="both", expand=True, padx=5, pady=5)

        # All Results Tree
        self.batch_results_tree = ttk.Treeview(results_tab_view.tab("All Results"),
                                               columns=("File", "Similarity", "Credibility", "Reason"),
                                               show="headings")
        self.batch_results_tree.heading("File", text="File Path", anchor='w');
        self.batch_results_tree.heading("Similarity", text="Similarity (%)", anchor='w')
        self.batch_results_tree.heading("Credibility", text="Credibility (%)", anchor='w');
        self.batch_results_tree.heading("Reason", text="Credibility Notes", anchor='w')
        self.batch_results_tree.pack(fill="both", expand=True, padx=5, pady=5)

    def _start_single_analysis(self):
        path = filedialog.askopenfilename(title="Select Fingerprint File", filetypes=[("FPT files", "*.fpt")])
        if not path: return
        self.single_load_button.configure(state="disabled")
        self.credibility_score_label.configure(text=" N/A", text_color="#a0a0a0")
        self.single_details_tree.delete(*self.single_details_tree.get_children())
        self.single_log_text.configure(state="normal");
        self.single_log_text.delete("1.0", "end");
        self.single_log_text.configure(state="disabled")
        threading.Thread(target=self._single_analysis_worker, args=(path,), daemon=True).start()

    def _single_analysis_worker(self, path):
        self._log_single(f"Loading file: {os.path.basename(path)}...")
        data, aes_key, msg = self.processor.load_and_decrypt_fpt(path)
        if not data:
            self._log_single(f"ERROR: {msg}", "ERROR")
            self.root.after(0, self.single_load_button.configure, {"state": "normal"})
            return

        self._log_single("File decrypted. Populating details...")
        for name, value in data['decrypted_items'].items():
            self.root.after(0,
                            lambda n=name, v=str(value): self.single_details_tree.insert("", "end", values=(n, v)))

        self._log_single("Verifying signatures and integrity...")
        verification_logs = self.processor.verify_single_fingerprint(data, aes_key)
        for level, log_msg in verification_logs:
            self._log_single(log_msg, level)

        self._log_single("Calculating credibility...")
        credibility, reason = self.processor.calculate_credibility(data, verification_logs)

        # --- NEW: Update credibility display ---
        color = "lightgreen" if credibility > 70 else ("orange" if credibility > 40 else "salmon")
        self.root.after(0, self.credibility_score_label.configure,
                        {"text": f" {credibility:.1f}% ({reason})", "text_color": color})
        self._log_single(f"Credibility Score: {credibility:.1f}%. Reason: {reason}", "INFO")

        self.root.after(0, self.single_load_button.configure, {"state": "normal"})
        self._log_single("Analysis complete.")

    def _select_target_file(self):
        path = filedialog.askopenfilename(filetypes=[("FPT files", "*.fpt")])
        if path:
            self.target_fpt_path = path
            self.target_label.configure(text=os.path.basename(path))
            threading.Thread(target=self._load_target_worker, daemon=True).start()

    def _load_target_worker(self):
        self.target_button.configure(state="disabled")
        data, key, msg = self.processor.load_and_decrypt_fpt(self.target_fpt_path)
        if data:
            self.target_fpt_data, self.target_aes_key = data, key
            if self.db_dir_path: self.run_button.configure(state="normal")
        else:
            messagebox.showerror("Error", f"Failed to load target file: {msg}")
        self.target_button.configure(state="normal")

    def _select_db_directory(self):
        path = filedialog.askdirectory()
        if path:
            self.db_dir_path = path
            self.db_label.configure(text=path)
            if self.target_fpt_data: self.run_button.configure(state="normal")

    def _start_comparison(self):
        if not self.target_fpt_data or not self.db_dir_path: return
        selected_features = [f for f, v in self.feature_vars.items() if v.get()]
        if not selected_features:
            messagebox.showwarning("Warning", "Please select at least one feature to compare.")
            return

        self.run_button.configure(state="disabled")
        self.batch_results_tree.delete(*self.batch_results_tree.get_children())
        self.similar_results_tree.delete(*self.similar_results_tree.get_children())
        self.progress_bar.set(0)

        threading.Thread(target=self._comparison_worker,
                         args=(selected_features, self.threshold_slider.get()),
                         daemon=True).start()

    def _process_single_db_file(self, file_path, selected_features, tolerance):
        """Worker function for a single file in the batch, designed for ThreadPoolExecutor."""
        if file_path == self.target_fpt_path: return None
        db_data, _, msg = self.processor.load_and_decrypt_fpt(file_path)
        if not db_data: return None

        similarity = self.processor.compare_fingerprints(self.target_fpt_data, db_data, selected_features,
                                                         tolerance / 100.0)
        credibility, reason = self.processor.calculate_credibility(db_data, [])
        return {"path": file_path, "sim": similarity, "cred": credibility, "reason": reason}

    def _comparison_worker(self, selected_features, threshold):
        db_files = [os.path.join(self.db_dir_path, f) for f in os.listdir(self.db_dir_path) if f.endswith(".fpt")]
        total_files = len(db_files)
        processed_count = 0

        # --- NEW: Using ThreadPoolExecutor for parallel processing ---
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            future_to_file = {executor.submit(self._process_single_db_file, fp, selected_features, threshold): fp for
                              fp in db_files}

            for future in concurrent.futures.as_completed(future_to_file):
                result = future.result()
                processed_count += 1
                progress = processed_count / total_files
                self.root.after(0, self.progress_bar.set, progress)

                if result:
                    # Always add to "All Results" table
                    self.root.after(0, lambda r=result: self.batch_results_tree.insert("", "end", values=(
                    r["path"], f"{r['sim']:.2f}", f"{r['cred']:.2f}", r["reason"])))

                    # --- NEW: Add to "High Similarity" table if it meets the threshold ---
                    if result["sim"] >= threshold:
                        self.root.after(0, lambda r=result: self.similar_results_tree.insert("", "end", values=(
                        r["path"], f"{r['sim']:.2f}", f"{r['cred']:.2f}", r["reason"])))

        self.root.after(0, self.run_button.configure, {"state": "normal"})

    def _log_single(self, message, level="INFO"):
        color_map = {"SUCCESS": "lightgreen", "ERROR": "salmon", "WARN": "orange", "INFO": "white"}

        def _update():
            self.single_log_text.configure(state="normal")
            # Create a tag for the color if it doesn't exist
            tag_name = f"tag_{level}"
            self.single_log_text.tag_config(tag_name, foreground=color_map.get(level, "white"))
            self.single_log_text.insert("end", f"[{time.strftime('%H:%M:%S')}] ", "white")
            self.single_log_text.insert("end", f"[{level}] {message}\n", tag_name)
            self.single_log_text.configure(state="disabled")
            self.single_log_text.see("end")

        self.root.after(0, _update)


if __name__ == '__main__':
    root = ctk.CTk()
    app = CombinedAnalyzerApp(root)
    root.mainloop()
import platform
import psutil
import wmi
from cpuinfo import get_cpu_info
import json
import time
import os
import hashlib
import base64
from ecdsa import SigningKey, NIST256p
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import moderngl
import struct
import ctypes


# RSA 公鑰（客戶端）
RSA_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnNa50/0cVgs8Jc+DitIx
HulEBSR7CiiMSXLWd26uMmhAhsiEZvyctf5enjgwDEOXy0PApkflhdJzSQS9eEaq
gP7Xv2Il/j3u2BaUwwIWEcY3vn4pw1z1Uu8BPlNapFEFUugpPXktdktWFwt1CVnM
ZonjeRPwhOKgfaUnhyRXGXkKXXlPMirPTPcQRaa348HbTcHbOD5+9cB+DGtOGo3q
nRZU1n9iRZndmzeG2PIwhc4SaUzp7kXHKvmflSFJiygMO3DZS1QMs8PxV9EM1hnO
QIWLS+Y6lpE2RqN2E4ryylsJlTmwCYlh43akmoEowI7dyjFGbKmmxZtU78tZD0Ur
WwIDAQAB
-----END PUBLIC KEY-----"""


def sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()


def build_merkle_tree(leaves):
    if not leaves:
        return None
    while len(leaves) > 1:
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])
        new_leaves = []
        for i in range(0, len(leaves), 2):
            combined = leaves[i] + leaves[i + 1]
            new_hash = sha256(combined)
            new_leaves.append(new_hash)
        leaves = new_leaves
    return leaves[0]


def is_virtualized():
    """檢測虛擬化環境"""
    try:
        w = wmi.WMI()
        system = w.Win32_ComputerSystem()[0]
        if "vmware" in system.Manufacturer.lower() or "virtual" in system.Manufacturer.lower():
            return True, "VMware/VirtualBox detected"
        # 檢查 CPUID 虛擬化位元
        import cpuid
        cpu = cpuid.CPUID()
        if cpu(0x1)[2] & (1 << 31):  # Hypervisor 位元
            return True, "Hypervisor detected via CPUID"
        # 檢查虛擬機進程
        vm_processes = ['vmtoolsd.exe', 'vboxservice.exe']
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in vm_processes:
                return True, f"VM process {proc.info['name']} detected"
        return False, "No virtualization detected"
    except Exception as e:
        return False, f"Virtualization check failed: {e}"


def anti_debug():
    """反調試檢查"""
    try:
        if ctypes.windll.kernel32.IsDebuggerPresent():
            raise RuntimeError("Debugger detected")
        start_time = time.time()
        for _ in range(1000):
            _ = hashlib.sha256(b"test").digest()
        if time.time() - start_time > 0.5:
            raise RuntimeError("Execution too slow, possible debugging")
    except Exception as e:
        raise RuntimeError(f"Anti-debug check failed: {e}")


def aes_encrypt(data, key):
    """AES-GCM 加密"""
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag


def aes_decrypt(nonce, ciphertext, tag, key):
    """AES-GCM 解密"""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def gpu_render_benchmark():
    try:
        ctx = moderngl.create_standalone_context()
        fbo = ctx.simple_framebuffer((1, 1))
        fbo.use()
        prog = ctx.program(
            vertex_shader='''
                #version 330
                in vec2 in_vert;
                void main() {
                    gl_Position = vec4(in_vert, 0.0, 1.0);
                }
            ''',
            fragment_shader='''
                #version 330
                out vec4 fragColor;
                void main() {
                    fragColor = vec4(1.0, 0.0, 0.0, 1.0);
                }
            '''
        )
        vertices = ctx.buffer(struct.pack('6f', 0.0, 0.0, 1.0, 0.0, 0.0, 1.0))
        vao = ctx.simple_vertex_array(prog, vertices, 'in_vert')
        ctx.clear(0.0, 0.0, 0.0)
        vao.render(moderngl.TRIANGLES)
        pixel_data = fbo.read(components=4)
        render_hash = hashlib.sha256(pixel_data).hexdigest()
        vertices.release()
        vao.release()
        prog.release()
        fbo.release()
        ctx.release()
        return render_hash
    except Exception as e:
        print(f"GPU render benchmark failed: {e}")
        return 'unknown'


def collect_fingerprints():
    # 反調試檢查
    anti_debug()

    fingerprints = []
    cpu_info = get_cpu_info()
    fingerprints.append({'name': 'cpu.vendor_id', 'value': cpu_info['vendor_id_raw'] or 'unknown'})
    fingerprints.append({'name': 'cpu.brand_string', 'value': cpu_info['brand_raw'] or 'unknown'})
    fingerprints.append({'name': 'cpu.core_count', 'value': psutil.cpu_count(logical=False)})
    fingerprints.append({'name': 'cpu.logical_processor_count', 'value': psutil.cpu_count(logical=True)})
    fingerprints.append({'name': 'cpu.features', 'value': ','.join(cpu_info['flags'])})

    w = wmi.WMI()
    baseboards = w.Win32_BaseBoard()
    if baseboards:
        baseboard = baseboards[0]
        fingerprints.append({'name': 'mainboard.serial_number', 'value': baseboard.SerialNumber or 'unknown'})
        fingerprints.append({'name': 'mainboard.product', 'value': baseboard.Product or 'unknown'})
        fingerprints.append({'name': 'mainboard.manufacturer', 'value': baseboard.Manufacturer or 'unknown'})

    bios = w.Win32_BIOS()[0]
    fingerprints.append({'name': 'bios.version', 'value': bios.Version or 'unknown'})
    fingerprints.append({'name': 'bios.serial_number', 'value': bios.SerialNumber or 'unknown'})

    # 虛擬機檢測
    is_vm, vm_info = is_virtualized()
    fingerprints.append({'name': 'virtualization.status', 'value': vm_info})
    fingerprints.append({'name': 'virtualization.uuid', 'value': w.Win32_ComputerSystemProduct()[0].UUID or 'unknown'})

    disks = w.Win32_DiskDrive()
    for i, disk in enumerate(disks):
        prefix = f'disk.{i}'
        fingerprints.append({'name': f'{prefix}.serial_number', 'value': disk.SerialNumber or 'unknown'})
        fingerprints.append({'name': f'{prefix}.model', 'value': disk.Model or 'unknown'})
        fingerprints.append({'name': f'{prefix}.firmware', 'value': disk.FirmwareRevision or 'unknown'})

    gpus = w.Win32_VideoController()
    for i, gpu in enumerate(gpus):
        prefix = f'gpu.{i}'
        fingerprints.append({'name': f'{prefix}.description', 'value': gpu.Name or 'unknown'})
        fingerprints.append(
            {'name': f'{prefix}.adapter_ram_mb', 'value': gpu.AdapterRAM / (1024 * 1024) if gpu.AdapterRAM else None})
        fingerprints.append({'name': f'{prefix}.driver_version', 'value': gpu.DriverVersion or 'unknown'})

    os_info = w.Win32_OperatingSystem()[0]
    fingerprints.append({'name': 'os.platform', 'value': platform.system()})
    fingerprints.append({'name': 'os.hostname', 'value': platform.node()})
    fingerprints.append({'name': 'os.name', 'value': os_info.Caption or 'unknown'})
    fingerprints.append({'name': 'os.install_date', 'value': os_info.InstallDate or 'unknown'})
    fingerprints.append({'name': 'os.boot_time', 'value': psutil.boot_time()})

    # 網絡接口（MAC 地址的哈希）
    for nic in psutil.net_if_addrs().values():
        for addr in nic:
            if addr.family == psutil.AF_LINK:
                fingerprints.append(
                    {'name': 'network.mac_hash', 'value': hashlib.sha256(addr.address.encode()).hexdigest()})

    def cpu_integer_benchmark():
        start = time.time()
        for _ in range(1000000):
            _ = 123456789 * 987654321
        return time.time() - start

    def cpu_float_benchmark():
        start = time.time()
        for _ in range(1000000):
            _ = 123.456 * 789.012
        return time.time() - start

    fingerprints.append({'name': 'benchmark.cpu_integer_score', 'value': cpu_integer_benchmark()})
    fingerprints.append({'name': 'benchmark.cpu_float_score', 'value': cpu_float_benchmark()})
    fingerprints.append({'name': 'benchmark.gpu_render_hash', 'value': gpu_render_benchmark()})
    fingerprints.append({'name': 'random_number_hash', 'value': hashlib.sha256(os.urandom(32)).hexdigest()})

    disk_io = psutil.disk_io_counters()
    if disk_io:
        fingerprints.append({'name': 'disk.io_read_count', 'value': disk_io.read_count})
        fingerprints.append({'name': 'disk.io_write_count', 'value': disk_io.write_count})
        fingerprints.append({'name': 'disk.io_read_bytes', 'value': disk_io.read_bytes})
        fingerprints.append({'name': 'disk.io_write_bytes', 'value': disk_io.write_bytes})

    partitions = psutil.disk_partitions()
    for i, part in enumerate(partitions):
        prefix = f'filesystem.{i}'
        fingerprints.append({'name': f'{prefix}.device', 'value': part.device})
        fingerprints.append({'name': f'{prefix}.mountpoint', 'value': part.mountpoint})
        fingerprints.append({'name': f'{prefix}.fstype', 'value': part.fstype})

    return fingerprints


def main():
    # 反調試檢查
    try:
        anti_debug()
    except Exception as e:
        print(f"Anti-debug check failed: {e}")
        return

    # 載入 RSA 公鑰
    try:
        public_key = serialization.load_pem_public_key(
            RSA_PUBLIC_KEY_PEM.encode('utf-8'),
            backend=default_backend()
        )
    except Exception as e:
        print(f"Error loading RSA public key: {e}")
        return

    # 初始化 ECDSA
    try:
        sk = SigningKey.generate(curve=NIST256p)
        pk = sk.verifying_key
    except Exception as e:
        print(f"Error generating ECDSA key pair: {e}")
        return

    # 生成 AES 密鑰
    aes_key = os.urandom(32)
    try:
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"Error encrypting AES key: {e}")
        return

    # 收集指紋
    fingerprint_items = collect_fingerprints()

    # 分級簽名與加密
    signed_items = []
    leaf_hashes = []
    for item in fingerprint_items:
        salt = os.urandom(32)
        name_data = item['name'].encode('utf-8')
        value_data = json.dumps(item['value'], sort_keys=True).encode('utf-8')
        salted_data = salt + name_data + value_data
        item_hash = sha256(salted_data)

        try:
            # AES 加密 name 和 value
            nonce, encrypted_name, tag = aes_encrypt(name_data, aes_key)
            nonce_value, encrypted_value, tag_value = aes_encrypt(value_data, aes_key)
            # ECDSA 簽名
            ecdsa_signature = sk.sign(salted_data, hashfunc=hashlib.sha256)
            # RSA 加密 ECDSA 簽名
            rsa_encrypted_signature = public_key.encrypt(
                ecdsa_signature,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            signed_items.append({
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'encrypted_name': base64.b64encode(encrypted_name).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'nonce_value': base64.b64encode(nonce_value).decode('utf-8'),
                'encrypted_value': base64.b64encode(encrypted_value).decode('utf-8'),
                'tag_value': base64.b64encode(tag_value).decode('utf-8'),
                'salt': base64.b64encode(salt).decode('utf-8'),
                'ecdsa_signature': base64.b64encode(ecdsa_signature).decode('utf-8'),
                'rsa_encrypted_ecdsa_signature': base64.b64encode(rsa_encrypted_signature).decode('utf-8')
            })
            leaf_hashes.append(item_hash)
        except Exception as e:
            print(f"Error processing {item['name']}: {e}")
            continue

    # 構建 Merkle 樹
    merkle_root = build_merkle_tree(leaf_hashes)
    if not merkle_root:
        print("Error: Failed to build Merkle tree.")
        return

    # 加密元數據
    metadata = {'timestamp': time.time(), 'version': '1.0'}
    metadata_json = json.dumps(metadata, sort_keys=True).encode('utf-8')
    metadata_salt = os.urandom(32)
    nonce_metadata, encrypted_metadata, tag_metadata = aes_encrypt(metadata_json, aes_key)

    # 整體簽名
    salted_report = metadata_salt + metadata_json + merkle_root
    report_hash = sha256(salted_report)
    ecdsa_report_signature = sk.sign(report_hash, hashfunc=hashlib.sha256)

    # 自訂二進位格式
    data_to_encrypt = {
        'metadata': {
            'nonce': base64.b64encode(nonce_metadata).decode('utf-8'),
            'encrypted_metadata': base64.b64encode(encrypted_metadata).decode('utf-8'),
            'tag': base64.b64encode(tag_metadata).decode('utf-8'),
            'salt': base64.b64encode(metadata_salt).decode('utf-8')
        },
        'signed_items': signed_items,
        'merkle_root': base64.b64encode(merkle_root).decode('utf-8'),
        'ecdsa_report_signature': base64.b64encode(ecdsa_report_signature).decode('utf-8'),
        'public_keys': {
            'ecdsa_pk': base64.b64encode(pk.to_string()).decode('utf-8'),
            'rsa_pk': RSA_PUBLIC_KEY_PEM
        }
    }
    data_json = json.dumps(data_to_encrypt, sort_keys=True).encode('utf-8')
    nonce_data, encrypted_data, tag_data = aes_encrypt(data_json, aes_key)

    # 構造二進位文件
    header = struct.pack('!4s4sQ', b'FPT1', b'AESG', len(encrypted_data))
    with open('fingerprint.fpt', 'wb') as f:
        f.write(header)
        f.write(base64.b64encode(encrypted_aes_key))
        f.write(nonce_data)
        f.write(tag_data)
        f.write(encrypted_data)
        f.write(ecdsa_report_signature)

    print("Fingerprint report generated: fingerprint.fpt")


if __name__ == '__main__':
    main()
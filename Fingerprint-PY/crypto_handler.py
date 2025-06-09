# crypto_handler.py
import hashlib
import oqs


class CryptoHandler:
    def __init__(self, sig_alg="Dilithium3"):
        self.sig_algorithm = sig_alg
        # 初始化签名处理器
        self.sig_handler = oqs.Signature(self.sig_algorithm)

    def sha256(self, data: bytes) -> bytes:
        """计算数据的SHA-256哈希"""
        return hashlib.sha256(data).digest()

    def sign(self, data_hash: bytes, private_key: bytes) -> bytes:
        """使用PQC私钥对哈希进行签名"""
        return self.sig_handler.sign(data_hash, private_key)

    def verify(self, data_hash: bytes, signature: bytes, public_key: bytes) -> bool:
        """使用PQC公钥验证签名"""
        try:
            return self.sig_handler.verify(data_hash, signature, public_key)
        except Exception:
            # oqs库在验证失败时可能会抛出异常
            return False

    def build_merkle_tree(self, leaf_hashes: list[bytes]) -> bytes:
        """根据叶子节点哈希列表构建Merkle树并返回根哈希"""
        if not leaf_hashes:
            return b''
        if len(leaf_hashes) == 1:
            return leaf_hashes[0]

        level = leaf_hashes
        while len(level) > 1:
            # 如果当前层节点数为奇数，复制最后一个节点以凑成偶数
            if len(level) % 2 != 0:
                level.append(level[-1])

            next_level = []
            for i in range(0, len(level), 2):
                # 将两个子节点的哈希拼接起来
                combined = level[i] + level[i + 1]
                # 计算父节点的哈希
                next_level.append(self.sha256(combined))

            level = next_level

        return level[0]

# encrypto.py
import secrets
from importlib import import_module

def _load_kem_module():
    for module_name in (
        "pqcrypto.kem.ml_kem_1024",
        "pqcrypto.kem.ml_kem_768",
        "pqcrypto.kem.ml_kem_512",
    ):
        try:
            return module_name, import_module(module_name)
        except ModuleNotFoundError:
            continue
    raise ModuleNotFoundError("No supported pqcrypto ML-KEM module found.")

_KEM_NAME, _KEM = _load_kem_module()
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "Missing dependency: cryptography. Install with 'pip install cryptography'."
    ) from exc

class MLKEMEncryption:
    def __init__(self):
        # 初始化生成密钥对
        self.public_key, self.private_key = self.generate_keys()

    def generate_keys(self):
        """
        生成后量子加密密钥对
        返回：公钥和私钥
        """
        # 使用 pqcrypto 提供的 generate_keypair 方法生成密钥对
        public_key, private_key = _KEM.generate_keypair()
        return public_key, private_key

    def encapsulate_key(self):
        """
        使用公钥封装共享密钥
        返回：
            kem_ciphertext (bytes): KEM 密文
            shared_key (bytes): 共享密钥
        """
        kem_ciphertext, shared_key = _KEM.encrypt(self.public_key)
        return kem_ciphertext, shared_key

    def decapsulate_key(self, kem_ciphertext: bytes):
        """
        使用私钥解封装共享密钥
        参数：
            kem_ciphertext (bytes): KEM 密文
        返回：
            shared_key (bytes): 共享密钥
        """
        shared_key = _KEM.decrypt(self.private_key, kem_ciphertext)
        return shared_key

    def encrypt_data(self, data: bytes, aad: bytes = b""):
        """
        使用 KEM 封装共享密钥，再用 AES-GCM 加密数据
        参数：
            data (bytes): 需要加密的数据
            aad (bytes): 额外认证数据（可选）
        返回：
            kem_ciphertext (bytes): KEM 密文
            salt (bytes): HKDF 盐
            nonce (bytes): AES-GCM 随机数
            data_ciphertext (bytes): 数据密文（含认证标签）
        """
        kem_ciphertext, shared_key = self.encapsulate_key()
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        aes_key = self._derive_aes_key(shared_key, salt)
        data_ciphertext = AESGCM(aes_key).encrypt(nonce, data, aad)
        return kem_ciphertext, salt, nonce, data_ciphertext

    def decrypt_data(
        self,
        kem_ciphertext: bytes,
        salt: bytes,
        nonce: bytes,
        data_ciphertext: bytes,
        aad: bytes = b"BugMaker",
    ):
        """
        使用私钥解封装共享密钥，再用 AES-GCM 解密数据
        参数：
            kem_ciphertext (bytes): KEM 密文
            salt (bytes): HKDF 盐
            nonce (bytes): AES-GCM 随机数
            data_ciphertext (bytes): 数据密文
            aad (bytes): 额外认证数据（可选）
        返回：
            decrypted_data (bytes): 解密后的数据
        """
        shared_key = self.decapsulate_key(kem_ciphertext)
        aes_key = self._derive_aes_key(shared_key, salt)
        return AESGCM(aes_key).decrypt(nonce, data_ciphertext, aad)

    def exchange_keys(self):
        """
        模拟密钥交换过程，使用加密算法封装共享密钥
        返回：
            kem_ciphertext (bytes): KEM 密文
            shared_key (bytes): 交换得到的共享密钥
        """
        kem_ciphertext, shared_key = self.encapsulate_key()
        return kem_ciphertext, shared_key

    @staticmethod
    def _derive_aes_key(shared_key: bytes, salt: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"ml-kem+aead",
        )
        return hkdf.derive(shared_key)

# 示例：如何使用后量子加密 ML-KEM 加密模块

def main():
    # 创建加密实例
    pq_encryption = MLKEMEncryption()

    # 生成密钥对
    public_key = pq_encryption.public_key
    print(f"KEM Variant: {_KEM_NAME}")
    print(f"Public Key: {public_key}")

    # 加密和解密数据
    data = b"Hello, this is a test message."
    aad = b"BugMaker"
    kem_ciphertext, salt, nonce, data_ciphertext = pq_encryption.encrypt_data(data, aad)
    print(f"KEM Ciphertext: {kem_ciphertext}")
    print(f"Salt: {salt}")
    print(f"Nonce: {nonce}")
    print(f"Data Ciphertext: {data_ciphertext}")

    decrypted_data = pq_encryption.decrypt_data(
        kem_ciphertext,
        salt,
        nonce,
        data_ciphertext,
        aad,
    )
    print(f"Decrypted Data: {decrypted_data.decode()}")

    # 密钥交换示例
    kem_ciphertext, shared_key_from_exchange = pq_encryption.exchange_keys()
    shared_key_receiver = pq_encryption.decapsulate_key(kem_ciphertext)
    print(f"Shared Key from Key Exchange: {shared_key_from_exchange}")
    print(f"Shared Key (receiver): {shared_key_receiver}")

if __name__ == "__main__":
    main()

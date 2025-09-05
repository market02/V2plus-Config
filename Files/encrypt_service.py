# 标准库导入
import base64
import hashlib
import os

# 第三方库导入
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class EncryptService:
    def __init__(self, password: str = "v2plus"):
        self.password = password
    
    def generate_key(self, password: str, key_size: int) -> bytes:
        """生成与C#版本完全兼容的密钥"""
        password_bytes = password.encode('utf-8')
        hash_value = hashlib.sha256(password_bytes).digest()
        
        if key_size <= len(hash_value):
            return hash_value[:key_size]
        else:
            key = bytearray()
            while len(key) < key_size:
                remaining = key_size - len(key)
                copy_length = min(remaining, len(hash_value))
                key.extend(hash_value[:copy_length])
            return bytes(key)

    def encrypt_aes(self, plainText: str, password: str) -> str:
        try:
            key = self.generate_key(password, 32)
            iv = self.generate_key(password + "salt", 16)

            # 关键：与 C# StreamWriter 默认一致，使用 UTF-8（不带 BOM）
            data_bytes = plainText.encode('utf-8')

            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data_bytes) + padder.finalize()

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as ex:
            raise Exception(f"AES加密失败：{str(ex)}") from ex

    def decrypt_aes(self, encrypted_data: str, password: str) -> str:
        """与 encrypt_aes 一致的函数签名：使用给定 password 派生 Key/IV 并解密"""
        # 使用密码生成密钥和IV，与C#版本保持一致
        key = self.generate_key(password, 32)
        iv = self.generate_key(password + "salt", 16)
        
        # 解码Base64字符串
        ciphertext = base64.b64decode(encrypted_data)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # 解密数据
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 移除PKCS7填充
        padding_length = padded_data[-1]
        unpadded_data = padded_data[:-padding_length]
        
        # 将字节转换回字符串（兼容可能存在的UTF-8 BOM）
        return unpadded_data.decode('utf-8-sig')
       
    def encrypt_file(self, file_path: str, output_path: str = None) -> str:
        """加密文件"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        if output_path is None:
            output_path = file_path + ".encrypted"
        
        # 读取明文：保留原始换行，避免 \r\n -> \n 的规范化
        with open(file_path, 'r', encoding='utf-8', newline='') as f:
            file_data = f.read()
        
        encrypted_data = self.encrypt_aes(file_data, self.password)
        
        # 写入密文：一般无换行，但为一致性依然使用 newline=''
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            f.write(encrypted_data)
        
        return output_path
    
    def decrypt_file(self, file_path: str, output_path: str = None) -> str:
        """解密文件"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        if output_path is None:
            output_path = file_path + ".decrypted"
        
        # 读取密文：对 Base64 无影响，保持一致
        with open(file_path, 'r', encoding='utf-8', newline='') as f:
            encrypted_data = f.read()
        
        decrypted_data = self.decrypt_aes(encrypted_data, self.password)
        
        # 写回明文：保留原始换行，确保与加密前一致
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            f.write(decrypted_data)
        
        return output_path
import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import asyncio
import hashlib
from cryptography.hazmat.primitives import padding
import io

class EncryptService:
    def __init__(self, password: str = "v2plus"):
        self.password = password
    
    # def generate_key(self, password: str, key_size: int) -> bytes:
    #     """与C#版本兼容的密钥生成方法"""
    #     password_bytes = password.encode('utf-8')
    #     hash_obj = hashlib.sha256()
    #     hash_obj.update(password_bytes)
    #     hash_bytes = hash_obj.digest()
        
    #     # 如果需要的密钥长度大于哈希长度，则重复哈希
    #     if key_size <= len(hash_bytes):
    #         return hash_bytes[:key_size]
    #     else:
    #         key = bytearray(key_size)
    #         offset = 0
    #         while offset < key_size:
    #             remaining = key_size - offset
    #             copy_length = min(remaining, len(hash_bytes))
    #             key[offset:offset+copy_length] = hash_bytes[:copy_length]
    #             offset += copy_length
    #         return bytes(key)
    
    # def encrypt_aes(self, data: str) -> str:
    #     """与C#版本兼容的AES加密"""
    #     # 使用密码生成密钥和IV，与C#版本保持一致
    #     key = self.generate_key(self.password, 32)  # AES-256需要32字节密钥
    #     iv = self.generate_key(self.password + "salt", 16)  # AES需要16字节IV
        
    #     cipher = Cipher(
    #         algorithms.AES(key),
    #         modes.CBC(iv),
    #         backend=default_backend()
    #     )
    #     encryptor = cipher.encryptor()
        
    #     # 将字符串转换为字节
    #     data_bytes = data.encode('utf-8')
        
    #     # PKCS7填充
    #     padding_length = 16 - (len(data_bytes) % 16)
    #     padded_data = data_bytes + bytes([padding_length] * padding_length)
        
    #     # 加密数据
    #     encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
    #     # 返回Base64编码的加密数据，与C#版本保持一致
    #     return base64.b64encode(encrypted_data).decode('utf-8')
    
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

    def encrypt_aes(self, data: str) -> str:
        """与C#版本完全兼容的AES加密"""
        # 使用与C#相同的密钥生成方法
        key = self.generate_key(self.password, 32)
        iv = self.generate_key(self.password + "salt", 16)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # 模拟C#的StreamWriter行为
        # 将字符串编码为UTF-8字节
        data_bytes = data.encode('utf-8')
        
        # 使用PKCS7填充，确保与C#的PaddingMode.PKCS7一致
        padder = padding.PKCS7(128).padder()  # AES块大小128位
        padded_data = padder.update(data_bytes)
        padded_data += padder.finalize()
        
        # 加密数据
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # 返回Base64编码的加密数据
        return base64.b64encode(encrypted_data).decode('utf-8')







    def decrypt_aes(self, encrypted_data: str) -> str:
        """与C#版本兼容的AES解密"""
        # 使用密码生成密钥和IV，与C#版本保持一致
        key = self.generate_key(self.password, 32)
        iv = self.generate_key(self.password + "salt", 16)
        
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
        
        # 将字节转换回字符串
        return unpadded_data.decode('utf-8')
   
    
    def encrypt_file(self, file_path: str, output_path: str = None) -> str:
        """同步加密文件"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        if output_path is None:
            output_path = file_path + ".encrypted"
        
        with open(file_path, 'r', encoding='utf-8') as f:
            file_data = f.read()
        
        encrypted_data = self.encrypt_aes(file_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(encrypted_data)
        
        return output_path
    
    def decrypt_file(self, file_path: str, output_path: str = None) -> str:
        """解密文件"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        if output_path is None:
            output_path = file_path + ".decrypted"
        
        with open(file_path, 'r', encoding='utf-8') as f:
            encrypted_data = f.read()
        
        decrypted_data = self.decrypt_aes(encrypted_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(decrypted_data)
        
        return output_path
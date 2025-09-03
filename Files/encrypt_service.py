import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import asyncio

class EncryptService:
    def __init__(self, password: str = "your_secret_password"):
        self.password = password.encode('utf-8')
        self.salt = b'salt_1234567890'  # 在实际使用中应该使用随机salt
    
    def generate_key(self) -> bytes:
        """从密码生成AES密钥"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256需要32字节密钥
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.password)
    
    def encrypt_aes(self, data: bytes) -> bytes:
        """AES加密"""
        key = self.generate_key()
        iv = os.urandom(16)  # 生成随机IV
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # PKCS7填充
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # 返回IV + 加密数据
        return iv + encrypted_data
    
    def decrypt_aes(self, encrypted_data: bytes) -> bytes:
        """AES解密"""
        key = self.generate_key()
        iv = encrypted_data[:16]  # 提取IV
        ciphertext = encrypted_data[16:]  # 提取加密数据
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 移除PKCS7填充
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    async def encrypt_file_async(self, file_path: str, output_path: str = None) -> str:
        """异步加密文件"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        if output_path is None:
            output_path = file_path + ".encrypted"
        
        # 异步读取文件
        loop = asyncio.get_event_loop()
        with open(file_path, 'rb') as f:
            file_data = await loop.run_in_executor(None, f.read)
        
        # 加密数据
        encrypted_data = await loop.run_in_executor(None, self.encrypt_aes, file_data)
        
        # 异步写入加密文件
        with open(output_path, 'wb') as f:
            await loop.run_in_executor(None, f.write, encrypted_data)
        
        return output_path
    
    def encrypt_file(self, file_path: str, output_path: str = None) -> str:
        """同步加密文件"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")
        
        if output_path is None:
            output_path = file_path + ".encrypted"
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = self.encrypt_aes(file_data)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        return output_path
    
    def decrypt_file(self, encrypted_file_path: str, output_path: str = None) -> str:
        """解密文件"""
        if not os.path.exists(encrypted_file_path):
            raise FileNotFoundError(f"加密文件不存在: {encrypted_file_path}")
        
        if output_path is None:
            output_path = encrypted_file_path.replace(".encrypted", "")
        
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = self.decrypt_aes(encrypted_data)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        return output_path
    
    def encrypt_text(self, text: str) -> str:
        """加密文本并返回base64编码的结果"""
        text_bytes = text.encode('utf-8')
        encrypted_data = self.encrypt_aes(text_bytes)
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt_text(self, encrypted_base64: str) -> str:
        """解密base64编码的加密文本"""
        encrypted_data = base64.b64decode(encrypted_base64.encode('utf-8'))
        decrypted_data = self.decrypt_aes(encrypted_data)
        return decrypted_data.decode('utf-8')

# 使用示例
if __name__ == "__main__":
    # 创建加密服务实例
    encrypt_service = EncryptService("your_secret_password_here")
    
    # 获取当前脚本所在目录的父目录（项目根目录）
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    
    # 加密All_Configs_Sub_valid.txt文件
    try:
        input_file = os.path.join(project_root, "All_Configs_Sub_valid.txt")
        encrypted_file = encrypt_service.encrypt_file(input_file, os.path.join(project_root, "All_Configs_Sub_valid.txt.encrypted"))
        print(f"文件已加密: {encrypted_file}")
        
        # 解密测试
        decrypted_file = encrypt_service.decrypt_file(encrypted_file, os.path.join(project_root, "All_Configs_Sub_valid_decrypted.txt"))
        print(f"文件已解密: {decrypted_file}")
        
    except FileNotFoundError as e:
        print(f"错误: {e}")
    except Exception as e:
        print(f"加密过程中出现错误: {e}")
import re
import socket
import subprocess
import sys
import os
from urllib.parse import urlparse, parse_qs
import concurrent.futures
import time

class V2rayConfigChecker:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.valid_configs = []
        self.invalid_configs = []
    
    def parse_config_line(self, config_line):
        """解析V2ray配置行，提取IP、端口等信息"""
        config_line = config_line.strip()
        
        # 解析不同协议的配置
        if config_line.startswith('vless://'):
            return self.parse_vless(config_line)
        elif config_line.startswith('vmess://'):
            return self.parse_vmess(config_line)
        elif config_line.startswith('trojan://'):
            return self.parse_trojan(config_line)
        elif config_line.startswith('ss://'):
            return self.parse_ss(config_line)
        elif config_line.startswith('ssr://'):
            return self.parse_ssr(config_line)
        
        return None
    
    def parse_vless(self, config):
        """解析VLESS配置"""
        try:
            # vless://uuid@host:port?params#name
            match = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?(.*)#?(.*)', config)
            if match:
                uuid, host, port, params, name = match.groups()
                return {
                    'protocol': 'vless',
                    'host': host,
                    'port': int(port),
                    'uuid': uuid,
                    'params': params,
                    'name': name,
                    'original': config
                }
        except Exception as e:
            print(f"解析VLESS配置失败: {e}")
        return None
    
    def parse_vmess(self, config):
        """解析VMess配置"""
        try:
            # vmess://base64_encoded_json 或 vmess://uuid@host:port
            if '://' in config:
                match = re.match(r'vmess://([^@]+)@([^:]+):(\d+)', config)
                if match:
                    uuid, host, port = match.groups()
                    return {
                        'protocol': 'vmess',
                        'host': host,
                        'port': int(port),
                        'uuid': uuid,
                        'original': config
                    }
        except Exception as e:
            print(f"解析VMess配置失败: {e}")
        return None
    
    def parse_trojan(self, config):
        """解析Trojan配置"""
        try:
            # trojan://password@host:port?params#name
            match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)', config)
            if match:
                password, host, port = match.groups()
                return {
                    'protocol': 'trojan',
                    'host': host,
                    'port': int(port),
                    'password': password,
                    'original': config
                }
        except Exception as e:
            print(f"解析Trojan配置失败: {e}")
        return None
    
    def parse_ss(self, config):
        """解析Shadowsocks配置"""
        try:
            # ss://base64@host:port 或 ss://method:password@host:port
            match = re.match(r'ss://([^@]+)@([^:]+):(\d+)', config)
            if match:
                auth, host, port = match.groups()
                return {
                    'protocol': 'ss',
                    'host': host,
                    'port': int(port),
                    'auth': auth,
                    'original': config
                }
        except Exception as e:
            print(f"解析SS配置失败: {e}")
        return None
    
    def parse_ssr(self, config):
        """解析ShadowsocksR配置"""
        try:
            # ssr://base64_encoded
            match = re.match(r'ssr://([^@]+)@([^:]+):(\d+)', config)
            if match:
                auth, host, port = match.groups()
                return {
                    'protocol': 'ssr',
                    'host': host,
                    'port': int(port),
                    'auth': auth,
                    'original': config
                }
        except Exception as e:
            print(f"解析SSR配置失败: {e}")
        return None
    
    def test_tcp_connectivity(self, host, port):
        """测试TCP端口连通性"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            print(f"TCP连接测试失败 {host}:{port} - {e}")
            return False
    
    def test_config_connectivity(self, config_info):
        """测试单个配置的连通性"""
        if not config_info:
            return False
        
        host = config_info['host']
        port = config_info['port']
        protocol = config_info['protocol']
        
        print(f"测试 {protocol}://{host}:{port}")
        
        # 只测试TCP端口连通性
        tcp_ok = self.test_tcp_connectivity(host, port)
        print(f"  TCP {port}: {'✓' if tcp_ok else '✗'}")
        
        return tcp_ok
    
    def check_file(self, file_path):
        """检查配置文件中的所有配置"""
        if not os.path.exists(file_path):
            print(f"文件不存在: {file_path}")
            return
        
        print(f"检查文件: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        valid_lines = []
        invalid_count = 0
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            
            # 跳过注释行和空行
            if not line or line.startswith('#'):
                valid_lines.append(line + '\n')
                continue
            
            # 解析配置
            config_info = self.parse_config_line(line)
            
            if config_info:
                # 测试连通性
                if self.test_config_connectivity(config_info):
                    valid_lines.append(line + '\n')
                    self.valid_configs.append(config_info)
                    print(f"  第{i}行: ✓ 有效")
                else:
                    self.invalid_configs.append(config_info)
                    invalid_count += 1
                    print(f"  第{i}行: ✗ 无效，已删除")
            else:
                # 无法解析的行保留
                valid_lines.append(line + '\n')
                print(f"  第{i}行: ? 无法解析，保留")
        
        # 生成新的文件名（检测后的有效配置）
        base_name = os.path.splitext(file_path)[0]
        extension = os.path.splitext(file_path)[1]
        valid_file_path = f"{base_name}_valid{extension}"
        
        # 写入检测后的有效配置到新文件
        if invalid_count > 0:
            with open(valid_file_path, 'w', encoding='utf-8') as f:
                f.writelines(valid_lines)
            
            print(f"已删除 {invalid_count} 个无效配置")
            print(f"原始文件保留: {file_path}")
            print(f"有效配置保存到: {valid_file_path}")
            
            # 同时生成Base64版本
            if file_path.endswith('All_Configs_Sub.txt'):
                import base64
                
                # 读取有效配置内容
                with open(valid_file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 生成Base64编码版本
                base64_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
                base64_file_path = f"{base_name}_valid_base64{extension}"
                
                with open(base64_file_path, 'w', encoding='utf-8') as f:
                    f.write(base64_content)
                
                print(f"Base64版本保存到: {base64_file_path}")
        else:
            print("所有配置都有效，无需生成新文件")
    
    def check_all_files(self):
        """检查所有配置文件"""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(base_dir)
        
        # 只检查All_Configs_Sub.txt文件
        files_to_check = [
            os.path.join(parent_dir, 'All_Configs_Sub.txt'),
        ]
        
        for file_path in files_to_check:
            if os.path.exists(file_path):
                print(f"\n{'='*50}")
                self.check_file(file_path)
        
        print(f"\n{'='*50}")
        print(f"检查完成:")
        print(f"  有效配置: {len(self.valid_configs)}")
        print(f"  无效配置: {len(self.invalid_configs)}")

def main():
    checker = V2rayConfigChecker(timeout=5)
    
    if len(sys.argv) > 1:
        # 检查指定文件
        file_path = sys.argv[1]
        checker.check_file(file_path)
    else:
        # 检查所有文件
        checker.check_all_files()

if __name__ == "__main__":
    main()
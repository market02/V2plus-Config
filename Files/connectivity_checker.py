import re
import socket
import subprocess
import sys
import os
from urllib.parse import urlparse, parse_qs
import concurrent.futures
import time
import base64
import json
from datetime import datetime

class V2rayConfigChecker:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.valid_configs = []
        self.invalid_configs = []
    
    def is_base64(self, s):
        """判断字符串是否为有效的base64编码"""
        try:
            if isinstance(s, str):
                # 检查字符串是否只包含base64字符
                if re.match('^[A-Za-z0-9+/]*={0,2}$', s):
                    base64.b64decode(s)
                    return True
            return False
        except Exception:
            return False
    
    def decode_base64_safely(self, data):
        """安全地解码base64数据"""
        try:
            return base64.b64decode(data).decode('utf-8')
        except Exception as e:
            print(f"Base64解码失败: {e}")
            return None
    
    def clean_config_line(self, config_line):
        """清理配置行，去除脏字符，返回清理后的配置行"""
        config_line = config_line.strip()
        
        # 定义支持的协议列表
        protocols = ['vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hy2://']
        
        # 查找协议并剔除脏字符
        for protocol in protocols:
            protocol_index = config_line.find(protocol)
            if protocol_index != -1:
                # 找到协议，剔除前面的脏字符
                return config_line[protocol_index:]
        
        # 如果没有找到任何协议，返回原始行
        return config_line

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
        elif config_line.startswith('hy2://'):
            return self.parse_hy2(config_line)
        
        return None
    
    def parse_vless(self, config):
        """解析VLESS配置"""
        try:
            # vless://uuid@host:port?params#name 或 vless://base64_encoded
            vless_data = config[8:]  # 去掉"vless://"
            
            # 检查是否为base64编码
            if self.is_base64(vless_data):
                # 解码base64
                decoded_data = self.decode_base64_safely(vless_data)
                if decoded_data:
                    try:
                        # 尝试解析JSON格式（类似vmess）
                        vless_config = json.loads(decoded_data)
                        return {
                            'protocol': 'vless',
                            'host': vless_config.get('add', ''),
                            'port': int(vless_config.get('port', 0)),
                            'original': config
                        }
                    except json.JSONDecodeError:
                        # 如果不是JSON，尝试解析为普通格式
                        url_part = decoded_data.split('?')[0].split('#')[0]
                        if '@' in url_part:
                            match = re.match(r'[^@]+@([^:]+):(\d+)', url_part)
                            if match:
                                host, port = match.groups()
                                return {
                                    'protocol': 'vless',
                                    'host': host,
                                    'port': int(port),
                                    'original': config
                                }
                        else:
                            match = re.match(r'([^:]+):(\d+)', url_part)
                            if match:
                                host, port = match.groups()
                                return {
                                    'protocol': 'vless',
                                    'host': host,
                                    'port': int(port),
                                    'original': config
                                }
            else:
                # 直接解析非base64格式
                url_part = vless_data.split('?')[0].split('#')[0]
                if '@' in url_part:
                    match = re.match(r'[^@]+@([^:]+):(\d+)', url_part)
                else:
                    match = re.match(r'([^:]+):(\d+)', url_part)
                
                if match:
                    host, port = match.groups()
                    return {
                        'protocol': 'vless',
                        'host': host,
                        'port': int(port),
                        'original': config
                    }
        except Exception as e:
            print(f"解析VLESS配置失败: {e}")
        return None
    
    def parse_vmess(self, config):
        """解析VMess配置"""
        try:
            # vmess://base64_encoded_json 或 vmess://uuid@host:port 或 vmess://host:port
            if '://' in config:
                vmess_data = config[8:]  # 去掉"vmess://"
                
                # 检查是否为base64编码
                if self.is_base64(vmess_data):
                    decoded_data = self.decode_base64_safely(vmess_data)
                    if decoded_data:
                        try:
                            # 解析JSON
                            vmess_config = json.loads(decoded_data)
                            return {
                                'protocol': 'vmess',
                                'host': vmess_config.get('add', ''),
                                'port': int(vmess_config.get('port', 0)),
                                'original': config
                            }
                        except json.JSONDecodeError as e:
                            print(f"VMess JSON解析失败: {e}")
                            return None
                else:
                    # 解析非base64格式
                    url_part = vmess_data.split('?')[0].split('#')[0]
                    if '@' in url_part:
                        match = re.match(r'[^@]+@([^:]+):(\d+)', url_part)
                    else:
                        # host:port 格式
                        match = re.match(r'([^:]+):(\d+)', url_part)
                    
                    if match:
                        host, port = match.groups()
                        return {
                            'protocol': 'vmess',
                            'host': host,
                            'port': int(port),
                            'original': config
                        }
        except Exception as e:
            print(f"解析VMess配置失败: {e}")
        return None
    
    def parse_trojan(self, config):
        """解析Trojan配置"""
        try:
            # trojan://password@host:port?params#name 或 trojan://base64_encoded
            trojan_data = config[9:]  # 去掉"trojan://"
            
            # 检查是否为base64编码
            if self.is_base64(trojan_data):
                # 解码base64
                decoded_data = self.decode_base64_safely(trojan_data)
                if decoded_data:
                    try:
                        # 尝试解析JSON格式
                        trojan_config = json.loads(decoded_data)
                        return {
                            'protocol': 'trojan',
                            'host': trojan_config.get('add', ''),
                            'port': int(trojan_config.get('port', 0)),
                            'password': trojan_config.get('password', ''),
                            'name': trojan_config.get('ps', ''),
                            'original': config
                        }
                    except json.JSONDecodeError:
                        # 如果不是JSON，尝试解析为普通格式
                        url_part = decoded_data.split('?')[0].split('#')[0]
                        if '@' in url_part:
                            # password@host:port 格式
                            match = re.match(r'([^@]+)@([^:]+):(\d+)', url_part)
                            if match:
                                password, host, port = match.groups()
                                return {
                                    'protocol': 'trojan',
                                    'host': host,
                                    'port': int(port),
                                    'password': password,
                                    'original': config
                                }
                        else:
                            # host:port 格式
                            match = re.match(r'([^:]+):(\d+)', url_part)
                            if match:
                                host, port = match.groups()
                                return {
                                    'protocol': 'trojan',
                                    'host': host,
                                    'port': int(port),
                                    'password': '',
                                    'original': config
                                }
            else:
                # 直接解析非base64格式
                # 先分离出参数和fragment部分
                url_part = trojan_data.split('?')[0].split('#')[0]
                
                if '@' in url_part:
                    # password@host:port 格式
                    match = re.match(r'([^@]+)@([^:]+):(\d+)', url_part)
                    if match:
                        password, host, port = match.groups()
                        return {
                            'protocol': 'trojan',
                            'host': host,
                            'port': int(port),
                            'password': password,
                            'original': config
                        }
                else:
                    # host:port 格式
                    match = re.match(r'([^:]+):(\d+)', url_part)
                    if match:
                        host, port = match.groups()
                        return {
                            'protocol': 'trojan',
                            'host': host,
                            'port': int(port),
                            'password': '',
                            'original': config
                        }
        except Exception as e:
            print(f"解析Trojan配置失败: {e}")
        return None
    
    def parse_ss(self, config):
        """解析Shadowsocks配置"""
        try:
            # ss://base64@host:port 或 ss://method:password@host:port 或 ss://base64_encoded 或 ss://base64_encoded_data#fragment
            ss_data = config[5:]  # 去掉"ss://"
            
            # 先移除fragment部分（#后面的内容）
            fragment = ''
            if '#' in ss_data:
                ss_data, fragment = ss_data.split('#', 1)
            
            # 情况1: ss://base64@host:port 或 ss://method:password@host:port
            if '@' in ss_data:
                auth_part, server_part = ss_data.split('@', 1)
                
                # 检查auth_part是否为base64
                if self.is_base64(auth_part):
                    decoded_auth = self.decode_base64_safely(auth_part)
                    if decoded_auth and ':' in decoded_auth:
                        method, password = decoded_auth.split(':', 1)
                    else:
                        method, password = '', decoded_auth or ''
                else:
                    # 直接的 method:password 格式
                    if ':' in auth_part:
                        method, password = auth_part.split(':', 1)
                    else:
                        method, password = '', auth_part
                
                # 解析服务器部分
                if ':' in server_part:
                    host, port = server_part.rsplit(':', 1)
                    # 移除可能的参数部分
                    port = port.split('?')[0]
                    try:
                        port_int = int(port)
                        return {
                            'protocol': 'ss',
                            'host': host,
                            'port': port_int,
                            'method': method,
                            'password': password,
                            'original': config
                        }
                    except ValueError:
                        print(f"端口转换失败: {port}")
                        return None
            
            # 情况2: ss://base64_encoded（整个连接信息都是base64编码）
            else:
                if self.is_base64(ss_data):
                    decoded_data = self.decode_base64_safely(ss_data)
                    if decoded_data:
                        # 解码后应该是 method:password@host:port 格式
                        if '@' in decoded_data:
                            auth_part, server_part = decoded_data.split('@', 1)
                            
                            # 解析认证部分 method:password
                            if ':' in auth_part:
                                method, password = auth_part.split(':', 1)
                            else:
                                method, password = '', auth_part
                            
                            # 解析服务器部分 host:port
                            if ':' in server_part:
                                host, port = server_part.rsplit(':', 1)
                                # 移除可能的参数部分
                                port = port.split('?')[0]
                                try:
                                    port_int = int(port)
                                    return {
                                        'protocol': 'ss',
                                        'host': host,
                                        'port': port_int,
                                        'method': method,
                                        'password': password,
                                        'original': config
                                    }
                                except ValueError:
                                    print(f"端口转换失败: {port}")
                                    return None
                        else:
                            # 如果解码后没有@符号，尝试其他格式
                            parts = decoded_data.split(':')
                            if len(parts) >= 4:  # method:password:host:port 格式
                                method = parts[0]
                                password = ':'.join(parts[1:-2])  # 密码可能包含冒号
                                host = parts[-2]
                                port = parts[-1]
                                try:
                                    port_int = int(port)
                                    return {
                                        'protocol': 'ss',
                                        'host': host,
                                        'port': port_int,
                                        'method': method,
                                        'password': password,
                                        'original': config
                                    }
                                except ValueError:
                                    print(f"端口转换失败: {port}")
                                    return None
                    else:
                        print(f"Base64解码失败: {ss_data}")
                        return None
                else:
                    print(f"不是有效的Base64: {ss_data}")
                    # 情况3: 非base64格式的其他处理
                    if ':' in ss_data:
                        parts = ss_data.split(':')
                        if len(parts) >= 2:
                            host = parts[-2]
                            port = parts[-1].split('?')[0]
                            method = parts[0] if len(parts) > 2 else ''
                            password = ':'.join(parts[1:-2]) if len(parts) > 3 else (parts[1] if len(parts) > 2 else '')
                            
                            try:
                                port_int = int(port)
                                return {
                                    'protocol': 'ss',
                                    'host': host,
                                    'port': port_int,
                                    'method': method,
                                    'password': password,
                                    'original': config
                                }
                            except ValueError:
                                print(f"端口转换失败: {port}")
                                return None
                            
        except Exception as e:
            print(f"解析SS配置失败: {e}")
            import traceback
            traceback.print_exc()
        return None
    
    def parse_ssr(self, config):
        """解析ShadowsocksR配置"""
        try:
            # ssr://base64_encoded 或 ssr://auth@host:port
            ssr_data = config[6:]  # 去掉"ssr://"
            
            # 检查是否为base64编码
            if self.is_base64(ssr_data):
                decoded_data = self.decode_base64_safely(ssr_data)
                if decoded_data:
                    # 先分离主要部分和参数部分
                    if '?' in decoded_data:
                        main_part, _ = decoded_data.split('?', 1)
                    else:
                        main_part = decoded_data
                    
                    # 解析复杂的SSR格式：host:port:protocol:method:obfs:password_base64
                    parts = main_part.split(':')
                    if len(parts) >= 2:
                        host = parts[0]
                        port = parts[1]
                        try:
                            return {
                                'protocol': 'ssr',
                                'host': host,
                                'port': int(port),
                                'original': config
                            }
                        except ValueError:
                            print(f"SSR端口转换失败: {port}")
                            return None
                else:
                    print(f"SSR Base64解码失败: {ssr_data}")
                    return None
            else:
                # 尝试解析非base64格式
                url_part = ssr_data.split('?')[0].split('#')[0]
                if '@' in url_part:
                    match = re.match(r'[^@]+@([^:]+):(\d+)', url_part)
                else:
                    match = re.match(r'([^:]+):(\d+)', url_part)
                
                if match:
                    host, port = match.groups()
                    return {
                        'protocol': 'ssr',
                        'host': host,
                        'port': int(port),
                        'original': config
                    }
        except Exception as e:
            print(f"解析SSR配置失败: {e}")
        return None
    
    def parse_hy2(self, config):
        """解析HY2配置"""
        try:
            # 使用正则表达式匹配 hy2://password@host:port 格式
            # 匹配模式：hy2://任意字符@主机:端口
            pattern = r'hy2://[^@]*@([^:/?#]+):(\d+)'
            match = re.match(pattern, config)
            
            if match:
                host = match.group(1)
                port = int(match.group(2))
                
                return {
                    'protocol': 'hy2',
                    'host': host,
                    'port': port,
                    'original': config
                }
            else:
                return None
                
        except Exception as e:
            print(f"解析HY2配置失败: {e}")
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
        
        # 获取当前时间戳
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] 测试 {protocol}://{host}:{port}")
        
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
            if not line.strip():  # 跳过空行
                continue
            if line.startswith('#'):  # 保留注释
                valid_lines.append(line + '\n')
                continue
            
            # 清理配置行
            line = self.clean_config_line(line)
            
            # 解析配置
            config_info = self.parse_config_line(line)
            
            if config_info:
                # 测试连通性
                if self.test_config_connectivity(config_info):
                    valid_lines.append(line + '\n')
                    self.valid_configs.append(config_info)
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[{timestamp}]   第{i}行: ✓ 有效")
                else:
                    self.invalid_configs.append(config_info)
                    invalid_count += 1
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[{timestamp}]   第{i}行: ✗ 无效，已删除")
            else:
                self.invalid_configs.append(config_info)
                invalid_count += 1
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}]   第{i}行: ? 无法解析，删除")
        
        # 生成新的文件名（检测后的有效配置）
        base_name = os.path.splitext(file_path)[0]
        extension = os.path.splitext(file_path)[1]
        valid_file_path = f"{base_name}_valid{extension}"
        
        # 写入检测后的有效配置到新文件
        if invalid_count > 0:
            with open(valid_file_path, 'w', encoding='utf-8', newline='\n') as f:
                f.writelines(valid_lines)
            
            print(f"已删除 {invalid_count} 个无效配置")
            print(f"原始文件保留: {file_path}")
            print(f"有效配置保存到: {valid_file_path}")
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
"""代理协议解析器模块 - 统一管理所有协议解析逻辑"""
import re
import json
import base64


class ProxyParser:
    """统一的代理协议解析器"""
    
    @staticmethod
    def is_base64(s):
        """判断字符串是否为有效的base64编码（兼容URL-safe）"""
        try:
            if isinstance(s, str):
                if re.match("^[A-Za-z0-9+/_-]*={0,2}$", s):
                    base64.b64decode(s + "=" * (-len(s) % 4))
                    return True
            return False
        except Exception:
            return False

    @staticmethod
    def decode_base64_safely(data):
        """安全地解码base64数据（兼容URL-safe）"""
        try:
            return base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="strict")
        except Exception:
            try:
                return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="strict")
            except Exception as e:
                print(f"Base64解码失败: {e}")
                return None

    @staticmethod
    def clean_config_line(config_line):
        """清理配置行，去除脏字符"""
        config_line = config_line.strip()
        protocols = ["vless://", "vmess://", "trojan://", "ss://", "ssr://", "hy2://"]
        
        for protocol in protocols:
            protocol_index = config_line.find(protocol)
            if protocol_index != -1:
                return config_line[protocol_index:]
        return None

    def parse_config_line(self, config_line):
        """解析配置行，根据协议类型分发到对应解析器"""
        config_line = config_line.strip()
        
        parsers = {
            "vless://": self.parse_vless,
            "vmess://": self.parse_vmess,
            "trojan://": self.parse_trojan,
            "ss://": self.parse_ss,
            "ssr://": self.parse_ssr,
            "hy2://": self.parse_hy2,
        }
        
        for prefix, parser in parsers.items():
            if config_line.startswith(prefix):
                return parser(config_line)
        return None

    def parse_vless(self, config):
        """解析VLESS配置 - 完整保留原始逻辑"""
        try:
            # vless://uuid@host:port?params#name 或 vless://base64_encoded
            if "://" in config:
                vless_data = config[8:]  # 去掉"vless://"

                # 检查是否为base64编码
                if self.is_base64(vless_data):
                    decoded_data = self.decode_base64_safely(vless_data)
                    if decoded_data:
                        try:
                            # 解析JSON
                            vless_config = json.loads(decoded_data)
                            return {
                                "protocol": "vless",
                                "host": vless_config.get("add", ""),
                                "port": int(vless_config.get("port", 0)),
                                "original": config,
                            }
                        except json.JSONDecodeError as e:
                            print(f"VLESS JSON解析失败: {e}")
                            # 如果不是JSON，尝试解析为普通格式
                            url_part = decoded_data.split("?")[0].split("#")[0]
                            if "@" in url_part:
                                match = re.match(r"[^@]+@([^:]+):(\d+)", url_part)
                            else:
                                match = re.match(r"([^:]+):(\d+)", url_part)

                            if match:
                                host, port = match.groups()
                                return {
                                    "protocol": "vless",
                                    "host": host,
                                    "port": int(port),
                                    "original": config,
                                }
                else:
                    # 解析非base64格式
                    url_part = vless_data.split("?")[0].split("#")[0]
                    if "@" in url_part:
                        match = re.match(r"[^@]+@([^:]+):(\d+)", url_part)
                    else:
                        match = re.match(r"([^:]+):(\d+)", url_part)

                    if match:
                        host, port = match.groups()
                        return {
                            "protocol": "vless",
                            "host": host,
                            "port": int(port),
                            "original": config,
                        }
        except Exception as e:
            print(f"解析VLESS配置失败: {e}")
        return None

    def parse_vmess(self, config):
        """解析VMess配置 - 完整保留原始逻辑"""
        try:
            # vmess://base64_encoded_json 或 vmess://uuid@host:port 或 vmess://host:port
            if "://" in config:
                vmess_data = config[8:]  # 去掉"vmess://"

                # 检查是否为base64编码
                if self.is_base64(vmess_data):
                    decoded_data = self.decode_base64_safely(vmess_data)
                    if decoded_data:
                        try:
                            # 解析JSON
                            vmess_config = json.loads(decoded_data)
                            return {
                                "protocol": "vmess",
                                "host": vmess_config.get("add", ""),
                                "port": int(vmess_config.get("port", 0)),
                                "original": config,
                            }
                        except json.JSONDecodeError as e:
                            print(f"VMess JSON解析失败: {e}")
                            return None
                else:
                    # 解析非base64格式
                    url_part = vmess_data.split("?")[0].split("#")[0]
                    if "@" in url_part:
                        match = re.match(r"[^@]+@([^:]+):(\d+)", url_part)
                    else:
                        # host:port 格式
                        match = re.match(r"([^:]+):(\d+)", url_part)

                    if match:
                        host, port = match.groups()
                        return {
                            "protocol": "vmess",
                            "host": host,
                            "port": int(port),
                            "original": config,
                        }
        except Exception as e:
            print(f"解析VMess配置失败: {e}")
        return None

    def parse_trojan(self, config):
        """解析Trojan配置 - 完整保留原始逻辑"""
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
                            "protocol": "trojan",
                            "host": trojan_config.get("add", ""),
                            "port": int(trojan_config.get("port", 0)),
                            "password": trojan_config.get("password", ""),
                            "name": trojan_config.get("ps", ""),
                            "original": config,
                        }
                    except json.JSONDecodeError:
                        # 如果不是JSON，尝试解析为普通格式
                        url_part = decoded_data.split("?")[0].split("#")[0]
                        if "@" in url_part:
                            # password@host:port 格式
                            match = re.match(r"([^@]+)@([^:]+):(\d+)", url_part)
                            if match:
                                password, host, port = match.groups()
                                return {
                                    "protocol": "trojan",
                                    "host": host,
                                    "port": int(port),
                                    "password": password,
                                    "original": config,
                                }
                        else:
                            # host:port 格式
                            match = re.match(r"([^:]+):(\d+)", url_part)
                            if match:
                                host, port = match.groups()
                                return {
                                    "protocol": "trojan",
                                    "host": host,
                                    "port": int(port),
                                    "password": "",
                                    "original": config,
                                }
            else:
                # 直接解析非base64格式
                # 先分离出参数和fragment部分
                url_part = trojan_data.split("?")[0].split("#")[0]

                if "@" in url_part:
                    # password@host:port 格式
                    match = re.match(r"([^@]+)@([^:]+):(\d+)", url_part)
                    if match:
                        password, host, port = match.groups()
                        return {
                            "protocol": "trojan",
                            "host": host,
                            "port": int(port),
                            "password": password,
                            "original": config,
                        }
                else:
                    # host:port 格式
                    match = re.match(r"([^:]+):(\d+)", url_part)
                    if match:
                        host, port = match.groups()
                        return {
                            "protocol": "trojan",
                            "host": host,
                            "port": int(port),
                            "password": "",
                            "original": config,
                        }
        except Exception as e:
            print(f"解析Trojan配置失败: {e}")
        return None

    def parse_ss(self, config):
        """解析Shadowsocks配置 - 完整保留原始复杂逻辑"""
        try:
            # ss://base64@host:port 或 ss://method:password@host:port 或 ss://base64_encoded 或 ss://base64_encoded_data#fragment
            ss_data = config[5:]  # 去掉"ss://"

            # 先移除fragment部分（#后面的内容）
            fragment = ""
            if "#" in ss_data:
                ss_data, fragment = ss_data.split("#", 1)

            # 情况1: ss://base64@host:port 或 ss://method:password@host:port
            if "@" in ss_data:
                auth_part, server_part = ss_data.split("@", 1)

                # 检查auth_part是否为base64
                if self.is_base64(auth_part):
                    decoded_auth = self.decode_base64_safely(auth_part)
                    if decoded_auth and ":" in decoded_auth:
                        method, password = decoded_auth.split(":", 1)
                    else:
                        method, password = "", decoded_auth or ""
                else:
                    # 直接的 method:password 格式
                    if ":" in auth_part:
                        method, password = auth_part.split(":", 1)
                    else:
                        method, password = "", auth_part

                # 解析服务器部分
                if ":" in server_part:
                    host, port = server_part.rsplit(":", 1)
                    # 移除可能的参数部分
                    port = port.split("?")[0]
                    try:
                        port_int = int(port)
                        return {
                            "protocol": "ss",
                            "host": host,
                            "port": port_int,
                            "method": method,
                            "password": password,
                            "original": config,
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
                        if "@" in decoded_data:
                            auth_part, server_part = decoded_data.split("@", 1)

                            # 解析认证部分 method:password
                            if ":" in auth_part:
                                method, password = auth_part.split(":", 1)
                            else:
                                method, password = "", auth_part

                            # 解析服务器部分 host:port
                            if ":" in server_part:
                                host, port = server_part.rsplit(":", 1)
                                # 移除可能的参数部分
                                port = port.split("?")[0]
                                try:
                                    port_int = int(port)
                                    return {
                                        "protocol": "ss",
                                        "host": host,
                                        "port": port_int,
                                        "method": method,
                                        "password": password,
                                        "original": config,
                                    }
                                except ValueError:
                                    print(f"端口转换失败: {port}")
                                    return None
                        else:
                            # 如果解码后没有@符号，尝试其他格式
                            parts = decoded_data.split(":")
                            if len(parts) >= 4:  # method:password:host:port 格式
                                method = parts[0]
                                password = ":".join(parts[1:-2])  # 密码可能包含冒号
                                host = parts[-2]
                                port = parts[-1]
                                try:
                                    port_int = int(port)
                                    return {
                                        "protocol": "ss",
                                        "host": host,
                                        "port": port_int,
                                        "method": method,
                                        "password": password,
                                        "original": config,
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
                    if ":" in ss_data:
                        parts = ss_data.split(":")
                        if len(parts) >= 2:
                            host = parts[-2]
                            port = parts[-1].split("?")[0]
                            method = parts[0] if len(parts) > 2 else ""
                            password = (
                                ":".join(parts[1:-2])
                                if len(parts) > 3
                                else (parts[1] if len(parts) > 2 else "")
                            )

                            try:
                                port_int = int(port)
                                return {
                                    "protocol": "ss",
                                    "host": host,
                                    "port": port_int,
                                    "method": method,
                                    "password": password,
                                    "original": config,
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
        """解析SSR配置 - 完整保留原始逻辑"""
        try:
            # ssr://base64_encoded
            ssr_data = config[6:]  # 去掉"ssr://"

            if self.is_base64(ssr_data):
                decoded_data = self.decode_base64_safely(ssr_data)
                if decoded_data:
                    # SSR格式通常是: host:port:protocol:method:obfs:password_base64/?params
                    parts = decoded_data.split(":")
                    if len(parts) >= 6:
                        host = parts[0]
                        port = parts[1]
                        protocol = parts[2]
                        method = parts[3]
                        obfs = parts[4]
                        password_and_params = ":".join(parts[5:])
                        
                        # 分离密码和参数
                        if "/?" in password_and_params:
                            password_part, params = password_and_params.split("/?", 1)
                        else:
                            password_part = password_and_params
                            params = ""
                        
                        # 密码可能是base64编码的
                        if self.is_base64(password_part):
                            password = self.decode_base64_safely(password_part) or password_part
                        else:
                            password = password_part

                        try:
                            port_int = int(port)
                            return {
                                "protocol": "ssr",
                                "host": host,
                                "port": port_int,
                                "method": method,
                                "password": password,
                                "original": config,
                            }
                        except ValueError:
                            print(f"SSR端口转换失败: {port}")
                            return None
        except Exception as e:
            print(f"解析SSR配置失败: {e}")
        return None

    def parse_hy2(self, config):
        """解析Hysteria2配置 - 完整保留原始逻辑"""
        try:
            # hy2://auth@host:port?params#name
            hy2_data = config[6:]  # 去掉"hy2://"
            
            # 分离参数和fragment
            url_part = hy2_data.split("?")[0].split("#")[0]
            
            if "@" in url_part:
                # auth@host:port 格式
                match = re.match(r"[^@]+@([^:]+):(\d+)", url_part)
            else:
                # host:port 格式
                match = re.match(r"([^:]+):(\d+)", url_part)

            if match:
                host, port = match.groups()
                return {
                    "protocol": "hy2",
                    "host": host,
                    "port": int(port),
                    "original": config,
                }
        except Exception as e:
            print(f"解析Hysteria2配置失败: {e}")
        return None
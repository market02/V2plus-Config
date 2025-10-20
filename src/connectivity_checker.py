import re
import socket
import subprocess
import sys
import os
from urllib.parse import urlparse, parse_qs
import concurrent.futures
import time
import base64
import requests
import json
from datetime import datetime
from encrypt_service import EncryptService
from proxy_parsers import ProxyParser


class V2rayConfigChecker:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.valid_configs = []
        self.invalid_configs = []
        # 并行阶段用到的缓存，以降低 DNS/Geo 查询开销
        self._dns_cache = {}
        self._geo_cache = {}
        # 使用统一的协议解析器
        self.parser = ProxyParser()

    def clean_config_line(self, config_line):
        """清理配置行，去除脏字符，返回清理后的配置行"""
        return self.parser.clean_config_line(config_line)

    def parse_config_line(self, config_line):
        """解析V2ray配置行，提取IP、端口等信息"""
        return self.parser.parse_config_line(config_line)

    def test_tcp_connectivity(self, host, port):
        """测试TCP端口连通性（同时尝试 IPv4/IPv6）"""
        try:
            # 解析所有可用地址（IPv4/IPv6）
            addrinfos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except Exception as e:
            print(f"解析地址失败 {host}:{port} - {e}")
            return False

        for af, socktype, proto, _, sockaddr in addrinfos:
            try:
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(self.timeout)
                result = sock.connect_ex(sockaddr)
                sock.close()
                if result == 0:
                    return True
            except Exception as e:
                # 尝试下一个地址族
                continue
        return False

    def test_config_connectivity(self, config_info):
        """测试单个配置的连通性"""
        if not config_info:
            return False

        host = config_info["host"]
        port = config_info["port"]
        protocol = config_info["protocol"]

        # 获取当前时间戳
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] 测试 {protocol}://{host}:{port}")

        # 只测试TCP端口连通性
        tcp_ok = self.test_tcp_connectivity(host, port)
        print(f"  TCP {port}: {'✓' if tcp_ok else '✗'}")

        return tcp_ok

    def _resolve_all_ips_parallel_safe(self, host):
        """解析域名为所有 IPv4 地址（带缓存，解析失败返回空列表）"""
        if not host:
            return []
        if host in self._dns_cache:
            return self._dns_cache[host]
        try:
            # 仅收集 IPv4，避免部分环境 IPv6 带来噪音
            infos = socket.getaddrinfo(host, None, socket.AF_INET, 0, 0, 0)
            ips = sorted(set([addr[4][0] for addr in infos]))
            self._dns_cache[host] = ips
            return ips
        except Exception as e:
            print(f"DNS解析失败 {host}: {e}")
            self._dns_cache[host] = []
            return []

    def _geolocate_ip(self, ip):
        """查询单个 IP 的地理信息（带缓存）"""
        if ip in self._geo_cache:
            return self._geo_cache[ip]
        try:
            # ip-api 免费接口，返回国家与国家码（注意免费版有频率限制）
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode",
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    self._geo_cache[ip] = {
                        "country": data.get("country", ""),
                        "countryCode": data.get("countryCode", ""),
                    }
                    return self._geo_cache[ip]
        except Exception as e:
            print(f"获取IP地理位置失败 {ip}: {e}")
        self._geo_cache[ip] = None
        return None

    def _regions_from_country_code(self, code):
        """根据国家码映射到区域标签集合"""
        if not code:
            return set()
        code = code.upper()

        # 欧洲国家代码
        eu_codes = {
            "DE",
            "FR",
            "IT",
            "ES",
            "NL",
            "BE",
            "AT",
            "CH",
            "SE",
            "NO",
            "DK",
            "FI",
            "PL",
            "CZ",
            "HU",
            "RO",
            "BG",
            "HR",
            "SI",
            "SK",
            "LT",
            "LV",
            "EE",
            "IE",
            "PT",
            "GR",
            "CY",
            "MT",
            "LU",
            "IS",
            "LI",
            "MC",
            "SM",
            "VA",
            "AD",
            "GB",
            "UK",
        }

        regions = set()
        if code in ("US", "CA"):
            regions.add("US_CA")
        if code in eu_codes or code in ("JP", "KR"):
            regions.add("EU_JP_KR")
        if not regions:
            regions.add("OTHER")
        return regions

    def classify_host_regions(self, host):
        """对主机解析所有 IP 并获取区域集合（可能跨多个区域）"""
        ips = self._resolve_all_ips_parallel_safe(host)
        if not ips:
            return {"OTHER"}
        regions = set()
        # 对每个 IP 查询地理信息（为了简单这里顺序查询，若量大可再并行）
        for ip in ips:
            geo = self._geolocate_ip(ip)
            if geo and geo.get("countryCode"):
                regions |= self._regions_from_country_code(geo["countryCode"])
        return regions or {"OTHER"}

    def _process_single_config(self, item):
        """处理单个配置项"""
        idx, raw_line = item
        clean = self.clean_config_line(raw_line)
        cfg = self.parse_config_line(clean)
        if not cfg:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{ts}]   第{idx}行: ✗ 无法解析，已删除")
            return None

        ok = self.test_config_connectivity(cfg)
        if not ok:
            self.invalid_configs.append(cfg)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{ts}]   第{idx}行: ✗ 无效，已删除")
            return None

        # 有效：分类归属地
        regions = self.classify_host_regions(cfg["host"])
        self.valid_configs.append(cfg)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}]   第{idx}行: ✓ 有效，区域={','.join(sorted(regions))}")
        return {"line": clean, "cfg": cfg, "regions": regions}

    def _save_regional_files(self, results, parent_dir):
        """保存区域分类文件"""
        us_ca_file = os.path.join(parent_dir, "US_CA.txt")
        eu_jp_kr_file = os.path.join(parent_dir, "EU_JP_KR.txt")
        other_file = os.path.join(parent_dir, "Other.txt")

        us_ca, eu_jp_kr, other = [], [], []
        for r in results:
            regs = r["regions"]
            if "US_CA" in regs:
                us_ca.append(r["line"])
            if "EU_JP_KR" in regs:
                eu_jp_kr.append(r["line"])
            # 仅当不属于前两个区域时，归为其它
            if regs == {"OTHER"} or (
                ("US_CA" not in regs) and ("EU_JP_KR" not in regs)
            ):
                other.append(r["line"])

        with open(us_ca_file, "w", encoding="utf-8") as f:
            for line in us_ca:
                f.write(line + "\n")
        print(f"美国/加拿大配置已保存到: {us_ca_file}（{len(us_ca)} 个）")

        with open(eu_jp_kr_file, "w", encoding="utf-8") as f:
            for line in eu_jp_kr:
                f.write(line + "\n")
        print(f"欧洲/日韩配置已保存到: {eu_jp_kr_file}（{len(eu_jp_kr)} 个）")

        with open(other_file, "w", encoding="utf-8") as f:
            for line in other:
                f.write(line + "\n")
        print(f"其他地区配置已保存到: {other_file}（{len(other)} 个）")

    def _split_valid_file_into_chunks(self, valid_file_path, parent_dir, chunk_size=2000):
        """将有效文件按每 chunk_size 个节点分割为多个文件"""
        try:
            with open(valid_file_path, "r", encoding="utf-8") as f:
                lines = [ln.rstrip("\n") for ln in f.readlines()]
            # 头部注释行：保留到每个分割文件
            header_lines = [ln for ln in lines if ln.startswith("#")]
            # 节点行：非空、非注释
            node_lines = [ln for ln in lines if ln and not ln.startswith("#")]

            if not node_lines:
                print("有效配置为空，跳过分割。")
                return []

            chunk_paths = []
            for start in range(0, len(node_lines), chunk_size):
                part_index = start // chunk_size
                chunk_nodes = node_lines[start : start + chunk_size]
                part_path = os.path.join(
                    parent_dir, f"All_Configs_Sub_valid_part{part_index}.txt"
                )
                with open(part_path, "w", encoding="utf-8") as out:
                    for ln in header_lines:
                        out.write(ln + "\n")
                    for ln in chunk_nodes:
                        out.write(ln + "\n")
                print(
                    f"分割文件已生成: {part_path}（{len(chunk_nodes)} 个节点）"
                )
                chunk_paths.append(part_path)

            return chunk_paths
        except Exception as e:
            print(f"分割有效文件失败：{e}")
            return []

    def _encrypt_files(self, valid_file_path, parent_dir, chunk_paths=None):
        """加密文件"""
        try:
            password = os.getenv("ENCRYPT_PASSWORD", "v2plus").strip() or "v2plus"
            enc = EncryptService(password)

            # 定义加密文件的自定义输出路径
            encryption_mappings = {
                valid_file_path: valid_file_path + ".encrypted",
                os.path.join(parent_dir, "US_CA.txt"): os.path.join(
                    parent_dir, "US_CA"
                ),
                os.path.join(parent_dir, "EU_JP_KR.txt"): os.path.join(
                    parent_dir, "EU_JP_KR"
                ),
                os.path.join(parent_dir, "Other.txt"): os.path.join(
                    parent_dir, "Other"
                ),
            }

            # 对分割的有效文件进行加密：result0、result1、...
            if chunk_paths:
                for i, part_path in enumerate(chunk_paths):
                    encryption_mappings[part_path] = os.path.join(
                        parent_dir, f"result{i}"
                    )

            for source_file, encrypted_file in encryption_mappings.items():
                # 如果加密文件已存在，先删除（实现覆盖）
                if os.path.exists(encrypted_file):
                    os.remove(encrypted_file)
                    print(f"已删除旧的加密文件: {encrypted_file}")

                # 执行加密
                outp = enc.encrypt_file(source_file, encrypted_file)
                print(f"文件已加密: {outp}")
        except Exception as e:
            print(f"加密阶段发生异常（不影响明文文件）：{e}")

    def check_file(self, file_path):
        """并行检查配置文件中的所有配置，并同时进行区域分类与最终加密"""
        if not os.path.exists(file_path):
            print(f"文件不存在: {file_path}")
            return

        print(f"检查文件: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # 注释行保留到有效文件头部
        header_comment_lines = []
        work_items = []  # (index, original_line)

        # 首先添加时间戳到头部
        header_comment_lines.append(
            f"# 文件更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        )
        header_comment_lines.append(
            f"# 连通性检测完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        for i, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                header_comment_lines.append(line + "\n")
                continue
            work_items.append((i, line))

        # 并行执行
        max_workers = min(32, (os.cpu_count() or 4) * 5)
        print(f"并行处理开始，共 {len(work_items)} 个节点，max_workers={max_workers}")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(self._process_single_config, item)
                for item in work_items
            ]
            for fut in concurrent.futures.as_completed(futures):
                try:
                    res = fut.result()
                    if res:
                        results.append(res)
                except Exception as e:
                    print(f"并行任务异常: {e}")

        # 汇总写出：只对有效节点进行写文件与分类
        base_name, extension = os.path.splitext(file_path)
        valid_file_path = f"{base_name}_valid{extension}"
        parent_dir = os.path.dirname(file_path)

        # 有效文件
        with open(valid_file_path, "w", encoding="utf-8") as f:
            f.writelines(header_comment_lines)
            for r in results:
                f.write(r["line"] + "\n")
        print(f"有效配置保存到: {valid_file_path}（{len(results)} 个）")

        # 区域分类写出（统一写到项目根目录，即 file_path 所在目录）
        self._save_regional_files(results, parent_dir)

        # 分割有效文件为多个部分，每份 2000 个节点
        chunk_paths = self._split_valid_file_into_chunks(
            valid_file_path, parent_dir, chunk_size=2000
        )

        # 最后对上述文件进行加密（包括分割文件）
        self._encrypt_files(valid_file_path, parent_dir, chunk_paths)

    # 第308-310行，修改检查文件路径
    def check_all_files(self):
        parent_dir = os.path.dirname(os.path.dirname(__file__))
        files_to_check = [
            os.path.join(parent_dir, "data", "All_Configs_Sub.txt"),
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
    timeout_env = os.getenv("CONNECT_TIMEOUT", "").strip()
    try:
        timeout = int(timeout_env) if timeout_env else 10
    except ValueError:
        timeout = 10

    checker = V2rayConfigChecker(timeout=timeout)

    if len(sys.argv) > 1:
        # 检查指定文件
        file_path = sys.argv[1]
        checker.check_file(file_path)
    else:
        # 检查所有文件
        checker.check_all_files()


if __name__ == "__main__":
    main()

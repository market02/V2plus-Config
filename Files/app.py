import datetime
import re
import requests
import logging
import pybase64
import base64
import binascii
import os
import json
from connectivity_checker import V2rayConfigChecker
from proxyUtil import *

# Define a fixed timeout for HTTP requests
TIMEOUT = 15  # seconds
# Define maximum number of configurations
MAX_CONFIGS = 10000

# Define the fixed text for the initial configuration
fixed_text = """#profile-title: base64:8J+GkyBHaXRodWIgfCBCYXJyeS1mYXIg8J+ltw==
#profile-update-interval: 1
#subscription-userinfo: upload=29; download=12; total=10737418240000000; expire=2546249531
#support-url: https://github.com/barry-far/V2ray-config
#profile-web-page-url: https://github.com/barry-far/V2ray-config
"""


# Base64 decoding function
def decode_base64(encoded):
    decoded = ""
    for encoding in ["utf-8", "iso-8859-1"]:
        try:
            decoded = pybase64.b64decode(encoded + b"=" * (-len(encoded) % 4)).decode(
                encoding
            )
            break
        except (UnicodeDecodeError, binascii.Error):
            pass
    return decoded


# Function to decode base64-encoded links with a timeout and config limit
def decode_links(links, max_configs, current_count=0):
    decoded_data = []
    for link in links:
        if current_count >= max_configs:
            break
        try:
            response = requests.get(link, timeout=TIMEOUT)
            encoded_bytes = response.content
            decoded_text = decode_base64(encoded_bytes)
            if decoded_text:
                decoded_data.append(decoded_text)
                # Rough estimate of configs in this source
                lines = decoded_text.strip().split("\n")
                config_lines = [
                    line
                    for line in lines
                    if line.strip() and not line.strip().startswith("#")
                ]
                current_count += len(config_lines)
        except requests.RequestException:
            pass  # If the request fails or times out, skip it
    return decoded_data, current_count


# Function to decode directory links with a timeout and config limit
def decode_dir_links(dir_links, max_configs, current_count=0):
    decoded_dir_links = []
    for link in dir_links:
        if current_count >= max_configs:
            break
        try:
            response = requests.get(link, timeout=TIMEOUT)
            decoded_text = response.text
            if decoded_text:
                decoded_dir_links.append(decoded_text)
                # Rough estimate of configs in this source
                lines = decoded_text.strip().split("\n")
                config_lines = [
                    line
                    for line in lines
                    if line.strip() and not line.strip().startswith("#")
                ]
                current_count += len(config_lines)
        except requests.RequestException:
            pass  # If the request fails or times out, skip it
    return decoded_dir_links, current_count


# 新增：依据内容来判定是否为 base64 订阅并完成解码，返回合并后的文本
def fetch_and_decode(urls, max_configs):
    protocols = ["vmess://", "vless://", "trojan://", "ss://", "ssr://", "hy2://"]
    decoded_chunks = []
    current_count = 0
    base64_sources = 0
    direct_sources = 0

    for url in urls:
        if current_count >= max_configs:
            break
        try:
            resp = requests.get(url, timeout=TIMEOUT)
            content_bytes = resp.content

            # 尝试作为 base64 解码
            decoded_b64 = decode_base64(content_bytes)
            is_b64 = bool(decoded_b64) and any(p in decoded_b64 for p in protocols)

            if is_b64:
                decoded_chunks.append(decoded_b64)
                base64_sources += 1
                # 估算当前源中的配置行数量
                lines = decoded_b64.strip().split("\n")
                config_lines = [
                    line
                    for line in lines
                    if line.strip() and not line.strip().startswith("#")
                ]
                current_count += len(config_lines)
            else:
                # 按明文处理
                text = resp.text or ""
                if text:
                    decoded_chunks.append(text)
                    direct_sources += 1
                    lines = text.strip().split("\n")
                    config_lines = [
                        line
                        for line in lines
                        if line.strip() and not line.strip().startswith("#")
                    ]
                    current_count += len(config_lines)
        except requests.RequestException:
            # 忽略失败的源
            pass

    return decoded_chunks, current_count, base64_sources, direct_sources


# Filter function to select lines based on specified protocols and remove duplicates (only for config lines)
def filter_for_protocols(data, protocols, max_configs):
    filtered_data = []
    seen_configs = set()  # 原有的完全匹配去重
    seen_endpoints = set()  # 新增：endpoint去重 (protocol+host+port)
    config_count = 0

    def get_endpoint_key(config_line):
        """提取节点的endpoint标识：protocol+host+port"""
        import re

        try:
            patterns = [
                (
                    r"(vless|vmess|trojan)://[^@]*@([^:/]+):(\d+)",
                    lambda m: f"{m.group(1)}_{m.group(2)}_{m.group(3)}",
                ),
                (
                    r"(ss|ssr)://[^@]*@([^:/]+):(\d+)",
                    lambda m: f"{m.group(1)}_{m.group(2)}_{m.group(3)}",
                ),
            ]
            for pattern, formatter in patterns:
                match = re.search(pattern, config_line)
                if match:
                    return formatter(match)
        except:
            pass
        return None

    for content in data:
        if config_count >= max_configs:
            break
        if content and content.strip():
            lines = content.strip().split("\n")
            for line in lines:
                if config_count >= max_configs:
                    break
                line = line.strip()
                # 仅保留配置行，不保留来源注释
                if any(p in line for p in protocols) and line:
                    if line not in seen_configs:
                        endpoint_key = get_endpoint_key(line)
                        if not endpoint_key or endpoint_key not in seen_endpoints:
                            filtered_data.append(line)
                            seen_configs.add(line)
                            if endpoint_key:
                                seen_endpoints.add(endpoint_key)
                            config_count += 1
    return filtered_data


# Create necessary directories if they don't exist
def ensure_directories_exist():
    output_folder = os.path.join(os.path.dirname(__file__), "..")

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    return output_folder


def checkURL(url):
    try:
        r = requests.head(url, timeout=3)
    except:
        return False
    return r.status_code // 100 == 2


# 新增：封装为函数，并使用绝对路径 + ScrapURL 统计“数量”
def update_resources_status():
    print("开始检测Resources.md文件中的URL状态...")
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    resources_path = os.path.join(base_dir, "Resources.md")

    if not os.path.exists(resources_path):
        print("警告：Resources.md 文件不存在，跳过状态更新")
        return

    output = []
    try:
        with open(resources_path, "r", encoding="utf8") as file:
            lines = file.readlines()

        in_comment_block = False
        for raw_line in lines:
            line = raw_line.strip()

            # 检查是否进入或退出注释块
            # 即使在一行内开始和结束，也能正确处理
            is_currently_commented = in_comment_block or "<!--" in line

            if not in_comment_block and "<!--" in line:
                in_comment_block = True
            if in_comment_block and "-->" in line:
                in_comment_block = False
                # 如果注释块在同一行结束，则当前行仍被视为注释
                is_currently_commented = True

            # 保留非数据行（注释、标题、分隔符、空行）
            if (
                is_currently_commented
                or not line
                or not line.startswith("|")
                or line.startswith("|:-")
                or "| available |" in line
            ):
                output.append(raw_line.rstrip("\n"))
                continue

            # 处理数据行
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) < 5:
                output.append(raw_line.rstrip("\n"))  # 保留格式不正确的行
                continue

            url = cells[-1]

            current_ok = False
            for _ in range(3):
                if checkURL(url):
                    current_ok = True
                    break
            status_symbol = "✅" if current_ok else "❌"

            try:
                resp_val = int(cells[1])
            except (ValueError, IndexError):
                resp_val = 5

            new_resp = resp_val if current_ok else resp_val - 1

            # 当 responsibility 减到1或以下时，删除该行
            if new_resp < 1 and not current_ok:
                continue

            try:
                p = ScrapURL(url)
            except Exception:
                p = []
            proxy_count = len(p)

            updated_every = cells[3]

            new_cells = [
                status_symbol,
                str(new_resp),
                str(proxy_count),
                updated_every,
                url,
            ]
            line = "| " + " | ".join(new_cells) + " |"
            output.append(line)

        with open(resources_path, "w", encoding="utf8", newline="\n") as f:
            f.write("\n".join(output) + "\n")

        print("Resources.md文件状态更新完成")
    except Exception as e:
        print(f"更新Resources.md状态时出错：{e}")


def load_links_from_resources():
    """从Resources文件中提取URL链接（只收集✅可用的URL，不在此处分类）"""
    urls = []

    # 先更新Resources文件状态
    update_resources_status()

    # 基于文件位置定位 Resources.md，避免依赖当前工作目录
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    resources_path = os.path.join(base_dir, "Resources.md")

    try:
        with open(resources_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        in_comment_block = False
        for raw in lines:
            line = raw.strip()

            # 检查是否进入或退出注释块
            is_currently_commented = in_comment_block or "<!--" in line
            if not in_comment_block and "<!--" in line:
                in_comment_block = True
            if in_comment_block and "-->" in line:
                in_comment_block = False
                is_currently_commented = True

            if (
                is_currently_commented
                or not line
                or line.startswith("#")
                or line.startswith("|:-")
                or line.startswith("---")
                or "| available |" in line
            ):
                continue

            if line.startswith("|") and line.endswith("|"):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if len(cells) >= 2:
                    status = cells[0]
                    url = None
                    if cells[-1].startswith("http"):
                        url = cells[-1]
                    else:
                        for c in reversed(cells):
                            if c.startswith("http"):
                                url = c
                                break

                    if (
                        status == "✅"
                        and url
                        and url.startswith(("http://", "https://"))
                        and len(url) > 10
                    ):
                        urls.append(url)

    except FileNotFoundError:
        print("警告：Resources.md文件未找到，返回空链接列表")
        urls = []
    except Exception as e:
        print(f"读取Resources.md文件时出错：{e}")
        urls = []

    print(
        f"从Resources.md文件中提取到 {len(urls)} 个可用链接（将按内容自动判定 base64 或明文）"
    )
    return urls


def main():
    # 生成阶段协议集与检测对齐：不包含 tuic/warp
    protocols = ["vmess", "vless", "trojan", "ss", "ssr", "hy2"]

    # 从外部文件加载链接（会自动检测和更新状态）
    urls = load_links_from_resources()

    output_folder = ensure_directories_exist()

    print("Starting to fetch and process configs...")

    # 基于内容自动判定 base64/明文并解码
    decoded_sources, config_count, b64_src_cnt, direct_src_cnt = fetch_and_decode(
        urls, MAX_CONFIGS
    )
    print(
        f"Decoded by content type: {b64_src_cnt} base64 sources, {direct_src_cnt} direct text sources, estimated {config_count} configs"
    )

    print("Combining and filtering configs...")
    merged_configs = filter_for_protocols(decoded_sources, protocols, MAX_CONFIGS)
    print(f"Found {len(merged_configs)} unique configs after filtering")

    # Write merged configs to output file
    print("Writing main config file...")
    output_filename = os.path.join(output_folder, "All_Configs_Sub.txt")
    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        f.write(fixed_text)
        for config in merged_configs:
            f.write(config + "\n")
    print(f"Main config file created: {output_filename}")

    print(f"\nProcess completed successfully!")
    print(f"Total configs processed: {len(merged_configs)}")
    print(f"Files created:")
    print(f"  - All_Configs_Sub.txt")


if __name__ == "__main__":
    main()

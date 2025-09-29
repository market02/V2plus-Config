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
from proxy_parsers import ProxyParser

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


def smart_decode_content(response, detection_protocols):
    # 智能解码响应内容，采用明文优先策略

    try:
        # 获取响应内容
        content_bytes = response.content
        if not content_bytes:
            return "", False

        # 策略1: 明文优先 - 尝试直接作为文本处理
        try:
            text_content = response.text or ""
            if text_content.strip():
                # 检查明文是否包含有效协议
                if any(protocol in text_content for protocol in detection_protocols):
                    return text_content, False
        except (UnicodeDecodeError, AttributeError):
            # 明文解码失败，继续尝试base64
            pass

        # 策略2: Base64解码尝试
        try:
            decoded_b64 = decode_base64(content_bytes)
            if decoded_b64 and decoded_b64.strip():
                # 检查base64解码结果是否包含有效协议
                if any(protocol in decoded_b64 for protocol in detection_protocols):
                    return decoded_b64, True
        except Exception:
            # Base64解码失败
            pass

        # 如果明文和base64都不包含有效协议，返回空内容
        return "", False

    except Exception:
        # 所有解码方式都失败，返回空内容
        return "", False


# 获取、解码并逐行过滤配置函数
def fetch_decode_and_filter(urls, protocols, max_configs):
    """
    获取、解码并逐行过滤配置.
    - 遍历URL，获取内容
    - 自动判断base64或明文并解码
    - 逐行进行协议过滤和去重（Protocol+Host+Port + 完全匹配双重去重）
    """
    filtered_data = []
    seen_configs = set()  # 完全匹配去重
    seen_endpoints = set()  # Protocol+Host+Port去重
    config_count = 0
    base64_sources = 0
    direct_sources = 0

    def is_base64_encoded(data_part):
        """判断协议头后面的内容是否为base64编码"""
        try:
            # 简单的base64检测：长度是4的倍数，且只包含base64字符
            if len(data_part) % 4 != 0:
                return False
            # 检查是否包含base64字符集
            import string

            base64_chars = string.ascii_letters + string.digits + "+/="
            return all(c in base64_chars for c in data_part)
        except:
            return False

    def extract_host_port_from_config(config_line):
        """从配置行提取Protocol+Host+Port，使用统一的解析器"""
        try:
            parser = ProxyParser()
            result = parser.parse_config_line(config_line)

            if result and result.get("host") and result.get("port"):
                protocol = result.get("protocol", "unknown")
                host = result["host"]
                port = result["port"]
                return f"{protocol}_{host}_{port}"
            return None
        except Exception as e:
            print(f"提取host:port失败: {e}")
            return None

    def should_add_config(config_line):
        """双重去重检查：完全匹配 + Protocol+Host+Port"""
        # 第一层：完全匹配去重
        if config_line in seen_configs:
            return False

        # 第二层：Protocol+Host+Port去重
        endpoint_key = extract_host_port_from_config(config_line)
        if not endpoint_key:
            return False

        if endpoint_key in seen_endpoints:
            return False

        # 通过双重检查，添加到去重集合
        seen_configs.add(config_line)
        seen_endpoints.add(endpoint_key)
        return True

    detection_protocols = [p + "://" for p in protocols]

    for url in urls:
        if config_count >= max_configs:
            break
        try:
            resp = requests.get(url, timeout=TIMEOUT)

            # 使用智能解码函数
            decoded_text, is_base64_source = smart_decode_content(
                resp, detection_protocols
            )

            if is_base64_source:
                base64_sources += 1
            elif decoded_text:  # 只有当有内容时才计为direct source
                direct_sources += 1

            if decoded_text:
                lines = decoded_text.strip().split("\n")
                for line in lines:
                    if config_count >= max_configs:
                        break

                    line = line.strip()
                    # 仅保留有效协议行，非空且非注释
                    if (
                        not line
                        or not any(p in line for p in protocols)
                        or line.startswith("#")
                    ):
                        continue

                    # 双重去重检查：完全匹配 + Protocol+Host+Port
                    if should_add_config(line):
                        filtered_data.append(line)
                        config_count += 1

        except requests.RequestException:
            # 忽略失败的源
            pass

    return filtered_data, config_count, base64_sources, direct_sources


# Create necessary directories if they don't exist
def ensure_directories_exist():
    # 原来：output_folder = os.path.join(os.path.dirname(__file__), "..")
    output_folder = os.path.join(os.path.dirname(__file__), "..", "data")

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    return output_folder


def checkURL(url):
    try:
        r = requests.head(url, timeout=3)
    except:
        return False
    return r.status_code // 100 == 2


# 封装为函数，并使用绝对路径 + ScrapURL 统计"数量"
def update_resources_status():
    print("开始检测Resources.md文件中的URL状态...")
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    resources_path = os.path.join(base_dir, "docs", "Resources.md")

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
                # 添加数据修正逻辑：如果 responsibility 值异常大，重置为 5
                if resp_val > 5:  # responsibility 不应该超过 5
                    resp_val = 5
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
    seen_urls = set()  # 添加去重集合

    # 先更新Resources文件状态
    update_resources_status()

    # 基于文件位置定位 Resources.md，避免依赖当前工作目录
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    resources_path = os.path.join(base_dir, "docs", "Resources.md")

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
                        and url not in seen_urls  # 添加去重检查
                    ):
                        urls.append(url)
                        seen_urls.add(url)  # 记录已处理的URL

    except FileNotFoundError:
        print("警告：Resources.md文件未找到，返回空链接列表")
        urls = []
    except Exception as e:
        print(f"读取Resources.md文件时出错：{e}")
        urls = []

    # 更新输出信息，显示去重效果
    total_found = len(seen_urls) if seen_urls else len(urls)
    duplicate_count = total_found - len(urls) if seen_urls else 0

    if duplicate_count > 0:
        print(
            f"从Resources.md文件中提取到 {len(urls)} 个可用链接（去重前: {total_found + duplicate_count}，去除重复: {duplicate_count}）"
        )
    else:
        print(f"从Resources.md文件中提取到 {len(urls)} 个可用链接（无重复URL）")

    return urls


def main():
    # 生成阶段协议集与检测对齐：不包含 tuic/warp
    protocols = ["vmess", "vless", "trojan", "ss", "ssr", "hy2"]

    # 从外部文件加载链接（会自动检测和更新状态）
    urls = load_links_from_resources()

    output_folder = ensure_directories_exist()

    print("Starting to fetch, process, and filter configs...")

    # 获取、解码并逐行过滤配置
    (
        merged_configs,
        config_count,
        b64_src_cnt,
        direct_src_cnt,
    ) = fetch_decode_and_filter(urls, protocols, MAX_CONFIGS)
    print(
        f"Processed sources: {b64_src_cnt} base64, {direct_src_cnt} direct text. "
        f"Found {config_count} unique configs."
    )

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

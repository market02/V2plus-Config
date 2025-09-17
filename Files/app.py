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
    base64_folder = os.path.join(output_folder, "Base64")

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    if not os.path.exists(base64_folder):
        os.makedirs(base64_folder)

    return output_folder, base64_folder


# Main function to process links and write output files
def checkURL(url):
    """检测URL是否可访问"""
    try:
        r = requests.head(url, timeout=3)
        return r.status_code // 100 == 2
    except:
        return False


def scrapURL(url):
    """从URL获取代理配置数量"""
    try:
        response = requests.get(url, timeout=TIMEOUT)
        if response.status_code != 200:
            return 0

        # 尝试判断是base64编码还是直接文本
        content = response.content

        # 先尝试作为base64解码
        try:
            decoded_text = decode_base64(content)
            if decoded_text:
                # 成功解码，使用解码后的内容
                text_content = decoded_text
            else:
                # 解码失败，使用原始文本
                text_content = response.text
        except:
            # 解码异常，使用原始文本
            text_content = response.text

        # 统计有效的代理配置行
        lines = text_content.strip().split("\n")
        config_count = 0

        # 定义支持的协议
        protocols = ["vless://", "vmess://", "trojan://", "ss://", "ssr://", "hy2://"]

        for line in lines:
            line = line.strip()
            # 跳过空行和注释行
            if not line or line.startswith("#"):
                continue

            # 检查是否包含支持的协议
            if any(line.startswith(protocol) for protocol in protocols):
                config_count += 1

        return config_count

    except Exception as e:
        print(f"获取代理配置失败 {url}: {e}")
        return 0


def update_resources_status():
    """更新Resources文件中的URL状态和代理数量"""
    # 基于文件位置定位 Resources，避免依赖当前工作目录
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    resources_path = os.path.join(base_dir, "Resources")

    if not os.path.exists(resources_path):
        print("Resources文件不存在，跳过状态更新")
        return

    print("开始检测Resources文件中的URL状态...")

    output = []
    with open(resources_path, encoding="utf8") as file:
        cnt = 0
        while line := file.readline():
            line = line.rstrip()
            if line.startswith("|"):
                if cnt > 1:  # 跳过表头行
                    columns = [col.strip() for col in line.split("|")]
                    # 参考你的 nodes.md 实现，URL 在倒数第二个分隔列
                    if len(columns) >= 2:
                        url = columns[-2].strip()

                        # 不修改正常的 https://，直接校验
                        if not url.startswith("https://"):
                            cnt += 1
                            output.append(line)
                            continue

                        # 检测URL状态（重试3次）
                        status_ok = False
                        for _ in range(3):
                            if checkURL(url):
                                status_ok = True
                                break
                        status_icon = "✅" if status_ok else "❌"

                        # 统计代理数量（可用时才统计）
                        try:
                            proxy_count = scrapURL(url) if status_ok else 0
                        except Exception as e:
                            print(f"获取代理数量失败 {url}: {e}")
                            proxy_count = 0

                        # 回写状态和数量到表格前两列
                        line = re.sub(
                            r"^\|+?(.*?)\|+?(.*?)\|+?",
                            f"| {status_icon} | {proxy_count} |",
                            line,
                            count=1,
                        )
                        print(
                            f"检测完成: {url} -> {status_icon} ({proxy_count} proxies)"
                        )
                cnt += 1
            output.append(line)

    # 写回文件
    with open(resources_path, "w", encoding="utf8") as f:
        f.write("\n".join(output))

    print("Resources文件状态更新完成")


def load_links_from_resources():
    """从Resources文件中提取URL链接（改进版）"""
    links = []
    dir_links = []

    # 先更新Resources文件状态
    update_resources_status()

    try:
        with open("../Resources", "r", encoding="utf-8") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()

            # 跳过空行、注释行、表格头部和分隔符
            if (
                not line
                or line.startswith("#")
                or line.startswith("|:-")
                or line.startswith("---")
                or line.startswith("<!---")
                or line.endswith("-->")
                or "| available |" in line
            ):
                continue

            # 处理表格行
            if line.startswith("|") and line.endswith("|"):
                columns = [col.strip() for col in line.split("|")]

                if len(columns) >= 5:
                    status = columns[1].strip()
                    url = columns[4].strip()

                    # 不要再截断 https://，直接使用原始URL
                    # if url.startswith("https://"):
                    #     url = url[1:]

                    if status == "✅" and url.startswith("https://") and len(url) > 10:
                        if any(
                            keyword in url.lower()
                            for keyword in ["sub.txt", "base64", "encoded"]
                        ):
                            links.append(url)
                        else:
                            dir_links.append(url)

    except FileNotFoundError:
        print("警告：Resources文件未找到，使用默认链接")
        links = [
            "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt"
        ]
        dir_links = []
    except Exception as e:
        print(f"读取Resources文件时出错：{e}")
        links = []
        dir_links = []

    print(
        f"从Resources文件中提取到 {len(links)} 个base64链接和 {len(dir_links)} 个直接文本链接"
    )
    return links, dir_links


def main():
    # 生成阶段协议集与检测对齐：不包含 tuic/warp
    protocols = ["vmess", "vless", "trojan", "ss", "ssr", "hy2"]

    # 从外部文件加载链接（会自动检测和更新状态）
    links, dir_links = load_links_from_resources()

    all_configs = []
    output_folder, base64_folder = ensure_directories_exist()

    # 删除第160-188行的硬编码链接部分

    print("Starting to fetch and process configs...")

    # protocols = ["vmess", "vless", "trojan", "ss", "ssr", "hy2"]
    # links = [
    # "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
    # "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    # "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    # "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    # "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/app/sub.txt",
    # "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
    # "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_2.txt",
    # "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_3.txt",
    # "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_4.txt",
    # "https://raw.githubusercontent.com/yebekhe/vpn-fail/refs/heads/main/sub-link",
    # "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed"
    # ]
    # dir_links = [
    # "https://raw.githubusercontent.com/itsyebekhe/PSG/main/lite/subscriptions/xray/normal/mix",
    # "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    # "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
    # "https://raw.githubusercontent.com/IranianCypherpunks/sub/main/config",
    # "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
    # "https://raw.githubusercontent.com/sashalsk/V2Ray/main/V2Config",
    # "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    # "https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/normal/mix",
    # "https://raw.githubusercontent.com/sarinaesmailzadeh/V2Hub/main/merged",
    # "https://raw.githubusercontent.com/freev2rayconfig/V2RAY_SUBSCRIPTION_LINK/main/v2rayconfigs.txt",
    # "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",
    # "https://raw.githubusercontent.com/C4ssif3r/V2ray-sub/main/all.txt",
    # "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
    # ]

    print("Fetching base64 encoded configs...")
    decoded_links, config_count = decode_links(links, MAX_CONFIGS)
    print(
        f"Decoded {len(decoded_links)} base64 sources, estimated {config_count} configs"
    )

    if config_count < MAX_CONFIGS:
        print("Fetching direct text configs...")
        decoded_dir_links, config_count = decode_dir_links(
            dir_links, MAX_CONFIGS, config_count
        )
        print(
            f"Decoded {len(decoded_dir_links)} direct text sources, total estimated {config_count} configs"
        )
    else:
        decoded_dir_links = []
        print("Skipping direct text configs as limit already reached")

    print("Combining and filtering configs...")
    combined_data = decoded_links + decoded_dir_links
    merged_configs = filter_for_protocols(combined_data, protocols, MAX_CONFIGS)

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

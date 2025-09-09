import pybase64
import base64
import requests
import binascii
import os

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
            decoded = pybase64.b64decode(encoded + b"=" * (-len(encoded) % 4)).decode(encoding)
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
                lines = decoded_text.strip().split('\n')
                config_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
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
                lines = decoded_text.strip().split('\n')
                config_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
                current_count += len(config_lines)
        except requests.RequestException:
            pass  # If the request fails or times out, skip it
    return decoded_dir_links, current_count

# Filter function to select lines based on specified protocols and remove duplicates (only for config lines)
def filter_for_protocols(data, protocols, max_configs):
    filtered_data = []
    seen_configs = set()      # 原有的完全匹配去重
    seen_endpoints = set()    # 新增：endpoint去重 (protocol+host+port)
    config_count = 0
    
    def get_endpoint_key(config_line):
        """提取节点的endpoint标识：protocol+host+port"""
        import re
        try:
            # 统一的正则匹配模式
            patterns = [
                (r'(vless|vmess|trojan)://[^@]*@([^:/]+):(\d+)', lambda m: f"{m.group(1)}_{m.group(2)}_{m.group(3)}"),
                (r'(ss|ssr)://[^@]*@([^:/]+):(\d+)', lambda m: f"{m.group(1)}_{m.group(2)}_{m.group(3)}")
            ]
            
            for pattern, formatter in patterns:
                match = re.search(pattern, config_line)
                if match:
                    return formatter(match)
        except:
            pass
        return None
    
    # Process each decoded content
    for content in data:
        if config_count >= max_configs:
            break
        if content and content.strip():  # Skip empty content
            lines = content.strip().split('\n')
            for line in lines:
                if config_count >= max_configs:
                    break
                line = line.strip()
                if line.startswith('#'):
                    filtered_data.append(line)  # 只保留注释
                elif any(protocol in line for protocol in protocols) and line.strip():
                    # 第一层：完全匹配去重（保留原逻辑）
                    if line not in seen_configs:
                        # 第二层：endpoint去重（新增逻辑）
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
def load_links_from_resources():
    with open('../Resources', 'r', encoding='utf-8') as f:
        links = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    with open('../C-Resources', 'r', encoding='utf-8') as f:
        dir_links = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    return links, dir_links

def main():
    protocols = ["vmess", "vless", "trojan", "ss", "ssr", "hy2", "tuic", "warp://"]
    
    # 从外部文件加载链接
    links, dir_links = load_links_from_resources()
    
    all_configs = []
    output_folder, base64_folder = ensure_directories_exist()  # Ensure directories are created

    # Clean existing output files FIRST before processing
    print("Cleaning existing files...")
    output_filename = os.path.join(output_folder, "All_Configs_Sub.txt")
    main_base64_filename = os.path.join(output_folder, "All_Configs_base64_Sub.txt")
    
    if os.path.exists(output_filename):
        os.remove(output_filename)
        print(f"Removed: {output_filename}")
    if os.path.exists(main_base64_filename):
        os.remove(main_base64_filename)
        print(f"Removed: {main_base64_filename}")



    print("Starting to fetch and process configs...")
    
    protocols = ["vmess", "vless", "trojan", "ss", "ssr", "hy2", "tuic", "warp://"]
    links = [
        "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
        #"https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
        #"https://raw.githubusercontent.com/ts-sf/fly/main/v2",
        #"https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
        #"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/app/sub.txt",
        #"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
        #"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_2.txt",
        #"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_3.txt",
        #"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_4.txt",
        #"https://raw.githubusercontent.com/yebekhe/vpn-fail/refs/heads/main/sub-link",
        #"https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed"
    ]
    dir_links = [
        "https://raw.githubusercontent.com/itsyebekhe/PSG/main/lite/subscriptions/xray/normal/mix",
        #"https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
        #"https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
        #"https://raw.githubusercontent.com/IranianCypherpunks/sub/main/config",
        #"https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
        #"https://raw.githubusercontent.com/sashalsk/V2Ray/main/V2Config",
        #"https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
        #"https://raw.githubusercontent.com/itsyebekhe/HiN-VPN/main/subscription/normal/mix",
        #"https://raw.githubusercontent.com/sarinaesmailzadeh/V2Hub/main/merged",
        #"https://raw.githubusercontent.com/freev2rayconfig/V2RAY_SUBSCRIPTION_LINK/main/v2rayconfigs.txt",
        #"https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",
        #"https://raw.githubusercontent.com/C4ssif3r/V2ray-sub/main/all.txt",
        #"https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
    ]

    print("Fetching base64 encoded configs...")
    decoded_links, config_count = decode_links(links, MAX_CONFIGS)
    print(f"Decoded {len(decoded_links)} base64 sources, estimated {config_count} configs")
    
    if config_count < MAX_CONFIGS:
        print("Fetching direct text configs...")
        decoded_dir_links, config_count = decode_dir_links(dir_links, MAX_CONFIGS, config_count)
        print(f"Decoded {len(decoded_dir_links)} direct text sources, total estimated {config_count} configs")
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

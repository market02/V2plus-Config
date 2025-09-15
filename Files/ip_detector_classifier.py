import re
import socket
import subprocess
import requests
import json
import os
from concurrent.futures import ThreadPoolExecutor
from connectivity_checker import V2rayConfigChecker

class IPGeoClassifier:
    def __init__(self, timeout=5):
        self.timeout = timeout
        # 本地缓存（DNS解析/地理信息）
        self._dns_cache = {}
        self._geo_cache = {}
    
    def _is_ip(self, address):
        """检查地址是否为IP地址"""
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False
    
    def _resolve_ip(self, host, get_all=False):
        """解析域名为IP地址，支持获取所有IP或单个IP"""
        if self._is_ip(host):
            return [host] if get_all else host
        
        cache_key = f"{host}_{get_all}"
        if cache_key in self._dns_cache:
            return self._dns_cache[cache_key]
        
        try:
            if get_all:
                # 获取所有IP地址
                result = socket.getaddrinfo(host, None, socket.AF_INET)
                ips = list(set([addr[4][0] for addr in result]))
                self._dns_cache[cache_key] = ips
                return ips
            else:
                # 获取单个IP地址
                ip = socket.gethostbyname(host)
                self._dns_cache[cache_key] = ip
                return ip
        except (socket.gaierror, socket.herror) as e:
            print(f"DNS解析失败 {host}: {e}")
            return [] if get_all else None
    
    def _resolve_all_ips(self, host):
        """解析域名获取所有IP地址"""
        return self._resolve_ip(host, get_all=True)
    
    def _geolocate_ip(self, ip):
        """获取IP地址的地理位置信息"""
        if ip in self._geo_cache:
            return self._geo_cache[ip]
        
        try:
            # 使用免费的IP地理位置API
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    geo_info = {
                        'country': data.get('country', ''),
                        'countryCode': data.get('countryCode', ''),
                        'region': data.get('regionName', ''),
                        'city': data.get('city', ''),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0)
                    }
                    self._geo_cache[ip] = geo_info
                    return geo_info
        except Exception as e:
            print(f"获取IP地理位置失败 {ip}: {e}")
        
        return None
    
    def _geolocate_all_ips(self, ips):
        """批量获取多个IP的地理位置信息"""
        geo_results = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self._geolocate_ip, ip): ip for ip in ips}
            for future in futures:
                ip = futures[future]
                try:
                    geo_info = future.result()
                    if geo_info:
                        geo_results.append({
                            'ip': ip,
                            'geo': geo_info
                        })
                except Exception as e:
                    print(f"获取IP {ip} 地理位置时出错: {e}")
        return geo_results
    
    def _is_us_ca_region(self, country_code):
        """判断是否为美国/加拿大地区"""
        return country_code.upper() in ['US', 'CA']
    
    def _is_eu_jp_kr_region(self, country_code):
        """判断是否为欧洲/日本/韩国地区"""
        eu_countries = [
            'DE', 'FR', 'IT', 'ES', 'NL', 'BE', 'AT', 'CH', 'SE', 'NO', 'DK', 'FI',
            'PL', 'CZ', 'HU', 'RO', 'BG', 'HR', 'SI', 'SK', 'LT', 'LV', 'EE',
            'IE', 'PT', 'GR', 'CY', 'MT', 'LU', 'IS', 'LI', 'MC', 'SM', 'VA',
            'AD', 'GB', 'UK'  # 包含英国
        ]
        return country_code.upper() in eu_countries or country_code.upper() in ['JP', 'KR']
    
    def classify_configs_by_ip(self, configs, output_dir="."):
        """根据IP地理位置对配置进行分类，支持节点归属多个地区"""
        us_ca_configs = []
        eu_jp_kr_configs = []
        other_configs = []
        
        print(f"开始分类 {len(configs)} 个配置...")
        
        for i, config_info in enumerate(configs, 1):
            host = config_info.get('host', '')
            original_config = config_info.get('original', '')
            
            if not host:
                other_configs.append(original_config)
                continue
            
            print(f"处理配置 {i}/{len(configs)}: {host}")
            
            # 获取所有IP地址
            ips = self._resolve_all_ips(host)
            if not ips:
                print(f"  无法解析域名: {host}")
                other_configs.append(original_config)
                continue
            
            print(f"  解析到 {len(ips)} 个IP: {', '.join(ips)}")
            
            # 获取所有IP的地理位置信息
            geo_results = self._geolocate_all_ips(ips)
            if not geo_results:
                print(f"  无法获取地理位置信息")
                other_configs.append(original_config)
                continue
            
            # 分析所有IP的地理位置，确定节点归属的地区
            regions_found = set()
            
            for geo_result in geo_results:
                country_code = geo_result['geo'].get('countryCode', '')
                country = geo_result['geo'].get('country', '')
                ip = geo_result['ip']
                
                print(f"    IP {ip}: {country} ({country_code})")
                
                if self._is_us_ca_region(country_code):
                    regions_found.add('US_CA')
                elif self._is_eu_jp_kr_region(country_code):
                    regions_found.add('EU_JP_KR')
                else:
                    regions_found.add('OTHER')
            
            # 根据发现的地区将配置添加到对应分类
            if 'US_CA' in regions_found:
                us_ca_configs.append(original_config)
                print(f"  -> 添加到美国/加拿大分类")
            
            if 'EU_JP_KR' in regions_found:
                eu_jp_kr_configs.append(original_config)
                print(f"  -> 添加到欧洲/日韩分类")
            
            if 'OTHER' in regions_found and 'US_CA' not in regions_found and 'EU_JP_KR' not in regions_found:
                other_configs.append(original_config)
                print(f"  -> 添加到其他地区分类")
            
            # 如果节点同时属于多个地区，会被添加到多个分类中
            if len(regions_found) > 1:
                print(f"  -> 节点跨越多个地区: {', '.join(regions_found)}")
        
        # 写入分类文件
        import os
        
        # 美国/加拿大配置
        us_ca_file = os.path.join(output_dir, "US_CA_configs.txt")
        with open(us_ca_file, 'w', encoding='utf-8') as f:
            for config in us_ca_configs:
                f.write(config + '\n')
        print(f"美国/加拿大配置已保存到: {us_ca_file} ({len(us_ca_configs)} 个)")
        
        # 欧洲/日韩配置
        eu_jp_kr_file = os.path.join(output_dir, "EU_JP_KR_configs.txt")
        with open(eu_jp_kr_file, 'w', encoding='utf-8') as f:
            for config in eu_jp_kr_configs:
                f.write(config + '\n')
        print(f"欧洲/日韩配置已保存到: {eu_jp_kr_file} ({len(eu_jp_kr_configs)} 个)")
        
        # 其他地区配置
        other_file = os.path.join(output_dir, "Other_configs.txt")
        with open(other_file, 'w', encoding='utf-8') as f:
            for config in other_configs:
                f.write(config + '\n')
        print(f"其他地区配置已保存到: {other_file} ({len(other_configs)} 个)")
        
        return {
            'us_ca': len(us_ca_configs),
            'eu_jp_kr': len(eu_jp_kr_configs),
            'other': len(other_configs)
        }

def main():
    # 固定使用All_Configs_Sub_valid.txt
    # 兼容GitHub Actions中 working-directory=Files 的情况：
    # 从脚本所在目录的上一级目录读取有效配置文件，将分类结果写入当前脚本目录（Files）
    import os
    base_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(base_dir)
    config_file = os.path.join(parent_dir, "All_Configs_Sub_valid.txt")
    output_dir = base_dir

    if not os.path.exists(config_file):
        print(f"文件不存在: {config_file}")
        print("请先运行 connectivity_checker.py 生成有效配置文件")
        return
    
    # 读取配置文件
    with open(config_file, 'r', encoding='utf-8') as f:
        raw_configs = [line.strip() for line in f if line.strip()]
    
    # 使用connectivity_checker的解析逻辑
    config_checker = V2rayConfigChecker()
    configs = []
    
    for config in raw_configs:
        if config.startswith('#'):
            continue
        
        # 直接使用现有的解析方法
        parsed_config = config_checker.parse_config_line(config)
        if parsed_config:
            configs.append(parsed_config)
        else:
            print(f"解析失败: {config[:50]}...")
    
    print(f"成功解析 {len(configs)} 个配置...")
    
    # 执行分类
    network_utils = IPGeoClassifier(timeout=10)
    result = network_utils.classify_configs_by_ip(configs, output_dir)
    
    print(f"分类完成:")
    print(f"  美国/加拿大: {result['us_ca']} 个")
    print(f"  欧洲/日韩: {result['eu_jp_kr']} 个")
    print(f"  其他地区: {result['other']} 个")

if __name__ == "__main__":
    main()
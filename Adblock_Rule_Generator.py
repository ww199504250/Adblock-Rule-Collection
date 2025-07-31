import os
import sys
import subprocess
import warnings
import importlib.util
import logging
import asyncio
import aiohttp
import re
import time
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timezone, timedelta

# 设置日志配置，日志文件名为'adblock_rule_downloader.log'，日志级别为INFO
logging.basicConfig(filename='adblock_rule_downloader.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def install_packages(packages):
    # 检查并安装所需的Python包
    for package in packages:
        if importlib.util.find_spec(package) is None:
            logging.info(f"Package '{package}' is not installed. Installing...")
            subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)
            logging.info(f"Package '{package}' installed successfully.")
        else:
            logging.info(f"Package '{package}' is already installed.")

# 确保安装的包列表
required_packages = ["aiohttp", "urllib3", "certifi"]

install_packages(required_packages)

warnings.simplefilter('ignore', InsecureRequestWarning)

# 判断是否为有效规则的行，去除注释和空白行
def is_valid_rule(line):
    line = line.strip()
    if not line or line.startswith(('!', '#', '[', ';', '//', '/*', '*/')):
        return False
    return True

# 判断是否为IPv4映射规则
def is_ip_domain_mapping(line):
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}\s+\S+', line) is not None

# 判断是否为纯IPv4地址
def is_ip_address(line):
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}$', line) is not None

# 判断是否为IPv6映射规则
def is_ipv6_domain_mapping(line):
    return re.match(r'^[\da-fA-F:]+\s+\S+', line) is not None

# 判断是否为纯IPv6地址
def is_ipv6_address(line):
    return re.match(r'^[\da-fA-F:]+$', line) is not None

# 判断是否为纯域名
def is_domain(line):
    # 检测是否是合法的域名
    domain_pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return re.match(domain_pattern, line) is not None

# 处理每一行规则，转换为统一格式
def process_line(line):
    line = line.strip()
    
    if not is_valid_rule(line):
        return None

    # 处理IPv4地址映射：0.0.0.0 和 127.0.0.1
    if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].split('#')[0].strip()
            return f"||{domain}^"
    
    # 处理IPv6地址映射：:: 和 ::1
    if line.startswith('::') or line.startswith('::1'):
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].split('#')[0].strip()
            return f"||{domain}^"

    # 忽略其他IPv4和IPv6域名映射
    if is_ip_domain_mapping(line) or is_ipv6_domain_mapping(line):
        return None

    # 处理纯IPv4地址
    if is_ip_address(line):
        return f"||{line}^"
    
    # 处理纯IPv6地址
    if is_ipv6_address(line):
        return f"||{line}^"

    # 处理Dnsmasq规则，address= 和 server=，添加对 IPv4 和 IPv6 的处理
    if line.startswith('address='):
        parts = line.split('=')  
        if len(parts) == 3:
            domain = parts[1].strip()
            target_ip = parts[2].strip()
            if target_ip in ['127.0.0.1', '0.0.0.0', '::1', '::']:
                return f"||{domain}^"

    elif line.startswith('server='):
        parts = line.split('=', 1)
        if len(parts) == 2:
            server_info = parts[1].split('/')
            if len(server_info) == 3:
                domain = server_info[1].strip()
                target_ip = server_info[2].strip()
                if target_ip in ['127.0.0.1', '0.0.0.0', '::1', '::']:
                    return f"||{domain}^"
    
    # 处理纯域名
    if is_domain(line):
        return f"||{line}^"
    
    return line


# 异步下载过滤器规则
async def download_filter(session, url, retries=5):
    rules = set()
    attempt = 0
    while attempt < retries:
        try:
            async with session.get(url, ssl=False) as response:
                logging.info(f"Downloading from {url}, attempt {attempt + 1}")
                if response.status == 200:
                    logging.info(f"Successfully downloaded from {url}")
                    text = await response.text()
                    lines = text.splitlines()
                    for line in lines:
                        line = line.strip()
                        if is_valid_rule(line):
                            processed_line = process_line(line)
                            if processed_line is not None:
                                rules.add(processed_line)
                    break
                else:
                    logging.error(f"Failed to download from {url} with status code {response.status}")
        except Exception as e:
            logging.error(f"Error downloading {url}: {e}")
        attempt += 1
        if attempt < retries:
            wait_time = 2 ** attempt
            logging.info(f"Retrying in {wait_time} seconds...")
            await asyncio.sleep(wait_time)
        else:
            logging.error(f"Max retries reached for {url}")
    return rules

# 异步下载多个过滤器规则
async def download_filters(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [download_filter(session, url) for url in urls]
        all_rules = set()
        for future in asyncio.as_completed(tasks):
            rules = await future
            all_rules.update(rules)
    return all_rules

# 验证规则的有效性
def validate_rules(rules):
    validated_rules = set()
    for rule in rules:
        if is_valid_rule(rule):
            validated_rules.add(rule)
    return validated_rules

# 将规则写入文件
def write_rules_to_file(rules, save_path):
    now = datetime.now(timezone(timedelta(hours=8)))
    timestamp = now.strftime('%Y-%m-%d %H:%M:%S %Z')
    header = f"""
!Title: Adblock-Rule-Collection
!Description: 一个汇总了多个广告过滤器过滤规则的广告过滤器订阅，每20分钟更新一次，确保即时同步上游减少误杀
!Homepage: https://github.com/REIJI007/Adblock-Rule-Collection
!LICENSE1: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-GPL 3.0
!LICENSE2: https://github.com/REIJI007/Adblock-Rule-Collection/blob/main/LICENSE-CC-BY-NC-SA 4.0
!生成时间: {timestamp}
!有效规则数目: {len(rules)}
"""
    with open(save_path, 'w', encoding='utf-8') as f:
        logging.info(f"Writing {len(rules)} rules to file {save_path}")
        f.write(header)
        f.write('\n')
        f.writelines(f"{rule}\n" for rule in sorted(rules) if rule is not None)
    logging.info(f"Successfully wrote rules to {save_path}")
    print(f"Successfully wrote rules to {save_path}")
    print(f"有效规则数目: {len(rules)}")

# 主函数
def main():
    logging.info("Starting to download filters...")
    print("Starting to download filters...")

    filter_urls = [
"https://raw.githubusercontent.com/REIJI007/Adblock-Rule-Collection/main/Whitelist.txt",
"https://raw.githubusercontent.com/hululu1068/AdGuard-Rule/main/rule/adgh.txt",
"https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
"https://raw.githubusercontent.com/uniartisan/adblock_list/master/adblock_plus.txt",     
"https://raw.githubusercontent.com/damengzhu/abpmerge/main/abpmerge.txt", 
"https://ad.kirychan.com/KR_DNS_Filter.txt",     
"https://raw.githubusercontent.com/045200/EasyAds/master/data/rules/dns.txt",   
"https://raw.githubusercontent.com/neodevpro/neodevhost/master/host",      
"https://raw.githubusercontent.com/xndeye/adblock_list/refs/heads/release/easylist.txt",   
"https://gh-proxy.com/raw.githubusercontent.com/Lynricsy/HyperADRules/master/dns.txt",      
"https://raw.githubusercontent.com/qq5460168/666/master/rules.txt",   
"https://raw.githubusercontent.com/qq5460168/666/master/dns.txt",  
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdnslite.txt",     
    ]

    save_path = os.path.join(os.getcwd(), 'ADBLOCK_RULE_COLLECTION.txt')
    rules = asyncio.run(download_filters(filter_urls))
    validated_rules = validate_rules(rules)
    write_rules_to_file(validated_rules, save_path)

if __name__ == '__main__':
    main()
    if sys.stdin.isatty():
        input("Press Enter to exit...")
    else:
        print("Non-interactive mode, exiting...")

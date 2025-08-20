#!/usr/bin/python
# -*- coding: UTF-8 -*-
# Author: R3start
# 改进版：支持命令行参数的IP和域名碰撞匹配工具

import argparse
import requests
import re
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(
        description="IP和域名碰撞匹配访问工具",
        epilog="使用示例: python script.py -if ip.txt -ih host.txt -o results.txt"
    )
    
    # 添加参数定义
    parser.add_argument("-if", "--ipfile", 
                        default="ip.txt",
                        help="IP列表文件路径（默认：ip.txt）")
    parser.add_argument("-ih", "--hostfile", 
                        default="host.txt",
                        help="域名列表文件路径（默认：host.txt）")
    parser.add_argument("-o", "--output", 
                        default="hosts_ok.txt",
                        help="结果输出文件路径（默认：hosts_ok.txt）")
    
    # 解析命令行参数
    args = parser.parse_args()
    
    # 读取IP和域名列表
    try:
        with open(args.ipfile, 'r') as ip_file:
            ip_list = [ip.strip() for ip in ip_file.readlines()]
        
        with open(args.hostfile, 'r') as host_file:
            host_list = [host.strip() for host in host_file.readlines()]
    except FileNotFoundError as e:
        print(f"文件未找到错误: {e}")
        sys.exit(1)
    
    # 结果存储
    successful_matches = []
    http_protocols = ['http://', 'https://']
    
    print("====================================开 始 匹 配====================================")
    
    # 使用with安全打开输出文件
    with open(args.output, 'w', encoding='utf-8') as output_file:
        for ip in ip_list:
            for protocol in http_protocols:
                for host in host_list:
                    headers = {
                        'Host': host,
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36'
                    }
                    
                    try:
                        url = protocol + ip
                        response = requests.get(
                            url, 
                            headers=headers, 
                            verify=False, 
                            timeout=5
                        )
                        response.encoding = 'utf-8'
                        
                        # 提取标题（带异常处理）
                        title_match = re.search('<title>(.*?)</title>', response.text, re.IGNORECASE)
                        title = title_match.group(1) if title_match else "无标题"
                        
                        # 构建结果信息
                        result_info = f"{ip} -- {host} 协议：{protocol} 状态码：{response.status_code} 数据包大小：{len(response.text)} 标题：{title}"
                        
                        # 保存成功结果
                        successful_matches.append(result_info)
                        output_file.write(result_info + "\n")
                        print(result_info)
                        
                    except Exception as e:
                        error_info = f"{ip} --- {host} --- {protocol}访问失败: {str(e)}"
                        print(error_info)
    
    # 打印成功匹配结果
    if successful_matches:
        print("\n====================================匹 配 成 功 的 列 表====================================")
        for match in successful_matches:
            print(match)
    else:
        print("\n====================================未 找 到 匹 配 项 目====================================")

if __name__ == "__main__":
    main()

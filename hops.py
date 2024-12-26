import re
import argparse
from datetime import datetime
import email
from email import policy
from email.parser import BytesParser
import os

# 設定命令行參數解析器
parser = argparse.ArgumentParser(description='Extract email hops information.')
parser.add_argument('filename', type=str, help='The name of the file containing email headers')

def parse_time(time_str):
    """解析時間字符串，返回 datetime 對象"""
    try:
        # 移除括號內的內容和多餘空格
        time_str = re.sub(r'\([^)]*\)', '', time_str).strip()
        return datetime.strptime(time_str, '%a, %d %b %Y %H:%M:%S %z')
    except ValueError:
        return None

def parse_received_headers(eml_file_path):
    """解析 EML 文件中的 Received 標頭"""
    if not os.path.exists(eml_file_path):  # 檢查文件是否存在
        raise FileNotFoundError(f"文件 {eml_file_path} 不存在")
    hops_info = []
    
    with open(eml_file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
        received_headers = msg.get_all('Received', [])

    previous_time = None
    
    for i, header in enumerate(received_headers):
        parts = header.split(';')
        if len(parts) < 2:
            continue

        # 解析時間
        time_str = parts[-1].strip()
        current_time = parse_time(time_str)

        # 使用正則表達式提取 from 和 by 信息
        match = re.search(r"from\s(.*?)\sby\s(.*?)(?:\swith|\Z)", parts[0], re.DOTALL)
        
        if match:
            from_address = match.group(1).strip()
            by_address = match.group(2).strip()
            
            # 計算延遲時間
            delay = None
            if previous_time and current_time:
                delay = (previous_time - current_time).total_seconds()

            hops_info.append({
                'from': from_address,
                'by': by_address,
                'time': time_str,
                'delay': f"{delay:.2f} seconds" if delay is not None else "N/A"
            })

        previous_time = current_time

    return hops_info

def main(eml_file_path):
    hops_info = parse_received_headers(eml_file_path)
    return hops_info

if __name__ == "__main__":
    args = parser.parse_args()
    hops_info = main(args.filename)
    print(hops_info)  # 或者將結果寫入文件

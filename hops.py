import re
import argparse
from datetime import datetime
import email
from email import policy
from email.parser import BytesParser
import os
import json  # 用於輸出 JSON 格式
import logging
import extract_msg  # 添加 extract_msg 導入

# 設定命令行參數解析器
parser = argparse.ArgumentParser(description='Extract email hops information.')
parser.add_argument('filename', type=str, help='The name of the file containing email headers')

def parse_time(time_str):
    """解析時間字符串，支援多種格式"""
    time_formats = [
        '%a, %d %b %Y %H:%M:%S %z',  # RFC 2822
        '%d %b %Y %H:%M:%S %z',      # 簡化格式
        '%Y-%m-%d %H:%M:%S %z'       # ISO 格式
    ]
    
    # 移除括號內的內容和多餘空格
    cleaned_time = re.sub(r'\([^)]*\)', '', time_str).strip()
    
    for fmt in time_formats:
        try:
            return datetime.strptime(cleaned_time, fmt)
        except ValueError:
            continue
    
    logging.warning(f'無法解析時間格式: {time_str}')
    return None

def parse_msg_file(msg_path):
    """解析 MSG 檔案中的 headers"""
    try:
        msg = extract_msg.Message(msg_path)
        headers = msg.header  # 使用 header 屬性
        if not headers:
            logging.warning(f'MSG 檔案無 headers: {msg_path}')
            return []

        # 檢查 headers 的類型
        if isinstance(headers, email.message.Message):
            received_headers = headers.get_all('Received', [])
            logging.debug(f'解析到的 Received headers: {received_headers}')
            return received_headers
        else:
            logging.error(f'未知的 headers 類型: {type(headers)}')
            return []

    except Exception as e:
        logging.error(f'解析 MSG 檔案時發生錯誤: {e}')
        return []

def parse_received_headers(file_path):
    """解析郵件檔案中的 Received 標頭"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"檔案 {file_path} 不存在")
    
    file_extension = os.path.splitext(file_path)[1].lower()
    received_headers = []
    
    try:
        if file_extension == '.msg':
            received_headers = parse_msg_file(file_path)
        elif file_extension == '.eml':
            with open(file_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
                received_headers = msg.get_all('Received', [])
        else:
            raise ValueError(f"不支援的檔案格式: {file_extension}")
        
        hops_info = []
        previous_time = None
        
        for header in received_headers:
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
        
    except Exception as e:
        logging.error(f'解析郵件時發生錯誤: {e}')
        return []

def main(eml_file_path):
    try:
        hops_info = parse_received_headers(eml_file_path)
        print(json.dumps(hops_info, indent=2))  # 以 JSON 格式輸出
    except Exception as e:
        error_message = {'error': str(e)}
        print(json.dumps(error_message, indent=2))  # 以 JSON 格式輸出錯誤

if __name__ == "__main__":
    args = parser.parse_args()
    main(args.filename)

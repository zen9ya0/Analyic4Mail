import requests
import logging
import json
import argparse
import re
from config import (
    ABUSEIPDB_API_KEY, 
    DEBUG_MODE, 
    LOG_LEVEL, 
    LOG_FORMAT, 
    LOG_FILE
)

# 設定日誌記錄
def setup_logging():
    """設定日誌記錄器"""
    # 設定日誌級別
    log_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    
    # 創建日誌處理器
    handlers = []
    if DEBUG_MODE:
        # 添加文件處理器
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        handlers.append(file_handler)
        
        # 添加控制台處理器
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        handlers.append(console_handler)
    
    # 配置日誌
    logging.basicConfig(
        level=log_level,
        format=LOG_FORMAT,
        handlers=handlers
    )

# 創建日誌記錄器
setup_logging()
logger = logging.getLogger('AbuseIPDB')

def extract_ip(input_string):
    """從字符串中提取 IP 地址"""
    # 匹配 IPv4 地址的正則表達式
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    # 尋找所有匹配的 IP 地址
    ip_matches = re.findall(ip_pattern, input_string)
    
    if ip_matches:
        logger.debug(f"從輸入中提取到 IP: {ip_matches[0]}")
        return ip_matches[0]
    else:
        logger.warning(f"無法從輸入中提取 IP: {input_string}")
        return None

def check_ip(ip_address, max_age_in_days=15):
    """
    檢查指定 IP 地址在 AbuseIPDB 中的記錄
    Args:
        ip_address (str): 要檢查的 IP 地址
        max_age_in_days (int): 檢查的時間範圍（天數）
    """
    # 提取純 IP 地址
    clean_ip = extract_ip(ip_address)
    if not clean_ip:
        error_msg = "無效的 IP 地址格式"
        logger.error(error_msg)
        return {
            'error': True,
            'message': error_msg
        }
    
    logger.debug(f"開始檢查 IP: {clean_ip}")
    
    # API 端點
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    # 查詢參數
    querystring = {
        'ipAddress': clean_ip,
        'maxAgeInDays': str(max_age_in_days)
    }
    
    # 請求標頭
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    
    try:
        logger.debug(f"發送請求到 AbuseIPDB API: {url}")
        logger.debug(f"查詢參數: {querystring}")
        
        # 發送請求
        response = requests.request(
            method='GET',
            url=url,
            headers=headers,
            params=querystring,
            timeout=10
        )
        
        # 檢查響應狀態
        response.raise_for_status()
        logger.debug(f"收到響應狀態碼: {response.status_code}")
        
        # 解析響應
        decoded_response = response.json()
        logger.debug(f"API 響應: {json.dumps(decoded_response, indent=2, ensure_ascii=False)}")
        
        return decoded_response
        
    except requests.exceptions.Timeout:
        error_msg = "請求超時"
        logger.error(error_msg)
        return {
            'error': True,
            'message': error_msg
        }
        
    except requests.exceptions.RequestException as e:
        error_msg = f'API request failed: {str(e)}'
        logger.error(error_msg)
        return {
            'error': True,
            'message': error_msg
        }
        
    except json.JSONDecodeError as e:
        error_msg = f'JSON 解析錯誤: {str(e)}'
        logger.error(error_msg)
        return {
            'error': True,
            'message': error_msg
        }
        
    except Exception as e:
        error_msg = f'Unexpected error: {str(e)}'
        logger.error(error_msg)
        return {
            'error': True,
            'message': error_msg
        }

def main():
    # 創建命令行參數解析器
    parser = argparse.ArgumentParser(description='檢查 IP 地址在 AbuseIPDB 中的記錄')
    parser.add_argument('--ip', required=True, help='要檢查的 IP 地址')
    parser.add_argument('--days', type=int, default=15, help='檢查的時間範圍（天數），預設為 15 天')
    
    # 解析命令行參數
    args = parser.parse_args()
    
    try:
        # 執行 IP 檢查
        logger.info(f"執行 IP 檢查: {args.ip}")
        result = check_ip(args.ip, args.days)
        
        # 輸出結果
        print("\n檢查結果:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
    except Exception as e:
        logger.exception("檢查過程中發生錯誤")
        print(f"\n錯誤: {str(e)}")

if __name__ == "__main__":
    main()

import requests
import logging
from config import ABUSEIPDB_API_KEY

# 設定日誌記錄
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('abuseipdb_debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def check_ip(ip_address, max_age_in_days=15):
    """
    檢查指定 IP 地址在 AbuseIPDB 中的記錄
    Args:
        ip_address (str): 要檢查的 IP 地址
        max_age_in_days (int): 檢查的時間範圍（天數）
    """
    logger.debug(f"開始檢查 IP: {ip_address}")
    
    # API 端點
    url = 'https://api.abuseipdb.com/api/v2/check'

    # 查詢參數
    querystring = {
        'ipAddress': ip_address,
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
        response = requests.request(method='GET', 
                                 url=url, 
                                 headers=headers, 
                                 params=querystring)
        
        # 檢查響應狀態
        response.raise_for_status()
        
        # 解析響應
        decoded_response = response.json()
        logger.debug(f"API 響應: {decoded_response}")
        
        return decoded_response
        
    except requests.exceptions.RequestException as e:
        error_msg = f'API request failed: {str(e)}'
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

# if __name__ == "__main__":
#     # 測試 IP 地址
#     test_ip = "8.8.8.8"
    
#     # 測試 IP 檢查
#     logger.info(f"執行 IP 檢查測試: {test_ip}")
#     result = check_ip(test_ip)
#     print(result)

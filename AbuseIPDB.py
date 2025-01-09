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
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': str(max_age_in_days)}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}

    try:
        logger.debug(f"發送請求到 AbuseIPDB API: {url}，查詢參數: {querystring}")
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()  # 確保響應狀態為 200
        
        decoded_response = response.json()
        logger.debug(f"API 響應: {decoded_response}")
        return decoded_response
        
    except requests.exceptions.RequestException as e:
        logger.error(f'API request failed: {e}')
        return {'error': True, 'message': str(e)}

# if __name__ == "__main__":
#     # 測試 IP 地址
#     test_ip = "8.8.8.8"
    
#     # 測試 IP 檢查
#     logger.info(f"執行 IP 檢查測試: {test_ip}")
#     result = check_ip(test_ip)
#     print(result)

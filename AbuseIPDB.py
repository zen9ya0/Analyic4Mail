import requests
import logging
import json
import argparse
import re
from config import (
    API_KEYS,
    API_URLS,
    LOGGING,
    COMMON
)
from utils.logger import setup_logger
from utils.api_handler import APIHandler

class AbuseIPDBAPI:
    def __init__(self):
        self.logger = setup_logger(__name__, LOGGING['LOG_FILES']['ABUSEIPDB'])
        
        # 檢查 API 金鑰是否存在
        if 'ABUSEIPDB' not in API_KEYS:
            error_msg = "找不到 AbuseIPDB API 金鑰"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        # 檢查 API URL 是否存在
        if 'ABUSEIPDB' not in API_URLS:
            error_msg = "找不到 AbuseIPDB API URL"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        self.api_handler = APIHandler(
            base_url=API_URLS['ABUSEIPDB'],
            api_key=API_KEYS['ABUSEIPDB'],
            logger=self.logger
        )
        self.logger.debug("AbuseIPDB API 初始化完成")

    def check_ip(self, ip_address: str, max_age_in_days: int = 15) -> dict:
        """檢查 IP 地址"""
        clean_ip = self.extract_ip(ip_address)
        if not clean_ip:
            error_msg = "無效的 IP 地址格式"
            self.logger.error(error_msg)
            return {"error": True, "message": error_msg}

        self.logger.debug(f"開始檢查 IP: {clean_ip}")
        
        try:
            params = {
                'ipAddress': clean_ip,
                'maxAgeInDays': str(max_age_in_days)
            }
            
            response = self.api_handler.make_request(
                'GET',
                '/check',
                params=params
            )
            
            self.logger.debug(f"IP 檢查響應: {json.dumps(response, indent=2)}")
            return response
            
        except Exception as e:
            self.logger.error(f"檢查 IP 時發生錯誤: {str(e)}")
            return {"error": True, "message": str(e)}

    @staticmethod
    def extract_ip(input_string: str) -> str:
        """從字符串中提取 IP 地址"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.findall(ip_pattern, input_string)
        return ip_matches[0] if ip_matches else None

def main():
    parser = argparse.ArgumentParser(description='AbuseIPDB API 工具')
    parser.add_argument('--ip', required=True, help='要檢查的 IP 地址')
    parser.add_argument('--days', type=int, default=15, help='檢查的時間範圍（天數），預設為 15 天')
    
    args = parser.parse_args()
    
    try:
        api = AbuseIPDBAPI()
        result = api.check_ip(args.ip, args.days)
        
        print("\n檢查結果:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
    except Exception as e:
        print(f"\n錯誤: {str(e)}")

if __name__ == "__main__":
    main()

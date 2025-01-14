import requests
import logging
import json
import argparse
import re
from config import (
    API_KEYS,
    API_URLS,
    COMMON,
    LOGGING
)
from utils.logger import setup_logger
from utils.api_handler import APIHandler

class BlacklistMasterAPI:
    def __init__(self):
        self.logger = setup_logger(__name__, LOGGING['LOG_FILES']['BLACKLISTMASTER'])
        
        # 檢查 API 金鑰是否存在
        if 'BLACKLISTMASTER' not in API_KEYS:
            error_msg = "找不到 BlacklistMaster API 金鑰"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        # 檢查 API URL 是否存在
        if 'BLACKLISTMASTER' not in API_URLS:
            error_msg = "找不到 BlacklistMaster API URL"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        self.api_handler = APIHandler(
            base_url=API_URLS['BLACKLISTMASTER'],
            api_key=API_KEYS['BLACKLISTMASTER'],
            logger=self.logger
        )
        self.logger.debug("BlacklistMasterAPI 初始化完成")

    def check_ip(self, ip_address: str) -> dict:
        """檢查 IP 地址"""
        self.logger.debug(f"開始檢查 IP: {ip_address}")
        try:
            response = self.api_handler.make_request(
                'GET',
                f'/ip/{ip_address}'
            )
            self.logger.debug(f"IP 檢查響應: {json.dumps(response, indent=2)}")
            return response
        except Exception as e:
            self.logger.error(f"檢查 IP 時發生錯誤: {str(e)}")
            return {"error": str(e)}

    def check_domain(self, domain: str) -> dict:
        """檢查域名"""
        self.logger.debug(f"開始檢查域名: {domain}")
        try:
            response = self.api_handler.make_request(
                'GET',
                f'/domain/{domain}'
            )
            self.logger.debug(f"域名檢查響應: {json.dumps(response, indent=2)}")
            return response
        except Exception as e:
            self.logger.error(f"檢查域名時發生錯誤: {str(e)}")
            return {"error": str(e)}

def extract_ip(input_string: str) -> str:
    """從字符串中提取 IP 地址"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_matches = re.findall(ip_pattern, input_string)
    return ip_matches[0] if ip_matches else None

def main():
    parser = argparse.ArgumentParser(description='BlacklistMaster API 工具')
    parser.add_argument('--ip', help='要檢查的 IP 地址')
    parser.add_argument('--domain', help='要檢查的域名')
    
    args = parser.parse_args()
    
    try:
        api = BlacklistMasterAPI()
        
        if args.ip:
            ip = extract_ip(args.ip)
            if ip:
                result = api.check_ip(ip)
                print("\nIP 檢查結果:")
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print("無效的 IP 地址格式")
                
        elif args.domain:
            result = api.check_domain(args.domain)
            print("\n域名檢查結果:")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"\n錯誤: {str(e)}")

if __name__ == "__main__":
    main()
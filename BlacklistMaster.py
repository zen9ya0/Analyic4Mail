import requests
import logging
import json
import argparse
import re
from config import BlacklistMaster_API_KEY
from typing import Dict, Any

# 設定 logging 為 DEBUG 級別，並添加更詳細的格式
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # 輸出到控制台
        logging.FileHandler('blacklist_master.log')  # 同時輸出到文件
    ]
)

# 創建一個專門的 logger
logger = logging.getLogger('BlacklistMaster')

class BlacklistChecker:
    def __init__(self):
        self.base_url = "https://www.blacklistmaster.com/restapi/v1"
        self.api_key = BlacklistMaster_API_KEY
        logger.info("Initializing BlacklistChecker")
        logger.debug(f"Base URL: {self.base_url}")
        logger.debug(f"API Key: {'*' * len(self.api_key)}")
        
        if not self.api_key:
            logger.error("API key is missing!")
            raise ValueError("BlacklistMaster API key is not configured")

    def extract_ip(self, input_string: str) -> str:
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

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """檢查IP地址的黑名單狀態"""
        try:
            logger.info(f"Starting IP check for: {ip_address}")
            
            # 提取純 IP 地址
            clean_ip = self.extract_ip(ip_address)
            if not clean_ip:
                logger.error("無法從輸入中提取有效的 IP 地址")
                return {"error": "無效的 IP 地址格式"}
            
            endpoint = f"{self.base_url}/ip/{clean_ip}?apikey={self.api_key}"
            logger.debug(f"Constructed endpoint: {endpoint.replace(self.api_key, '*' * len(self.api_key))}")
            
            return self._make_request(endpoint)
            
        except Exception as e:
            logger.exception(f"Error checking IP {ip_address}: {str(e)}")
            return {"error": f"檢查 IP 時發生錯誤: {str(e)}"}

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """檢查網域的黑名單狀態"""
        try:
            logger.info(f"Starting domain check for: {domain}")
            if not domain:
                logger.error("Empty domain provided")
                return {"error": "域名不能為空"}
            
            endpoint = f"{self.base_url}/domain/{domain}?apikey={self.api_key}"
            logger.debug(f"Constructed endpoint: {endpoint.replace(self.api_key, '*' * len(self.api_key))}")
            
            return self._make_request(endpoint)
            
        except Exception as e:
            logger.exception(f"Error checking domain {domain}: {str(e)}")
            return {"error": f"檢查域名時發生錯誤: {str(e)}"}

    def _make_request(self, endpoint: str) -> Dict[str, Any]:
        """發送API請求並處理回應"""
        try:
            logger.debug("Making API request")
            response = requests.get(endpoint, timeout=10)
            logger.debug(f"Response status code: {response.status_code}")
            
            if response.status_code == 204:
                logger.info("Target is clean (status code 204)")
                return {
                    "status": "clean",
                    "message": "目標未被列入任何黑名單",
                    "response_code": 204
                }
            elif response.status_code == 200:
                response_json = response.json()
                logger.info("Received successful response")
                logger.debug(f"Response content: {json.dumps(response_json, indent=2)}")
                return response_json
            else:
                error_msg = f"API returned unexpected status code: {response.status_code}"
                logger.error(error_msg)
                logger.debug(f"Response content: {response.text}")
                return {
                    "error": error_msg,
                    "response_code": response.status_code,
                    "response_text": response.text
                }
                
        except requests.Timeout:
            error_msg = "Request timed out after 10 seconds"
            logger.error(error_msg)
            return {"error": error_msg}
            
        except requests.RequestException as e:
            error_msg = f"Request failed: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
            
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse JSON response: {str(e)}"
            logger.error(error_msg)
            return {"error": error_msg}
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.exception(error_msg)
            return {"error": error_msg}

def main():
    # 創建命令行參數解析器
    parser = argparse.ArgumentParser(description='檢查 IP 或域名的黑名單狀態')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--ip', help='要檢查的 IP 地址')
    group.add_argument('--domain', help='要檢查的域名')
    
    # 解析命令行參數
    args = parser.parse_args()
    
    try:
        # 初始化檢查器
        checker = BlacklistChecker()
        
        # 根據提供的參數執行相應的檢查
        if args.ip:
            logger.info(f"Checking IP: {args.ip}")
            result = checker.check_ip(args.ip)
        else:  # domain
            logger.info(f"Checking domain: {args.domain}")
            result = checker.check_domain(args.domain)
        
        # 輸出結果
        print("\n檢查結果:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
    except Exception as e:
        logger.exception("檢查過程中發生錯誤")
        print(f"\n錯誤: {str(e)}")

if __name__ == "__main__":
    main()
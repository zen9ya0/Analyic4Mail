import requests
import json
import argparse
from typing import Dict, Optional
from config import BlacklistMaster_API_KEY

class BlacklistChecker:
    def __init__(self):
        self.base_url = "https://www.blacklistmaster.com/restapi/v1"
        self.api_key = BlacklistMaster_API_KEY
        
    def _make_request(self, endpoint: str) -> Optional[Dict]:
        """
        發送API請求並處理回應
        
        Args:
            endpoint: API端點URL
            
        Returns:
            Optional[Dict]: API回應的JSON數據，如果失敗則返回None
        """
        try:
            response = requests.get(endpoint)
            
            # 處理204狀態碼 (No Content) - 表示IP/域名沒有被列入黑名單
            if response.status_code == 204:
                return {"status": "clean", "message": "目標未被列入任何黑名單"}
                
            # 處理200狀態碼 - 有找到黑名單記錄
            elif response.status_code == 200:
                return response.json()
                
            else:
                print(f"API返回非預期的狀態碼: {response.status_code}")
                print(f"Response Text: {response.text}")
                return None
                
        except requests.RequestException as e:
            print(f"API請求失敗: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            print(f"JSON解析錯誤: {str(e)}")
            print(f"原始回應內容: {response.text}")
            return None
            
    def check_ip(self, ip: str) -> Optional[Dict]:
        """
        檢查IP地址的黑名單狀態
        
        Args:
            ip: 要檢查的IP地址
            
        Returns:
            Optional[Dict]: API回應的結果
        """
        endpoint = f"{self.base_url}/ip/{ip}?apikey={self.api_key}"
        print(f"正在請求: {endpoint.replace(self.api_key, 'HIDDEN_API_KEY')}")
        return self._make_request(endpoint)
        
    def check_domain(self, domain: str) -> Optional[Dict]:
        """
        檢查網域的黑名單狀態
        
        Args:
            domain: 要檢查的網域名稱
            
        Returns:
            Optional[Dict]: API回應的結果
        """
        endpoint = f"{self.base_url}/domain/{domain}?apikey={self.api_key}"
        print(f"正在請求: {endpoint.replace(self.api_key, 'HIDDEN_API_KEY')}")
        return self._make_request(endpoint)

def main():
    # 設定命令列參數
    parser = argparse.ArgumentParser(description='檢查IP或網域的黑名單狀態')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--ip', help='要檢查的IP地址')
    group.add_argument('--domain', help='要檢查的網域名稱')
    args = parser.parse_args()

    checker = BlacklistChecker()
    
    # 根據提供的參數執行相應的檢查
    if args.ip:
        result = checker.check_ip(args.ip)
        if result:
            print("\n檢查結果:", json.dumps(result, indent=2, ensure_ascii=False))
    
    elif args.domain:
        result = checker.check_domain(args.domain)
        if result:
            print("\n檢查結果:", json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
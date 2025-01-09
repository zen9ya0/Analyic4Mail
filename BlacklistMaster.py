import requests
import json
from config import BlacklistMaster_API_KEY

class BlacklistChecker:
    def __init__(self):
        self.base_url = "https://www.blacklistmaster.com/restapi/v1"
        self.api_key = BlacklistMaster_API_KEY
        
    def check_ip(self, ip: str) -> dict:
        """檢查IP地址的黑名單狀態"""
        return self._make_request(f"{self.base_url}/ip/{ip}?apikey={self.api_key}")

    def check_domain(self, domain: str) -> dict:
        """檢查網域的黑名單狀態"""
        return self._make_request(f"{self.base_url}/domain/{domain}?apikey={self.api_key}")

    def _make_request(self, endpoint: str) -> dict:
        """發送API請求並處理回應"""
        response = requests.get(endpoint)
        if response.status_code == 204:
            return {"status": "clean", "message": "目標未被列入任何黑名單"}
        elif response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API返回非預期的狀態碼: {response.status_code}"}
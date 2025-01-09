import requests
import os
import importlib.util
import logging

def load_config():
    """Load API key from config.py"""
    try:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.py')
        spec = importlib.util.spec_from_file_location("config", config_path)
        config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config)
        return config.VT_API_KEY
    except Exception as e:
        raise Exception(f"Error loading config.py: {e}")

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {"accept": "application/json", "x-apikey": self.api_key}

    def check_ip(self, ip_address: str) -> dict:
        """Check IP address reputation"""
        return self._make_request(f"{self.base_url}/ip_addresses/{ip_address}")

    def check_domain(self, domain: str) -> dict:
        """Check domain reputation"""
        return self._make_request(f"{self.base_url}/domains/{domain}")

    def _make_request(self, url: str) -> dict:
        """發送請求並返回結果"""
        response = requests.get(url, headers=self.headers)
        return response.json() if response.status_code == 200 else {"error": "Request failed"}

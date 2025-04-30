import requests
from typing import Dict, Any, Optional
import json
from config import COMMON

class APIHandler:
    def __init__(self, base_url: str, api_key: str, logger):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.logger = logger

    def make_request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        files: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """發送 API 請求"""
        url = f"{self.base_url}{endpoint}"
        
        # 初始化 headers 和 params
        if headers is None:
            headers = {}
        if params is None:
            params = {}
            
        # 根據不同的 API 服務設置不同的認證方式
        if 'virustotal.com' in self.base_url:
            headers.update({
                'x-apikey': self.api_key,
                'accept': 'application/json'
            })
        elif 'blacklistmaster.com' in self.base_url:
            # BlacklistMaster 使用 URL 參數進行認證
            params['apikey'] = self.api_key
            headers.update({
                'Accept': 'application/json'
            })
        elif 'abuseipdb.com' in self.base_url:
            headers.update({
                'Key': self.api_key,
                'Accept': 'application/json'
            })
            
        self.logger.debug(f"發送請求到: {url}")
        self.logger.debug(f"請求方法: {method}")
        self.logger.debug(f"請求參數: {json.dumps({k: '***' if k == 'apikey' else v for k, v in params.items()})}")
        self.logger.debug(f"請求頭: {json.dumps({k: v for k, v in headers.items() if k not in ['Authorization', 'Key']})}")
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                files=files,
                timeout=COMMON['REQUEST_TIMEOUT']
            )
            
            # 記錄響應狀態
            self.logger.debug(f"響應狀態碼: {response.status_code}")
            
            # 特殊處理 BlacklistMaster 的 204 響應
            if 'blacklistmaster.com' in self.base_url and response.status_code == 204:
                return {
                    'status': 'clean',
                    'message': 'IP 未被列入黑名單',
                    'found': False
                }
            
            # 嘗試解析 JSON 響應
            try:
                response_data = response.json()
            except json.JSONDecodeError:
                if response.status_code == 200:
                    response_data = {'text': response.text}
                else:
                    error_msg = f"無效的 JSON 響應: {response.text}"
                    self.logger.error(error_msg)
                    return {
                        'error': True,
                        'message': error_msg,
                        'status_code': response.status_code
                    }
                
            # 檢查響應狀態
            if response.status_code not in [200, 204]:
                error_msg = f"API 請求失敗: {response.status_code} - {response_data}"
                self.logger.error(error_msg)
                return {
                    'error': True,
                    'message': error_msg,
                    'status_code': response.status_code
                }
                
            return response_data
            
        except requests.exceptions.RequestException as e:
            error_msg = f"請求異常: {str(e)}"
            self.logger.error(error_msg)
            return {
                'error': True,
                'message': error_msg
            }
        except Exception as e:
            error_msg = f"未預期的錯誤: {str(e)}"
            self.logger.error(error_msg)
            return {
                'error': True,
                'message': error_msg
            } 
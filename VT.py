import requests
import argparse
import json
import os
from typing import Optional, Dict, Any
import time
from utils.logger import setup_logger
from utils.api_handler import APIHandler
from config import (
    API_KEYS,
    API_URLS,
    COMMON,
    LOGGING
)

class VirusTotalAPI:
    def __init__(self):
        self.logger = setup_logger(__name__, LOGGING['LOG_FILES']['VIRUSTOTAL'])
        
        self.logger.debug("開始初始化 VirusTotalAPI")
        
        # 檢查 API 金鑰是否存在
        if 'VIRUSTOTAL' not in API_KEYS:
            error_msg = "找不到 VirusTotal API 金鑰"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        self.logger.debug(f"找到 API 金鑰: {API_KEYS['VIRUSTOTAL'][:8]}...")
            
        # 檢查 API URL 是否存在
        if 'VIRUSTOTAL' not in API_URLS:
            error_msg = "找不到 VirusTotal API URL"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        self.logger.debug(f"找到 API URL: {API_URLS['VIRUSTOTAL']}")
            
        self.api_handler = APIHandler(
            base_url=API_URLS['VIRUSTOTAL'],
            api_key=API_KEYS['VIRUSTOTAL'],
            logger=self.logger
        )
        self.logger.debug("APIHandler 初始化完成")
        self.logger.debug("VirusTotalAPI 初始化完成")

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """檢查 IP 信譽"""
        self.logger.debug(f"開始檢查 IP: {ip_address}")
        try:
            response = self.api_handler.make_request(
                'GET',
                f'/ip_addresses/{ip_address}'
            )
            self.logger.debug(f"IP 檢查響應: {json.dumps(response, indent=2)}")
            return response
        except Exception as e:
            self.logger.error(f"檢查 IP 時發生錯誤: {str(e)}")
            return {"error": str(e)}

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """檢查域名信譽"""
        self.logger.debug(f"開始檢查域名: {domain}")
        try:
            response = self.api_handler.make_request(
                'GET',
                f'/domains/{domain}'
            )
            self.logger.debug(f"域名檢查響應: {json.dumps(response, indent=2)}")
            return response
        except Exception as e:
            self.logger.error(f"檢查域名時發生錯誤: {str(e)}")
            return {"error": str(e)}

    def upload_file(self, file_path: str, password: Optional[str] = None) -> Dict[str, Any]:
        """上傳文件進行掃描"""
        try:
            files = {
                "file": (
                    os.path.basename(file_path),
                    open(file_path, "rb"),
                    "application/octet-stream"
                )
            }
            data = {"password": password} if password else {}
            
            return self.api_handler.make_request(
                'POST',
                '/files',
                data=data,
                files=files
            )
        except Exception as e:
            self.logger.error(f"上傳文件時發生錯誤: {str(e)}")
            return {"error": str(e)}

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """獲取文件掃描報告"""
        try:
            response = self.api_handler.make_request(
                'GET',
                f'/files/{file_hash}'
            )
            
            if response.get('error'):
                return {
                    'data': {
                        'attributes': {
                            'last_analysis_results': {},
                            'size': 0,
                            'type_tags': ['未知'],
                            'type_extension': '未知',
                            'names': ['未知檔案']
                        }
                    },
                    'message': '在 VirusTotal 資料庫中未找到此檔案'
                }
            
            return response
            
        except Exception as e:
            self.logger.error(f"獲取文件報告時發生錯誤: {str(e)}")
            return {"error": str(e)}

    def scan_url(self, url: str) -> Dict[str, Any]:
        """掃描 URL"""
        self.logger.debug(f"開始掃描 URL: {url}")
        try:
            # 修改請求格式
            data = {"url": url}
            headers = {
                "x-apikey": API_KEYS['VIRUSTOTAL'],
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded"
            }
            
            self.logger.debug(f"提交 URL 掃描請求: {url}")
            response = self.api_handler.make_request(
                'POST',
                '/urls',
                data=data,
                headers=headers
            )
            self.logger.debug(f"URL 掃描響應: {json.dumps(response, indent=2)}")
            
            # 改進錯誤處理邏輯
            if isinstance(response, dict) and response.get('error'):
                error_msg = response.get('message', '未知錯誤')
                self.logger.error(f"URL 掃描錯誤: {error_msg}")
                return {
                    'error': True,
                    'message': error_msg
                }
            
            # 檢查響應格式
            if not isinstance(response, dict) or 'data' not in response:
                error_msg = "無效的 API 響應格式"
                self.logger.error(error_msg)
                return {
                    'error': True,
                    'message': error_msg
                }
            
            analysis_id = response['data']['id']
            self.logger.debug(f"獲取到分析 ID: {analysis_id}")
            
            # 獲取分析結果
            return self.get_analysis_results(
                analysis_id,
                COMMON['MAX_RETRIES'],
                COMMON['REQUEST_TIMEOUT']
            )
            
        except Exception as e:
            self.logger.error(f"掃描 URL 時發生錯誤: {str(e)}")
            return {
                'error': True,
                'message': str(e)
            }

    def get_analysis_results(self, analysis_id: str, max_retries: int, wait_time: int) -> Dict[str, Any]:
        """獲取分析結果"""
        for attempt in range(max_retries):
            self.logger.debug(f"嘗試 {attempt + 1}/{max_retries}")
            
            response = self.api_handler.make_request(
                'GET',
                f'/analyses/{analysis_id}'
            )
            
            status = response['data']['attributes']['status']
            if status == "completed":
                return response
            elif status == "failed":
                return {"error": "分析失敗"}
                
            time.sleep(wait_time)
            
        return {"error": f"分析在 {max_retries} 次重試後仍未完成"}

def main():
    parser = argparse.ArgumentParser(description='VirusTotal API 工具')
    subparsers = parser.add_subparsers(dest='command', help='要執行的命令')
    
    # 添加子命令
    subparsers.add_parser('ip', help='檢查 IP').add_argument('ip_address')
    subparsers.add_parser('domain', help='檢查域名').add_argument('domain')
    upload_parser = subparsers.add_parser('upload', help='上傳文件')
    upload_parser.add_argument('file_path')
    upload_parser.add_argument('--password', help='加密文件密碼')
    subparsers.add_parser('report', help='獲取文件報告').add_argument('file_hash')
    url_parser = subparsers.add_parser('url', help='掃描 URL')
    url_parser.add_argument('url')
    
    args = parser.parse_args()
    vt = VirusTotalAPI()
    
    try:
        result = None
        if args.command == 'ip':
            result = vt.check_ip(args.ip_address)
        elif args.command == 'domain':
            result = vt.check_domain(args.domain)
        elif args.command == 'upload':
            result = vt.upload_file(args.file_path, args.password)
        elif args.command == 'report':
            result = vt.get_file_report(args.file_hash)
        elif args.command == 'url':
            result = vt.scan_url(args.url)
        
        if result:
            print(json.dumps(result, indent=2))
            
    except Exception as e:
        print(f"錯誤: {str(e)}")

if __name__ == "__main__":
    main()

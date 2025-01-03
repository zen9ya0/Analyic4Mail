import requests
import argparse
import json
import os
from typing import Optional
import importlib.util
import time
import logging

def load_config():
    """Load API key from config.py"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(current_dir, 'config.py')
        
        spec = importlib.util.spec_from_file_location("config", config_path)
        config = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config)
        
        return config.VT_API_KEY
    except Exception as e:
        raise Exception(f"Error loading config.py: {str(e)}")

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        # 設定最大重試次數和等待時間
        self.max_retries = 3
        self.retry_delay = 1
        self.analysis_timeout = 30  # 設定分析超時時間（秒）

    def check_ip(self, ip_address: str) -> dict:
        """Check IP address reputation"""
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        response = requests.get(url, headers=self.headers)
        return response.json()

    def check_domain(self, domain: str) -> dict:
        """Check domain reputation"""
        url = f"{self.base_url}/domains/{domain}"
        response = requests.get(url, headers=self.headers)
        return response.json()

    def upload_file(self, file_path: str, password: Optional[str] = None) -> dict:
        """Upload file for scanning"""
        url = f"{self.base_url}/files"
        files = {"file": (os.path.basename(file_path), open(file_path, "rb"), "application/octet-stream")}
        payload = {"password": password} if password else {}
        response = requests.post(url, data=payload, files=files, headers=self.headers)
        return response.json()

    def get_file_report(self, file_hash):
        """獲取檔案掃描報告"""
        try:
            # 首先嘗試直接獲取檔案報告
            response = requests.get(
                f"{self.base_url}files/{file_hash}",
                headers=self.headers,
                timeout=10  # 設定請求超時
            )
            
            if response.status_code == 200:
                result = response.json()
                # 格式化並返回結果
                return self._format_file_report(result)
            
            # 如果找不到報告，嘗試重新分析
            elif response.status_code == 404:
                logging.info(f"找不到檔案 {file_hash} 的報告，開始新的分析")
                return self._start_new_analysis(file_hash)
            
            else:
                return {
                    "error": f"API 請求失敗 (狀態碼: {response.status_code})",
                    "status": "error"
                }

        except requests.Timeout:
            return {"error": "請求超時", "status": "error"}
        except Exception as e:
            logging.error(f"獲取檔案報告時發生錯誤: {str(e)}")
            return {"error": f"獲取報告失敗: {str(e)}", "status": "error"}

    def _start_new_analysis(self, file_hash):
        """開始新的檔案分析"""
        try:
            # 提交分析請求
            response = requests.post(
                f"{self.base_url}files/{file_hash}/analyse",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                analysis_id = response.json().get('data', {}).get('id')
                if not analysis_id:
                    return {"error": "無法獲取分析 ID", "status": "error"}
                
                # 立即返回初始狀態
                return {
                    "status": "pending",
                    "message": "分析已開始，請稍後重新檢查結果",
                    "analysis_id": analysis_id
                }
            
            return {"error": "無法啟動分析", "status": "error"}

        except Exception as e:
            logging.error(f"啟動分析時發生錯誤: {str(e)}")
            return {"error": f"啟動分析失敗: {str(e)}", "status": "error"}

    def _format_file_report(self, result):
        """格式化檔案報告結果"""
        try:
            data = result.get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('stats', {})
            
            return {
                "status": "completed",
                "scan_results": {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "undetected": stats.get('undetected', 0),
                    "total": sum(stats.values()),
                },
                "scan_date": attributes.get('last_analysis_date'),
                "detailed_results": self._format_scan_results(attributes.get('last_analysis_results', {})),
                "file_info": {
                    "name": attributes.get('meaningful_name'),
                    "size": attributes.get('size'),
                    "type": attributes.get('type_description'),
                    "first_seen": attributes.get('first_submission_date'),
                    "last_seen": attributes.get('last_analysis_date')
                }
            }
        except Exception as e:
            logging.error(f"格式化報告時發生錯誤: {str(e)}")
            return {"error": "格式化報告失敗", "status": "error"}

    def _format_scan_results(self, results):
        """格式化掃描結果詳情"""
        formatted_results = []
        for engine_name, result in results.items():
            formatted_results.append({
                "engine": engine_name,
                "category": result.get('category', 'unknown'),
                "result": result.get('result', 'N/A'),
                "method": result.get('method', 'N/A'),
                "update": result.get('engine_update', 'N/A')
            })
        
        # 根據威脅等級排序
        return sorted(formatted_results, 
                     key=lambda x: (x['category'] == 'malicious', 
                                  x['category'] == 'suspicious', 
                                  x['category'] == 'undetected'))

    def scan_url(self, url, retries=5, wait=3):
        """Scan URL and retrieve the report"""
        try:
            # Submit URL for scanning
            scan_response = requests.post(
                f"{self.base_url}urls",
                headers=self.headers,
                data={"url": url}
            )
            
            if scan_response.status_code != 200:
                return {"error": "URL submission failed"}

            # Get analysis ID from the response
            analysis_id = scan_response.json().get('data', {}).get('id')
            logging.debug(f"Analysis ID: {analysis_id}")

            if not analysis_id:
                return {"error": "Unable to retrieve analysis ID"}

            # Retry mechanism to get the analysis report
            for attempt in range(retries):
                report = self.get_analysis_report(analysis_id)
                if report.get('status') == 'completed':
                    return report
                logging.info(f"Report not ready, retrying in {wait} seconds...")
                time.sleep(wait)

            return {"error": "Report not ready after retries"}

        except Exception as e:
            logging.error(f"Error scanning URL: {str(e)}")
            return {"error": f"Scan failed: {str(e)}"}

    def get_analysis_report(self, analysis_id):
        """Retrieve the analysis report using the analysis ID"""
        try:
            response = requests.get(
                f"{self.base_url}analyses/{analysis_id}",
                headers=self.headers
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Failed to retrieve report (status code: {response.status_code})"}

        except Exception as e:
            logging.error(f"Error retrieving analysis report: {str(e)}")
            return {"error": f"Failed to retrieve report: {str(e)}"}

def main():
    parser = argparse.ArgumentParser(description='VirusTotal API Integration Tool')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # IP address parser
    ip_parser = subparsers.add_parser('ip', help='Check IP address')
    ip_parser.add_argument('ip_address', help='IP address to check')
    
    # Domain parser
    domain_parser = subparsers.add_parser('domain', help='Check domain')
    domain_parser.add_argument('domain', help='Domain to check')
    
    # File upload parser
    upload_parser = subparsers.add_parser('upload', help='Upload file')
    upload_parser.add_argument('file_path', help='Path to file')
    upload_parser.add_argument('--password', help='Password for encrypted file')
    
    # File report parser
    report_parser = subparsers.add_parser('report', help='Get file report')
    report_parser.add_argument('file_hash', help='File hash (SHA-256)')
    
    # URL scan parser
    url_parser = subparsers.add_parser('url', help='Scan URL')
    url_parser.add_argument('url', help='URL to scan')
    url_parser.add_argument('--retries', type=int, default=5, help='Maximum number of retries')
    url_parser.add_argument('--wait', type=int, default=3, help='Seconds to wait between retries')
    
    args = parser.parse_args()
    
    try:
        # Load API key from config
        api_key = load_config()
        
        # Initialize API
        vt = VirusTotalAPI(api_key)
        
        # Execute command based on argument
        if args.command == 'ip':
            result = vt.check_ip(args.ip_address)
        elif args.command == 'domain':
            result = vt.check_domain(args.domain)
        elif args.command == 'upload':
            result = vt.upload_file(args.file_path, args.password)
        elif args.command == 'report':
            result = vt.get_file_report(args.file_hash)
        elif args.command == 'url':
            result = vt.scan_url(args.url, args.retries, args.wait)
        else:
            parser.print_help()
            return
        
        # Print result in pretty format
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()

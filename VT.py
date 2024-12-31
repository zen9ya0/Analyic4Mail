import requests
import argparse
import json
import os
from typing import Optional
import importlib.util
import time

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
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

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

    def get_file_report(self, file_hash: str) -> dict:
        """Get file scan report by hash"""
        url = f"{self.base_url}/files/{file_hash}"
        response = requests.get(url, headers=self.headers)
        return response.json()

    def scan_url(self, target_url: str, max_retries: int = 5, wait_time: int = 3) -> dict:
        """
        Scan a URL and get the analysis results
        
        Args:
            target_url: URL to scan
            max_retries: Maximum number of retries for getting analysis results
            wait_time: Time to wait between retries in seconds
            
        Returns:
            dict: Analysis results
        """
        # First request: Submit URL for scanning
        submit_url = f"{self.base_url}/urls"
        headers = {**self.headers, "content-type": "application/x-www-form-urlencoded"}
        payload = {"url": target_url}
        
        response = requests.post(submit_url, data=payload, headers=headers)
        submit_result = response.json()
        
        # Extract analysis ID from the response
        try:
            analysis_id = submit_result['data']['id']
            print(f"Analysis ID: {analysis_id}")
        except KeyError:
            raise Exception("Failed to get analysis ID from response")
        
        # Second request: Get analysis results with retries
        analysis_url = f"{self.base_url}/analyses/{analysis_id}"
        
        for attempt in range(max_retries):
            response = requests.get(analysis_url, headers=self.headers)
            result = response.json()
            
            # Check if analysis is completed
            try:
                status = result['data']['attributes']['status']
                if status == "completed":
                    return result
                elif status == "failed":
                    raise Exception("Analysis failed")
                else:
                    print(f"Analysis in progress (status: {status}), waiting {wait_time} seconds...")
                    time.sleep(wait_time)
            except KeyError:
                raise Exception("Unexpected response format")
        
        raise Exception(f"Analysis not completed after {max_retries} retries")

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

import email
import base64
import dns.resolver
import argparse
from typing import Tuple, Dict, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
import re
import extract_msg
import os
from email.parser import Parser
from email.policy import default

class EmailParser:
    """處理不同格式的郵件檔案"""
    
    @staticmethod
    def parse_email_file(file_path: str) -> Optional[str]:
        """解析郵件檔案，支援 .eml 和 .msg 格式"""
        file_extension = os.path.splitext(file_path)[1].lower()
        
        try:
            if file_extension == '.msg':
                return EmailParser._parse_msg(file_path)
            elif file_extension == '.eml':
                return EmailParser._parse_eml(file_path)
            else:
                raise ValueError(f"不支援的檔案格式: {file_extension}")
        except Exception as e:
            raise Exception(f"郵件解析錯誤: {str(e)}")

    @staticmethod
    def _parse_msg(msg_path: str) -> str:
        """解析 .msg 檔案並轉換為郵件格式字符串"""
        try:
            # 使用 extract_msg 開啟 .msg 檔案
            msg = extract_msg.Message(msg_path)
            
            # 建立郵件頭
            headers = []
            
            # 添加基本郵件頭
            if msg.sender:
                headers.append(f"From: {msg.sender}")
            if msg.to:
                headers.append(f"To: {msg.to}")
            if msg.subject:
                headers.append(f"Subject: {msg.subject}")
            if msg.date:
                headers.append(f"Date: {msg.date}")
            
            # 獲取所有郵件頭（包括 DKIM 簽名等）
            for header in msg.header.items():
                # 跳過已添加的基本郵件頭
                if header[0].lower() not in ['from', 'to', 'subject', 'date']:
                    headers.append(f"{header[0]}: {header[1]}")
            
            # 添加郵件內容
            body = msg.body
            
            # 組合完整郵件
            full_email = "\r\n".join(headers) + "\r\n\r\n" + body
            
            return full_email
            
        except Exception as e:
            raise Exception(f"MSG 檔案解析錯誤: {str(e)}")

    @staticmethod
    def _parse_eml(eml_path: str) -> str:
        """解析 .eml 檔案"""
        try:
            with open(eml_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            raise Exception(f"EML 檔案解析錯誤: {str(e)}")

class DKIMValidator:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.hash_algorithms = {
            'sha1': hashes.SHA1(),
            'sha256': hashes.SHA256(),
            'sha512': hashes.SHA512()
        }

    # [前面的方法保持不變...]
    # parse_signature_header, get_hash_algorithm, get_public_key 方法保持原樣

    def validate_email(self, file_path: str) -> Tuple[bool, str, Dict]:
        """驗證郵件的 DKIM 簽名（支援 .eml 和 .msg）"""
        validation_info = {
            'domain': None,
            'selector': None,
            'algorithm': None,
            'headers_signed': None,
            'dns_record_found': False,
            'public_key_valid': False,
            'signature_valid': False,
            'file_type': os.path.splitext(file_path)[1].lower()
        }
        
        try:
            # 解析郵件檔案
            email_content = EmailParser.parse_email_file(file_path)
            if not email_content:
                return False, "無法解析郵件檔案", validation_info

            # 解析郵件內容
            message = email.message_from_string(email_content, policy=default)
            dkim_header = message.get('DKIM-Signature')
            
            if not dkim_header:
                return False, "找不到 DKIM-Signature header", validation_info

            # 其餘驗證邏輯與原先相同
            dkim_parts = self.parse_signature_header(dkim_header)
            
            validation_info['domain'] = dkim_parts.get('d')
            validation_info['selector'] = dkim_parts.get('s')
            validation_info['algorithm'] = dkim_parts.get('a', 'rsa-sha256')
            validation_info['headers_signed'] = dkim_parts.get('h', '').split(':')

            # [其餘驗證邏輯保持不變...]
            
        except Exception as e:
            return False, f"驗證過程發生錯誤: {str(e)}", validation_info

class EmailAuthenticationChecker:
    def __init__(self):
        self.dkim_validator = DKIMValidator()
        self.resolver = dns.resolver.Resolver()

    def check_all(self, file_path: str) -> dict:
        """檢查郵件的 DKIM、SPF 和 DMARC"""
        results = {
            'dkim': self._check_dkim(file_path),
            'spf': self._check_spf(file_path),
            'dmarc': self._check_dmarc(file_path)
        }
        return results

    def _check_dkim(self, file_path: str) -> dict:
        """檢查 DKIM"""
        success, message, info = self.dkim_validator.validate_email(file_path)
        return {
            'status': 'pass' if success else 'fail',
            'message': message,
            'details': {
                'domain': info['domain'],
                'selector': info['selector'],
                'algorithm': info['algorithm'],
                'headers_signed': info['headers_signed']
            }
        }

    def _check_spf(self, file_path: str) -> dict:
        """檢查 SPF"""
        try:
            email_content = EmailParser.parse_email_file(file_path)
            message = email.message_from_string(email_content)
            
            # 從 Received-SPF 標頭獲取 SPF 結果
            spf_header = message.get('Received-SPF', '')
            if spf_header:
                result = re.search(r'^(\w+)', spf_header)
                status = result.group(1) if result else 'unknown'
                return {
                    'status': status.lower(),
                    'message': spf_header,
                    'details': {'header': spf_header}
                }
            return {
                'status': 'neutral',
                'message': '未找到 SPF 記錄',
                'details': {}
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e),
                'details': {}
            }

    def _check_dmarc(self, file_path: str) -> dict:
        """檢查 DMARC"""
        try:
            email_content = EmailParser.parse_email_file(file_path)
            message = email.message_from_string(email_content)
            
            # 從 From 標頭獲取域名
            from_header = message.get('From', '')
            domain_match = re.search(r'@([\w.-]+)', from_header)
            if not domain_match:
                return {
                    'status': 'error',
                    'message': '無法從 From 標頭獲取域名',
                    'details': {}
                }
            
            domain = domain_match.group(1)
            try:
                # 查詢 DMARC 記錄
                dmarc_records = self.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for record in dmarc_records:
                    for string in record.strings:
                        if string.startswith(b'v=DMARC1'):
                            return {
                                'status': 'pass',
                                'message': '找到有效的 DMARC 記錄',
                                'details': {'record': string.decode()}
                            }
            except dns.resolver.NXDOMAIN:
                return {
                    'status': 'fail',
                    'message': '未找到 DMARC 記錄',
                    'details': {'domain': domain}
                }
            except Exception as e:
                return {
                    'status': 'error',
                    'message': f'DMARC 查詢錯誤: {str(e)}',
                    'details': {}
                }
            
            return {
                'status': 'fail',
                'message': '未找到有效的 DMARC 記錄',
                'details': {}
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e),
                'details': {}
            }

# 如果直接執行腳本
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='郵件認證檢查工具')
    parser.add_argument('--file', '-f', required=True, help='郵件檔案路徑 (.eml 或 .msg)')
    args = parser.parse_args()
    
    checker = EmailAuthenticationChecker()
    results = checker.check_all(args.file)
    
    print("\n郵件認證檢查結果:")
    for check_type, result in results.items():
        print(f"\n{check_type.upper()}:")
        print(f"狀態: {result['status']}")
        print(f"訊息: {result['message']}")
        if result['details']:
            print("詳細資訊:")
            for key, value in result['details'].items():
                print(f"  {key}: {value}")

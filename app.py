from flask import Flask, request, jsonify, render_template, send_from_directory
from markupsafe import escape
import os
import platform
import tempfile
import email
from email import policy
from email.parser import BytesParser
import extract_msg
import logging
import re
import hashlib
import subprocess
import json
from email.utils import parseaddr, getaddresses
from datetime import datetime
from AbuseIPDB import check_ip
from VT import VirusTotalAPI, load_config
from dkim_checker import EmailAuthenticationChecker
import pdb
from urllib.parse import urlparse


app = Flask(__name__)

# 設定 logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# 根據作業系統設定上傳目錄
def get_upload_folder():
    system = platform.system().lower()
    if system == 'windows':
        base_path = os.environ.get('TEMP', tempfile.gettempdir())
    else:
        base_path = os.environ.get('TMPDIR', '/tmp')
    upload_folder = os.path.join(base_path, 'email_analyzer_uploads')
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
        logging.info(f'創建上傳目錄: {upload_folder}')
    return upload_folder

UPLOAD_FOLDER = get_upload_folder()
ALLOWED_EXTENSIONS = {'msg', 'eml'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    logging.debug('訪問首頁')
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        logging.warning('沒有檔案被上傳')
        return jsonify({'error': '沒有檔案被上傳'}), 400
    
    file = request.files['file']
    if file and allowed_file(file.filename):
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        new_filename = f"{timestamp}.{file_extension}"
        file_path = os.path.join(UPLOAD_FOLDER, new_filename)
        
        try:
            file.save(file_path)
            logging.info(f'檔案上傳成功: {new_filename} 到 {file_path}')
            
            try:
                msg = parse_email(file_path, new_filename)
                if not msg:
                    return jsonify({'error': '無法解析郵件'}), 500

                logging.debug(f'解析郵件成功: {msg["subject"]}')
                urls, modified_urls = extract_urls(msg['body'])
                hash_values = save_attachments(msg['attachments'])
                logging.debug(f"生成的附件哈希值: {hash_values}")
                logging.debug(f"提取的 URLs: {urls}")

                if not hash_values:
                    logging.warning('無附件哈希值生成，可能未解析到附件')
                    hash_values = [{'filename': '無附件', 'md5': 'N/A', 'sha1': 'N/A', 'sha256': 'N/A'}]

                hops_info = []
                try:
                    result = subprocess.run(['python3', 'hops.py', file_path], capture_output=True, text=True)
                    if result.returncode == 0:
                        hops_info = json.loads(result.stdout)
                        logging.debug(f'hops.py 返回的結果: {hops_info}')
                    else:
                        logging.error(f'hops.py 執行失敗，返回碼: {result.returncode}')
                except Exception as e:
                    logging.error(f'執行 hops.py 時發生錯誤: {e}')

                return render_template(
                    'display.html',
                    sender=escape(msg['sender']),
                    recipient=escape(msg['recipient']),
                    cc=escape(', '.join(msg['cc'])),
                    subject=escape(msg['subject']),
                    body=escape(msg['body']),
                    attachments=msg['attachments'],
                    hash_values=hash_values,
                    urls=urls,
                    modified_urls=modified_urls,
                    hops_info=hops_info,
                    headers=msg['headers']
                )

            except Exception as e:
                logging.error(f'解析郵件時發生錯誤: {e}', exc_info=True)
                return jsonify({'error': f'解析郵件時發生錯誤: {str(e)}'}), 500

        except Exception as e:
            logging.error(f'檔案處理時發生錯誤: {str(e)}')
            return jsonify({'error': f'檔案處理時發生錯誤: {str(e)}'}), 500

    logging.warning('上傳的檔案類型不正確')
    return jsonify({'error': '請上傳 .msg 或 .eml 檔案'}), 400

def decode_header_value(value):
    """解码邮件头部的值"""
    try:
        if not value:
            return ''
        
        # 如果是字符串，先处理可能的换行
        if isinstance(value, str):
            value = ' '.join(value.split())
        
        # 使用 email.header.decode_header 解码
        parts = email.header.decode_header(value)
        decoded_parts = []
        
        for part, charset in parts:
            if isinstance(part, bytes):
                try:
                    if charset:
                        decoded_parts.append(part.decode(charset))
                    else:
                        decoded_parts.append(part.decode('utf-8', errors='replace'))
                except (UnicodeDecodeError, LookupError):
                    decoded_parts.append(part.decode('utf-8', errors='replace'))
            else:
                decoded_parts.append(str(part))
        
        result = ' '.join(decoded_parts)
        logging.debug(f'解码头部值: {value} -> {result}')
        return result.strip()
    except Exception as e:
        logging.error(f'解码头部值失败: {str(e)}')
        return str(value).strip()

def analyze_email_security(headers, body, urls):
    """分析邮件安全特征"""
    security_risks = []
    risk_level = "low"  # 默认风险级别
    
    try:
        # 检查发件人域名
        from_header = headers.get('from', '').lower()
        suspicious_tlds = ['.ru', '.cn', '.tk', '.top', '.xyz']
        if any(tld in from_header for tld in suspicious_tlds):
            security_risks.append({
                'type': 'suspicious_sender_domain',
                'detail': f'可疑发件人域名: {from_header}',
                'severity': 'high'
            })
            risk_level = "high"

        # 检查伪装特征
        impersonation_keywords = ['microsoft', 'apple', 'google', 'facebook', 'linkedin']
        if any(keyword in body.lower() for keyword in impersonation_keywords):
            security_risks.append({
                'type': 'brand_impersonation',
                'detail': '疑似品牌仿冒',
                'severity': 'high'
            })
            risk_level = "high"

        # 检查 URL 特征
        for url in urls:
            # 检查数字域名
            domain = urlparse(url).netloc
            if re.match(r'^\d+\.', domain):
                security_risks.append({
                    'type': 'numeric_domain',
                    'detail': f'可疑数字域名: {domain}',
                    'severity': 'high'
                })
                risk_level = "high"

            # 检查随机字符串路径
            path = urlparse(url).path
            if len(path.split('/')) > 3 and all(len(p) > 8 for p in path.split('/')[1:]):
                security_risks.append({
                    'type': 'random_path',
                    'detail': f'可疑随机路径: {path}',
                    'severity': 'high'
                })
                risk_level = "high"

        # 返回完整的安全分析结果
        return {
            'risks': security_risks,
            'risk_level': risk_level,
            'analysis_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        logging.error(f'安全分析失败: {str(e)}')
        return {
            'risks': [{'type': 'analysis_error', 'detail': str(e), 'severity': 'unknown'}],
            'risk_level': 'unknown',
            'analysis_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

def parse_email(file_path, new_filename):
    """解析邮件内容"""
    try:
        attachments = []
        headers = {}
        all_urls = []  # 初始化 urls 列表
        body = ""
        
        if new_filename.lower().endswith('.eml'):
            with open(file_path, 'rb') as f:
                raw_email = f.read()
                
            logging.debug("=== 原始邮件内容开始 ===")
            logging.debug(raw_email.decode('utf-8', errors='replace'))
            logging.debug("=== 原始邮件内容结束 ===")
            
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)
            
            # 解析邮件头
            logging.debug("=== 所有邮件头 ===")
            for name, value in msg.items():
                logging.debug(f"{name}: {value}")
                try:
                    decoded_value = decode_header_value(value)
                    headers[name.lower()] = decoded_value
                except Exception as e:
                    logging.error(f'Header {name} 解码失败: {str(e)}')
                    headers[name.lower()] = str(value)
            
            # 解析邮件内容
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        try:
                            charset = part.get_content_charset() or 'utf-8'
                            content = part.get_payload(decode=True)
                            decoded_text = content.decode(charset, errors='replace')
                            body += decoded_text
                            # 从 HTML 内容中提取 URL
                            extracted_urls = extract_urls_from_html(decoded_text)
                            all_urls.extend(extracted_urls)
                        except Exception as e:
                            logging.error(f'HTML 内容解码失败: {str(e)}')
                    elif part.get_content_type() == "text/plain":
                        try:
                            charset = part.get_content_charset() or 'utf-8'
                            content = part.get_payload(decode=True)
                            decoded_text = content.decode(charset, errors='replace')
                            body += decoded_text
                            # 从纯文本中提取 URL
                            text_urls, _ = extract_urls(decoded_text)  # 修改这里，只获取第一个返回值
                            all_urls.extend(text_urls)
                        except Exception as e:
                            logging.error(f'Plain text 解码失败: {str(e)}')
            else:
                try:
                    charset = msg.get_content_charset() or 'utf-8'
                    content = msg.get_payload(decode=True)
                    if content:
                        body = content.decode(charset, errors='replace')
                        # 提取 URL
                        text_urls, _ = extract_urls(body)  # 修改这里，只获取第一个返回值
                        all_urls.extend(text_urls)
                except Exception as e:
                    logging.error(f'单部分内容解码失败: {str(e)}')
                    body = '無法解碼內文'

            # 去重 URLs（使用列表推导式去重）
            unique_urls = []
            [unique_urls.append(url) for url in all_urls if url not in unique_urls]
            logging.debug(f"提取到的 URLs: {unique_urls}")

            # 进行安全分析
            security_analysis = analyze_email_security(headers, body, unique_urls)
            logging.info(f"安全分析结果: {security_analysis}")

            return {
                'sender': headers.get('from', '無發件人'),
                'recipient': headers.get('to', '無收件人'),
                'cc': clean_email_list(msg.get_all('cc', [])),
                'subject': headers.get('subject', '無主題'),
                'body': body,
                'attachments': attachments,
                'headers': headers,
                'urls': unique_urls,
                'security_risks': security_analysis
            }
    except Exception as e:
        logging.error(f'解析邮件时发生错误: {e}', exc_info=True)
        return None

def extract_urls_from_html(html_content):
    """从 HTML 内容中提取 URL"""
    try:
        # 使用 BeautifulSoup 解析 HTML
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')
        
        urls = []
        # 提取所有链接
        for a in soup.find_all('a', href=True):
            url = a['href'].strip()
            if url.startswith('http'):
                urls.append(url)
        
        # 提取所有图片源
        for img in soup.find_all('img', src=True):
            url = img['src'].strip()
            if url.startswith('http'):
                urls.append(url)
        
        return urls
    except Exception as e:
        logging.error(f'HTML URL 提取失败: {str(e)}')
        return []

def clean_email_list(email_list):
    """清理电子邮件地址列表"""
    cleaned_emails = []
    logging.debug(f'清理前的 CC 列表: {email_list}')
    for email_item in email_list:
        individual_emails = re.split(r',\s*(?![^<]*>)', email_item)
        for email_addr in individual_emails:
            match = re.search(r'<([^>]+)>', email_addr)
            if match:
                cleaned_emails.append(match.group(1).strip())
            else:
                email_addr = email_addr.strip().strip("'\"")
                if re.match(r'^[^@]+@[^@]+\.[^@]+$', email_addr):
                    cleaned_emails.append(email_addr)
    logging.debug(f'清理后的 CC 列表: {cleaned_emails}')
    return cleaned_emails

def extract_urls(text):
    """提取正文中的网址并去除重复"""
    try:
        if isinstance(text, bytes):
            decoded_text = text.decode('utf-8', errors='replace')
        else:
            decoded_text = text

        # 处理 quoted-printable 编码
        if '=3D' in decoded_text:
            try:
                import quopri
                decoded_text = quopri.decodestring(decoded_text.encode('utf-8')).decode('utf-8')
            except Exception as e:
                logging.warning(f'Quoted-printable 解码失败: {str(e)}')

        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            re.IGNORECASE
        )
        
        urls = url_pattern.findall(decoded_text)
        
        cleaned_urls = []
        for url in urls:
            # 清理 URL
            cleaned_url = url.strip('=').split(';')[0].split('"')[0].split("'")[0]
            if cleaned_url not in cleaned_urls:
                cleaned_urls.append(cleaned_url)
        
        return cleaned_urls, [url.replace('http', 'hxxp') for url in cleaned_urls]
    except Exception as e:
        logging.error(f'URL 提取失败: {str(e)}')
        return [], []

def save_attachments(attachments):
    """保存附件并计算哈希值"""
    hash_values = []
    for attachment in attachments:
        if attachment['data']:
            original_filename = attachment['filename']
            file_extension = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
            attachment_path = os.path.join(UPLOAD_FOLDER, original_filename)

            counter = 1
            while os.path.exists(attachment_path):
                name_without_ext = original_filename.rsplit('.', 1)[0]
                attachment_path = os.path.join(
                    UPLOAD_FOLDER, 
                    f"{name_without_ext}_{counter}.{file_extension}" if file_extension else f"{name_without_ext}_{counter}"
                )
                counter += 1
            
            try:
                with open(attachment_path, 'wb') as f:
                    f.write(attachment['data'])

                md5_hash = hashlib.md5(attachment['data']).hexdigest()
                sha1_hash = hashlib.sha1(attachment['data']).hexdigest()
                sha256_hash = hashlib.sha256(attachment['data']).hexdigest()

                hash_values.append({
                    'original_filename': original_filename,
                    'md5': md5_hash,
                    'sha1': sha1_hash,
                    'sha256': sha256_hash
                })

                logging.info(f'附件保存成功: {attachment_path}')
                
            except Exception as e:
                logging.error(f'保存附件时发生错误: {str(e)}')
                continue
                
    return hash_values

def generate_default_filename(data):
    return f"attachment_{hashlib.md5(data).hexdigest()}"

@app.route('/check_ip', methods=['GET'])
def check_ip_route():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({'error': 'IP 地址未提供'}), 400

    result = check_ip(ip)  # 调用 AbuseIPDB 的检查函数
    return jsonify(result)

@app.route('/download/<filename>')
def download_file(filename):
    """处理文件下载请求"""
    try:
        # 获取当前系统的临时目录路径
        system = platform.system().lower()
        if system == 'windows':
            # Windows 环境使用 %TEMP%
            base_path = os.environ.get('TEMP', tempfile.gettempdir())
        else:
            # Linux/Unix 环境使用 $TMPDIR 或 /tmp
            base_path = os.environ.get('TMPDIR', '/tmp')
        
        # 构建完整的文件路径
        file_path = os.path.join(base_path, 'email_analyzer_uploads', filename)
        
        # 检查文件是否存在
        if not os.path.exists(file_path):
            logging.error(f'文件不存在: {file_path}')
            return jsonify({'error': '文件不存在'}), 404

        # 从正确的目录提供文件下载
        logging.info(f'开始下载文件: {filename}, 路径: {file_path}')
        return send_from_directory(
            directory=os.path.dirname(file_path),  # 使用文件所在的目录
            path=filename,
            as_attachment=True,  # 这会触发下载而不是在浏览器中显示
            download_name=filename  # 确保下载时使用原始文件名
        )
    except Exception as e:
        logging.error(f'下载文件时发生错误: {str(e)}')
        return jsonify({'error': '文件下载失败'}), 500

@app.route('/virustotal/<file_hash>', methods=['GET'])
def virustotal_report(file_hash):
    """获取 VirusTotal 报告"""
    try:
        # 获取 API 密钥
        api_key = load_config()
        vt = VirusTotalAPI(api_key)
        
        # 获取报告
        report = vt.get_file_report(file_hash)
        return jsonify(report)
    except Exception as e:
        logging.error(f'获取 VirusTotal 报告时发生错误: {e}')
        return jsonify({'error': '无法获取 VirusTotal 报告'}), 500

@app.route('/virustotal/scan_url', methods=['POST'])
def virustotal_scan_url():
    """执行 URL 扫描"""
    try:
        data = request.get_json()
        target_url = data.get('url')
        if not target_url:
            return jsonify({'error': '无效的 URL'}), 400

        # 获取 API 密钥
        api_key = load_config()
        vt = VirusTotalAPI(api_key)
        
        # 执行 URL 扫描
        scan_result = vt.scan_url(target_url)
        return jsonify(scan_result)
    except Exception as e:
        logging.error(f'执行 URL 扫描时发生错误: {e}')
        return jsonify({'error': '无法执行 URL 扫描'}), 500

@app.route('/check_auth/<filename>')
def check_auth(filename):
    """检查邮件认证（DKIM、SPF、DMARC）"""
    try:
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        if not os.path.exists(file_path):
            return jsonify({'error': '找不到文件'}), 404

        checker = EmailAuthenticationChecker()
        results = checker.check_all(file_path)
        return jsonify(results)
    except Exception as e:
        logging.error(f"检查邮件认证时发生错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
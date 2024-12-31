from flask import Flask, request, jsonify, render_template
from markupsafe import escape
import os
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
import datetime  # 確保導入 datetime 模組
from AbuseIPDB import check_ip  # 導入 check_ip 函數

app = Flask(__name__)

# 設定 logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_FOLDER = 'uploads'
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
        # 獲取當前時間並格式化為 yyyymmddhhmmss
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        # 獲取檔案的擴展名
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        # 生成新的檔案名稱
        new_filename = f"{timestamp}.{file_extension}"
        file_path = os.path.join(UPLOAD_FOLDER, new_filename)  # 使用新的檔案名稱
        
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)
            logging.info(f'創建上傳目錄: {UPLOAD_FOLDER}')

        file.save(file_path)
        logging.info(f'檔案上傳成功: {new_filename} 到 {file_path}')

        try:
            msg = parse_email(file_path, new_filename)  # 使用新的檔案名稱
            if not msg:
                return jsonify({'error': '無法解析郵件'}), 500

            logging.debug(f'解析郵件成功: {msg["subject"]}')
            urls, modified_urls = extract_urls(msg['body'])
            hash_values = save_attachments(msg['attachments'])  # 使用新的檔案名稱並獲取哈希值
            logging.debug(f"生成的附件哈希值: {hash_values}")

            if not hash_values:
                logging.warning('無附件哈希值生成，可能未解析到附件')
                hash_values = [{'filename': '無附件', 'md5': 'N/A', 'sha1': 'N/A', 'sha256': 'N/A'}]

            # 執行 hops.py 並獲取結果
            hops_info = []
            try:
                result = subprocess.run(['python3', 'hops.py', file_path], capture_output=True, text=True)
                if result.returncode == 0:
                    hops_info = json.loads(result.stdout)  # 將結果轉換為 Python 對象
                    logging.debug(f'hops.py 返回的結果: {hops_info}')
                else:
                    logging.error(f'hops.py 執行失敗，返回碼: {result.returncode}')
            except Exception as e:
                logging.error(f'執行 hops.py 時發生錯誤: {e}')

            return render_template(
                'display.html',
                sender=escape(msg['sender']),
                recipient=escape(msg['recipient']),
                cc=escape(', '.join(msg['cc'])),  # 傳遞 CC 資料
                subject=escape(msg['subject']),
                body=escape(msg['body']),
                attachments=msg['attachments'],  # 傳遞附件
                hash_values=hash_values,  # 傳遞哈希值
                urls=modified_urls,
                hops_info=hops_info  # 傳遞 Hops 資訊
            )

        except Exception as e:
            logging.error(f'解析郵件時發生錯誤: {e}', exc_info=True)
            return jsonify({'error': f'解析郵件時發生錯誤: {str(e)}'}), 500

    logging.warning('上傳的檔案類型不正確')
    return jsonify({'error': '請上傳 .msg 或 .eml 檔案'}), 400

def parse_email(file_path, new_filename):
    """解析郵件內容"""
    try:
        attachments = []
        if new_filename.lower().endswith('.eml'):
            with open(file_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
                attachments = []
                
                # 檢查郵件是否為多部分
                if msg.is_multipart():
                    for part in msg.walk():
                        # 檢查是否為附件
                        if part.get_content_disposition() == 'attachment':
                            attachments.append({
                                'filename': part.get_filename() or generate_default_filename(part.get_payload(decode=True)),
                                'data': part.get_payload(decode=True)
                            })
                else:
                    # 如果不是多部分，檢查是否有附件
                    if msg.get_content_disposition() == 'attachment':
                        attachments.append({
                            'filename': msg.get_filename(),
                            'data': msg.get_payload(decode=True)
                        })
                body = msg.get_body(preferencelist=('plain')).get_content() if msg.get_body(preferencelist=('plain')) else '無內文'
                reply_to = msg['reply-to'] if msg['reply-to'] else None  # 獲取 Reply-To
                return {
                    'sender': msg['from'],
                    'recipient': msg['to'],
                    'cc': clean_email_list(msg.get_all('cc', [])),  # 清理 CC
                    'subject': msg['subject'],
                    'body': body,
                    'attachments': attachments,
                    'reply_to': reply_to  # 新增回覆收件人
                }
        elif new_filename.lower().endswith('.msg'):
            msg = extract_msg.Message(file_path)
            attachments = []
            for attachment in msg.attachments:
                try:
                    # 使用 extract_msg 提供的方法獲取附件的原始檔名
                    original_filename = attachment.longFilename or attachment.shortFilename
                    attachments.append({
                        'filename': original_filename,
                        'data': attachment.data
                    })
                except Exception as e:
                    logging.error(f'處理附件時發生錯誤: {str(e)}')
            
            return {
                'sender': msg.sender,
                'recipient': msg.to,
                'cc': clean_email_list(msg.cc.split(',')) if msg.cc else [],
                'subject': msg.subject,
                'body': msg.body or '無內文',
                'attachments': attachments,
                'ip_check_results': ip_check_results,  # 傳遞 IP 檢查結果
                'hops_info': hops_info  # 傳遞 Hops 資訊
            }
    except Exception as e:
        logging.error(f'解析郵件時發生錯誤: {e}')
        return None

def clean_email_list(email_list):
    """清理電子郵件地址列表"""
    cleaned_emails = []
    logging.debug(f'清理前的 CC 列表: {email_list}')
    for email_item in email_list:
        # 分割多個電子郵件項目
        individual_emails = re.split(r',\s*(?![^<]*>)', email_item)  # 分隔不在 < > 內的逗號
        for email in individual_emails:
            # 提取電子郵件地址
            match = re.search(r'<([^>]+)>', email)
            if match:
                cleaned_emails.append(match.group(1).strip())  # 匹配 <email@example.com>
            else:
                # 如果沒有 < >，則取直接地址並去除多餘的引號
                email = email.strip().strip("'\"")  # 去除包裹的引號
                if re.match(r'^[^@]+@[^@]+\.[^@]+$', email):  # 確認是有效的電子郵件格式
                    cleaned_emails.append(email)
    logging.debug(f'清理後的 CC 列表: {cleaned_emails}')
    return cleaned_emails

def extract_urls(body):
    """提取內文中的網址"""
    urls = re.findall(r'https?://[^\s]+', body)
    unique_urls = set(urls)
    modified_urls = [url.replace('.', '[.]') for url in unique_urls]
    return urls, modified_urls

def save_attachments(attachments):
    """保存附件並計算哈希值"""
    hash_values = []  # 用於存儲每個附件的哈希值
    for attachment in attachments:
        if attachment['data']:
            # 獲取原始檔案的副檔名
            original_filename = attachment['filename']
            file_extension = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
            
            # 生成新的檔案名稱，保留原始檔名
            attachment_path = os.path.join(UPLOAD_FOLDER, original_filename)

            # 檢查檔案是否已存在，若存在則添加數字後綴
            counter = 1
            while os.path.exists(attachment_path):
                attachment_path = os.path.join(UPLOAD_FOLDER, f"{original_filename.rsplit('.', 1)[0]}_{counter}.{file_extension}")
                counter += 1
            
            with open(attachment_path, 'wb') as f:
                f.write(attachment['data'])  # 保存附件數據

            # 計算哈希值
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            md5_hash.update(attachment['data'])
            sha1_hash.update(attachment['data'])
            sha256_hash.update(attachment['data'])

            # 將哈希值和原始檔名存儲到列表中
            hash_values.append({
                'original_filename': original_filename,  # 新增原始檔名
                'md5': md5_hash.hexdigest(),
                'sha1': sha1_hash.hexdigest(),
                'sha256': sha256_hash.hexdigest()
            })

            logging.info(f'附件保存成功: {attachment_path}')
    return hash_values  # 返回哈希值列表

def generate_default_filename(data):
    return f"attachment_{hashlib.md5(data).hexdigest()}"

@app.route('/check_ip', methods=['GET'])
def check_ip_route():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({'error': 'IP 地址未提供'}), 400

    result = check_ip(ip)  # 調用 AbuseIPDB 的檢查函數
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)

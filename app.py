from flask import Flask, request, jsonify, render_template
from markupsafe import escape
import os
import email
from email import policy
from email.parser import BytesParser
import extract_msg
import logging
import re  # 引入正則表達式模組
import hashlib  # 引入 hashlib 模組
import subprocess  # 用於執行 hops.py

app = Flask(__name__)

# 設定 logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

UPLOAD_FOLDER = 'uploads'  # 確保這是正確的上傳目錄
ALLOWED_EXTENSIONS = {'msg', 'eml'}

# 判斷上傳的檔案類型是否允許
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
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        
        # 確保 uploads 目錄存在
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)
            logging.info(f'創建上傳目錄: {UPLOAD_FOLDER}')

        file.save(file_path)
        logging.info(f'檔案上傳成功: {file.filename} 到 {file_path}')

        # 檢查檔案是否存在
        if os.path.exists(file_path):
            logging.info(f'檔案存在: {file_path}')
        else:
            logging.error(f'檔案不存在: {file_path}')

        # 解析郵件內容
        try:
            if file.filename.endswith('.eml'):
                with open(file_path, 'rb') as f:
                    msg = BytesParser(policy=policy.default).parse(f)
                    sender = msg['from']
                    recipient = msg['to']
                    subject = msg['subject']
                    body = msg.get_body(preferencelist=('plain')).get_content() if msg.get_body(preferencelist=('plain')) else '無內文'
                    attachments = [part.get_filename() for part in msg.iter_attachments()] or ['無附件']
            elif file.filename.endswith('.msg'):
                msg = extract_msg.Message(file_path)
                sender = msg.sender
                recipient = msg.to
                subject = msg.subject
                body = msg.body or '無內文'
                attachments = msg.attachments or ['無附件']
                logging.debug(f'提取的附件: {attachments}')

            logging.debug(f'解析郵件成功: {subject}')
            logging.debug(f'寄件人: {sender}, 收件人: {recipient}, 主旨: {subject}, 內文: {body}, 附件: {attachments}')

            # 檢查內文中的網址
            urls = re.findall(r'https?://[^\s]+', body)  # 匹配網址
            unique_urls = set(urls)  # 使用 set 去除重複網址
            modified_urls = [url.replace('.', '[.]') for url in unique_urls]  # 替換 . 為 [.]

            logging.debug(f'找到的網址: {modified_urls}')

            # 計算每個附件的 SHA256 值
            attachments = []
            sha256_values = []

            # 提取附件
            if file.filename.endswith('.eml'):
                for part in msg.iter_attachments():
                    filename = part.get_filename()
                    if filename:
                        attachment_path = os.path.join(UPLOAD_FOLDER, filename)
                        with open(attachment_path, 'wb') as f:
                            f.write(part.get_content())
                        attachments.append(filename)
                        logging.info(f'附件保存成功: {attachment_path}')

            elif file.filename.endswith('.msg'):
                for attachment in msg.attachments:
                    attachment_path = os.path.join(UPLOAD_FOLDER, attachment.filename)
                    with open(attachment_path, 'wb') as f:
                        f.write(attachment.data)
                    attachments.append(attachment.filename)
                    logging.info(f'附件保存成功: {attachment_path}')

            # 計算附件的 SHA256 值
            for attachment in attachments:
                attachment_path = os.path.join(UPLOAD_FOLDER, attachment)
                sha256_hash = hashlib.sha256()
                with open(attachment_path, "rb") as f:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                sha256_values.append(sha256_hash.hexdigest())

            logging.debug(f'附件 SHA256 值: {sha256_values}')

            return render_template(
                'display.html',
                sender=escape(sender),
                recipient=escape(recipient),
                subject=escape(subject),
                body=escape(body),
                attachments=[escape(attachment) for attachment in attachments],
                sha256_values=sha256_values,
                urls=modified_urls
            )

        except Exception as e:
            logging.error(f'解析郵件時發生錯誤: {e}', exc_info=True)
            return jsonify({'error': f'解析郵件時發生錯誤: {str(e)}'}), 500

    else:
        logging.warning('上傳的檔案類型不正確')
        return jsonify({'error': '請上傳 .msg 或 .eml 檔案'}), 400

@app.route('/hops', methods=['POST'])
def get_hops_info():
    if 'file' not in request.files:
        return jsonify({'error': '沒有檔案被上傳'}), 400
    
    file = request.files['file']
    if file and allowed_file(file.filename):
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        # 執行 hops.py 並獲取結果
        try:
            result = subprocess.run(['python3', 'hops.py', file_path], capture_output=True, text=True)
            if result.returncode != 0:
                return jsonify({'error': '執行 hops.py 時發生錯誤'}), 500
            
            hops_info = eval(result.stdout)  # 將結果轉換為 Python 對象
            return jsonify(hops_info), 200

        except Exception as e:
            return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)

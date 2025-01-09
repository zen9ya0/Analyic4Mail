from flask import Flask, request, jsonify, render_template, send_from_directory
import os
import platform
import tempfile
import logging
from datetime import datetime
from AbuseIPDB import check_ip
from VT import VirusTotalAPI, load_config
from dkim_checker import EmailAuthenticationChecker

app = Flask(__name__)

# 設定 logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def get_upload_folder():
    """根據作業系統設定上傳目錄"""
    base_path = os.environ.get('TEMP', tempfile.gettempdir()) if platform.system().lower() == 'windows' else os.environ.get('TMPDIR', '/tmp')
    upload_folder = os.path.join(base_path, 'email_analyzer_uploads')
    os.makedirs(upload_folder, exist_ok=True)  # 確保目錄存在
    logging.info(f'上傳目錄: {upload_folder}')
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
        new_filename = f"{timestamp}.{file.filename.rsplit('.', 1)[1].lower()}"
        file_path = os.path.join(UPLOAD_FOLDER, new_filename)
        
        try:
            file.save(file_path)
            logging.info(f'檔案上傳成功: {new_filename} 到 {file_path}')
            # 進行後續處理...
            return jsonify({'message': '檔案已成功處理！'}), 200
        except Exception as e:
            logging.error(f'檔案上傳失敗: {e}')
            return jsonify({'error': '檔案上傳失敗'}), 500
    else:
        logging.warning('上傳的檔案類型不正確')
        return jsonify({'error': '不支援的檔案類型'}), 400
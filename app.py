from flask import Flask, request, render_template
import os
import logging  # 添加 logging 模塊的導入
import hops  # 假設 hops.py 在同一目錄下

app = Flask(__name__)

UPLOAD_FOLDER = '/tmp/email_analyzer_uploads'  # 假設上傳目錄為 /tmp/email_analyzer_uploads
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
        return "No file part", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    # 保存文件到臨時路徑
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # 根據文件類型提取信息
    if file.filename.lower().endswith('.msg'):
        sender, recipient, reply_to, subject, body, headers = hops.extract_email_info_from_msg(file_path)
    else:
        sender, recipient, reply_to, subject, body = hops.extract_email_info(file_path)
        headers = hops.extract_headers(file_path)

    # 調用 hops.py 的功能
    hops_info = hops.parse_received_headers(file_path)

    # 渲染模板，傳遞所有信息
    return render_template('display.html', sender=sender, recipient=recipient, reply_to=reply_to, subject=subject, body=body, headers=headers, hops_info=hops_info)

if __name__ == '__main__':
    app.run(debug=True)
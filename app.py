from flask import Flask, request, render_template_string
import email
import re
from email.header import decode_header
from AbuseIPDB import check_ip
import logging

# 設定日誌
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app_debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

def extract_urls(text):
    """提取文本中的 URL，去除重複項並將點號替換為 [.]"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    unique_urls = list(dict.fromkeys(urls))
    defanged_urls = [url.replace('.', '[.]') for url in unique_urls]
    return defanged_urls

def extract_ip(text):
    """從文本中提取 IP 地址"""
    ipv4_pattern = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    ipv6_pattern = r'(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
    
    bracket_pattern = r'\[(.*?)\]'
    bracket_match = re.search(bracket_pattern, text)
    
    if bracket_match:
        bracket_content = bracket_match.group(1)
        for pattern in [ipv4_pattern, ipv6_pattern]:
            ip_match = re.search(pattern, bracket_content)
            if ip_match:
                return ip_match.group(0)
    
    for pattern in [ipv4_pattern, ipv6_pattern]:
        ip_match = re.search(pattern, text)
        if ip_match:
            return ip_match.group(0)
    
    return None

def create_button(ip):
    """為 IP 創建檢查按鈕"""
    if ip:
        return f' <button onclick="checkIP(\'{ip}\')" class="check-button"><i class="fas fa-search"></i> 檢查</button>'
    return ''

@app.route('/check_ip/<ip>', methods=['GET'])
def check_ip_route(ip):
    """處理 IP 檢查請求"""
    try:
        result = check_ip(ip)
        logger.debug(f"IP 檢查結果: {result}")
        return result
    except Exception as e:
        error_msg = f"檢查 IP 時發生錯誤: {str(e)}"
        logger.error(error_msg)
        return {'error': True, 'message': error_msg}

@app.route('/', methods=['GET', 'POST'])
def index():
    """處理首頁請求"""
    if request.method == 'POST':
        if 'file' not in request.files:
            return '沒有上傳文件'
        
        file = request.files['file']
        if file.filename == '':
            return '沒有選擇文件'
        
        try:
            email_content = file.read()
            msg = email.message_from_bytes(email_content)
            
            recipients = []
            if msg['to']:
                for name, email_addr in email.utils.getaddresses([msg['to']]):
                    recipients.append((name, email_addr))
            
            ccs = []
            if msg['cc']:
                for name, email_addr in email.utils.getaddresses([msg['cc']]):
                    ccs.append((name, email_addr))
            
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode()
                        break
            else:
                body = msg.get_payload(decode=True).decode()
            
            urls = extract_urls(body)
            urls_html = ""
            if urls:
                urls_html = """
                <tr>
                    <td>發現的 URL<br>（已去重）</td>
                    <td>
                        <ul class="url-list">
                            {}
                        </ul>
                    </td>
                </tr>
                """.format('\n'.join(f'<li>{url}</li>' for url in urls))
            
            email_info = f"""
            <tr><td>寄件人</td><td>{msg['from']}</td></tr>
            <tr><td>收件人</td><td>{'<br>'.join(f"{name} &lt;{email}&gt;" for name, email in recipients)}</td></tr>
            <tr><td>副本</td><td>{'<br>'.join(f"{name} &lt;{email}&gt;" for name, email in ccs) if ccs else '無'}</td></tr>
            <tr><td>主旨</td><td>{msg['subject']}</td></tr>
            <tr><td>郵件內容</td><td>{body}</td></tr>
            {urls_html}
            """
            
            return render_template_string(
                html_template,
                email_info=email_info
            )
            
        except Exception as e:
            logger.error(f"處理郵件時發生錯誤: {str(e)}")
            return f'處理郵件時發生錯誤: {str(e)}'
    
    return '''
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="上傳">
        </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)

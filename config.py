# API 配置
API_KEYS = {
    'ABUSEIPDB': '492daa8168563815136f7953a5228e4606bbd59c248f3610bc6e88473a324c4df4b34c61d235a325',
    'VIRUSTOTAL': 'd39ac249f32882e8a0e2fb75ead00136a08c2eaa368d577acf7830c9d9998509',
    'BLACKLISTMASTER': 'rV3PJXApDpn9KRTJSo8Yd2f5VTYIvD8x'
}

# API URLs
API_URLS = {
    'ABUSEIPDB': 'https://api.abuseipdb.com/api/v2',
    'VIRUSTOTAL': 'https://www.virustotal.com/api/v3',
    'BLACKLISTMASTER': 'https://www.blacklistmaster.com/restapi/v1'
}

# 日誌配置
LOGGING = {
    'DEBUG_MODE': True,
    'LOG_LEVEL': 'DEBUG',
    'LOG_FORMAT': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'LOG_FILES': {
        'ABUSEIPDB': 'abuseipdb_debug.log',
        'VIRUSTOTAL': 'vt_debug.log',
        'BLACKLISTMASTER': 'blacklist_master.log',
        'GENERAL': 'app.log'
    }
}

# 通用配置
COMMON = {
    'CLEANUP_INTERVAL': 180,  # 清理間隔（秒）
    'REQUEST_TIMEOUT': 10,    # API 請求超時時間（秒）
    'MAX_RETRIES': 3         # API 請求重試次數
}

# 檔案處理配置
FILE_HANDLING = {
    'ALLOWED_EXTENSIONS': {'.msg', '.eml'},
    'MAX_FILE_SIZE': 10 * 1024 * 1024,  # 10MB
    'CLEANUP_INTERVAL': 180  # 清理間隔（秒），例如每小時清理一次
}
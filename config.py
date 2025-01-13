# API KEY配置
ABUSEIPDB_API_KEY = '492daa8168563815136f7953a5228e4606bbd59c248f3610bc6e88473a324c4df4b34c61d235a325'
CHECK_IP = '127.0.0.1'  # 預設IP，可以根據需要修改
VT_API_KEY = 'd39ac249f32882e8a0e2fb75ead00136a08c2eaa368d577acf7830c9d9998509'
BlacklistMaster_API_KEY = 'rV3PJXApDpn9KRTJSo8Yd2f5VTYIvD8x'

# Debug 設定
DEBUG_MODE = True  # Debug 模式開關
LOG_LEVEL = 'DEBUG'  # 可選: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FILE = 'abuseipdb_debug.log'  # debug log 檔案名稱

# 清除檔案的時間間隔（以秒為單位）
CLEANUP_INTERVAL = 180  # 每小時清除一次

# Logging 設定
#VT_LOG_FILE = 'vt_debug.log'  # VirusTotal debug log 檔案名稱
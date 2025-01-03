import os
import time
import logging
from datetime import datetime

# 設定日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/email_analyzer_cleanup.log'),
        logging.StreamHandler()
    ]
)

TARGET_DIR = '/tmp/email_analyzer'
INTERVAL = 180  # 3分鐘 = 180秒

def cleanup_files():
    try:
        if not os.path.exists(TARGET_DIR):
            logging.info(f"目錄不存在: {TARGET_DIR}")
            return
            
        # 取得目錄中的所有項目
        items = os.listdir(TARGET_DIR)
        if not items:
            logging.info("目錄為空，無需清理")
            return
            
        # 刪除目錄中的所有文件和子目錄
        for item in items:
            item_path = os.path.join(TARGET_DIR, item)
            try:
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                logging.info(f"已刪除: {item_path}")
            except Exception as e:
                logging.error(f"刪除 {item_path} 時發生錯誤: {str(e)}")
                
        logging.info(f"完成清理目錄內容: {TARGET_DIR}")
    except Exception as e:
        logging.error(f"清理過程發生錯誤: {str(e)}")

def main():
    logging.info("啟動目錄檔案清理監控程序")
    
    while True:
        cleanup_files()
        time.sleep(INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("程序被手動停止")
        exit(0)
    except Exception as e:
        logging.error(f"程序發生未預期的錯誤: {str(e)}")
        exit(1)
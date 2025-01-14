#本專案主要功能為可上傳.msg或.eml檔案進行分析
#檢視郵件內文
#檢視各節點(Hops)傳遞狀態
#檢查附件
#檢查來源IP
#持續更新功能中
#python3 app.py

#修正msg分析功能失效問題
#新增VirusTotal功能
#新增檔案HASH值
#新增DKIM、SPF、DMARC檢查功能


啟動與安裝
下載專案檔案後，進入專案資料夾
sudo python3 -m venv venv #建議在虛擬環境下運行
source venv/bin/activate
pip install -r requirements.txt ＃安裝相關套件
python app.py ＃啟動專案



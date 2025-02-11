import os
from datetime import datetime

LOG_FILE_PATH = "logs/system_logs.txt"

def log_dosyasini_olustur():
    """Log dosyasını ve gerekli klasörleri oluşturur."""
    try:
        log_klasoru = os.path.dirname(LOG_FILE_PATH)
        if not os.path.exists(log_klasoru):
            os.makedirs(log_klasoru)
        if not os.path.exists(LOG_FILE_PATH):
            with open(LOG_FILE_PATH, "w") as log_file:
                log_file.write("Log dosyası oluşturuldu.\n")
    except Exception as e:
        print(f"Log dosyası oluşturma hatası: {e}")

def log_yaz(islem_turu, kullanici_adi, detay=""):
    """Log dosyasına işlem türü, kullanıcı adı ve detay ekler."""
    if not islem_turu or not kullanici_adi:
        print("Log yazma hatası: 'islem_turu' ve 'kullanici_adi' boş bırakılamaz.")
        return
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_mesaji = f"{timestamp} | {islem_turu} | Kullanıcı: {kullanici_adi} | {detay}\n"
        with open(LOG_FILE_PATH, "a") as log_file:
            log_file.write(log_mesaji)
    except Exception as e:
        print(f"Log yazma hatası: {e}")

def log_goruntule():
    """Log dosyasını okur ve döndürür."""
    try:
        if not os.path.exists(LOG_FILE_PATH):
            return ["Log dosyası bulunamadı."]
        with open(LOG_FILE_PATH, "r") as log_file:
            icerik = log_file.readlines()
        return icerik if icerik else ["Log dosyası boş."]
    except Exception as e:
        return [f"Hata: {e}"]

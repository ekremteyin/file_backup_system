import os
import subprocess
import shutil

BACKUP_DIR = "yedekler"

def yedekleme_dizini_olusturr():
    """Yedekleme dizini yoksa oluşturur."""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

def log_yazz(kategori, kaynak, mesaj):
    """Loglama işlemini gerçekleştirir."""
    print(f"[{kategori}] {kaynak}: {mesaj}")

def yedekle_dosya_process(dosya_yolu, dosya_adi):
    """Belirtilen dosyayı subprocess ile yedekleme dizinine kopyalar."""
    try:
        yedekleme_dizini_olusturr()
        hedef_yol = os.path.join(BACKUP_DIR, dosya_adi)

        # Sistem komutuyla dosyayı kopyala (platform bağımlılığına dikkat edin)
        if os.name == 'posix':  # Linux/Mac
            subprocess.run(["cp", dosya_yolu, hedef_yol], check=True)
        elif os.name == 'nt':  # Windows
            subprocess.run(["copy", dosya_yolu, hedef_yol], shell=True, check=True)

        log_yazz("Dosya Yedekleme", "Sistem", f"Dosya yedeklendi: {dosya_adi}")
    except subprocess.CalledProcessError as e:
        log_yazz("Hata", "Sistem", f"Dosya yedekleme hatası: {dosya_adi}, Hata: {e}")
    except Exception as e:
        log_yazz("Hata", "Sistem", f"Beklenmedik hata: {e}")

# Kullanım Örneği:
# yedekle_dosya_process("ornek_dosya.txt", "yedek_ornek_dosya.txt")

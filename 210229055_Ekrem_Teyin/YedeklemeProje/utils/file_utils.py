import os
import shutil
from dbconnection.db_connection import veritabani_baglantisi
from utils.hash_utils import hash_parola
from utils.logs_utils import log_yaz

BACKUP_DIR = "backups"  # Yedekleme dizini
UPLOAD_DIR = "uploads"  # Ana yükleme dizini


def kullanici_dizini_olustur(kullanici_id):
    """Kullanıcıya özel dizin oluşturur veya mevcut dizini döner."""
    kullanici_dizini = os.path.join(UPLOAD_DIR, f"user_{kullanici_id}")
    if not os.path.exists(kullanici_dizini):
        os.makedirs(kullanici_dizini)
        log_yaz("Dizin Oluşturma", f"Kullanıcı ID: {kullanici_id}", f"Dizin: {kullanici_dizini}")
    return kullanici_dizini


def parola_talebi_olustur(kullanici_id):
    """Kullanıcı için parola değiştirme talebi oluşturur."""
    try:
        db = veritabani_baglantisi()
        cursor = db.cursor()
        cursor.execute("""
            UPDATE Kullanici
            SET parola_talebi = 1
            WHERE id = %s
        """, (kullanici_id,))
        db.commit()
        db.close()
        log_yaz("Parola Talebi", f"Kullanıcı ID: {kullanici_id}", "Parola değiştirme talebi oluşturuldu.")
        return "Parola değiştirme talebi başarıyla oluşturuldu. Adminin onayı bekleniyor."
    except Exception as e:
        log_yaz("Parola Talebi Hatası", f"Kullanıcı ID: {kullanici_id}", f"Hata: {e}")
        return f"Hata: {e}"


def parola_degistir(kullanici_id, yeni_parola):
    """Kullanıcının parolasını değiştirir."""
    try:
        yeni_parola_hash = hash_parola(yeni_parola)
        db = veritabani_baglantisi()
        cursor = db.cursor()
        cursor.execute("""
            UPDATE Kullanici
            SET parola_hash = %s
            WHERE id = %s
        """, (yeni_parola_hash, kullanici_id))
        db.commit()
        db.close()
        log_yaz("Parola Değiştirme", f"Kullanıcı ID: {kullanici_id}", "Parola başarıyla değiştirildi.")
        return "Parola başarıyla değiştirildi!"
    except Exception as e:
        log_yaz("Parola Değiştirme Hatası", f"Kullanıcı ID: {kullanici_id}", f"Hata: {e}")
        return f"Hata: {e}"


def dosya_yukle(dosya_yolu):
    """Belirtilen dosyayı uploads dizinine yükler."""
    if not dosya_yolu:
        return "Dosya yolu seçilmedi."

    try:
        if not os.path.exists(UPLOAD_DIR):
            os.makedirs(UPLOAD_DIR)

        dosya_adi = os.path.basename(dosya_yolu)
        hedef_yol = os.path.join(UPLOAD_DIR, dosya_adi)
        shutil.copy(dosya_yolu, hedef_yol)
        log_yaz("Dosya Yükleme", "Sistem", f"Dosya: {dosya_adi} başarıyla yüklendi.")
        return f"{dosya_adi} başarıyla yüklendi!"
    except Exception as e:
        log_yaz("Dosya Yükleme Hatası", "Sistem", f"Dosya: {dosya_yolu}, Hata: {e}")
        return f"Hata: {e}"

def yedekleme_dizini_olustur():
    """Yedekleme dizinini oluşturur."""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        log_yaz("Yedekleme", "Sistem", f"Yedekleme dizini oluşturuldu: {BACKUP_DIR}")
def yedekle_dosya(dosya_yolu, dosya_adi):
    """Belirtilen dosyayı yedekleme dizinine kopyalar."""
    try:
        yedekleme_dizini_olustur()
        hedef_yol = os.path.join(BACKUP_DIR, dosya_adi)
        shutil.copy(dosya_yolu, hedef_yol)
        log_yaz("Dosya Yedekleme", "Sistem", f"Dosya yedeklendi: {dosya_adi}")
    except Exception as e:
        log_yaz("Hata", "Sistem", f"Dosya yedekleme hatası: {dosya_adi}, Hata: {e}")

def dosya_yukle_kullanici(dosya_yolu, kullanici_id):
    """Kullanıcının dizinine dosya yükler."""
    if not dosya_yolu:
        return "Dosya yolu seçilmedi."

    try:
        kullanici_dizini = kullanici_dizini_olustur(kullanici_id)
        dosya_adi = os.path.basename(dosya_yolu)
        hedef_yol = os.path.join(kullanici_dizini, dosya_adi)
        shutil.copy(dosya_yolu, hedef_yol)

        # Dosyayı yedekleme dizinine de kopyala
        yedekle_dosya(hedef_yol, dosya_adi)

        log_yaz("Dosya Yükleme", f"Kullanıcı ID: {kullanici_id}", f"Dosya: {dosya_adi}")
        return f"{dosya_adi} başarıyla yüklendi!"
    except Exception as e:
        log_yaz("Dosya Yükleme Hatası", f"Kullanıcı ID: {kullanici_id}", f"Dosya: {dosya_yolu}, Hata: {e}")
        return f"Hata: {e}"


def dosyalari_listele():
    """Uploads dizinindeki tüm dosyaları listeler."""
    try:
        if not os.path.exists(UPLOAD_DIR):
            os.makedirs(UPLOAD_DIR)

        dosyalar = os.listdir(UPLOAD_DIR)
        log_yaz("Dosya Listeleme", "Sistem", "Uploads dizinindeki dosyalar listelendi.")
        return dosyalar
    except Exception as e:
        log_yaz("Dosya Listeleme Hatası", "Sistem", f"Hata: {e}")
        return f"Hata: {e}"


def dosyalari_listele_kullanici(kullanici_id):
    """Kullanıcının dizinindeki dosyaları listeler ve paylaşım dosyalarını ekler."""
    try:
        kullanici_dizini = kullanici_dizini_olustur(kullanici_id)
        dosyalar = os.listdir(kullanici_dizini)

        # Paylaşım dosyalarını ekle
        db = veritabani_baglantisi()
        cursor = db.cursor()
        cursor.execute("""
            SELECT dosya_adi FROM DosyaPaylasim
            WHERE paylasilan_kullanici_id = %s
        """, (kullanici_id,))
        paylasilan_dosyalar = [row[0] for row in cursor.fetchall()]
        db.close()

        log_yaz("Dosya Listeleme", f"Kullanıcı ID: {kullanici_id}", "Dosyalar başarıyla listelendi.")
        return dosyalar + paylasilan_dosyalar
    except Exception as e:
        log_yaz("Dosya Listeleme Hatası", f"Kullanıcı ID: {kullanici_id}", f"Hata: {e}")
        return f"Hata: {e}"


def dosya_sil(dosya_adi):
    """Uploads dizinindeki belirtilen dosyayı siler."""
    try:
        hedef_yol = os.path.join(UPLOAD_DIR, dosya_adi)
        if os.path.exists(hedef_yol):
            os.remove(hedef_yol)
            log_yaz("Dosya Silme", "Sistem", f"Dosya silindi: {dosya_adi}")
            return f"{dosya_adi} başarıyla silindi!"
        else:
            log_yaz("Dosya Silme Hatası", "Sistem", f"Dosya bulunamadı: {dosya_adi}")
            return "Dosya bulunamadı."
    except Exception as e:
        log_yaz("Dosya Silme Hatası", "Sistem", f"Dosya: {dosya_adi}, Hata: {e}")
        return f"Hata: {e}"


def dosya_sil_kullanici(dosya_adi, kullanici_id):
    """Kullanıcının dizininden veya paylaşımlarından dosya siler."""
    try:
        kullanici_dizini = kullanici_dizini_olustur(kullanici_id)
        hedef_yol = os.path.join(kullanici_dizini, dosya_adi)

        # Dosya fiziksel olarak kullanıcı dizininden siliniyor.
        if os.path.exists(hedef_yol):
            os.remove(hedef_yol)

        # Veritabanından paylaşım kaydını sil
        db = veritabani_baglantisi()
        cursor = db.cursor()
        cursor.execute("""
            DELETE FROM DosyaPaylasim
            WHERE dosya_adi = %s AND (yukleyen_kullanici_id = %s OR paylasilan_kullanici_id = %s)
        """, (dosya_adi, kullanici_id, kullanici_id))
        db.commit()
        db.close()

        log_yaz("Dosya Silme", f"Kullanıcı ID: {kullanici_id}", f"Dosya silindi: {dosya_adi}")
        return f"{dosya_adi} başarıyla silindi!"
    except Exception as e:
        log_yaz("Dosya Silme Hatası", f"Kullanıcı ID: {kullanici_id}", f"Dosya: {dosya_adi}, Hata: {e}")
        return f"Hata: {e}"


def dosya_paylas(dosya_adi, yukleyen_id, paylasilan_id):
    """Bir dosyayı belirli bir kullanıcıyla paylaşır."""
    try:
        db = veritabani_baglantisi()
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO DosyaPaylasim (dosya_adi, yukleyen_kullanici_id, paylasilan_kullanici_id)
            VALUES (%s, %s, %s)
        """, (dosya_adi, yukleyen_id, paylasilan_id))
        db.commit()
        db.close()
        log_yaz("Dosya Paylaşma", f"Kullanıcı ID: {yukleyen_id}", f"Dosya: {dosya_adi}, Paylaşılan: {paylasilan_id}")
        return f"{dosya_adi} başarıyla paylaşıldı!"
    except Exception as e:
        log_yaz("Dosya Paylaşma Hatası", f"Kullanıcı ID: {yukleyen_id}", f"Dosya: {dosya_adi}, Hata: {e}")
        return f"Hata: {e}"

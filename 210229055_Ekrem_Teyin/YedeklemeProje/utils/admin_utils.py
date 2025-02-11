from tkinter import messagebox
import tkinter as tk
from dbconnection.db_connection import veritabani_baglantisi
from utils.hash_utils import hash_parola
from utils.logs_utils import log_goruntule, log_yaz


def listele_kullanicilar_admin(listbox):
    """Admin için kullanıcıları listele."""
    try:
        db = veritabani_baglantisi()
        cursor = db.cursor()
        cursor.execute("SELECT id, kullanici_adi FROM Kullanici")
        kullanicilar = cursor.fetchall()
        db.close()

        listbox.delete(0, tk.END)  # Önce mevcut listeyi temizle
        for kullanici in kullanicilar:
            listbox.insert(tk.END, f"{kullanici[0]} - {kullanici[1]}")
    except Exception as e:
        messagebox.showerror("Hata", f"Veritabanı hatası: {e}")


def kullanici_guncelle(parent_window, listbox):
    """Kullanıcıyı güncelleme ekranı."""
    secili_kullanici = listbox.get(tk.ACTIVE)
    if not secili_kullanici:
        messagebox.showerror("Hata", "Lütfen bir kullanıcı seçin!")
        return

    kullanici_id = secili_kullanici.split(" - ")[0]

    def guncelle():
        yeni_kullanici_adi = entry_kullanici_adi.get()

        if not yeni_kullanici_adi:
            messagebox.showerror("Hata", "Kullanıcı adı boş bırakılamaz!")
            return

        try:
            db = veritabani_baglantisi()
            cursor = db.cursor()
            cursor.execute("""
                UPDATE Kullanici
                SET kullanici_adi = %s
                WHERE id = %s
            """, (yeni_kullanici_adi, kullanici_id))
            db.commit()
            db.close()

            log_yaz("Kullanıcı Güncelleme", "admin", f"Kullanıcı ID: {kullanici_id} güncellendi.")
            messagebox.showinfo("Başarılı", "Kullanıcı başarıyla güncellendi!")
            guncelle_pencere.destroy()
            listele_kullanicilar_admin(listbox)
        except Exception as e:
            messagebox.showerror("Hata", f"Veritabanı hatası: {e}")

    guncelle_pencere = tk.Toplevel(parent_window)
    guncelle_pencere.title("Kullanıcı Güncelle")

    tk.Label(guncelle_pencere, text="Kullanıcı Adı:").grid(row=0, column=0, padx=10, pady=5)
    entry_kullanici_adi = tk.Entry(guncelle_pencere)
    entry_kullanici_adi.grid(row=0, column=1, padx=10, pady=5)

    tk.Button(guncelle_pencere, text="Güncelle", command=guncelle).grid(row=1, column=0, columnspan=2, pady=10)


def listele_parola_talepleri(listbox):
    """Parola değiştirme taleplerini listele."""
    try:
        db = veritabani_baglantisi()
        cursor = db.cursor()
        cursor.execute("SELECT id, kullanici_adi FROM Kullanici WHERE parola_talebi = 1")
        talepler = cursor.fetchall()
        db.close()

        listbox.delete(0, tk.END)  # Listeyi temizle
        for talep in talepler:
            listbox.insert(tk.END, f"{talep[0]} - {talep[1]}")
    except Exception as e:
        messagebox.showerror("Hata", f"Veritabanı hatası: {e}")


def parola_talebi_onayla(listbox):
    """Parola talebini onayla ve yeni parolayı aktif hale getir."""
    secili_talep = listbox.get(tk.ACTIVE)
    if not secili_talep:
        messagebox.showerror("Hata", "Lütfen bir talep seçin!")
        return

    kullanici_id = secili_talep.split(" - ")[0]

    try:
        db = veritabani_baglantisi()
        cursor = db.cursor()

        # Yeni parolayı al ve aktif hale getir
        cursor.execute("""
            SELECT yeni_parola_hash FROM Kullanici WHERE id = %s AND parola_talebi = 1
        """, (kullanici_id,))
        sonuc = cursor.fetchone()

        if not sonuc:
            messagebox.showerror("Hata", "Geçerli bir parola talebi bulunamadı!")
            db.close()
            return

        yeni_parola_hash = sonuc[0]
        cursor.execute("""
            UPDATE Kullanici
            SET parola_hash = %s, parola_talebi = 0, yeni_parola_hash = NULL
            WHERE id = %s
        """, (yeni_parola_hash, kullanici_id))
        db.commit()
        db.close()

        messagebox.showinfo("Başarılı", "Parola talebi onaylandı ve parola güncellendi!")
        listele_parola_talepleri(listbox)
    except Exception as e:
        messagebox.showerror("Hata", f"Veritabanı hatası: {e}")


def goster_log_dosyalari():
    """Log dosyalarını yeni bir pencere içinde görüntüleme."""
    try:
        loglar = log_goruntule()
        log_pencere = tk.Toplevel()
        log_pencere.title("Log Dosyaları")

        text_area = tk.Text(log_pencere, wrap="word", height=20, width=60)
        text_area.insert(tk.END, "\n".join(loglar))
        text_area.grid(row=0, column=0, padx=10, pady=5)

        log_yaz("Log Görüntüleme", "admin", "Log dosyası görüntülendi")
    except Exception as e:
        messagebox.showerror("Hata", f"Bir hata oluştu: {e}")

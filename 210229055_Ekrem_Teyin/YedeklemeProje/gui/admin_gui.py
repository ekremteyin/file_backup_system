import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from dbconnection.db_connection import veritabani_baglantisi
from utils.admin_utils import listele_kullanicilar_admin, kullanici_guncelle, listele_parola_talepleri, \
    parola_talebi_onayla, goster_log_dosyalari
from utils.logs_utils import log_yaz, log_goruntule
from utils.file_utils import dosyalari_listele_kullanici


def admin_menu():
    """Admin için sadeleştirilmiş ana menü."""
    admin_pencere = tk.Tk()
    admin_pencere.title("Admin Paneli")
    admin_pencere.geometry("900x500")
    admin_pencere.configure(bg="#e8e8e8")

    # Başlık
    tk.Label(
        admin_pencere,
        text="Admin Paneli",
        font=("Arial", 16, "bold"),
        bg="#e8e8e8",
        fg="#333"
    ).pack(pady=10)

    # Üst çerçeve: Kullanıcı Profilleri ve Dosyalar
    ust_frame = tk.Frame(admin_pencere, bg="#e8e8e8")
    ust_frame.pack(pady=5, fill=tk.BOTH, expand=True)

    # Kullanıcı Profilleri Bölümü
    frame_kullanicilar = tk.Frame(ust_frame, bg="#e8e8e8", bd=2, relief=tk.GROOVE)
    frame_kullanicilar.pack(side=tk.LEFT, padx=10, fill=tk.BOTH, expand=True)

    tk.Label(frame_kullanicilar, text="Kullanıcı Profilleri", font=("Arial", 12, "bold"), bg="#e8e8e8").pack(pady=5)
    kullanici_listbox = tk.Listbox(frame_kullanicilar, width=30, height=15, font=("Arial", 10))
    kullanici_listbox.pack(padx=5, pady=5)
    listele_kullanicilar_admin(kullanici_listbox)

    tk.Button(
        frame_kullanicilar,
        text="Kullanıcıyı Güncelle",
        font=("Arial", 10),
        bg="#4CAF50",
        fg="white",
        command=lambda: kullanici_guncelle(admin_pencere, kullanici_listbox)
    ).pack(pady=5)

    # Kullanıcı Dosyaları Bölümü
    frame_dosyalar = tk.Frame(ust_frame, bg="#e8e8e8", bd=2, relief=tk.GROOVE)
    frame_dosyalar.pack(side=tk.LEFT, padx=10, fill=tk.BOTH, expand=True)

    tk.Label(frame_dosyalar, text="Kullanıcı Dosyaları", font=("Arial", 12, "bold"), bg="#e8e8e8").pack(pady=5)
    dosya_listbox = tk.Listbox(frame_dosyalar, width=30, height=15, font=("Arial", 10))
    dosya_listbox.pack(padx=5, pady=5)

    tk.Button(
        frame_dosyalar,
        text="Dosyaları Görüntüle",
        font=("Arial", 10),
        bg="#4CAF50",
        fg="white",
        command=lambda: kullanici_dosyalarini_goster(kullanici_listbox, dosya_listbox)
    ).pack(pady=5)

    # Alt çerçeve: Parola Talepleri ve Loglar
    alt_frame = tk.Frame(admin_pencere, bg="#e8e8e8")
    alt_frame.pack(pady=5, fill=tk.BOTH, expand=True)

    # Parola Talepleri Bölümü
    frame_parola_talepleri = tk.Frame(alt_frame, bg="#e8e8e8", bd=2, relief=tk.GROOVE)
    frame_parola_talepleri.pack(side=tk.LEFT, padx=10, fill=tk.BOTH, expand=True)

    tk.Label(frame_parola_talepleri, text="Parola Talepleri", font=("Arial", 12, "bold"), bg="#e8e8e8").pack(pady=5)
    parola_talep_listbox = tk.Listbox(frame_parola_talepleri, width=30, height=15, font=("Arial", 10))
    parola_talep_listbox.pack(padx=5, pady=5)
    listele_parola_talepleri(parola_talep_listbox)

    tk.Button(
        frame_parola_talepleri,
        text="Talebi Onayla",
        font=("Arial", 10),
        bg="#4CAF50",
        fg="white",
        command=lambda: parola_talebi_onayla(parola_talep_listbox)
    ).pack(pady=5)

    # Log Dosyaları Bölümü
    frame_loglar = tk.Frame(alt_frame, bg="#e8e8e8", bd=2, relief=tk.GROOVE)
    frame_loglar.pack(side=tk.LEFT, padx=10, fill=tk.BOTH, expand=True)

    tk.Label(frame_loglar, text="Log Dosyaları", font=("Arial", 12, "bold"), bg="#e8e8e8").pack(pady=5)
    log_listbox = tk.Listbox(frame_loglar, width=60, height=15, font=("Arial", 10))
    log_listbox.pack(padx=5, pady=5)

    tk.Button(
        frame_loglar,
        text="Logları Görüntüle",
        font=("Arial", 10),
        bg="#4CAF50",
        fg="white",
        command=lambda: loglari_goster(log_listbox)
    ).pack(pady=5)

    admin_pencere.mainloop()


def kullanici_dosyalarini_goster(kullanici_listbox, dosya_listbox):
    """Seçilen kullanıcının dosyalarını listeler."""
    secili_kullanici = kullanici_listbox.get(tk.ACTIVE)
    if not secili_kullanici:
        messagebox.showerror("Hata", "Lütfen bir kullanıcı seçin!")
        return

    kullanici_id = secili_kullanici.split(" - ")[0]
    try:
        dosyalar = dosyalari_listele_kullanici(kullanici_id)
        dosya_listbox.delete(0, tk.END)
        if isinstance(dosyalar, list):
            for dosya in dosyalar:
                dosya_listbox.insert(tk.END, dosya)
            log_yaz("Dosya Görüntüleme", "admin", f"Kullanıcı ID: {kullanici_id} dosyaları görüntülendi.")
        else:
            messagebox.showerror("Hata", dosyalar)
    except Exception as e:
        messagebox.showerror("Hata", f"Dosyalar listelenirken hata oluştu: {e}")


def loglari_goster(log_listbox):
    """Log dosyasını admin panelindeki listbox içinde görüntüleme."""
    try:
        log_listbox.delete(0, tk.END)  # Mevcut logları temizle
        loglar = log_goruntule()  # Logları al

        if loglar:
            for line in loglar:
                log_listbox.insert(tk.END, line.strip())
            log_yaz("Log Görüntüleme", "admin", "Log dosyası görüntülendi")
        else:
            log_listbox.insert(tk.END, "Log dosyası boş.")
    except Exception as e:
        messagebox.showerror("Hata", f"Bir hata oluştu: {e}")

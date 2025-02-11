import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, filedialog
from dbconnection.db_connection import veritabani_baglantisi
from gui.admin_gui import admin_menu
from utils.hash_utils import hash_parola
from utils.file_utils import dosya_yukle_kullanici, dosyalari_listele_kullanici, dosya_sil_kullanici, dosya_paylas
from utils.logs_utils import log_yaz
from utils.team_utils import listele_kullanicilar
from utils.file_utils import parola_degistir
from utils.file_utils import parola_talebi_olustur



# Giriş ekranı
import hashlib

def hash_parola(parola):
    """Parolayı SHA-256 ile hashler."""
    return hashlib.sha256(parola.encode()).hexdigest()

# Admin şifre kontrolü için sabit bilgiler
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = hash_parola("123456")  # "123456" şifresinin hashlenmiş hali

def giris_yap():
    """Giriş işlemi."""
    kullanici_adi = entry_kullanici_adi.get()
    parola = entry_parola.get()

    if not (kullanici_adi and parola):
        messagebox.showerror("Hata", "Tüm alanlar doldurulmalıdır!")
        return

    parola_hash = hash_parola(parola)

    if kullanici_adi == ADMIN_USERNAME and parola_hash == ADMIN_PASSWORD_HASH:
        log_yaz(None, ADMIN_USERNAME, "Admin giriş yaptı")
        messagebox.showinfo("Başarılı", "Admin olarak giriş yapıldı!")
        giris_pencere.destroy()
        admin_menu()  # Admin paneline yönlendir
        return

    try:
        db = veritabani_baglantisi()
        cursor = db.cursor()
        cursor.execute(
            "SELECT id, kullanici_adi FROM Kullanici WHERE kullanici_adi = %s AND parola_hash = %s",
            (kullanici_adi, parola_hash)
        )
        sonuc = cursor.fetchone()
        db.close()

        if sonuc:
            kullanici_id, kullanici_adi = sonuc
            log_yaz(kullanici_id, kullanici_adi, "Başarılı giriş")
            messagebox.showinfo("Başarılı", "Giriş başarılı!")
            giris_pencere.destroy()
            ana_menu(kullanici_id, kullanici_adi)
        else:
            log_yaz(None, kullanici_adi, "Başarısız giriş denemesi")
            messagebox.showerror("Hata", "Geçersiz kullanıcı adı veya parola!")
    except Exception as e:
        messagebox.showerror("Hata", f"Veritabanı hatası: {e}")


# Kayıt ekranını aç
def kayit_ekranini_ac():
    giris_pencere.withdraw()  # Giriş penceresini gizle
    kayit_ol_penceresi()

# Kayıt ekranı
def kayit_ol():
    kullanici_adi = entry_kayit_kullanici_adi.get()
    parola = entry_kayit_parola.get()

    if not (kullanici_adi and parola):
        messagebox.showerror("Hata", "Tüm alanlar doldurulmalıdır!")
        return

    parola_hash = hash_parola(parola)

    try:
        db = veritabani_baglantisi()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO Kullanici (kullanici_adi, parola_hash) VALUES (%s, %s)",
            (kullanici_adi, parola_hash)
        )
        db.commit()
        db.close()
        messagebox.showinfo("Başarılı", "Kayıt başarılı!")
        kayit_pencere.destroy()
        giris_pencere.deiconify()  # Giriş penceresini tekrar göster
    except Exception as e:
        messagebox.showerror("Hata", f"Veritabanı hatası: {e}")

def kayit_ol_penceresi():
    global kayit_pencere, entry_kayit_kullanici_adi, entry_kayit_parola

    kayit_pencere = tk.Toplevel()
    kayit_pencere.title("Kayıt Ol")
    kayit_pencere.geometry("400x250")
    kayit_pencere.configure(bg="#f5f5f5")  # Arka plan rengi

    # Başlık
    tk.Label(
        kayit_pencere,
        text="Kayıt Ol",
        font=("Arial", 18, "bold"),
        bg="#f5f5f5",
        fg="#333"
    ).pack(pady=10)

    # Form çerçevesi
    form_frame = tk.Frame(kayit_pencere, bg="#f5f5f5")
    form_frame.pack(pady=10)

    # Kullanıcı adı
    tk.Label(
        form_frame,
        text="Kullanıcı Adı:",
        font=("Arial", 12),
        bg="#f5f5f5"
    ).grid(row=0, column=0, padx=10, pady=5, sticky="w")
    entry_kayit_kullanici_adi = ttk.Entry(form_frame, font=("Arial", 12), width=25)
    entry_kayit_kullanici_adi.grid(row=0, column=1, padx=10, pady=5)

    # Parola
    tk.Label(
        form_frame,
        text="Parola:",
        font=("Arial", 12),
        bg="#f5f5f5"
    ).grid(row=1, column=0, padx=10, pady=5, sticky="w")
    entry_kayit_parola = ttk.Entry(form_frame, font=("Arial", 12), width=25, show="*")
    entry_kayit_parola.grid(row=1, column=1, padx=10, pady=5)

    # Butonlar
    button_frame = tk.Frame(kayit_pencere, bg="#f5f5f5")
    button_frame.pack(pady=10)

    ttk.Button(
        button_frame,
        text="Kayıt Ol",
        command=kayit_ol,
        style="Accent.TButton"
    ).grid(row=0, column=0, padx=10, pady=10)

    ttk.Button(
        button_frame,
        text="Geri Dön",
        command=lambda: kayit_pencere.destroy(),  # Kayıt penceresini kapat
        style="TButton"
    ).grid(row=0, column=1, padx=10, pady=10)

# Stil ayarları
style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", font=("Arial", 12), padding=6)
style.configure("Accent.TButton", font=("Arial", 12, "bold"), background="#4caf50", foreground="white")

def dosya_yukle_arayuz(kullanici_id):
    dosya_yolu = filedialog.askopenfilename()
    if not dosya_yolu:
        return

    sonuc = dosya_yukle_kullanici(dosya_yolu, kullanici_id)
    if "başarıyla" in sonuc:
        messagebox.showinfo("Başarılı", sonuc)
        dosyalari_listele_arayuz(kullanici_id)
    else:
        messagebox.showerror("Hata", sonuc)

def dosyalari_listele_arayuz(kullanici_id):
    listbox.delete(0, tk.END)
    dosyalar = dosyalari_listele_kullanici(kullanici_id)
    if isinstance(dosyalar, list):
        for dosya in dosyalar:
            listbox.insert(tk.END, dosya)
    else:
        messagebox.showerror("Hata", dosyalar)

def dosya_sil_arayuz(kullanici_id):
    secili_dosya = listbox.get(tk.ACTIVE)
    if not secili_dosya:
        messagebox.showerror("Hata", "Lütfen silmek için bir dosya seçin!")
        return

    sonuc = dosya_sil_kullanici(secili_dosya, kullanici_id)
    if "başarıyla" in sonuc:
        messagebox.showinfo("Başarılı", sonuc)
        dosyalari_listele_arayuz(kullanici_id)  # Listeyi güncelle
    else:
        messagebox.showerror("Hata", sonuc)


def dosya_paylas_arayuz(kullanici_id):
    """Dosya paylaşma arayüzü."""
    def paylas():
        secili_kullanici = kullanici_listbox.get(tk.ACTIVE)
        secili_dosya = dosya_listbox.get(tk.ACTIVE)

        if not secili_kullanici or not secili_dosya:
            messagebox.showerror("Hata", "Lütfen bir kullanıcı ve dosya seçin!")
            return

        paylasilan_id = secili_kullanici.split(" - ")[0]  # Kullanıcı ID'yi al
        sonuc = dosya_paylas(secili_dosya, kullanici_id, paylasilan_id)

        if "başarıyla" in sonuc:
            messagebox.showinfo("Başarılı", sonuc)
        else:
            messagebox.showerror("Hata", sonuc)

    # Yeni pencere
    paylas_pencere = tk.Toplevel()
    paylas_pencere.title("Dosya Paylaş")
    paylas_pencere.geometry("700x400")
    paylas_pencere.configure(bg="#f5f5f5")

    # Başlık
    tk.Label(
        paylas_pencere,
        text="Dosya Paylaş",
        font=("Arial", 18, "bold"),
        bg="#f5f5f5",
        fg="#333"
    ).pack(pady=10)

    # Kullanıcılar ve Dosyalar çerçevesi
    frame = tk.Frame(paylas_pencere, bg="#f5f5f5")
    frame.pack(padx=20, pady=10, fill="both", expand=True)

    # Kullanıcılar Listesi
    tk.Label(
        frame,
        text="Kullanıcılar:",
        font=("Arial", 14),
        bg="#f5f5f5"
    ).grid(row=0, column=0, padx=10, pady=5, sticky="w")

    kullanici_listbox = tk.Listbox(frame, width=30, height=15, font=("Arial", 12), selectmode=tk.SINGLE, bd=1, relief="solid")
    kullanici_listbox.grid(row=1, column=0, padx=10, pady=5)

    listele_kullanicilar(kullanici_listbox)  # Kullanıcıları listele

    # Dosyalar Listesi
    tk.Label(
        frame,
        text="Dosyalar:",
        font=("Arial", 14),
        bg="#f5f5f5"
    ).grid(row=0, column=1, padx=10, pady=5, sticky="w")

    dosya_listbox = tk.Listbox(frame, width=50, height=15, font=("Arial", 12), selectmode=tk.SINGLE, bd=1, relief="solid")
    dosya_listbox.grid(row=1, column=1, padx=10, pady=5)

    dosyalar = dosyalari_listele_kullanici(kullanici_id)  # Kullanıcının dosyalarını listele
    for dosya in dosyalar:
        dosya_listbox.insert(tk.END, dosya)

    # Paylaş Butonu
    button_frame = tk.Frame(paylas_pencere, bg="#f5f5f5")
    button_frame.pack(pady=20)

    ttk.Button(
        button_frame,
        text="Paylaş",
        command=paylas,
        style="Accent.TButton"
    ).grid(row=0, column=0, padx=10, pady=5)

    ttk.Button(
        button_frame,
        text="Kapat",
        command=paylas_pencere.destroy
    ).grid(row=0, column=1, padx=10, pady=5)

# Ana Menü


def ana_menu(kullanici_id, kullanici_adi):
    global listbox

    # Ana pencereyi oluştur
    ana_pencere = tk.Tk()
    ana_pencere.title(f"Hoşgeldiniz, {kullanici_adi}!")
    ana_pencere.geometry("600x400")  # Pencere boyutunu belirle
    ana_pencere.config(bg="#f4f4f4")  # Arka plan rengini açık gri yap

    # Başlık etiketini ekle
    tk.Label(ana_pencere, text="Yüklenen ve Paylaşılan Dosyalar", font=("Arial", 14, "bold"), bg="#f4f4f4").grid(row=0, column=0, padx=10, pady=10, sticky="w")

    # Dosya listesi için Listbox
    listbox = tk.Listbox(ana_pencere, width=50, height=10, font=("Arial", 12), bd=1, relief="solid", selectmode=tk.SINGLE)
    listbox.grid(row=1, column=0, columnspan=3, padx=20, pady=10)

    # Dosyaları listele
    dosyalari_listele_arayuz(kullanici_id)

    # İşlem Butonları
    button_font = ("Arial", 12)
    button_bg = "#4CAF50"  # Yeşil arka plan
    button_fg = "white"  # Beyaz metin rengi

    tk.Button(ana_pencere, text="Dosya Yükle", font=button_font, bg=button_bg, fg=button_fg, command=lambda: dosya_yukle_arayuz(kullanici_id)).grid(row=2, column=0, padx=20, pady=15, ipadx=20, sticky="ew")
    tk.Button(ana_pencere, text="Dosya Sil", font=button_font, bg=button_bg, fg=button_fg, command=lambda: dosya_sil_arayuz(kullanici_id)).grid(row=2, column=1, padx=20, pady=15, ipadx=20, sticky="ew")
    tk.Button(ana_pencere, text="Dosya Paylaş", font=button_font, bg=button_bg, fg=button_fg, command=lambda: dosya_paylas_arayuz(kullanici_id)).grid(row=2, column=2, padx=20, pady=15, ipadx=20, sticky="ew")

    # Parola değiştir butonu
    tk.Button(ana_pencere, text="Parola Değiştir", font=button_font, bg="#FF9800", fg="white", command=lambda: parola_degistir_talebi(kullanici_id)).grid(row=3, column=0, columnspan=3, pady=20, ipadx=20)

    # Ana pencereyi başlat
    ana_pencere.mainloop()



def giris_penceresi():
    global giris_pencere, entry_kullanici_adi, entry_parola

    # Ana pencere
    giris_pencere = tk.Tk()
    giris_pencere.title("Giriş Yap")
    giris_pencere.geometry("400x250")
    giris_pencere.configure(bg="#f5f5f5")  # Arka plan rengi

    # Başlık
    tk.Label(
        giris_pencere,
        text="Hoşgeldiniz",
        font=("Arial", 18, "bold"),
        bg="#f5f5f5",
        fg="#333"
    ).pack(pady=10)

    # Form çerçevesi
    form_frame = tk.Frame(giris_pencere, bg="#f5f5f5")
    form_frame.pack(pady=10)

    # Kullanıcı adı
    tk.Label(
        form_frame,
        text="Kullanıcı Adı:",
        font=("Arial", 12),
        bg="#f5f5f5"
    ).grid(row=0, column=0, padx=10, pady=5, sticky="w")
    entry_kullanici_adi = ttk.Entry(form_frame, font=("Arial", 12), width=25)
    entry_kullanici_adi.grid(row=0, column=1, padx=10, pady=5)

    # Parola
    tk.Label(
        form_frame,
        text="Parola:",
        font=("Arial", 12),
        bg="#f5f5f5"
    ).grid(row=1, column=0, padx=10, pady=5, sticky="w")
    entry_parola = ttk.Entry(form_frame, font=("Arial", 12), width=25, show="*")
    entry_parola.grid(row=1, column=1, padx=10, pady=5)

    # Butonlar
    button_frame = tk.Frame(giris_pencere, bg="#f5f5f5")
    button_frame.pack(pady=10)

    ttk.Button(
        button_frame,
        text="Giriş Yap",
        command=giris_yap,
        style="Accent.TButton"
    ).grid(row=0, column=0, padx=10, pady=10)

    ttk.Button(
        button_frame,
        text="Kayıt Ol",
        command=kayit_ekranini_ac
    ).grid(row=0, column=1, padx=10, pady=10)

    giris_pencere.mainloop()


# Stil ayarları
style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", font=("Arial", 12), padding=6)
style.configure("Accent.TButton", font=("Arial", 12, "bold"), background="#4caf50", foreground="white")


def parola_degistir_arayuz(kullanici_id):
    """Parola değiştirme talebi arayüzü."""
    def talep_olustur():
        mevcut_parola = entry_mevcut_parola.get()

        if not mevcut_parola:
            messagebox.showerror("Hata", "Mevcut parolayı girin!")
            return

        mevcut_parola_hash = hash_parola(mevcut_parola)
        try:
            db = veritabani_baglantisi()
            cursor = db.cursor()
            cursor.execute("""
                SELECT parola_hash FROM Kullanici WHERE id = %s
            """, (kullanici_id,))
            sonuc = cursor.fetchone()
            db.close()

            if not sonuc or sonuc[0] != mevcut_parola_hash:
                messagebox.showerror("Hata", "Mevcut parola yanlış!")
                return

            # Parola değiştirme talebi oluştur
            sonuc = parola_talebi_olustur(kullanici_id)
            if "başarıyla" in sonuc:
                messagebox.showinfo("Başarılı", sonuc)
                talep_pencere.destroy()
            else:
                messagebox.showerror("Hata", sonuc)
        except Exception as e:
            messagebox.showerror("Hata", f"Veritabanı hatası: {e}")

    talep_pencere = tk.Toplevel()
    talep_pencere.title("Parola Değiştirme Talebi")

    tk.Label(talep_pencere, text="Mevcut Parola:").grid(row=0, column=0, padx=10, pady=5)
    entry_mevcut_parola = tk.Entry(talep_pencere, show="*")
    entry_mevcut_parola.grid(row=0, column=1, padx=10, pady=5)

    tk.Button(talep_pencere, text="Talep Oluştur", command=talep_olustur).grid(row=1, column=0, columnspan=2, pady=10)
def parola_degistir_talebi(kullanici_id):
    """Kullanıcı parola değiştirme talebi oluşturur."""
    def talep_olustur():
        mevcut_parola = entry_mevcut_parola.get()
        yeni_parola = entry_yeni_parola.get()

        if not mevcut_parola or not yeni_parola:
            messagebox.showerror("Hata", "Lütfen tüm alanları doldurun!")
            return

        try:
            # Mevcut parolayı doğrula
            mevcut_parola_hash = hash_parola(mevcut_parola)
            db = veritabani_baglantisi()
            cursor = db.cursor()
            cursor.execute("""
                SELECT id FROM Kullanici WHERE id = %s AND parola_hash = %s
            """, (kullanici_id, mevcut_parola_hash))
            sonuc = cursor.fetchone()

            if not sonuc:
                messagebox.showerror("Hata", "Mevcut parolanız yanlış!")
                db.close()
                return

            # Talebi ve yeni parolayı veritabanına kaydet
            yeni_parola_hash = hash_parola(yeni_parola)
            cursor.execute("""
                UPDATE Kullanici
                SET parola_talebi = 1, yeni_parola_hash = %s
                WHERE id = %s
            """, (yeni_parola_hash, kullanici_id))
            db.commit()
            db.close()

            messagebox.showinfo("Başarılı", "Parola değiştirme talebiniz oluşturuldu. Adminin onaylamasını bekleyin.")
            talep_pencere.destroy()
        except Exception as e:
            messagebox.showerror("Hata", f"Veritabanı hatası: {e}")

    # Kullanıcı parola değiştirme ekranı
    talep_pencere = tk.Toplevel()
    talep_pencere.title("Parola Değiştirme Talebi")

    tk.Label(talep_pencere, text="Mevcut Parola:").grid(row=0, column=0, padx=10, pady=5)
    entry_mevcut_parola = tk.Entry(talep_pencere, show="*")
    entry_mevcut_parola.grid(row=0, column=1, padx=10, pady=5)

    tk.Label(talep_pencere, text="Yeni Parola:").grid(row=1, column=0, padx=10, pady=5)
    entry_yeni_parola = tk.Entry(talep_pencere, show="*")
    entry_yeni_parola.grid(row=1, column=1, padx=10, pady=5)

    tk.Button(talep_pencere, text="Talep Oluştur", command=talep_olustur).grid(row=2, column=0, columnspan=2, pady=10)


def main():
    giris_penceresi()

if __name__ == "__main__":
      main()


if __name__ == "__main__":
    giris_penceresi()

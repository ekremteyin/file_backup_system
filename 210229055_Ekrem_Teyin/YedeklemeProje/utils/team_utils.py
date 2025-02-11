from tkinter import messagebox
from dbconnection.db_connection import veritabani_baglantisi

def listele_kullanicilar(listbox_kullanici_listesi):
    try:
        db = veritabani_baglantisi()
        cursor = db.cursor()
        cursor.execute("SELECT id, kullanici_adi FROM kullanici")
        kullanicilar = cursor.fetchall()
        db.close()

        listbox_kullanici_listesi.delete(0, "end")  # Mevcut listeyi temizle
        for kullanici in kullanicilar:
            listbox_kullanici_listesi.insert("end", f"{kullanici[0]} - {kullanici[1]}")
    except Exception as e:
        messagebox.showerror("Hata", f"Veritabanı hatası: {e}")



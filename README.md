# 🗂️ Dosya Yedekleme ve Paylaşım Sistemi

Bu proje, Python ve Tkinter kullanılarak geliştirilmiş bir **dosya yedekleme, paylaşım ve kullanıcı yönetim** uygulamasıdır. Amaç, kullanıcıların güvenli şekilde dosya yüklemesi, yönetmesi, silmesi, parola korumalı paylaşım yapabilmesi ve tüm bu işlemlerin loglanmasıdır.

---

## 🚀 Özellikler

- 🧑‍💻 **Kullanıcı ve Admin Giriş Paneli**
  - Admin için sabit kimlik bilgileri ile giriş
  - Kullanıcılar için veritabanı tabanlı giriş doğrulama

- 🗃️ **Dosya Yükleme ve Yönetim**
  - Dosya yükleme (GUI üzerinden)
  - Yedekleme klasöründe saklama
  - Dosya listeleme, silme ve log kaydı

- 🔐 **Parola Korumalı Dosya Paylaşımı**
  - Paylaşılan dosyalar için parola belirleme
  - Dosya erişimi sadece doğru parolayla sağlanır

- 🧾 **Loglama Sistemi**
  - Yapılan tüm işlemler (`giriş`, `dosya yükleme`, `silme`, `paylaşım`) `logs` klasöründe saklanır

- 🔄 **Parola Güncelleme ve Talep Yönetimi**
  - Kullanıcı parolası güncellenebilir
  - Parola sıfırlama talebi oluşturulabilir

- 👥 **Kullanıcı Listesi**
  - Admin panelinde tüm kullanıcıları listeleme özelliği

---

## 🛠️ Kullanılan Teknolojiler

| Teknoloji | Açıklama                     |
|-----------|------------------------------|
| Python    | Uygulama dili                |
| Tkinter   | Grafiksel kullanıcı arayüzü |
| MSSQL    | Hafif veritabanı            |
| Hashlib   | SHA-256 parola şifreleme    |
| Logging   | İşlem loglama                |

---

## 🏁 Kurulum

```bash
git clone https://github.com/kullanici_adiniz/proje-adi.git
cd proje-adi/YedeklemeProje
python -m venv .venv
# Windows için:
.venv\Scripts\activate
# Linux/macOS için:
source .venv/bin/activate
pip install -r requirements.txt
python main.py

import mysql.connector

def veritabani_baglantisi():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="123456",  # MySQL şifreniz
        database="kullanicisistemi"
    )

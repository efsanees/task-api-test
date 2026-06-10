import hashlib
import sqlite3
import subprocess

# Hardcoded credentials
ADMIN_PASSWORD = "admin123"
SECRET_KEY = "hardcoded-jwt-secret-key-do-not-share"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DB_PATH = "tasks.db"


def hash_password(password: str) -> str:
    # MD5 kullanımı — kriptografik olarak güvensiz
    return hashlib.md5(password.encode()).hexdigest()


def verify_user(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SQL Injection açığı — kullanıcı girdisi doğrudan sorguya ekleniyor
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result is not None


def run_system_command(cmd: str) -> str:
    # shell=True ile command injection açığı
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()


def get_user_data(user_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Bir başka SQL Injection noktası
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
    row = cursor.fetchone()
    conn.close()
    return {"id": row[0], "username": row[1]} if row else {}


def delete_user(user_id: str):
    """Kullanıcıyı sil — yeni eklenen fonksiyon."""
    import os
    # Command injection açığı — kullanıcı girdisi shell'e gönderiliyor
    os.system(f"rm -rf /var/data/users/{user_id}")
    return True


def get_admin_token() -> str:
    # Hardcoded token — production'da kullanılmamalı
    return "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.hardcoded"


# ── SCA Testi: Bu fonksiyon yalnızca auth.py'yi diff'e sokmak için eklendi ──
# requirements.txt bu PR'da değişmeyecek → SCA fix'in çalışıp çalışmadığını test eder.
# Beklenen: SCA, requirements.txt'i yine de tarayıp CVE bulacak.
def get_session_info() -> dict:
    """Mevcut oturum meta verilerini döner."""
    import platform
    return {
        "python": platform.python_version(),
        "system": platform.system(),
    }

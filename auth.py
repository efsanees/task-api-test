import hashlib
import sqlite3
import subprocess
import os
import pickle
import yaml

# ============================================================
# HARDCODED CREDENTIALS — Secret Detection (Gitleaks) bulacak
# ============================================================
ADMIN_PASSWORD = "admin123"
SECRET_KEY = "hardcoded-jwt-secret-key-do-not-share"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae298v54dE"
STRIPE_SECRET_KEY = "sk_test_DEMO_KEY_NOT_REAL_xxxxxxxxxxx"

DB_PATH = "tasks.db"


# ============================================================
# SAST — Bandit B324: Weak hash (MD5)
# ============================================================
def hash_password(password: str) -> str:
    # MD5 kullanımı — kriptografik olarak güvensiz (CWE-327)
    return hashlib.md5(password.encode()).hexdigest()


def hash_token(token: str) -> str:
    # SHA1 de güvensiz kabul edilir (CWE-327)
    return hashlib.sha1(token.encode()).hexdigest()


# ============================================================
# SAST — SQL Injection (CWE-89)
# ============================================================
def verify_user(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SQL Injection açığı — kullanıcı girdisi doğrudan sorguya ekleniyor
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result is not None


def get_user_data(user_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Bir başka SQL Injection noktası (CWE-89)
    cursor.execute("SELECT * FROM users WHERE id=" + user_id)
    row = cursor.fetchone()
    conn.close()
    return {"id": row[0], "username": row[1]} if row else {}


# ============================================================
# SAST — Bandit B602/B605: subprocess shell=True (CWE-78)
# ============================================================
def run_system_command(cmd: str) -> str:
    # shell=True ile command injection açığı (CWE-78)
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()


def run_ping(host: str) -> str:
    # Kullanıcı girdisi doğrudan shell'e gidiyor
    result = subprocess.Popen(f"ping -c 1 {host}", shell=True, stdout=subprocess.PIPE)
    return result.stdout.read().decode()


# ============================================================
# SAST — Bandit B605: os.system injection (CWE-78)
# ============================================================
def delete_user(user_id: str):
    """Kullanıcıyı sil — yeni eklenen fonksiyon."""
    # Command injection açığı — kullanıcı girdisi shell'e gönderiliyor
    os.system(f"rm -rf /var/data/users/{user_id}")
    return True


def backup_logs(log_path: str):
    """Log dosyasını yedekle."""
    # Başka bir os.system injection noktası
    os.system(f"cp {log_path} /backup/logs/")


# ============================================================
# SAST — Bandit B301: pickle.loads güvensiz deserialization
# ============================================================
def load_session(session_data: bytes) -> dict:
    # Güvensiz deserialization — arbitrary code execution riski (CWE-502)
    return pickle.loads(session_data)


# ============================================================
# SAST — Bandit B506: yaml.load güvensiz kullanım
# ============================================================
def load_config(config_str: str) -> dict:
    # yaml.load Loader belirtilmeden kullanılıyor — güvensiz (CWE-20)
    return yaml.load(config_str)


# ============================================================
# Hardcoded token — Secret Detection bulacak
# ============================================================
def get_admin_token() -> str:
    # Hardcoded token — production'da kullanılmamalı
    return "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.hardcoded"


# ============================================================
# TEST — yeni eklenen fonksiyon (PR yorum özelliğini test eder)
# ============================================================
def reset_user_password(username: str) -> str:
    # Güvensiz: kullanıcı girdisi shell'e gidiyor (CWE-78)
    os.system(f"echo 'Password reset for {username}' >> /var/log/auth.log")
    # Güvensiz: MD5 ile geçici şifre üretiliyor (CWE-327)
    temp_pass = hashlib.md5(username.encode()).hexdigest()[:8]
    return temp_pass

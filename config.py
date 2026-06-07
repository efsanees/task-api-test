"""
config.py — Uygulama konfigürasyonu
UYARI: Bu dosya demo amaçlıdır, production'da kullanmayın!
"""

# ============================================================
# HARDCODED SECRETS — Gitleaks tüm bunları bulacak
# ============================================================

# Database bağlantı bilgileri — plaintext credential
DATABASE_URL = "postgresql://admin:SuperSecret123@prod-db.company.com:5432/taskdb"

# AWS Credentials (demo/fake values)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"
S3_BUCKET = "company-prod-backups"

# Payment Keys (demo values)
STRIPE_PUBLISHABLE_KEY = "pk_test_DEMO_NOT_REAL_xxxxxxxxxxxxxxxxx"
STRIPE_SECRET_KEY = "sk_test_DEMO_NOT_REAL_xxxxxxxxxxxxxxxxxx"

# Email API (fake/invalidated)
SENDGRID_API_KEY = "SG.DEMO_KEY_NOT_REAL.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# Slack Webhook (fake)
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/TXXXXXXXX/BXXXXXXXX/DEMO_FAKE_WEBHOOK_KEY"

# JWT
JWT_SECRET = "my-super-secret-jwt-key-never-expose"
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30

# Redis
REDIS_URL = "redis://:redis_password_123@prod-redis.company.com:6379"

# ============================================================
# Debug mode production'da açık bırakılmış
# ============================================================
DEBUG = True
TESTING = True
LOG_LEVEL = "DEBUG"

# ============================================================
# CORS — tüm originlere izin veriliyor (güvensiz)
# ============================================================
ALLOWED_ORIGINS = ["*"]
ALLOWED_METHODS = ["*"]
ALLOWED_HEADERS = ["*"]

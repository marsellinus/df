"""
Configuration module untuk Forensic Research Project
"""
import os
from pathlib import Path
from datetime import datetime

# ============ PATHS ============
BASE_DIR = Path(__file__).parent.parent
LOG_DIR = BASE_DIR / 'logs'
DATA_DIR = BASE_DIR / 'data'
SCRIPT_DIR = BASE_DIR / 'scripts'
ANALYSIS_DIR = BASE_DIR / 'analysis'

# Ensure directories exist
LOG_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

# ============ MinIO CONFIGURATION ============
MINIO_ENDPOINT = os.getenv('MINIO_ENDPOINT', 'http://minio:9000')
MINIO_ACCESS_KEY = os.getenv('MINIO_ACCESS_KEY', 'minioadmin')
MINIO_SECRET_KEY = os.getenv('MINIO_SECRET_KEY', 'minioadmin')
MINIO_BUCKET = os.getenv('MINIO_BUCKET', 'foresc')
MINIO_SECURE = os.getenv('MINIO_SECURE', 'false').lower() == 'true'

# ============ DATABASE CONFIGURATION ============
DB_PATH = DATA_DIR / 'forensic.db'
DB_TYPE = 'sqlite3'  # or 'elasticsearch'

# ============ LOG CONFIGURATION ============
MINIO_AUDIT_LOG = LOG_DIR / 'minio_audit.log'
PARSED_LOG_FILE = DATA_DIR / 'parsed_logs.json'
PARSED_CSV_FILE = DATA_DIR / 'access_logs.csv'

# ============ LOGGING FORMAT ============
LOG_FORMAT = '[%(asctime)s] %(levelname)s - %(name)s - %(message)s'
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# ============ FORENSIC ANALYSIS CONFIG ============
# Threshold untuk deteksi anomali
ANOMALY_THRESHOLDS = {
    'bulk_download_count': 5,        # Jumlah file download dalam 1 jam = anomali
    'bulk_download_size_mb': 500,    # Total size dalam 1 jam
    'access_time_window': 3600,      # seconds (1 jam)
    'unusual_hours_start': '18:00',  # Luar jam kerja: 18:00 - 06:00
    'unusual_hours_end': '06:00',
    'ip_change_threshold': 3,        # IP berbeda dalam short timeframe
}

# ============ ATTACK SIMULATION CONFIG ============
ATTACKER_USERS = {
    'attacker1': 'attacker1_pass_123',
    'attacker2': 'attacker2_pass_456',
}

NORMAL_USERS = {
    'user1': 'pass1',
    'user2': 'pass2',
    'user3': 'pass3',
}

# ============ SIMULATION PARAMETERS ============
NORMAL_FILE_SIZE_KB = 100  # Typical file size untuk normal operations
SENSITIVE_FILES = [
    'financial_report_2024.xlsx',
    'technical_architecture.pdf',
    'customer_database.csv',
    'api_keys.txt',
    'private_certificates.pem',
    'hr_records_2024.xlsx',
    'source_code_backup.zip',
]

# ============ SERVICES PORT ============
LOG_COLLECTOR_PORT = 5000
ANALYZER_PORT = 5001
DASHBOARD_PORT = 5002

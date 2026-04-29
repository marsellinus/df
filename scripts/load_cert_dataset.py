#!/usr/bin/env python3
"""
load_cert_dataset.py - Load CERT Insider Threat Dataset ke forensic pipeline.

Dataset publik: CMU CERT Insider Threat Dataset r4.2
Sumber: https://kilthub.cmu.edu/articles/dataset/CERT_Insider_Threat_Dataset/12841247

Cara pakai:
  # Gunakan sample data bawaan (tanpa download):
  python scripts/load_cert_dataset.py --sample

  # Pakai file CSV asli dari CERT (setelah download manual):
  python scripts/load_cert_dataset.py --file path/to/file.csv --type logon
  python scripts/load_cert_dataset.py --file path/to/device.csv --type device
  python scripts/load_cert_dataset.py --file path/to/http.csv --type http

File CSV yang tersedia di dataset CERT r4.2:
  logon.csv   - login/logout events
  device.csv  - USB/removable device events
  http.csv    - web browsing events
  email.csv   - email events
  file.csv    - file access events (paling relevan untuk eksfiltrasi)
"""

import csv
import sys
import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from analysis.log_parser import ingest_log_file
from config.config import DATA_DIR


# ── Sample data generator ─────────────────────────────────────────────────────

def generate_cert_sample(out_path: Path):
    """
    Generate sample CERT-style file.csv dengan skenario insider threat:
    - User normal: akses file sporadis
    - Insider (ACM2278): bulk download file sensitif sebelum resign
    """
    random.seed(42)
    base_time = datetime(2010, 1, 4, 8, 0, 0)

    users = {
        'TGT-ACM2278': {'ip': '192.168.1.45', 'malicious': True},
        'TGT-BDK0391': {'ip': '192.168.1.12', 'malicious': False},
        'TGT-CJL1847': {'ip': '192.168.1.78', 'malicious': False},
        'TGT-DPM0562': {'ip': '192.168.1.33', 'malicious': False},
    }

    sensitive = [
        'C:/Users/ACM2278/Documents/financial_report_Q4.xlsx',
        'C:/Users/ACM2278/Documents/customer_database_export.csv',
        'C:/Users/ACM2278/Documents/api_credentials.txt',
        'C:/Users/ACM2278/Documents/architecture_diagram.pdf',
        'C:/Users/ACM2278/Documents/hr_salary_records.xlsx',
        'C:/Users/ACM2278/Documents/source_code_backup.zip',
        'C:/Users/ACM2278/Documents/private_keys.pem',
    ]
    normal_files = [
        'C:/Users/{u}/Documents/meeting_notes.docx',
        'C:/Users/{u}/Documents/project_plan.xlsx',
        'C:/Users/{u}/Desktop/presentation.pptx',
        'C:/Users/{u}/Documents/report_draft.docx',
    ]

    rows = []
    t = base_time

    # Normal activity for all users (2 weeks)
    for day in range(14):
        for uid, info in users.items():
            short = uid.split('-')[1]
            # 3-8 file accesses per day
            for _ in range(random.randint(3, 8)):
                t = base_time + timedelta(days=day, hours=random.randint(8, 17),
                                          minutes=random.randint(0, 59))
                fname = random.choice(normal_files).format(u=short)
                rows.append({
                    'id': f'F{len(rows)+1:06d}',
                    'date': t.strftime('%m/%d/%Y %H:%M:%S'),
                    'user': uid,
                    'pc': f'PC-{short}',
                    'filename': fname,
                    'activity': random.choice(['Open', 'Write', 'Copy']),
                    'to_removable_media': 'False',
                    'from_removable_media': 'False',
                    'content': '',
                })

    # Malicious insider: bulk exfiltration on day 13 (off-hours)
    insider = 'TGT-ACM2278'
    for i, fname in enumerate(sensitive):
        t = base_time + timedelta(days=13, hours=22, minutes=i * 3)
        rows.append({
            'id': f'F{len(rows)+1:06d}',
            'date': t.strftime('%m/%d/%Y %H:%M:%S'),
            'user': insider,
            'pc': 'PC-ACM2278',
            'filename': fname,
            'activity': 'Copy',
            'to_removable_media': 'True',
            'from_removable_media': 'False',
            'content': '',
        })

    # Also add multi-IP logon for insider (from home IP)
    for i in range(3):
        t = base_time + timedelta(days=12, hours=23, minutes=i * 10)
        rows.append({
            'id': f'F{len(rows)+1:06d}',
            'date': t.strftime('%m/%d/%Y %H:%M:%S'),
            'user': insider,
            'pc': 'PC-HOME',
            'filename': sensitive[i],
            'activity': 'Open',
            'to_removable_media': 'False',
            'from_removable_media': 'False',
            'content': '',
        })

    rows.sort(key=lambda r: r['date'])

    with open(out_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['id', 'date', 'user', 'pc',
                                               'filename', 'activity',
                                               'to_removable_media',
                                               'from_removable_media', 'content'])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Sample dataset dibuat: {out_path} ({len(rows)} records)")
    return out_path


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Load CERT Insider Threat Dataset')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--sample', action='store_true',
                       help='Generate & ingest sample CERT dataset')
    group.add_argument('--file', metavar='CSV',
                       help='Path ke file CSV dari dataset CERT asli')
    parser.add_argument('--type', choices=['file', 'logon', 'device', 'http'],
                        default='file', help='Tipe CSV (default: file)')
    args = parser.parse_args()

    if args.sample:
        csv_path = DATA_DIR / 'cert_sample.csv'
        generate_cert_sample(csv_path)
        count = ingest_log_file(csv_path)
        print(f"Ingested {count} records ke forensic pipeline.")
        print("Jalankan: python main.py --output data/forensic_report.json")
    else:
        csv_path = Path(args.file)
        if not csv_path.exists():
            print(f"ERROR: File tidak ditemukan: {csv_path}")
            sys.exit(1)
        count = ingest_log_file(csv_path)
        print(f"Ingested {count} records dari {csv_path}")
        print("Jalankan: python main.py --output data/forensic_report.json")


if __name__ == '__main__':
    main()

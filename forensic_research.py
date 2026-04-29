#!/usr/bin/env python3
"""
Forensic Research Project - Pure Python Version (No External Dependencies)
Fully functional forensic analysis tool using only standard library
"""

import json
import csv
import sqlite3
import logging
import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Tuple, Set
from collections import defaultdict
import random
import time

# ============ SETUP PATHS ============
BASE_DIR = Path(__file__).parent
LOG_DIR = BASE_DIR / 'logs'
DATA_DIR = BASE_DIR / 'data'

LOG_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

# ============ LOGGING SETUP ============
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'forensic_analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============ CONFIGURATION ============
ANOMALY_THRESHOLDS = {
    'bulk_download_count': 5,
    'bulk_download_size_mb': 500,
    'access_time_window': 3600,
    'ip_change_threshold': 3,
}

SENSITIVE_FILES = [
    'financial_report_2024.xlsx',
    'technical_architecture.pdf',
    'customer_database.csv',
    'api_keys.txt',
    'private_certificates.pem',
]

# ============ DATABASE HELPER ============
class ForensicDB:
    """SQLite database for forensic analysis"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                user_id TEXT,
                source_ip TEXT,
                operation TEXT,
                object_name TEXT,
                file_size INTEGER,
                UNIQUE(timestamp, user_id, operation, object_name)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY,
                detected_at TEXT,
                anomaly_type TEXT,
                severity TEXT,
                user_id TEXT,
                source_ip TEXT,
                description TEXT,
                evidence TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized: {self.db_path}")
    
    def insert_log(self, log_data: Dict) -> bool:
        """Insert access log"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO access_logs 
                (timestamp, user_id, source_ip, operation, object_name, file_size)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                log_data['timestamp'],
                log_data['user_id'],
                log_data['source_ip'],
                log_data['operation'],
                log_data['object_name'],
                log_data.get('file_size', 0)
            ))
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def insert_anomaly(self, anomaly_data: Dict):
        """Insert detected anomaly"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO anomalies 
            (detected_at, anomaly_type, severity, user_id, source_ip, description, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            anomaly_data.get('detected_at', datetime.now().isoformat()),
            anomaly_data['anomaly_type'],
            anomaly_data['severity'],
            anomaly_data['user_id'],
            anomaly_data['source_ip'],
            anomaly_data['description'],
            json.dumps(anomaly_data.get('evidence', {}))
        ))
        conn.commit()
        conn.close()
    
    def get_all_logs(self) -> List[Dict]:
        """Get all access logs"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM access_logs ORDER BY timestamp')
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return logs
    
    def get_anomalies(self) -> List[Dict]:
        """Get all anomalies"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM anomalies ORDER BY detected_at DESC')
        anomalies = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return anomalies

# ============ ANOMALY DETECTOR ============
class AnomalyDetector:
    """Forensic anomaly detection"""
    
    def __init__(self):
        self.db = ForensicDB(DATA_DIR / 'forensic.db')
    
    def detect_bulk_downloads(self, logs: List[Dict]) -> List[Dict]:
        """Detect bulk download patterns"""
        anomalies = []
        user_logs = defaultdict(list)
        
        for log in logs:
            if log['operation'] == 'GET':
                user_logs[log['user_id']].append(log)
        
        for user, user_access in user_logs.items():
            user_access.sort(key=lambda x: x['timestamp'])
            
            for i, log in enumerate(user_access):
                window_start = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                window_end = window_start + timedelta(seconds=ANOMALY_THRESHOLDS['access_time_window'])
                
                window_logs = [
                    l for l in user_access[i:]
                    if datetime.fromisoformat(l['timestamp'].replace('Z', '+00:00')) <= window_end
                ]
                
                file_count = len(window_logs)
                total_size = sum(l.get('file_size', 0) for l in window_logs) / (1024 * 1024)
                
                if file_count >= ANOMALY_THRESHOLDS['bulk_download_count']:
                    anomalies.append({
                        'anomaly_type': 'BULK_DOWNLOAD',
                        'severity': 'HIGH',
                        'user_id': user,
                        'source_ip': log['source_ip'],
                        'timestamp': log['timestamp'],
                        'description': f"Bulk download: {file_count} files, {total_size:.2f} MB",
                        'evidence': {'file_count': file_count, 'total_size_mb': total_size}
                    })
        
        return anomalies
    
    def detect_sensitive_file_access(self, logs: List[Dict]) -> List[Dict]:
        """Detect access to sensitive files"""
        anomalies = []
        
        for log in logs:
            for sensitive in SENSITIVE_FILES:
                if sensitive.lower() in log.get('object_name', '').lower():
                    anomalies.append({
                        'anomaly_type': 'SENSITIVE_FILE_ACCESS',
                        'severity': 'CRITICAL' if log['operation'] == 'GET' else 'HIGH',
                        'user_id': log['user_id'],
                        'source_ip': log['source_ip'],
                        'timestamp': log['timestamp'],
                        'description': f"Access to sensitive file: {log['object_name']}",
                        'evidence': {'file': log['object_name'], 'operation': log['operation']}
                    })
        
        return anomalies
    
    def run_analysis(self, logs: List[Dict]) -> List[Dict]:
        """Run full analysis"""
        all_anomalies = []
        
        logger.info(f"Running analysis on {len(logs)} log entries")
        
        all_anomalies.extend(self.detect_bulk_downloads(logs))
        all_anomalies.extend(self.detect_sensitive_file_access(logs))
        
        # Store anomalies
        for anom in all_anomalies:
            anom['detected_at'] = datetime.now().isoformat()
            self.db.insert_anomaly(anom)
        
        logger.info(f"Detected {len(all_anomalies)} anomalies")
        return all_anomalies

# ============ ATTACK SIMULATOR ============
class AttackSimulator:
    """Simulate unauthorized data exfiltration"""
    
    def __init__(self):
        self.db = ForensicDB(DATA_DIR / 'forensic.db')
        self.attacker_ips = ['192.168.1.200', '192.168.1.201', '192.168.1.202']
    
    def generate_log_entry(self, user: str, op: str, file: str, size: int, ip: str) -> Dict:
        """Generate log entry"""
        return {
            'timestamp': datetime.now().isoformat() + 'Z',
            'user_id': user,
            'source_ip': ip,
            'operation': op,
            'object_name': file,
            'file_size': size
        }
    
    def run_attack(self, scenario: str = 'full'):
        """Run attack scenario"""
        logger.info(f"Starting {scenario} attack scenario")
        
        if scenario in ['normal', 'full']:
            self._normal_operations()
        
        if scenario in ['bulk_download', 'full']:
            self._bulk_download()
        
        if scenario in ['sensitive', 'full']:
            self._sensitive_access()
        
        logger.info("Attack simulation complete")
    
    def _normal_operations(self):
        """Normal user operations"""
        logger.info("Simulating normal operations")
        for i in range(10):
            user = f"user{random.randint(1, 3)}"
            op = random.choice(['GET', 'PUT'])
            file = f"document_{i}.txt"
            size = random.randint(100, 500) * 1024
            ip = f"192.168.1.{random.randint(100, 150)}"
            
            log = self.generate_log_entry(user, op, file, size, ip)
            self.db.insert_log(log)
    
    def _bulk_download(self):
        """Bulk download attack"""
        logger.info("Simulating bulk download attack")
        for i in range(10):
            log = self.generate_log_entry(
                'attacker1', 'GET',
                SENSITIVE_FILES[i % len(SENSITIVE_FILES)],
                random.randint(10, 50) * 1024 * 1024,
                self.attacker_ips[0]
            )
            self.db.insert_log(log)
    
    def _sensitive_access(self):
        """Sensitive file access"""
        logger.info("Simulating sensitive file access")
        for file in SENSITIVE_FILES[:3]:
            log = self.generate_log_entry(
                'attacker1', 'GET', file,
                random.randint(5, 20) * 1024 * 1024,
                random.choice(self.attacker_ips)
            )
            self.db.insert_log(log)

# ============ REPORT GENERATOR ============
class ReportGenerator:
    """Generate forensic reports"""
    
    def __init__(self):
        self.db = ForensicDB(DATA_DIR / 'forensic.db')
    
    def generate_report(self):
        """Generate comprehensive report"""
        logs = self.db.get_all_logs()
        anomalies = self.db.get_anomalies()
        
        report = {
            'generated': datetime.now().isoformat(),
            'summary': {
                'total_events': len(logs),
                'total_anomalies': len(anomalies),
                'unique_users': len(set(log['user_id'] for log in logs)),
                'unique_ips': len(set(log['source_ip'] for log in logs))
            },
            'anomaly_breakdown': {},
            'findings': []
        }
        
        for anom in anomalies:
            atype = anom['anomaly_type']
            report['anomaly_breakdown'][atype] = report['anomaly_breakdown'].get(atype, 0) + 1
            if anom['severity'] in ['HIGH', 'CRITICAL']:
                report['findings'].append({
                    'type': atype,
                    'severity': anom['severity'],
                    'user': anom['user_id'],
                    'ip': anom['source_ip'],
                    'description': anom['description']
                })
        
        # Save report
        report_path = DATA_DIR / 'forensic_report.json'
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to {report_path}")
        return report

# ============ MAIN CLI ============
def main():
    parser = argparse.ArgumentParser(description='Forensic Research - Pure Python')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # simulate command
    sim_parser = subparsers.add_parser('simulate', help='Run attack simulation')
    sim_parser.add_argument('scenario', nargs='?', default='full',
                           choices=['normal', 'bulk_download', 'sensitive', 'full'])
    
    # analyze command
    subparsers.add_parser('analyze', help='Run forensic analysis')
    
    # report command
    subparsers.add_parser('report', help='Generate report')
    
    # list command
    subparsers.add_parser('list', help='List logs and anomalies')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    db = ForensicDB(DATA_DIR / 'forensic.db')
    
    if args.command == 'simulate':
        simulator = AttackSimulator()
        simulator.run_attack(args.scenario)
    
    elif args.command == 'analyze':
        logs = db.get_all_logs()
        detector = AnomalyDetector()
        anomalies = detector.run_analysis(logs)
        print(f"\n✓ Detected {len(anomalies)} anomalies")
    
    elif args.command == 'report':
        gen = ReportGenerator()
        report = gen.generate_report()
        print("\n" + "="*50)
        print("FORENSIC ANALYSIS REPORT")
        print("="*50)
        print(f"Total Events: {report['summary']['total_events']}")
        print(f"Total Anomalies: {report['summary']['total_anomalies']}")
        print(f"Unique Users: {report['summary']['unique_users']}")
        print(f"Unique IPs: {report['summary']['unique_ips']}")
        print("\nAnomalies by Type:")
        for atype, count in report['anomaly_breakdown'].items():
            print(f"  - {atype}: {count}")
        print("\nCritical Findings:")
        for finding in report['findings']:
            print(f"  [{finding['severity']}] {finding['type']} - {finding['description']}")
        print("="*50 + "\n")
    
    elif args.command == 'list':
        logs = db.get_all_logs()
        anomalies = db.get_anomalies()
        
        print(f"\n{len(logs)} access log entries:")
        for log in logs[:5]:
            print(f"  {log['timestamp']} - {log['user_id']} @ {log['source_ip']} - {log['operation']} {log['object_name']}")
        if len(logs) > 5:
            print(f"  ... and {len(logs)-5} more")
        
        print(f"\n{len(anomalies)} anomalies detected:")
        for anom in anomalies[:5]:
            print(f"  [{anom['severity']}] {anom['anomaly_type']} - {anom['description']}")
        if len(anomalies) > 5:
            print(f"  ... and {len(anomalies)-5} more")
        print()

if __name__ == '__main__':
    main()

"""
Utility functions untuk forensic analysis
"""
import json
import csv
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any
import sqlite3

logger = logging.getLogger(__name__)


class ForensicLogger:
    """Logger dengan JSON formatting untuk structured logs"""
    
    @staticmethod
    def setup_logger(name: str, log_file: Path) -> logging.Logger:
        """Setup logger dengan JSON formatter"""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        
        # File handler
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # JSON Formatter
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "%(name)s", "message": "%(message)s"}'
        )
        
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        logger.addHandler(fh)
        logger.addHandler(ch)
        
        return logger


class DatabaseHelper:
    """Helper untuk SQLite database operations"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._create_tables()

    def _connect(self):
        """Buka koneksi dengan WAL mode dan timeout untuk mencegah 'database is locked'."""
        conn = sqlite3.connect(self.db_path, timeout=30,
                               check_same_thread=False)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.row_factory = sqlite3.Row
        return conn

    def _create_tables(self):
        """Create forensic analysis tables"""
        conn = self._connect()
        cursor = conn.cursor()
        
        # Access logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT,
                source_ip TEXT,
                operation TEXT,
                bucket TEXT,
                object_name TEXT,
                file_size INTEGER,
                status_code INTEGER,
                user_agent TEXT,
                UNIQUE(timestamp, user_id, operation, object_name)
            )
        ''')
        
        # Anomalies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_at TEXT,
                anomaly_type TEXT,
                severity TEXT,
                user_id TEXT,
                source_ip TEXT,
                description TEXT,
                evidence TEXT
            )
        ''')
        
        # Timeline table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_timestamp TEXT,
                event_type TEXT,
                user_id TEXT,
                source_ip TEXT,
                object_name TEXT,
                file_size INTEGER,
                anomaly_score REAL,
                is_suspicious INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"Database tables initialized at {self.db_path}")
    
    def insert_access_log(self, log_data: Dict[str, Any]):
        """Insert access log entry"""
        conn = self._connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO access_logs 
                (timestamp, user_id, source_ip, operation, bucket, object_name, file_size, status_code, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_data.get('timestamp'),
                log_data.get('user_id'),
                log_data.get('source_ip'),
                log_data.get('operation'),
                log_data.get('bucket'),
                log_data.get('object_name'),
                log_data.get('file_size', 0),
                log_data.get('status_code', 200),
                log_data.get('user_agent', 'unknown')
            ))
            conn.commit()
        except sqlite3.IntegrityError as e:
            logger.debug(f"Duplicate entry: {e}")
        finally:
            conn.close()
    
    def get_all_logs(self) -> List[Dict]:
        """Get all access logs"""
        conn = self._connect()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM access_logs ORDER BY timestamp')
        rows = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return rows
    
    def insert_anomaly(self, anomaly_data: Dict[str, Any]):
        """Record detected anomaly"""
        conn = self._connect()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO anomalies 
            (detected_at, anomaly_type, severity, user_id, source_ip, description, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            anomaly_data.get('detected_at', datetime.now().isoformat()),
            anomaly_data.get('anomaly_type'),
            anomaly_data.get('severity'),
            anomaly_data.get('user_id'),
            anomaly_data.get('source_ip'),
            anomaly_data.get('description'),
            json.dumps(anomaly_data.get('evidence', {}))
        ))
        
        conn.commit()
        conn.close()
    
    def get_anomalies(self) -> List[Dict]:
        """Get all detected anomalies"""
        conn = self._connect()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM anomalies ORDER BY detected_at DESC')
        rows = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return rows


class LogParser:
    """Parser untuk MinIO/S3 access logs"""
    
    @staticmethod
    def parse_s3_log_line(line: str) -> Dict[str, Any]:
        """Parse S3 access log line into structured data
        Format: bucket owner requester timestamp operation key request_uri http_status ...
        """
        parts = line.split(' ')
        
        if len(parts) < 15:
            return None
        
        try:
            return {
                'bucket': parts[0],
                'owner': parts[1],
                'requester': parts[2],
                'timestamp': f"{parts[3]} {parts[4]}",
                'source_ip': parts[4].split(';')[0] if ';' in parts[4] else 'unknown',
                'operation': parts[5],
                'object_name': parts[6],
                'request_uri': parts[7],
                'http_status': parts[8],
                'error_code': parts[9] if parts[9] != '-' else None,
                'bytes_sent': int(parts[10]) if parts[10] != '-' else 0,
                'file_size': int(parts[11]) if parts[11] != '-' else 0,
                'total_time': int(parts[12]) if parts[12] != '-' else 0,
                'turn_around_time': int(parts[13]) if parts[13] != '-' else 0,
                'user_agent': ' '.join(parts[15:]) if len(parts) > 15 else 'unknown'
            }
        except (ValueError, IndexError) as e:
            logger.error(f"Failed to parse log line: {e}")
            return None
    
    @staticmethod
    def parse_json_log(log_dict: Dict) -> Dict[str, Any]:
        """Parse JSON format log (MinIO audit log).

        user_id priority:
          1. body.principalId  (real IAM/MinIO user)
          2. principalId at top level
          3. requestUserAgent  (only if it looks like a plain username, not a tool string)
        """
        body = log_dict.get('requestParameters', {}) or {}
        principal = (
            body.get('principalId') or
            log_dict.get('principalId') or
            log_dict.get('requestUserAgent', 'unknown')
        )
        # Strip ARN prefix  e.g. "arn:aws:iam::123:user/alice" → "alice"
        if ':user/' in str(principal):
            principal = str(principal).split(':user/')[-1]
        # If the value still looks like a tool string (contains '/'), use 'unknown'
        if '/' in str(principal):
            principal = 'unknown'
        return {
            'timestamp': log_dict.get('time', datetime.now().isoformat()),
            'user_id': principal or 'unknown',
            'source_ip': log_dict.get('sourceIP', 'unknown'),
            'operation': log_dict.get('api', 'unknown'),
            'bucket': log_dict.get('bucket', ''),
            'object_name': log_dict.get('object', ''),
            'file_size': log_dict.get('objectSize', 0),
            'status_code': log_dict.get('statusCode', 0),
            'user_agent': log_dict.get('userAgent', 'unknown')
        }


class TimelineBuilder:
    """Build forensic timeline dari access logs"""
    
    @staticmethod
    def build_timeline_for_user(logs: List[Dict], user_id: str) -> List[Dict]:
        """Build timeline untuk specific user"""
        user_logs = [log for log in logs if log.get('user_id') == user_id]
        user_logs.sort(key=lambda x: x.get('timestamp', ''))
        return user_logs
    
    @staticmethod
    def build_timeline_for_period(logs: List[Dict], start_time: datetime, end_time: datetime) -> List[Dict]:
        """Build timeline untuk specific time period"""
        period_logs = []
        for log in logs:
            try:
                log_time = datetime.fromisoformat(log.get('timestamp', '').replace('Z', '+00:00'))
                if start_time <= log_time <= end_time:
                    period_logs.append(log)
            except:
                pass
        
        period_logs.sort(key=lambda x: x.get('timestamp', ''))
        return period_logs
    
    @staticmethod
    def export_timeline_json(timeline: List[Dict], output_file: Path):
        """Export timeline to JSON"""
        with open(output_file, 'w') as f:
            json.dump(timeline, f, indent=2, default=str)
        logger.info(f"Timeline exported to {output_file}")
    
    @staticmethod
    def export_timeline_csv(timeline: List[Dict], output_file: Path):
        """Export timeline to CSV"""
        if not timeline:
            logger.warning("No timeline data to export")
            return
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=timeline[0].keys())
            writer.writeheader()
            writer.writerows(timeline)
        logger.info(f"Timeline exported to {output_file}")


# ============ EXPORT ============
__all__ = ['ForensicLogger', 'DatabaseHelper', 'LogParser', 'TimelineBuilder']

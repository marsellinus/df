"""
Log Collector Service - mengumpulkan dan memparse logs dari MinIO
Berjalan sebagai background service yang monitor access logs
"""

import json
import logging
import os
import time
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config import (
    LOG_DIR, DATA_DIR, MINIO_ENDPOINT, MINIO_BUCKET,
    PARSED_LOG_FILE, PARSED_CSV_FILE
)
from config.utils import ForensicLogger, LogParser, DatabaseHelper

# ============ SETUP LOGGING ============
logger = ForensicLogger.setup_logger(
    'log_collector',
    LOG_DIR / 'log_collector.log'
)

# ============ INITIALIZE SERVICES ============
app = Flask(__name__)
db = DatabaseHelper(DATA_DIR / 'forensic.db')
log_parser = LogParser()


def _get_log_stats():
    logs = db.get_all_logs()
    operations = {}
    for log in logs:
        op = log.get('operation', 'unknown')
        operations[op] = operations.get(op, 0) + 1

    return {
        'total_entries': len(logs),
        'unique_users': len(set(log.get('user_id', 'unknown') for log in logs)),
        'unique_ips': len(set(log.get('source_ip', 'unknown') for log in logs)),
        'operations': operations,
    }


@app.route('/', methods=['GET'])
def index():
    """Simple UI for the log collector"""
    stats = _get_log_stats()
    return render_template_string(
        """
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Log Collector UI</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
                .wrap { max-width: 1000px; margin: 0 auto; padding: 32px; }
                .card { background: #111827; border: 1px solid #334155; border-radius: 16px; padding: 20px; margin-bottom: 16px; }
                .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
                .metric { background: #0b1220; border: 1px solid #1f2937; border-radius: 12px; padding: 16px; }
                .value { font-size: 28px; font-weight: 700; }
                a { color: #7dd3fc; }
                code { background: #0b1220; padding: 2px 6px; border-radius: 6px; }
            </style>
        </head>
        <body>
            <div class="wrap">
                <div class="card">
                    <h1>Log Collector UI</h1>
                    <p>Endpoint penerimaan log: <code>/logs</code></p>
                    <p>MinIO bucket: <code>{{ bucket }}</code></p>
                    <p>Tailscale access: buka <code>http://&lt;tailscale-ip&gt;:5000</code> atau <code>http://&lt;device-name&gt;.ts.net:5000</code> jika tailnet sudah aktif.</p>
                </div>
                <div class="grid">
                    <div class="metric"><div>Total Logs</div><div class="value">{{ stats.total_entries }}</div></div>
                    <div class="metric"><div>Unique Users</div><div class="value">{{ stats.unique_users }}</div></div>
                    <div class="metric"><div>Unique IPs</div><div class="value">{{ stats.unique_ips }}</div></div>
                    <div class="metric"><div>Operations</div><div class="value">{{ stats.operations|length }}</div></div>
                </div>
                <div class="card">
                    <h2>Quick Links</h2>
                    <ul>
                        <li><a href="/health">/health</a></li>
                        <li><a href="/logs/stats">/logs/stats</a></li>
                        <li><a href="/logs/export">/logs/export</a></li>
                    </ul>
                </div>
            </div>
        </body>
        </html>
        """,
        stats=stats,
        bucket=MINIO_BUCKET,
    )

# ============ ROUTES ============

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()}), 200


@app.route('/logs', methods=['POST'])
def receive_logs():
    """
    Receive logs dari MinIO atau client
    Expected JSON format:
    {
        "timestamp": "2024-01-01T12:00:00Z",
        "user_id": "user1",
        "source_ip": "192.168.1.100",
        "operation": "GET",
        "bucket": "foresc",
        "object_name": "file.txt",
        "file_size": 1024,
        "status_code": 200,
        "user_agent": "aws-sdk-python"
    }
    """
    try:
        log_entries = request.get_json()
        
        # Handle both single entry dan array
        if isinstance(log_entries, dict):
            log_entries = [log_entries]
        
        processed_count = 0
        for entry in log_entries:
            # Parse dan normalize log entry
            parsed_log = log_parser.parse_json_log(entry)
            
            # Store ke database
            db.insert_access_log(parsed_log)
            
            # Also append to JSON file untuk reference
            _append_to_json_log(parsed_log)
            
            processed_count += 1
            logger.info(f"Processed log entry: {entry.get('object_name', 'unknown')} - {entry.get('api', 'unknown')}")
        
        return jsonify({
            'status': 'success',
            'processed': processed_count,
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Error processing logs: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 400


@app.route('/logs/stats', methods=['GET'])
def get_log_stats():
    """Get statistics tentang collected logs"""
    try:
        logs = db.get_all_logs()
        
        stats = {
            'total_entries': len(logs),
            'unique_users': len(set(log.get('user_id', 'unknown') for log in logs)),
            'unique_ips': len(set(log.get('source_ip', 'unknown') for log in logs)),
            'operations': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Count operations
        for log in logs:
            op = log.get('operation', 'unknown')
            stats['operations'][op] = stats['operations'].get(op, 0) + 1
        
        return jsonify(stats), 200
    
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/logs/parse', methods=['POST'])
def parse_logs():
    """
    Parse log file dan store ke database
    Expected: {"log_file": "path/to/logfile"}
    """
    try:
        data = request.get_json()
        log_file_path = data.get('log_file')
        
        if not log_file_path:
            return jsonify({'error': 'log_file parameter required'}), 400
        
        log_path = Path(log_file_path)
        if not log_path.exists():
            return jsonify({'error': 'Log file not found'}), 404
        
        parsed_count = 0
        with open(log_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                try:
                    # Coba parse sebagai JSON
                    log_entry = json.loads(line)
                    parsed_log = log_parser.parse_json_log(log_entry)
                except json.JSONDecodeError:
                    # Fallback ke S3 format parser
                    parsed_log = log_parser.parse_s3_log_line(line)
                
                if parsed_log:
                    db.insert_access_log(parsed_log)
                    _append_to_json_log(parsed_log)
                    parsed_count += 1
        
        logger.info(f"Parsed {parsed_count} entries from {log_file_path}")
        return jsonify({
            'status': 'success',
            'parsed': parsed_count,
            'log_file': str(log_file_path)
        }), 200
    
    except Exception as e:
        logger.error(f"Error parsing logs: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/logs/export', methods=['GET'])
def export_logs():
    """Export collected logs as CSV"""
    try:
        import csv
        
        logs = db.get_all_logs()
        
        if not logs:
            return jsonify({'error': 'No logs to export'}), 404
        
        # Write to CSV
        csv_file = DATA_DIR / 'exported_logs.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=logs[0].keys())
            writer.writeheader()
            writer.writerows(logs)
        
        logger.info(f"Exported {len(logs)} logs to {csv_file}")
        return jsonify({
            'status': 'success',
            'exported': len(logs),
            'file': str(csv_file)
        }), 200
    
    except Exception as e:
        logger.error(f"Error exporting logs: {e}")
        return jsonify({'error': str(e)}), 500


# ============ HELPER FUNCTIONS ============

def _append_to_json_log(log_entry: dict):
    """Append log entry to JSON file"""
    try:
        # Read existing logs
        if PARSED_LOG_FILE.exists():
            with open(PARSED_LOG_FILE, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
        
        # Append new entry
        logs.append(log_entry)
        
        # Write back
        with open(PARSED_LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=2, default=str)
    
    except Exception as e:
        logger.error(f"Error appending to JSON log: {e}")


def monitor_minio_logs():
    """Monitor MinIO audit log file untuk new entries"""
    minio_audit_log = Path('/root/.minio/logs/audit.log')
    last_position = 0
    
    if not minio_audit_log.exists():
        logger.warning(f"MinIO audit log not found at {minio_audit_log}")
        return
    
    while True:
        try:
            # Read new entries
            with open(minio_audit_log, 'r') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                last_position = f.tell()
            
            # Process new lines
            for line in new_lines:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        parsed_log = log_parser.parse_json_log(entry)
                        db.insert_access_log(parsed_log)
                        _append_to_json_log(parsed_log)
                    except Exception as e:
                        logger.debug(f"Failed to process MinIO log line: {e}")
            
            time.sleep(5)  # Check every 5 seconds
        
        except Exception as e:
            logger.error(f"Error monitoring MinIO logs: {e}")
            time.sleep(10)


# ============ MAIN ============

if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("Log Collector Service Started")
    logger.info(f"Data directory: {DATA_DIR}")
    logger.info(f"Log directory: {LOG_DIR}")
    logger.info("=" * 60)
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)

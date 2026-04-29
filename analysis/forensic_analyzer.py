"""
Forensic Analyzer - menganalisis access logs untuk mendeteksi anomali
dan merekonstruksi attack timeline
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
import sys
from flask import Flask, jsonify, request, render_template_string

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config import (
    LOG_DIR, DATA_DIR, ANOMALY_THRESHOLDS,
    PARSED_LOG_FILE, PARSED_CSV_FILE
)
from config.utils import ForensicLogger, DatabaseHelper, TimelineBuilder

# ============ SETUP LOGGING ============
logger = ForensicLogger.setup_logger(
    'forensic_analyzer',
    LOG_DIR / 'forensic_analyzer.log'
)

# ============ INITIALIZE SERVICES ============
app = Flask(__name__)
db = DatabaseHelper(DATA_DIR / 'forensic.db')
timeline_builder = TimelineBuilder()


def _get_analyzer_stats():
    logs = db.get_all_logs()
    anomalies = db.get_anomalies()
    anomaly_types = {}
    for anomaly in anomalies:
        atype = anomaly.get('anomaly_type', 'unknown')
        anomaly_types[atype] = anomaly_types.get(atype, 0) + 1

    return {
        'total_logs': len(logs),
        'total_anomalies': len(anomalies),
        'unique_users': len(set(log.get('user_id', 'unknown') for log in logs)),
        'unique_ips': len(set(log.get('source_ip', 'unknown') for log in logs)),
        'anomaly_types': anomaly_types,
    }


@app.route('/', methods=['GET'])
def index():
    """Simple UI for the forensic analyzer"""
    stats = _get_analyzer_stats()
    return render_template_string(
        """
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Forensic Analyzer UI</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; background: #111827; color: #e5e7eb; }
                .wrap { max-width: 1000px; margin: 0 auto; padding: 32px; }
                .card { background: #0f172a; border: 1px solid #334155; border-radius: 16px; padding: 20px; margin-bottom: 16px; }
                .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
                .metric { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 16px; }
                .value { font-size: 28px; font-weight: 700; }
                a, button { color: #93c5fd; }
                button { background: #1d4ed8; border: 0; color: white; padding: 10px 14px; border-radius: 10px; cursor: pointer; }
                code { background: #020617; padding: 2px 6px; border-radius: 6px; }
                form { display: inline-block; margin-right: 8px; }
            </style>
        </head>
        <body>
            <div class="wrap">
                <div class="card">
                    <h1>Forensic Analyzer UI</h1>
                    <p>Analisis dan rekonstruksi timeline serangan.</p>
                    <p>Tailscale access: buka <code>http://&lt;tailscale-ip&gt;:5001</code> atau <code>http://&lt;device-name&gt;.ts.net:5001</code> jika tailnet sudah aktif.</p>
                </div>
                <div class="grid">
                    <div class="metric"><div>Total Logs</div><div class="value">{{ stats.total_logs }}</div></div>
                    <div class="metric"><div>Total Anomalies</div><div class="value">{{ stats.total_anomalies }}</div></div>
                    <div class="metric"><div>Unique Users</div><div class="value">{{ stats.unique_users }}</div></div>
                    <div class="metric"><div>Unique IPs</div><div class="value">{{ stats.unique_ips }}</div></div>
                </div>
                <div class="card">
                    <h2>Quick Actions</h2>
                    <form action="/analyze" method="post"><button type="submit">Run Analysis</button></form>
                    <a href="/anomalies">View Anomalies</a> |
                    <a href="/timeline">View Timeline</a> |
                    <a href="/report">View Report</a>
                </div>
                <div class="card">
                    <h2>Anomaly Types</h2>
                    <ul>
                        {% for key, value in stats.anomaly_types.items() %}
                        <li>{{ key }}: {{ value }}</li>
                        {% endfor %}
                        {% if not stats.anomaly_types %}
                        <li>No anomalies yet.</li>
                        {% endif %}
                    </ul>
                </div>
            </div>
        </body>
        </html>
        """,
        stats=stats,
    )

# ============ ANALYZER CLASS ============

class AnomalyDetector:
    """Deteksi anomali dalam access patterns"""
    
    def __init__(self, thresholds: Optional[Dict] = None):
        self.thresholds = thresholds or ANOMALY_THRESHOLDS
        self.anomalies = []
    
    def detect_bulk_downloads(self, logs: List[Dict]) -> List[Dict]:
        """
        Deteksi bulk download activity
        Anomali: Banyak file didownload dalam waktu singkat
        """
        anomalies = []
        time_window = self.thresholds['access_time_window']
        file_threshold = self.thresholds['bulk_download_count']
        size_threshold = self.thresholds['bulk_download_size_mb'] * 1024 * 1024  # Convert to bytes
        
        # Group logs by user
        user_logs = defaultdict(list)
        for log in logs:
            user = log.get('user_id', 'unknown')
            if log.get('operation') == 'GET':  # Download operations
                user_logs[user].append(log)
        
        # Analyze each user
        for user, user_access in user_logs.items():
            user_access.sort(key=lambda x: x.get('timestamp', ''))
            
            # Sliding window analysis
            for i, log in enumerate(user_access):
                window_start = datetime.fromisoformat(log.get('timestamp', '').replace('Z', '+00:00'))
                window_end = window_start + timedelta(seconds=time_window)
                
                # Count files dan size dalam window
                window_logs = [
                    l for l in user_access[i:]
                    if datetime.fromisoformat(l.get('timestamp', '').replace('Z', '+00:00')) <= window_end
                ]
                
                file_count = len(window_logs)
                total_size = sum(l.get('file_size', 0) for l in window_logs)
                
                # Check thresholds
                if file_count >= file_threshold or total_size >= size_threshold:
                    anomalies.append({
                        'anomaly_type': 'BULK_DOWNLOAD',
                        'severity': 'HIGH' if file_count >= file_threshold * 2 else 'MEDIUM',
                        'user_id': user,
                        'source_ip': log.get('source_ip', 'unknown'),
                        'timestamp': log.get('timestamp'),
                        'description': f"Bulk download detected: {file_count} files, {total_size / 1024 / 1024:.2f} MB",
                        'evidence': {
                            'file_count': file_count,
                            'total_size_mb': total_size / 1024 / 1024,
                            'time_window_seconds': time_window,
                            'files': [l.get('object_name') for l in window_logs]
                        }
                    })
        
        return anomalies
    
    def detect_unusual_hours_access(self, logs: List[Dict]) -> List[Dict]:
        """
        Deteksi akses diluar jam kerja normal
        Normal hours: 06:00 - 18:00
        """
        anomalies = []
        unusual_start = datetime.strptime(self.thresholds['unusual_hours_start'], '%H:%M').time()
        unusual_end = datetime.strptime(self.thresholds['unusual_hours_end'], '%H:%M').time()
        
        for log in logs:
            try:
                log_time = datetime.fromisoformat(log.get('timestamp', '').replace('Z', '+00:00'))
                hour = log_time.time()
                
                # Check if outside working hours
                if hour >= unusual_start or hour <= unusual_end:
                    anomalies.append({
                        'anomaly_type': 'UNUSUAL_HOURS_ACCESS',
                        'severity': 'MEDIUM',
                        'user_id': log.get('user_id', 'unknown'),
                        'source_ip': log.get('source_ip', 'unknown'),
                        'timestamp': log.get('timestamp'),
                        'description': f"Access outside working hours ({hour.strftime('%H:%M:%S')})",
                        'evidence': {
                            'access_time': hour.isoformat(),
                            'operation': log.get('operation'),
                            'object': log.get('object_name')
                        }
                    })
            except Exception as e:
                logger.debug(f"Failed to parse timestamp: {e}")
        
        return anomalies
    
    def detect_ip_anomalies(self, logs: List[Dict]) -> List[Dict]:
        """
        Deteksi perubahan IP address yang mencurigakan
        Anomali: Satu user akses dari banyak IP dalam short timeframe
        """
        anomalies = []
        time_window = 3600  # 1 hour
        ip_threshold = self.thresholds['ip_change_threshold']
        
        user_ips = defaultdict(lambda: defaultdict(list))
        
        for log in logs:
            user = log.get('user_id', 'unknown')
            ip = log.get('source_ip', 'unknown')
            ts = log.get('timestamp')
            user_ips[user][ts].append((ip, ts))
        
        # Check each user
        for user, ip_timeline in user_ips.items():
            sorted_times = sorted(ip_timeline.keys())
            
            for i, curr_time in enumerate(sorted_times):
                window_start = datetime.fromisoformat(curr_time.replace('Z', '+00:00'))
                window_end = window_start + timedelta(seconds=time_window)
                
                # Gather IPs dalam window
                ips_in_window = set()
                for t in sorted_times[i:]:
                    if datetime.fromisoformat(t.replace('Z', '+00:00')) <= window_end:
                        ips = [ip for ip, _ in user_ips[user][t]]
                        ips_in_window.update(ips)
                    else:
                        break
                
                # Check threshold
                if len(ips_in_window) >= ip_threshold:
                    anomalies.append({
                        'anomaly_type': 'MULTIPLE_IP_ADDRESSES',
                        'severity': 'HIGH',
                        'user_id': user,
                        'source_ip': ', '.join(ips_in_window),
                        'timestamp': curr_time,
                        'description': f"User accessed from {len(ips_in_window)} different IPs",
                        'evidence': {
                            'ip_count': len(ips_in_window),
                            'ips': list(ips_in_window),
                            'time_window_seconds': time_window
                        }
                    })
        
        return anomalies
    
    def detect_sensitive_file_access(self, logs: List[Dict], sensitive_files: List[str]) -> List[Dict]:
        """
        Deteksi akses ke file sensitif
        """
        anomalies = []
        
        for log in logs:
            obj_name = log.get('object_name', '').lower()
            for sensitive in sensitive_files:
                if sensitive.lower() in obj_name:
                    anomalies.append({
                        'anomaly_type': 'SENSITIVE_FILE_ACCESS',
                        'severity': 'CRITICAL' if log.get('operation') == 'GET' else 'HIGH',
                        'user_id': log.get('user_id', 'unknown'),
                        'source_ip': log.get('source_ip', 'unknown'),
                        'timestamp': log.get('timestamp'),
                        'description': f"Access to sensitive file: {log.get('object_name')}",
                        'evidence': {
                            'file': log.get('object_name'),
                            'operation': log.get('operation'),
                            'size': log.get('file_size')
                        }
                    })
        
        return anomalies
    
    def run_full_analysis(self, logs: List[Dict], sensitive_files: Optional[List[str]] = None) -> List[Dict]:
        """Run semua deteksi anomali"""
        all_anomalies = []
        
        logger.info(f"Starting full forensic analysis on {len(logs)} log entries")
        
        # Run all detectors
        all_anomalies.extend(self.detect_bulk_downloads(logs))
        all_anomalies.extend(self.detect_unusual_hours_access(logs))
        all_anomalies.extend(self.detect_ip_anomalies(logs))
        
        if sensitive_files:
            all_anomalies.extend(self.detect_sensitive_file_access(logs, sensitive_files))
        
        logger.info(f"Detected {len(all_anomalies)} anomalies")
        
        return all_anomalies


# ============ ROUTES ============

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()}), 200


@app.route('/analyze', methods=['POST'])
def run_analysis():
    """
    Run forensic analysis pada collected logs
    Optional: specify sensitive files list
    """
    try:
        from config.config import SENSITIVE_FILES
        
        # Get logs dari database
        logs = db.get_all_logs()
        
        if not logs:
            return jsonify({'error': 'No logs available for analysis'}), 404
        
        # Run detector
        detector = AnomalyDetector()
        anomalies = detector.run_full_analysis(logs, SENSITIVE_FILES)
        
        # Store anomalies to database
        for anomaly in anomalies:
            anomaly['detected_at'] = datetime.now().isoformat()
            db.insert_anomaly(anomaly)
        
        logger.info(f"Analysis complete. Stored {len(anomalies)} anomalies")
        
        return jsonify({
            'status': 'success',
            'total_logs': len(logs),
            'anomalies_found': len(anomalies),
            'anomalies': anomalies[:10]  # Return first 10
        }), 200
    
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/anomalies', methods=['GET'])
def get_anomalies():
    """Get all detected anomalies"""
    try:
        anomalies = db.get_anomalies()
        return jsonify({
            'status': 'success',
            'count': len(anomalies),
            'anomalies': anomalies
        }), 200
    except Exception as e:
        logger.error(f"Error fetching anomalies: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/timeline', methods=['GET'])
def get_timeline():
    """
    Get attack timeline
    Query params:
    - user_id: filter by user
    - start_time: ISO format
    - end_time: ISO format
    """
    try:
        user_id = request.args.get('user_id')
        start_time_str = request.args.get('start_time')
        end_time_str = request.args.get('end_time')
        
        logs = db.get_all_logs()
        
        # Filter by user if specified
        if user_id:
            timeline = timeline_builder.build_timeline_for_user(logs, user_id)
        # Filter by time period if specified
        elif start_time_str and end_time_str:
            start_time = datetime.fromisoformat(start_time_str)
            end_time = datetime.fromisoformat(end_time_str)
            timeline = timeline_builder.build_timeline_for_period(logs, start_time, end_time)
        else:
            # Return all logs as timeline
            timeline = sorted(logs, key=lambda x: x.get('timestamp', ''))
        
        return jsonify({
            'status': 'success',
            'timeline_entries': len(timeline),
            'timeline': timeline
        }), 200
    
    except Exception as e:
        logger.error(f"Error generating timeline: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/report', methods=['GET'])
def generate_report():
    """
    Generate forensic report
    Returns: JSON dengan summary findings
    """
    try:
        logs = db.get_all_logs()
        anomalies = db.get_anomalies()
        
        # Generate statistics
        report = {
            'report_generated': datetime.now().isoformat(),
            'summary': {
                'total_access_logs': len(logs),
                'total_anomalies_detected': len(anomalies),
                'unique_users': len(set(log.get('user_id') for log in logs)),
                'unique_ips': len(set(log.get('source_ip') for log in logs))
            },
            'anomaly_breakdown': {},
            'high_severity_events': [],
            'timeline_summary': '',
            'recommendations': []
        }
        
        # Count anomaly types
        for anomaly in anomalies:
            atype = anomaly.get('anomaly_type', 'unknown')
            report['anomaly_breakdown'][atype] = report['anomaly_breakdown'].get(atype, 0) + 1
            
            if anomaly.get('severity') in ['HIGH', 'CRITICAL']:
                report['high_severity_events'].append({
                    'type': atype,
                    'user': anomaly.get('user_id'),
                    'ip': anomaly.get('source_ip'),
                    'timestamp': anomaly.get('timestamp'),
                    'description': anomaly.get('description')
                })
        
        # Recommendations
        if report['anomaly_breakdown'].get('BULK_DOWNLOAD', 0) > 0:
            report['recommendations'].append("High bulk download activity detected - review user permissions")
        
        if report['anomaly_breakdown'].get('MULTIPLE_IP_ADDRESSES', 0) > 0:
            report['recommendations'].append("Multiple IP addresses detected - check for unauthorized access")
        
        if report['anomaly_breakdown'].get('SENSITIVE_FILE_ACCESS', 0) > 0:
            report['recommendations'].append("Sensitive files accessed - audit access logs immediately")
        
        return jsonify(report), 200
    
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'error': str(e)}), 500


# ============ MAIN ============

if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("Forensic Analyzer Service Started")
    logger.info("=" * 60)
    
    app.run(host='0.0.0.0', port=5001, debug=False)

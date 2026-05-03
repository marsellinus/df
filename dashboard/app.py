"""dashboard/app.py - Forensic Investigation Dashboard API."""

import json
import logging
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from config.config import DATA_DIR, LOG_DIR
from config.utils import ForensicLogger, DatabaseHelper
from analysis.log_parser import get_all_parsed_logs, get_logs_for_user, get_logs_for_ip, get_logs_in_range
from analysis.metadata_correlator import correlate
from analysis.anomaly_detector import run_all_detectors
from analysis.timeline_reconstructor import reconstruct, summarise
from analysis.risk_engine import compute_risk_scores

logger = ForensicLogger.setup_logger('dashboard', LOG_DIR / 'dashboard.log')
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.secret_key = 'forensic-secret-2024'
db = DatabaseHelper(DATA_DIR / 'forensic.db')

_pipeline_lock = threading.Lock()


def _run_pipeline_and_save():
    """Run full forensic pipeline and persist report. Thread-safe."""
    if not _pipeline_lock.acquire(blocking=False):
        return  # already running
    try:
        from main import run_pipeline
        logs = get_all_parsed_logs()
        report = run_pipeline(logs)
        out = DATA_DIR / 'forensic_report.json'
        out.write_text(json.dumps(report, indent=2, default=str))
        logger.info(f"Pipeline refreshed: {len(logs)} events")
    except Exception as e:
        logger.error(f"Pipeline refresh error: {e}")
    finally:
        _pipeline_lock.release()


def _background_refresh(interval: int = 30):
    """Background thread: refresh pipeline every `interval` seconds."""
    while True:
        time.sleep(interval)
        _run_pipeline_and_save()


# Start background refresh thread
threading.Thread(target=_background_refresh, args=(30,), daemon=True).start()

USERS = {'admin': 'forensic2024', 'analyst': 'analyst123'}
SEV_ORDER = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form
        if USERS.get(data.get('username', '')) == data.get('password', ''):
            session['user'] = data['username']
            return jsonify({'status': 'ok', 'user': data['username']})
        return jsonify({'error': 'Invalid credentials'}), 401
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('dashboard.html')


# ── Core forensic APIs ────────────────────────────────────────────────────────

@app.route('/api/stats')
def get_stats():
    try:
        logs = db.get_all_logs()
        anomalies = db.get_anomalies()
        ops, users, ips, atypes = {}, {}, {}, {}
        for l in logs:
            ops[l.get('operation','unknown')] = ops.get(l.get('operation','unknown'),0)+1
            users[l.get('user_id','unknown')] = users.get(l.get('user_id','unknown'),0)+1
            ips[l.get('source_ip','unknown')] = ips.get(l.get('source_ip','unknown'),0)+1
        for a in anomalies:
            atypes[a.get('anomaly_type','unknown')] = atypes.get(a.get('anomaly_type','unknown'),0)+1
        return jsonify({
            'total_logs': len(logs), 'total_anomalies': len(anomalies),
            'unique_users': len(users), 'unique_ips': len(ips),
            'operations': ops, 'anomaly_types': atypes,
            'user_activity': users, 'ip_activity': ips,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/risk-score')
def risk_score():
    try:
        # Serve from cached report (updated by background pipeline every 30s)
        cache_file = DATA_DIR / 'forensic_report.json'
        if cache_file.exists():
            data = json.loads(cache_file.read_text())
            how_much = data.get('how_much', {})
            how      = data.get('how', {})
            return jsonify({
                'session_risk_score': data.get('session_risk_score', 0),
                'session_risk_band':  data.get('session_risk_band', 'SAFE'),
                'user_scores': {
                    uid: {
                        'user_id':   uid,
                        'risk_score': u.get('risk_score', 0),
                        'risk_band':  u.get('risk_band', 'SAFE'),
                        'signals':    how.get(uid, {}),
                        'profile_summary': {
                            'total_events':    u.get('total_events', 0),
                            'get_count':       how_much.get(uid, {}).get('files_downloaded', 0),
                            'bytes_total_mb':  how_much.get(uid, {}).get('bytes_total_mb', 0),
                            'unique_ip_count': u.get('ips_used', 0),
                            'sensitive_files': u.get('sensitive_files_accessed', []),
                            'off_hours_events': how.get(uid, {}).get('off_hours_ratio', 0),
                        },
                    }
                    for uid, u in data.get('who', {}).items()
                },
                'anomalies': [
                    {
                        'anomaly_type': a.get('type', ''),
                        'severity':     a.get('severity', ''),
                        'user_id':      a.get('user', ''),
                        'source_ip':    '',
                        'description':  a.get('description', ''),
                        'evidence':     a.get('evidence', {}),
                        'detected_at':  data.get('generated_at', ''),
                    }
                    for a in data.get('what', [])
                ],
                'timeline_summary': data.get('when', {}),
                'total_logs': data.get('when', {}).get('total_events', 0),
            })
        # Fallback: compute live
        logs = get_all_parsed_logs()
        result = compute_risk_scores(logs)
        result['total_logs'] = len(logs)
        return jsonify(result)
    except Exception as e:
        logger.error(f"risk-score: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/reconstruction')
def reconstruction():
    try:
        cache_file = DATA_DIR / 'forensic_report.json'
        if cache_file.exists():
            return jsonify(json.loads(cache_file.read_text()))
        from main import run_pipeline
        report = run_pipeline()
        return jsonify(report)
    except Exception as e:
        logger.error(f"reconstruction: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts')
def get_alerts():
    try:
        min_val = SEV_ORDER.get(request.args.get('min_severity', 'HIGH'), 3)
        user    = request.args.get('user')
        atype   = request.args.get('type')
        alerts  = [a for a in db.get_anomalies()
                   if SEV_ORDER.get(a.get('severity','LOW'),0) >= min_val]
        if user:  alerts = [a for a in alerts if a.get('user_id') == user]
        if atype: alerts = [a for a in alerts if a.get('anomaly_type') == atype]
        alerts.sort(key=lambda x: (SEV_ORDER.get(x.get('severity','LOW'),0), x.get('detected_at','')), reverse=True)
        return jsonify({'count': len(alerts), 'alerts': alerts})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs/raw')
def logs_raw():
    try:
        page     = max(int(request.args.get('page', 1)), 1)
        per_page = min(int(request.args.get('per_page', 50)), 500)
        user, ip = request.args.get('user'), request.args.get('ip')
        start, end = request.args.get('start'), request.args.get('end')
        operation = request.args.get('operation')
        source    = request.args.get('source')

        if user:        logs = get_logs_for_user(user)
        elif ip:        logs = get_logs_for_ip(ip)
        elif start and end: logs = get_logs_in_range(start, end)
        else:           logs = get_all_parsed_logs()

        if operation: logs = [l for l in logs if l.get('operation','').upper() == operation.upper()]
        if source:    logs = [l for l in logs if l.get('bucket','') == source]
        
        # Filter out background noise
        if not user and not source:
            logs = [l for l in logs if not (l.get('user_id') == 'unknown' and not l.get('object_name','').strip())]

        total = len(logs)
        offset = (page - 1) * per_page
        return jsonify({
            'total': total, 'page': page, 'per_page': per_page,
            'pages': (total + per_page - 1) // per_page,
            'logs': logs[offset: offset + per_page],
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analysis/correlate', methods=['GET', 'POST'])
def analysis_correlate():
    try:
        logs = get_all_parsed_logs()
        report = correlate(logs)
        report['user_profiles'] = {
            uid: {k: (list(v) if isinstance(v, set) else v) for k, v in p.items()}
            for uid, p in report['user_profiles'].items()
        }
        return jsonify(report)
    except Exception as e:
        return jsonify({'error': str(e)}), 500





@app.route('/api/pipeline/refresh', methods=['POST'])
def pipeline_refresh():
    """Trigger forensic pipeline immediately and return updated report."""
    try:
        threading.Thread(target=_run_pipeline_and_save, daemon=True).start()
        return jsonify({'status': 'started', 'message': 'Pipeline refresh triggered'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── ML APIs ───────────────────────────────────────────────────────────────────

@app.route('/api/ml/summary')
def ml_summary():
    try:
        f = Path(__file__).parent.parent / 'models' / 'training_results.json'
        if not f.exists():
            return jsonify({'error': 'Models not trained yet. Run: python scripts/ml_training.py'}), 404
        data = json.loads(f.read_text())
        return jsonify({
            **{k: data.get(k) for k in ('timestamp','dataset','train_size','test_size','features','feature_names')},
            'models': {
                name: {k: round(m.get(k,0),4) for k in ('test_accuracy','precision','recall','f1','roc_auc')}
                for name, m in data.get('models',{}).items()
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/predict', methods=['POST'])
def ml_predict():
    """Run ML prediction on a single event dict."""
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent / 'scripts'))
        from ml_prediction import MLPredictor
        predictor = MLPredictor(models_dir=str(Path(__file__).parent.parent / 'models'))
        if not predictor.models:
            return jsonify({'error': 'No models loaded'}), 404
        data = request.get_json(silent=True) or {}
        preds = predictor.predict(data)
        return jsonify(preds)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Dataset APIs ──────────────────────────────────────────────────────────────

@app.route('/api/dataset/summary')
def dataset_summary():
    """Live traffic dataset breakdown."""
    try:
        logs = get_all_parsed_logs()
        sources = {}
        for l in logs:
            bucket = l.get('bucket') or ''
            src = 'Nextcloud' if bucket in ('nextcloud', '') else (bucket or 'Nextcloud')
            if src not in sources:
                sources[src] = {'events': 0, 'users': set(), 'operations': {}}
            sources[src]['events'] += 1
            sources[src]['users'].add(l.get('user_id','unknown'))
            op = l.get('operation','unknown')
            sources[src]['operations'][op] = sources[src]['operations'].get(op,0)+1

        return jsonify({
            'total_events': len(logs),
            'sources': {
                src: {
                    'events': v['events'],
                    'unique_users': len(v['users']),
                    'users': list(v['users']),
                    'operations': v['operations'],
                }
                for src, v in sources.items()
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500





# ── Utility APIs ──────────────────────────────────────────────────────────────

@app.route('/api/logs/list')
def list_logs():
    try:
        files = [{'name': f.name, 'size_kb': round(f.stat().st_size/1024,2),
                  'modified': datetime.fromtimestamp(f.stat().st_mtime).isoformat()}
                 for f in LOG_DIR.glob('*.log')]
        return jsonify({'log_files': files})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs/tail/<filename>')
def tail_log(filename):
    try:
        limit = request.args.get('limit', 50, type=int)
        path = LOG_DIR / filename
        if not path.exists():
            return jsonify({'error': 'Not found'}), 404
        lines = path.read_text(errors='replace').splitlines()
        return jsonify({'filename': filename, 'lines': lines[-limit:], 'total_lines': len(lines)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/user/<user_id>')
def get_user_activity(user_id):
    try:
        logs = get_logs_for_user(user_id)
        anomalies = [a for a in db.get_anomalies() if a.get('user_id') == user_id]
        ops, ips, files = {}, set(), set()
        for l in logs:
            ops[l.get('operation','unknown')] = ops.get(l.get('operation','unknown'),0)+1
            ips.add(l.get('source_ip')); files.add(l.get('object_name'))
        return jsonify({'user_id': user_id, 'total_events': len(logs),
                        'operations': ops, 'ips_used': list(ips),
                        'files_accessed': list(files), 'anomalies': anomalies})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/system/metrics')
def system_metrics():
    try:
        logs = db.get_all_logs()
        anomalies = db.get_anomalies()
        return jsonify({
            'total_events': len(logs), 'total_anomalies': len(anomalies),
            'anomaly_rate': round(len(anomalies)/max(len(logs),1)*100,2),
            'unique_users': len(set(l.get('user_id') for l in logs if l)),
            'unique_ips': len(set(l.get('source_ip') for l in logs if l)),
            'severity_breakdown': {s: len([a for a in anomalies if a.get('severity')==s])
                                   for s in ('CRITICAL','HIGH','MEDIUM','LOW')},
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.errorhandler(404)
def not_found(e): return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e): return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.info("Dashboard starting on :5002")
    app.run(host='0.0.0.0', port=5002, debug=False)

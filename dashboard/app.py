"""dashboard/app.py - Forensic Investigation Dashboard API."""

import json
import logging
import subprocess
import sys
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
app.secret_key = 'forensic-secret-2024'
db = DatabaseHelper(DATA_DIR / 'forensic.db')

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
        from main import run_pipeline
        return jsonify(run_pipeline())
    except Exception as e:
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
        source    = request.args.get('source')  # cert_dataset / nextcloud / etc.

        if user:        logs = get_logs_for_user(user)
        elif ip:        logs = get_logs_for_ip(ip)
        elif start and end: logs = get_logs_in_range(start, end)
        else:           logs = get_all_parsed_logs()

        if operation: logs = [l for l in logs if l.get('operation','').upper() == operation.upper()]
        if source:    logs = [l for l in logs if l.get('bucket','') == source]

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


@app.route('/api/simulate', methods=['POST'])
def simulate():
    try:
        data     = request.get_json(silent=True) or {}
        scenario = data.get('scenario', 'full')
        attacker = data.get('attacker', 'attacker1')
        files    = int(data.get('files', 5))
        valid    = {'full','normal','bulk_download','multi_ip','off_hours','sensitive'}
        if scenario not in valid:
            return jsonify({'error': f'Choose from: {valid}'}), 400
        script = Path(__file__).parent.parent / 'scripts' / 'attack_simulator.py'
        proc = subprocess.Popen(
            [sys.executable, str(script), scenario, '--attacker', attacker, '--files', str(files)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try: proc.communicate(timeout=2)
        except subprocess.TimeoutExpired: pass
        return jsonify({'status': 'started', 'scenario': scenario, 'attacker': attacker, 'pid': proc.pid})
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
    """Cross-source dataset breakdown: CERT vs Nextcloud."""
    try:
        logs = get_all_parsed_logs()
        sources = {}
        for l in logs:
            bucket = l.get('bucket') or ''
            src = 'CERT-InsiderThreat' if 'cert' in bucket else \
                  'Nextcloud' if bucket in ('nextcloud', '') else (bucket or 'Nextcloud')
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


@app.route('/api/dataset/cert-sample')
def cert_sample():
    """Generate and return CERT sample dataset info."""
    try:
        csv_path = DATA_DIR / 'cert_sample.csv'
        if not csv_path.exists():
            return jsonify({'error': 'cert_sample.csv not found. Run: python scripts/load_cert_dataset.py --sample'}), 404
        import csv
        rows = []
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
        users = {}
        for r in rows:
            u = r.get('user','')
            if u not in users: users[u] = {'events':0,'exfil':0}
            users[u]['events'] += 1
            if r.get('to_removable_media','').lower() == 'true':
                users[u]['exfil'] += 1
        return jsonify({
            'total_records': len(rows),
            'users': users,
            'sample': rows[:5],
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

@app.errorhandler(404)
def not_found(e): return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e): return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.info("Dashboard starting on :5002")
    app.run(host='0.0.0.0', port=5002, debug=False)

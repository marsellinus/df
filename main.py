#!/usr/bin/env python3
"""
main.py - Unified forensic pipeline entry point.

Usage:
  python main.py                        # run full pipeline on DB data
  python main.py --ingest <logfile>     # ingest a log file then run pipeline
  python main.py --simulate <scenario>  # run attack simulation then pipeline
  python main.py --serve                # start the web dashboard (port 5002)
  python main.py --output report.json   # write structured report to file

Pipeline:
  1. Load logs (from DB or ingest file)
  2. Parse & normalise
  3. Correlate metadata (user + IP profiles)
  4. Detect anomalies (5 rule-based detectors)
  5. Score risk (Distributed Metadata Correlation Engine)
  6. Reconstruct timeline with attack phases
  7. Output structured forensic report
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Ensure project root is on path
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from analysis.log_parser             import get_all_parsed_logs, ingest_log_file
from analysis.metadata_correlator    import correlate
from analysis.anomaly_detector       import run_all_detectors
from analysis.timeline_reconstructor import reconstruct, summarise
from analysis.risk_engine            import compute_risk_scores
from config.config                   import DATA_DIR, LOG_DIR


def _run_ml_predictions(logs: list) -> list:
    """
    Jalankan ML prediction pada logs. Return list anomaly dicts (format sama dengan rule-based).
    Gracefully skip jika model belum di-training.
    """
    try:
        import sys
        sys.path.insert(0, str(ROOT / 'scripts'))
        from ml_prediction import MLPredictor
        predictor = MLPredictor(models_dir=str(ROOT / 'models'))
        if not predictor.models:
            return []
    except Exception:
        return []

    ml_anomalies = []
    from datetime import datetime as _dt
    for log in logs:
        raw = {
            'timestamp':        log.get('timestamp', ''),
            'user':             log.get('user_id', 'unknown'),
            'source_ip':        log.get('source_ip', '0.0.0.0'),
            'object':           log.get('object_name', ''),
            'bytes_transferred': log.get('file_size', 0),
            'action':           log.get('operation', 'GET'),
        }
        try:
            preds = predictor.predict(raw)
            ensemble = preds.get('ensemble', {})
            prob = ensemble.get('probability', 0)
            if ensemble.get('prediction') == 1 and prob >= 0.6:
                severity = 'CRITICAL' if prob >= 0.85 else 'HIGH' if prob >= 0.70 else 'MEDIUM'
                ml_anomalies.append({
                    'detected_at':  _dt.now().isoformat(),
                    'anomaly_type': 'ML_ANOMALY',
                    'severity':     severity,
                    'user_id':      log.get('user_id', 'unknown'),
                    'source_ip':    log.get('source_ip', 'unknown'),
                    'description':  f"ML ensemble flagged event (confidence {prob:.0%})",
                    'evidence':     {
                        'ml_probability': round(prob, 4),
                        'model_votes': {k: round(v['probability'], 4)
                                        for k, v in preds.items() if k != 'ensemble'},
                        'object': log.get('object_name', ''),
                    },
                })
        except Exception:
            continue

    # Deduplicate: satu ML_ANOMALY per user, ambil confidence tertinggi
    seen = {}
    for a in ml_anomalies:
        uid = a['user_id']
        if uid not in seen or a['evidence']['ml_probability'] > seen[uid]['evidence']['ml_probability']:
            seen[uid] = a
    return list(seen.values())


# ── Pipeline ──────────────────────────────────────────────────────────────────

def _classify_source(logs: list, user_id: str) -> str:
    """Tentukan asal data user: CERT, Nextcloud, atau Mixed."""
    buckets = {l.get('bucket', '') for l in logs if l.get('user_id') == user_id}
    has_cert = any('cert' in b for b in buckets)
    has_nc   = any(b in ('nextcloud', '') for b in buckets)
    if has_cert and has_nc:
        return 'Mixed'
    if has_cert:
        return 'CERT-InsiderThreat'
    return 'Nextcloud'


def run_pipeline(logs=None) -> dict:
    """
    Execute the full forensic pipeline.

    Returns a structured forensic report:
      who   – per-user risk scores and profiles
      when  – timeline summary (first/last event, phases)
      what  – anomaly list with evidence
      how   – method signals (bulk download, multi-IP, off-hours, etc.)
      how_much – bytes exfiltrated per user
    """
    if logs is None:
        logs = get_all_parsed_logs()

    if not logs:
        return {'error': 'No log data available. Run --ingest or --simulate first.'}

    # Step 1-5: full risk engine (correlate → detect → score)
    result = compute_risk_scores(logs)

    # Step 5b: ML-based anomaly detection (augments rule-based)
    ml_anomalies = _run_ml_predictions(logs)
    if ml_anomalies:
        result['anomalies'] = result.get('anomalies', []) + ml_anomalies

    # Step 6: detailed timeline
    timeline = reconstruct(logs, result['anomalies'])
    tl_summary = summarise(timeline)

    # Step 7: build structured forensic report
    who_dict = {
        uid: {
            'risk_score':  u['risk_score'],
            'risk_band':   u['risk_band'],
            'total_events': u['profile_summary']['total_events'],
            'ips_used':    u['profile_summary']['unique_ip_count'],
            'sensitive_files_accessed': u['profile_summary']['sensitive_files'],
            'data_source': _classify_source(logs, uid),
        }
        for uid, u in result['user_scores'].items()
    }

    cross_source = {}
    for src in ('CERT-InsiderThreat', 'Nextcloud', 'Mixed'):
        users = [uid for uid, u in who_dict.items() if u['data_source'] == src]
        if users:
            cross_source[src] = users

    report = {
        'report_title': 'Forensic Reconstruction – Unauthorized Data Exfiltration',
        'generated_at': datetime.now().isoformat(),
        'session_risk_score': result['session_risk_score'],
        'session_risk_band':  result['session_risk_band'],

        # WHO
        'who': who_dict,

        # WHEN
        'when': {
            'first_event':      tl_summary.get('first_event'),
            'last_event':       tl_summary.get('last_event'),
            'total_events':     tl_summary.get('total_events'),
            'suspicious_events': tl_summary.get('suspicious_events'),
            'attack_phases':    tl_summary.get('phases', {}),
        },

        # WHAT
        'what': [
            {
                'severity':    a['severity'],
                'type':        a['anomaly_type'],
                'user':        a['user_id'],
                'description': a['description'],
                'evidence':    a['evidence'],
            }
            for a in result['anomalies']
        ],

        # HOW (top attacker signals)
        'how': {
            uid: u['signals']
            for uid, u in result['user_scores'].items()
            if u['risk_band'] not in ('SAFE', 'LOW')
        },

        # HOW MUCH
        'how_much': {
            uid: {
                'bytes_total_mb': u['profile_summary']['bytes_total_mb'],
                'files_downloaded': u['profile_summary']['get_count'],
            }
            for uid, u in result['user_scores'].items()
        },

        # Correlation findings
        'correlation': result['correlation'],

        # Cross-source breakdown: pisahkan user dari CERT vs Nextcloud
        'cross_source_summary': cross_source,

        # Full timeline (first 200 events to keep report readable)
        'timeline': timeline[:200],
    }

    return report


def _print_summary(report: dict):
    """Print a human-readable summary to stdout."""
    if 'error' in report:
        print(f"ERROR: {report['error']}")
        return

    SEV_COLOR = {'CRITICAL': '\033[91m', 'HIGH': '\033[93m',
                 'MEDIUM': '\033[33m', 'LOW': '\033[94m', 'SAFE': '\033[92m'}
    RESET = '\033[0m'

    band = report['session_risk_band']
    color = SEV_COLOR.get(band, '')
    print(f"\n{'='*60}")
    print(f"  FORENSIC RECONSTRUCTION REPORT")
    print(f"  Generated: {report['generated_at']}")
    print(f"{'='*60}")
    print(f"  Session Risk Score: {color}{report['session_risk_score']} ({band}){RESET}")
    print()

    print("  WHO (User Risk Scores):")
    for uid, u in sorted(report['who'].items(), key=lambda x: -x[1]['risk_score']):
        c = SEV_COLOR.get(u['risk_band'], '')
        print(f"    {uid:35s} {c}{u['risk_score']:3d} ({u['risk_band']}){RESET}"
              f"  events={u['total_events']}  ips={u['ips_used']}")

    print()
    print("  WHEN (Timeline):")
    w = report['when']
    print(f"    First event : {w['first_event']}")
    print(f"    Last event  : {w['last_event']}")
    print(f"    Total events: {w['total_events']}  Suspicious: {w['suspicious_events']}")
    print(f"    Phases      : {w['attack_phases']}")

    print()
    print("  WHAT (Anomalies Detected):")
    for a in report['what']:
        c = SEV_COLOR.get(a['severity'], '')
        print(f"    [{c}{a['severity']:8s}{RESET}] {a['type']:30s} user={a['user']}")
        print(f"             {a['description']}")

    print()
    print("  HOW MUCH (Data Exfiltrated):")
    for uid, d in report['how_much'].items():
        if d['files_downloaded'] > 0:
            print(f"    {uid:35s} {d['files_downloaded']} files  {d['bytes_total_mb']:.1f} MB")

    print(f"\n{'='*60}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Forensic Reconstruction Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--ingest',   metavar='FILE',     help='Ingest a log file before running pipeline')
    parser.add_argument('--simulate', metavar='SCENARIO', help='Run attack simulation (full|normal|bulk_download|multi_ip|off_hours|sensitive)')
    parser.add_argument('--serve',    action='store_true', help='Start the web dashboard on port 5002')
    parser.add_argument('--output',   metavar='FILE',     help='Write JSON report to file')
    parser.add_argument('--quiet',    action='store_true', help='Suppress console output')
    args = parser.parse_args()

    # Start web server
    if args.serve:
        print("Starting ForensicControl dashboard on http://localhost:5002")
        print("Login: admin / forensic2024")
        subprocess.run([sys.executable, str(ROOT / 'dashboard' / 'app.py')])
        return

    # Ingest log file
    if args.ingest:
        path = Path(args.ingest)
        if not path.exists():
            print(f"ERROR: File not found: {path}")
            sys.exit(1)
        count = ingest_log_file(path)
        print(f"Ingested {count} records from {path}")

    # Run simulation
    if args.simulate:
        script = ROOT / 'scripts' / 'attack_simulator.py'
        print(f"Running simulation: {args.simulate}")
        result = subprocess.run(
            [sys.executable, str(script), args.simulate],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"Simulation error: {result.stderr}")
            sys.exit(1)
        print(f"Simulation complete.")

    # Run pipeline
    report = run_pipeline()

    # Output
    if not args.quiet:
        _print_summary(report)

    if args.output:
        out = Path(args.output)
        out.write_text(json.dumps(report, indent=2, default=str))
        print(f"Report written to {out}")
    else:
        # Always write to default location
        default_out = DATA_DIR / 'forensic_report.json'
        default_out.write_text(json.dumps(report, indent=2, default=str))
        if not args.quiet:
            print(f"Report saved to {default_out}")


if __name__ == '__main__':
    main()

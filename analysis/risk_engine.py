"""
risk_engine.py - Distributed Metadata Correlation Engine
Combines signals from all forensic modules to produce an
"Exfiltration Risk Score" (0-100) per user and for the whole session.

Score bands:
  0-24   SAFE
  25-49  LOW
  50-69  MEDIUM
  70-84  HIGH
  85-100 CRITICAL
"""

from datetime import datetime
from typing import Dict, List, Tuple
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.log_parser        import get_all_parsed_logs
from analysis.metadata_correlator import correlate, build_user_profiles, build_ip_profiles
from analysis.anomaly_detector  import run_all_detectors
from analysis.timeline_reconstructor import reconstruct, summarise
from config.config import DATA_DIR, SENSITIVE_FILES
from config.utils  import DatabaseHelper

db = DatabaseHelper(DATA_DIR / 'forensic.db')


# ── Scoring weights ───────────────────────────────────────────────────────────
WEIGHTS = {
    'bulk_download_gets':      0.20,   # normalised GET count
    'bulk_download_mb':        0.15,   # normalised MB
    'multi_ip':                0.20,   # normalised unique-IP count
    'off_hours_ratio':         0.10,   # fraction of events off-hours
    'sensitive_file_ratio':    0.15,   # fraction of files that are sensitive
    'rapid_succession':        0.10,   # rapid-fire events flag
    'delete_ratio':            0.10,   # DELETE ops (evidence destruction)
}

# Normalisation caps (values at or above cap → score = 1.0 for that signal)
CAPS = {
    'bulk_download_gets': 20,
    'bulk_download_mb':   500,
    'multi_ip':           6,
}


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def _score_user(profile: Dict, anomaly_types: set, anomalies: list = None) -> Tuple[float, Dict]:
    """Return (raw_score 0-1, signal_breakdown) for one user."""
    signals = {}

    # Bulk download – GET count
    gets = profile.get('get_count', 0)
    signals['bulk_download_gets'] = _clamp(gets / CAPS['bulk_download_gets'])

    # Bulk download – volume
    mb = profile.get('bytes_total_mb', 0)
    signals['bulk_download_mb'] = _clamp(mb / CAPS['bulk_download_mb'])

    # Multi-IP
    ip_count = profile.get('unique_ip_count', 0)
    signals['multi_ip'] = _clamp(ip_count / CAPS['multi_ip'])

    # Off-hours ratio
    total = max(profile.get('total_events', 1), 1)
    off   = profile.get('off_hours_events', 0)
    signals['off_hours_ratio'] = _clamp(off / total)

    # Sensitive file ratio
    file_count = max(profile.get('unique_file_count', 1), 1)
    sf_count   = profile.get('sensitive_file_count', 0)
    signals['sensitive_file_ratio'] = _clamp(sf_count / file_count)

    # Rapid succession (binary from anomaly types)
    signals['rapid_succession'] = 1.0 if 'RAPID_SUCCESSION' in anomaly_types else 0.0

    # DELETE ratio
    deletes = profile.get('delete_count', 0)
    signals['delete_ratio'] = _clamp(deletes / max(total, 1))

    raw = sum(WEIGHTS[k] * signals[k] for k in WEIGHTS)

    # Severity bonus: CRITICAL anomaly adds 0.25, HIGH adds 0.10 (capped at 1.0)
    SEV_BONUS = {'CRITICAL': 0.25, 'HIGH': 0.10, 'MEDIUM': 0.05, 'LOW': 0.0}
    uid = profile.get('user_id', '')
    if anomalies:
        user_anomalies = [a for a in anomalies if a.get('user_id') == uid]
        max_bonus = max((SEV_BONUS.get(a.get('severity', 'LOW'), 0) for a in user_anomalies), default=0)
        raw = _clamp(raw + max_bonus)

    return raw, signals


def _band(score: int) -> str:
    if score >= 85: return 'CRITICAL'
    if score >= 70: return 'HIGH'
    if score >= 50: return 'MEDIUM'
    if score >= 25: return 'LOW'
    return 'SAFE'


# ── Public API ────────────────────────────────────────────────────────────────

def compute_risk_scores(logs: List[Dict] = None) -> Dict:
    """
    Run the full Distributed Metadata Correlation Engine.

    Returns a report with:
      - per-user risk scores
      - session-level risk score
      - correlation data
      - anomalies
      - timeline summary
    """
    if logs is None:
        logs = get_all_parsed_logs()

    if not logs:
        return {
            'generated_at': datetime.now().isoformat(),
            'session_risk_score': 0,
            'session_risk_band': 'SAFE',
            'user_scores': {},
            'anomalies': [],
            'correlation': {},
            'timeline_summary': {},
            'total_logs': 0,
        }

    # Step 1 – Correlate metadata
    correlation = correlate(logs)
    user_profiles = correlation['user_profiles']

    # Step 2 – Detect anomalies
    anomalies = run_all_detectors(logs, user_profiles)

    # Build per-user anomaly-type index
    user_atypes: Dict[str, set] = {}
    for a in anomalies:
        uid = a.get('user_id', 'unknown')
        user_atypes.setdefault(uid, set()).add(a.get('anomaly_type', ''))

    # Step 3 – Score each user
    user_scores = {}
    for uid, profile in user_profiles.items():
        profile['user_id'] = uid  # ensure user_id is in profile for _score_user
        raw, signals = _score_user(profile, user_atypes.get(uid, set()), anomalies)
        score = round(raw * 100)
        user_scores[uid] = {
            'user_id':    uid,
            'risk_score': score,
            'risk_band':  _band(score),
            'signals':    {k: round(v * 100) for k, v in signals.items()},
            'profile_summary': {
                'total_events':      profile['total_events'],
                'get_count':         profile['get_count'],
                'bytes_total_mb':    profile['bytes_total_mb'],
                'unique_ip_count':   profile['unique_ip_count'],
                'sensitive_files':   profile['sensitive_files_accessed'],
                'off_hours_events':  profile['off_hours_events'],
            },
        }

    # Step 4 – Session-level score = max of user scores (worst actor)
    session_score = max((v['risk_score'] for v in user_scores.values()), default=0)

    # Step 5 – Timeline
    timeline = reconstruct(logs, anomalies)
    tl_summary = summarise(timeline)

    return {
        'generated_at':      datetime.now().isoformat(),
        'session_risk_score': session_score,
        'session_risk_band':  _band(session_score),
        'user_scores':        user_scores,
        'anomalies':          anomalies,
        'anomaly_count':      len(anomalies),
        'correlation': {
            'unique_users':    correlation['unique_users'],
            'unique_ips':      correlation['unique_ips'],
            'shared_ips':      correlation['shared_ips'],
            'contested_files': correlation['contested_files'],
        },
        'timeline_summary':  tl_summary,
        'total_logs':        len(logs),
    }

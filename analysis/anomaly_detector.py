"""
anomaly_detector.py - Rule-based anomaly detection on user/IP profiles.

Each detector returns a list of anomaly dicts with:
  type, severity, user_id, source_ip, description, evidence
"""

from datetime import datetime
from typing import Dict, List
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import DATA_DIR, ANOMALY_THRESHOLDS, SENSITIVE_FILES
from config.utils import DatabaseHelper

db = DatabaseHelper(DATA_DIR / 'forensic.db')

SEVERITY = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}


def _anomaly(atype, severity, user_id, source_ip, description, evidence=None) -> Dict:
    return {
        'detected_at': datetime.now().isoformat(),
        'anomaly_type': atype,
        'severity': severity,
        'user_id': user_id,
        'source_ip': source_ip or 'unknown',
        'description': description,
        'evidence': evidence or {},
    }


# ── Individual detectors ──────────────────────────────────────────────────────

def detect_bulk_download(user_profiles: Dict) -> List[Dict]:
    """Flag users who downloaded many files with actual data transfer.

    Requires bytes_total > 0 to exclude audit-log internal access events
    that carry no file size (e.g. Nextcloud internal file-access records).
    """
    results = []
    threshold_count = ANOMALY_THRESHOLDS.get('bulk_download_count', 5)
    threshold_mb    = ANOMALY_THRESHOLDS.get('bulk_download_size_mb', 500)

    for uid, p in user_profiles.items():
        gets = p.get('get_count', 0)
        mb   = p.get('bytes_total_mb', 0)
        if mb == 0:
            continue  # no actual bytes transferred — skip
        if gets >= threshold_count or mb >= threshold_mb:
            sev = 'CRITICAL' if (gets >= threshold_count * 3 or mb >= threshold_mb * 2) else 'HIGH'
            results.append(_anomaly(
                'BULK_DOWNLOAD', sev, uid,
                p.get('unique_ips', ['unknown'])[0] if p.get('unique_ips') else 'unknown',
                f"Bulk download: {gets} GET ops, {mb:.1f} MB total",
                {'get_count': gets, 'bytes_mb': mb},
            ))
    return results


def detect_multi_ip(user_profiles: Dict) -> List[Dict]:
    """Flag users accessing from many different IPs.

    Requires at least 1 GET (download) to avoid flagging pure-upload users
    whose IPs vary due to NAT/DHCP. Threshold raised to 5 to reduce false positives.
    """
    results = []
    threshold = max(ANOMALY_THRESHOLDS.get('ip_change_threshold', 3), 5)

    for uid, p in user_profiles.items():
        ip_count = p.get('unique_ip_count', 0)
        gets = p.get('get_count', 0)
        # Must have downloads AND many IPs to be suspicious
        if ip_count >= threshold and gets >= 1:
            sev = 'CRITICAL' if ip_count >= threshold * 2 else 'HIGH'
            results.append(_anomaly(
                'MULTIPLE_IP_ADDRESSES', sev, uid, None,
                f"Access from {ip_count} different IPs with {gets} download(s)",
                {'ips': p.get('unique_ips', []), 'get_count': gets},
            ))
    return results


def detect_off_hours(user_profiles: Dict) -> List[Dict]:
    """Flag users with significant off-hours activity."""
    results = []
    for uid, p in user_profiles.items():
        off = p.get('off_hours_events', 0)
        total = p.get('total_events', 1)
        if off > 0 and (off / total) > 0.5:
            sev = 'HIGH' if off >= 5 else 'MEDIUM'
            results.append(_anomaly(
                'OFF_HOURS_ACCESS', sev, uid, None,
                f"{off}/{total} events outside business hours",
                {'off_hours_count': off, 'total': total},
            ))
    return results


def detect_sensitive_file_access(user_profiles: Dict) -> List[Dict]:
    """Flag users accessing sensitive files."""
    results = []
    for uid, p in user_profiles.items():
        sf = p.get('sensitive_file_count', 0)
        if sf > 0:
            sev = 'CRITICAL' if sf >= 3 else 'HIGH'
            results.append(_anomaly(
                'SENSITIVE_FILE_ACCESS', sev, uid, None,
                f"Accessed {sf} sensitive file(s): {', '.join(p.get('sensitive_files_accessed', []))}",
                {'files': p.get('sensitive_files_accessed', [])},
            ))
    return results


def detect_rapid_succession(logs: List[Dict]) -> List[Dict]:
    """Flag users with many events in a very short window (< 5 s apart)."""
    from collections import defaultdict
    results = []
    user_ts: Dict[str, List[str]] = defaultdict(list)
    for log in logs:
        user_ts[log.get('user_id', 'unknown')].append(log.get('timestamp', ''))

    for uid, timestamps in user_ts.items():
        timestamps.sort()
        rapid = 0
        for i in range(1, len(timestamps)):
            try:
                t1 = datetime.fromisoformat(timestamps[i-1].replace('Z', '+00:00'))
                t2 = datetime.fromisoformat(timestamps[i].replace('Z', '+00:00'))
                if (t2 - t1).total_seconds() < 5:
                    rapid += 1
            except Exception:
                pass
        if rapid >= 5:
            results.append(_anomaly(
                'RAPID_SUCCESSION', 'HIGH', uid, None,
                f"{rapid} events within 5-second windows (automated tool suspected)",
                {'rapid_pairs': rapid},
            ))
    return results


# ── Main entry point ──────────────────────────────────────────────────────────

def run_all_detectors(logs: List[Dict], user_profiles: Dict) -> List[Dict]:
    """Run every detector, persist results (deduplicated), and return sorted list."""
    anomalies = []
    anomalies += detect_bulk_download(user_profiles)
    anomalies += detect_multi_ip(user_profiles)
    anomalies += detect_off_hours(user_profiles)
    anomalies += detect_sensitive_file_access(user_profiles)
    anomalies += detect_rapid_succession(logs)

    # Deduplicate in-memory by (type, user_id) before persisting
    seen = set()
    unique = []
    for a in anomalies:
        key = (a['anomaly_type'], a['user_id'])
        if key not in seen:
            seen.add(key)
            unique.append(a)

    # Replace existing anomalies in DB for this run (avoid accumulation across calls)
    import sqlite3
    conn = sqlite3.connect(DATA_DIR / 'forensic.db')
    conn.execute('DELETE FROM anomalies')
    conn.commit()
    conn.close()
    for a in unique:
        db.insert_anomaly(a)

    unique.sort(key=lambda x: SEVERITY.get(x['severity'], 0), reverse=True)
    return unique

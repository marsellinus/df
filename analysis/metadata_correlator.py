"""
metadata_correlator.py - Correlate metadata across multiple log sources.

Produces per-user and per-IP correlation profiles used by the risk engine.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Any
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import DATA_DIR, SENSITIVE_FILES
from config.utils import DatabaseHelper

db = DatabaseHelper(DATA_DIR / 'forensic.db')


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except Exception:
        return datetime.now(timezone.utc)


def _hour(ts: str) -> int:
    return _parse_ts(ts).hour


# ── User profile ──────────────────────────────────────────────────────────────

def build_user_profiles(logs: List[Dict]) -> Dict[str, Dict]:
    """
    Aggregate per-user metadata from all logs.
    Returns a dict keyed by user_id.
    """
    profiles: Dict[str, Any] = defaultdict(lambda: {
        'total_events': 0,
        'operations': defaultdict(int),
        'ips': set(),
        'files': set(),
        'sensitive_files': set(),
        'bytes_total': 0,
        'hours': defaultdict(int),
        'first_seen': None,
        'last_seen': None,
        'off_hours_events': 0,
    })

    for log in logs:
        uid = log.get('user_id', 'unknown')
        p = profiles[uid]
        p['total_events'] += 1
        p['operations'][log.get('operation', 'unknown')] += 1
        p['ips'].add(log.get('source_ip', 'unknown'))
        fname = log.get('object_name', '')
        p['files'].add(fname)
        if fname in SENSITIVE_FILES:
            p['sensitive_files'].add(fname)
        p['bytes_total'] += int(log.get('file_size', 0) or 0)
        h = _hour(log.get('timestamp', ''))
        p['hours'][h] += 1
        if h < 6 or h >= 18:
            p['off_hours_events'] += 1
        ts = log.get('timestamp', '')
        if p['first_seen'] is None or ts < p['first_seen']:
            p['first_seen'] = ts
        if p['last_seen'] is None or ts > p['last_seen']:
            p['last_seen'] = ts

    # Serialise sets
    result = {}
    for uid, p in profiles.items():
        result[uid] = {
            'user_id': uid,
            'total_events': p['total_events'],
            'operations': dict(p['operations']),
            'unique_ips': list(p['ips']),
            'unique_ip_count': len(p['ips']),
            'unique_files': list(p['files']),
            'unique_file_count': len(p['files']),
            'sensitive_files_accessed': list(p['sensitive_files']),
            'sensitive_file_count': len(p['sensitive_files']),
            'bytes_total': p['bytes_total'],
            'bytes_total_mb': round(p['bytes_total'] / (1024 * 1024), 2),
            'hour_distribution': {str(k): v for k, v in p['hours'].items()},
            'off_hours_events': p['off_hours_events'],
            'first_seen': p['first_seen'],
            'last_seen': p['last_seen'],
            'get_count': p['operations'].get('GET', 0),
            'put_count': p['operations'].get('PUT', 0),
            'delete_count': p['operations'].get('DELETE', 0),
        }
    return result


# ── IP profile ────────────────────────────────────────────────────────────────

def build_ip_profiles(logs: List[Dict]) -> Dict[str, Dict]:
    """Aggregate per-IP metadata."""
    profiles: Dict[str, Any] = defaultdict(lambda: {
        'total_events': 0,
        'users': set(),
        'files': set(),
        'bytes_total': 0,
        'operations': defaultdict(int),
    })

    for log in logs:
        ip = log.get('source_ip', 'unknown')
        p = profiles[ip]
        p['total_events'] += 1
        p['users'].add(log.get('user_id', 'unknown'))
        p['files'].add(log.get('object_name', ''))
        p['bytes_total'] += int(log.get('file_size', 0) or 0)
        p['operations'][log.get('operation', 'unknown')] += 1

    result = {}
    for ip, p in profiles.items():
        result[ip] = {
            'source_ip': ip,
            'total_events': p['total_events'],
            'unique_users': list(p['users']),
            'unique_user_count': len(p['users']),
            'unique_files': list(p['files']),
            'bytes_total_mb': round(p['bytes_total'] / (1024 * 1024), 2),
            'operations': dict(p['operations']),
        }
    return result


# ── Cross-source correlation ──────────────────────────────────────────────────

def correlate(logs: List[Dict]) -> Dict:
    """
    Run full metadata correlation across all logs.
    Returns a combined correlation report.
    """
    user_profiles = build_user_profiles(logs)
    ip_profiles   = build_ip_profiles(logs)

    # Users sharing IPs
    ip_to_users: Dict[str, set] = defaultdict(set)
    for log in logs:
        ip_to_users[log.get('source_ip', 'unknown')].add(log.get('user_id', 'unknown'))

    shared_ips = {
        ip: list(users)
        for ip, users in ip_to_users.items()
        if len(users) > 1
    }

    # Files accessed by multiple users
    file_to_users: Dict[str, set] = defaultdict(set)
    for log in logs:
        file_to_users[log.get('object_name', '')].add(log.get('user_id', 'unknown'))

    contested_files = {
        f: list(users)
        for f, users in file_to_users.items()
        if len(users) > 1 and f
    }

    return {
        'generated_at': datetime.now().isoformat(),
        'total_logs': len(logs),
        'user_profiles': user_profiles,
        'ip_profiles': ip_profiles,
        'shared_ips': shared_ips,
        'contested_files': contested_files,
        'unique_users': len(user_profiles),
        'unique_ips': len(ip_profiles),
    }

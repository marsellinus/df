"""
timeline_reconstructor.py - Reconstruct a chronological forensic timeline.

Enriches each event with anomaly flags and phase labels so investigators
can follow the attack narrative step-by-step.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import DATA_DIR, SENSITIVE_FILES
from config.utils import DatabaseHelper

db = DatabaseHelper(DATA_DIR / 'forensic.db')


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except Exception:
        return datetime.now(timezone.utc)


def _phase(event: Dict, anomaly_types: set) -> str:
    """Assign an attack-phase label to an event."""
    op = event.get('operation', '')
    fname = event.get('object_name', '')
    uid = event.get('user_id', '')

    if 'BULK_DOWNLOAD' in anomaly_types and op == 'GET':
        return 'EXFILTRATION'
    if fname in SENSITIVE_FILES:
        return 'TARGET_ACCESS'
    if 'OFF_HOURS_ACCESS' in anomaly_types:
        return 'STEALTH_OPERATION'
    if 'MULTIPLE_IP_ADDRESSES' in anomaly_types:
        return 'LATERAL_MOVEMENT'
    if op == 'PUT':
        return 'DATA_STAGING'
    if op == 'DELETE':
        return 'EVIDENCE_DESTRUCTION'
    return 'RECONNAISSANCE'


def reconstruct(
    logs: List[Dict],
    anomalies: List[Dict],
    user_filter: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
) -> List[Dict]:
    """
    Build a sorted, enriched timeline from logs + anomalies.

    Parameters
    ----------
    logs       : normalised log records
    anomalies  : detected anomaly records
    user_filter: restrict to a single user_id
    start/end  : ISO timestamp strings for time-range filter
    """
    # Build per-user anomaly-type index
    user_anomaly_types: Dict[str, set] = {}
    for a in anomalies:
        uid = a.get('user_id', 'unknown')
        user_anomaly_types.setdefault(uid, set()).add(a.get('anomaly_type', ''))

    # Filter logs
    filtered = logs
    if user_filter:
        filtered = [l for l in filtered if l.get('user_id') == user_filter]
    if start:
        s = _parse_ts(start)
        filtered = [l for l in filtered if _parse_ts(l.get('timestamp', '')) >= s]
    if end:
        e = _parse_ts(end)
        filtered = [l for l in filtered if _parse_ts(l.get('timestamp', '')) <= e]

    # Sort chronologically
    filtered.sort(key=lambda x: x.get('timestamp', ''))

    # Enrich
    timeline = []
    for event in filtered:
        uid = event.get('user_id', 'unknown')
        atypes = user_anomaly_types.get(uid, set())
        is_suspicious = bool(atypes)
        phase = _phase(event, atypes)

        timeline.append({
            'timestamp':    event.get('timestamp'),
            'user_id':      uid,
            'source_ip':    event.get('source_ip'),
            'operation':    event.get('operation'),
            'object_name':  event.get('object_name'),
            'file_size_kb': round(int(event.get('file_size', 0) or 0) / 1024, 1),
            'status_code':  event.get('status_code'),
            'phase':        phase,
            'is_suspicious': is_suspicious,
            'anomaly_types': list(atypes),
        })

    return timeline


def summarise(timeline: List[Dict]) -> Dict:
    """High-level summary of a reconstructed timeline."""
    if not timeline:
        return {}

    phases: Dict[str, int] = {}
    suspicious = 0
    for e in timeline:
        phases[e['phase']] = phases.get(e['phase'], 0) + 1
        if e['is_suspicious']:
            suspicious += 1

    return {
        'total_events': len(timeline),
        'suspicious_events': suspicious,
        'first_event': timeline[0]['timestamp'],
        'last_event':  timeline[-1]['timestamp'],
        'phases': phases,
        'users_involved': list({e['user_id'] for e in timeline}),
        'ips_involved':   list({e['source_ip'] for e in timeline}),
    }

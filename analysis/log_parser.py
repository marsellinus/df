"""
log_parser.py - Parse raw logs from multiple sources into normalized records.
Supports: MinIO audit JSON, S3 access log format, generic web server logs.
"""

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterator, Dict, Any, Optional
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import DATA_DIR, LOG_DIR
from config.utils import DatabaseHelper

db = DatabaseHelper(DATA_DIR / 'forensic.db')

# ── Normalised record schema ──────────────────────────────────────────────────
def _record(timestamp, user_id, source_ip, operation, bucket, object_name,
            file_size, status_code, user_agent, raw=None) -> Dict:
    return {
        'timestamp':   timestamp,
        'user_id':     user_id or 'unknown',
        'source_ip':   source_ip or 'unknown',
        'operation':   operation or 'unknown',
        'bucket':      bucket or '',
        'object_name': object_name or '',
        'file_size':   int(file_size or 0),
        'status_code': int(status_code or 0),
        'user_agent':  user_agent or 'unknown',
        'raw':         raw,
    }


# ── Source parsers ────────────────────────────────────────────────────────────

def parse_minio_audit_json(line: str) -> Optional[Dict]:
    """Parse a single MinIO audit-log JSON line."""
    try:
        d = json.loads(line.strip())
        body = d.get('requestParameters', {}) or {}
        # user_id: prefer principalId (real user), never use requestUserAgent (tool string)
        user = body.get('principalId') or d.get('principalId') or 'unknown'
        if ':user/' in str(user):
            user = str(user).split(':user/')[-1]
        if '/' in str(user):
            user = 'unknown'
        return _record(
            timestamp   = d.get('time', datetime.now().isoformat()),
            user_id     = user,
            source_ip   = d.get('sourceIP') or body.get('sourceIPAddress', 'unknown'),
            operation   = d.get('api', 'unknown'),
            bucket      = d.get('bucket', ''),
            object_name = d.get('object', ''),
            file_size   = d.get('objectSize', 0),
            status_code = d.get('statusCode', 0),
            user_agent  = d.get('userAgent', 'unknown'),
            raw         = line.strip(),
        )
    except (json.JSONDecodeError, KeyError):
        return None


def parse_s3_access_log(line: str) -> Optional[Dict]:
    """Parse AWS/MinIO S3 access log format (space-delimited)."""
    parts = line.split()
    if len(parts) < 12:
        return None
    try:
        ts_raw = f"{parts[2].lstrip('[')} {parts[3].rstrip(']')}"
        try:
            ts = datetime.strptime(ts_raw, '%d/%b/%Y:%H:%M:%S %z').isoformat()
        except ValueError:
            ts = datetime.now().isoformat()
        return _record(
            timestamp   = ts,
            user_id     = parts[1],
            source_ip   = parts[4],
            operation   = parts[5],
            bucket      = parts[0],
            object_name = parts[6],
            file_size   = parts[10] if parts[10] != '-' else 0,
            status_code = parts[8],
            user_agent  = ' '.join(parts[11:]) if len(parts) > 11 else 'unknown',
            raw         = line.strip(),
        )
    except (IndexError, ValueError):
        return None


def parse_generic_json_log(line: str) -> Optional[Dict]:
    """Parse generic JSON log that already has normalised fields."""
    try:
        d = json.loads(line.strip())
        return _record(
            timestamp   = d.get('timestamp') or d.get('time', datetime.now().isoformat()),
            user_id     = d.get('user_id') or d.get('user', 'unknown'),
            source_ip   = d.get('source_ip') or d.get('ip', 'unknown'),
            operation   = d.get('operation') or d.get('method', 'unknown'),
            bucket      = d.get('bucket', ''),
            object_name = d.get('object_name') or d.get('object', ''),
            file_size   = d.get('file_size') or d.get('objectSize', 0),
            status_code = d.get('status_code') or d.get('statusCode', 0),
            user_agent  = d.get('user_agent') or d.get('userAgent', 'unknown'),
            raw         = line.strip(),
        )
    except (json.JSONDecodeError, KeyError):
        return None


# ── File-level helpers ────────────────────────────────────────────────────────

def _detect_format(path: Path) -> str:
    """Heuristic: peek at first non-empty line to decide format."""
    with open(path, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('{'):
                d = json.loads(line)
                if 'api' in d or 'requestUserAgent' in d:
                    return 'minio_audit'
                return 'generic_json'
            return 's3_access'
    return 'generic_json'


def parse_log_file(path: Path) -> Iterator[Dict]:
    """Yield normalised records from a log file (auto-detects format)."""
    fmt = _detect_format(path)
    parsers = {
        'minio_audit':    parse_minio_audit_json,
        's3_access':      parse_s3_access_log,
        'generic_json':   parse_generic_json_log,
        'nc_nginx':       parse_nc_nginx_json,
        'nc_admin_audit': parse_nc_admin_audit,
    }
    parser = parsers.get(fmt, parse_generic_json_log)
    with open(path, 'r', errors='replace') as f:
        for line in f:
            if not line.strip():
                continue
            rec = parser(line)
            if rec:
                yield rec


def ingest_log_file(path: Path) -> int:
    """Parse a log file and persist all records to the database. Returns count."""
    count = 0
    for rec in parse_log_file(path):
        db.insert_access_log(rec)
        count += 1
    return count


def get_all_parsed_logs() -> list:
    """Return all normalised records from the database."""
    return db.get_all_logs()


def get_logs_for_user(user_id: str) -> list:
    conn = sqlite3.connect(DATA_DIR / 'forensic.db', timeout=30); conn.execute("PRAGMA journal_mode=WAL"); conn.row_factory = sqlite3.Row
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute('SELECT * FROM access_logs WHERE user_id=? ORDER BY timestamp', (user_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_logs_for_ip(ip: str) -> list:
    conn = sqlite3.connect(DATA_DIR / 'forensic.db', timeout=30); conn.execute("PRAGMA journal_mode=WAL"); conn.row_factory = sqlite3.Row
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute('SELECT * FROM access_logs WHERE source_ip=? ORDER BY timestamp', (ip,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_logs_in_range(start: str, end: str) -> list:
    """start/end are ISO timestamp strings."""
    conn = sqlite3.connect(DATA_DIR / 'forensic.db', timeout=30); conn.execute("PRAGMA journal_mode=WAL"); conn.row_factory = sqlite3.Row
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        'SELECT * FROM access_logs WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp',
        (start, end)
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# ── Nextcloud-specific parsers ────────────────────────────────────────────────

def parse_nc_nginx_json(line: str) -> Optional[Dict]:
    """
    Parse Nextcloud nginx JSON access log line.

    Format (real example):
      {"timestamp":"2026-04-26T02:23:13+00:00","remote_addr":"172.19.0.1",
       "request_method":"GET","request_uri":"/remote.php/dav/files/alice/financial_report_2024.xlsx",
       "status":200,"bytes_sent":131129,"user_agent":"curl/8.5.0",...}

    Extracts:
      - user_id  from the DAV path  /remote.php/dav/files/<user>/...
      - object_name from the filename portion of the URI
      - operation from HTTP method (GET=download, PUT=upload, PROPFIND=enumerate, DELETE)
      - file_size from bytes_sent (actual bytes transferred)
    """
    try:
        d = json.loads(line.strip())
        uri = d.get('request_uri', '')
        method = d.get('request_method', 'unknown')
        status = int(d.get('status', 0))

        # Extract user and filename from WebDAV URI
        # /remote.php/dav/files/<user>/<filename>
        user_id = 'unknown'
        object_name = ''
        import re as _re
        m = _re.match(r'/remote\.php/dav/files/([^/]+)(/(.+))?', uri)
        if m:
            user_id = m.group(1)
            object_name = m.group(3) or ''
            # URL-decode
            from urllib.parse import unquote
            user_id = unquote(user_id)
            object_name = unquote(object_name)

        # Map HTTP method to forensic operation
        op_map = {'GET': 'GET', 'PUT': 'PUT', 'DELETE': 'DELETE',
                  'PROPFIND': 'PROPFIND', 'MKCOL': 'MKCOL', 'MOVE': 'MOVE',
                  'COPY': 'COPY', 'POST': 'POST'}
        operation = op_map.get(method, method)

        # bytes_sent includes HTTP headers; body_bytes_sent is the actual file size
        file_size = int(d.get('body_bytes_sent', d.get('bytes_sent', 0)))

        return _record(
            timestamp   = d.get('timestamp', datetime.now().isoformat()),
            user_id     = user_id,
            source_ip   = d.get('remote_addr', 'unknown'),
            operation   = operation,
            bucket      = 'nextcloud',
            object_name = object_name,
            file_size   = file_size,
            status_code = status,
            user_agent  = d.get('user_agent', 'unknown'),
            raw         = line.strip(),
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        return None


def parse_nc_admin_audit(line: str) -> Optional[Dict]:
    """
    Parse Nextcloud admin_audit.log JSON line.

    Format:
      {"reqId":"...","level":1,"time":"2026-04-26T02:23:13+00:00",
       "remoteAddr":"172.19.0.1","user":"alice","app":"admin_audit",
       "method":"GET","url":"/remote.php/dav/files/alice/financial_report_2024.xlsx",
       "message":"File accessed: \"/financial_report_2024.xlsx\"","userAgent":"curl/8.5.0"}

    Only ingests entries with forensically relevant messages:
      - Login attempt / Login successful / Login failed
      - File accessed / File written / File created / File deleted
      - PROPFIND (enumeration)
    """
    RELEVANT = ('Login attempt', 'Login successful', 'Login failed',
                'File accessed', 'File written to', 'File created',
                'File deleted', 'File updated', 'File moved')
    try:
        d = json.loads(line.strip())
        msg = d.get('message', '')

        # Skip non-forensic noise (console commands, DB queries, etc.)
        if not any(msg.startswith(r) for r in RELEVANT):
            # Also keep PROPFIND enumeration events
            if d.get('method') != 'PROPFIND':
                return None

        url = d.get('url', '')
        user = d.get('user', '--')
        if user == '--':
            user = 'unknown'

        # Extract filename from message  e.g. File accessed: "/financial_report_2024.xlsx"
        import re as _re
        fname = ''
        fm = _re.search(r'"(/[^"]*)"', msg)
        if fm:
            fname = fm.group(1).lstrip('/')
        if not fname:
            # Fall back to URL path
            from urllib.parse import unquote
            fname = unquote(url.split('/')[-1]) if '/' in url else url

        # Determine operation from message prefix
        if msg.startswith('Login attempt'):
            operation = 'LOGIN_ATTEMPT'
        elif msg.startswith('Login successful'):
            operation = 'LOGIN_SUCCESS'
        elif msg.startswith('Login failed'):
            operation = 'LOGIN_FAILED'
        elif msg.startswith('File accessed'):
            operation = 'GET'
        elif msg.startswith('File written') or msg.startswith('File created') or msg.startswith('File updated'):
            operation = 'PUT'
        elif msg.startswith('File deleted'):
            operation = 'DELETE'
        elif msg.startswith('File moved'):
            operation = 'MOVE'
        elif d.get('method') == 'PROPFIND':
            operation = 'PROPFIND'
        else:
            operation = d.get('method', 'unknown')

        return _record(
            timestamp   = d.get('time', datetime.now().isoformat()),
            user_id     = user,
            source_ip   = d.get('remoteAddr', 'unknown'),
            operation   = operation,
            bucket      = 'nextcloud',
            object_name = fname,
            file_size   = 0,  # audit log doesn't include size
            status_code = 0,
            user_agent  = d.get('userAgent', 'unknown'),
            raw         = line.strip(),
        )
    except (json.JSONDecodeError, KeyError):
        return None





def _detect_format(path: Path) -> str:
    """Heuristic: peek at first non-empty line to decide format."""
    name = path.name.lower()
    # Filename-based hints
    if 'admin_audit' in name:
        return 'nc_admin_audit'

    with open(path, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('{'):
                d = json.loads(line)
                if 'request_method' in d and 'remote_addr' in d:
                    return 'nc_nginx'
                if 'reqId' in d and 'app' in d:
                    return 'nc_admin_audit'
                if 'api' in d or 'requestUserAgent' in d:
                    return 'minio_audit'
                return 'generic_json'
            return 's3_access'
    return 'generic_json'

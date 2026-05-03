"""
log_watcher.py - Realtime nginx log ingestion from Docker container.

Polls nc-web container every 10 seconds, copies access.log, ingests only
NEW lines (tracks byte offset), runs forensic pipeline, updates report.
"""

import subprocess
import time
import sys
import json
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from analysis.log_parser import ingest_log_file
from config.config import LOG_DIR, DATA_DIR

CONTAINER   = 'nc-web'
REMOTE_LOG  = '/var/log/nginx/access.log'
LOCAL_LOG   = LOG_DIR / 'nginx' / 'access.log'
INGEST_LOG  = LOG_DIR / 'nc_nginx_access.log'
OFFSET_FILE = DATA_DIR / '.nginx_log_offset'
INTERVAL    = 10  # seconds


def _get_offset() -> int:
    try:
        return int(OFFSET_FILE.read_text().strip())
    except Exception:
        return 0


def _save_offset(offset: int):
    OFFSET_FILE.write_text(str(offset))


def _copy_log() -> bool:
    """docker cp nc-web:/var/log/nginx/access.log → local path."""
    LOCAL_LOG.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ['docker', 'cp', f'{CONTAINER}:{REMOTE_LOG}', str(LOCAL_LOG)],
        capture_output=True
    )
    return r.returncode == 0


def _ingest_new_lines() -> int:
    """Read only lines after last offset, write to temp file, ingest."""
    if not LOCAL_LOG.exists():
        return 0

    offset = _get_offset()
    size   = LOCAL_LOG.stat().st_size

    if size < offset:
        # Log rotated — reset
        offset = 0

    if size == offset:
        return 0  # nothing new

    with open(LOCAL_LOG, 'rb') as f:
        f.seek(offset)
        new_data = f.read()

    new_offset = offset + len(new_data)

    # Write new lines to ingest file
    INGEST_LOG.write_bytes(new_data)

    count = ingest_log_file(INGEST_LOG)
    _save_offset(new_offset)
    return count


def _refresh_pipeline():
    """Re-run forensic pipeline and update forensic_report.json."""
    try:
        from main import run_pipeline
        from analysis.log_parser import get_all_parsed_logs
        logs = get_all_parsed_logs()
        report = run_pipeline(logs)
        out = DATA_DIR / 'forensic_report.json'
        out.write_text(json.dumps(report, indent=2, default=str))
    except Exception as e:
        print(f"[watcher] pipeline error: {e}", flush=True)


def run():
    print(f"[watcher] Started — polling every {INTERVAL}s", flush=True)
    while True:
        try:
            if _copy_log():
                count = _ingest_new_lines()
                if count > 0:
                    ts = datetime.now().strftime('%H:%M:%S')
                    print(f"[{ts}] Ingested {count} new events → refreshing pipeline", flush=True)
                    _refresh_pipeline()
                    print(f"[{ts}] Pipeline refreshed", flush=True)
        except Exception as e:
            print(f"[watcher] error: {e}", flush=True)
        time.sleep(INTERVAL)


if __name__ == '__main__':
    run()

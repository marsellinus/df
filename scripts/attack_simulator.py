"""
Attack Simulation Script - real WebDAV traffic against Nextcloud
Scenarios:
1. Bulk Download      - rapid GET requests for sensitive files
2. Multi-IP Access    - same actor from multiple spoofed IPs (via X-Forwarded-For)
3. Off-Hours Access   - access pattern at 02:00 local time
4. Sensitive File     - repeated targeted access to credentials/financial data
5. Full               - all scenarios in sequence
"""

import argparse
import time
import random
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config import LOG_DIR, SENSITIVE_FILES, ATTACKER_USERS
from config.utils import ForensicLogger

logger = ForensicLogger.setup_logger(
    'attack_simulator',
    LOG_DIR / 'attack_simulation.log'
)

NEXTCLOUD_URL = os.getenv('NEXTCLOUD_URL', 'http://localhost:8080')
ADMIN_USER = os.getenv('NC_ADMIN_USER', 'admin')
ADMIN_PASS = os.getenv('NC_ADMIN_PASS', 'admin_password_change_me')


def _dav_url(username: str, filename: str = '') -> str:
    return f"{NEXTCLOUD_URL}/remote.php/dav/files/{username}/{filename}"


def _ensure_user(username: str, password: str):
    """Create Nextcloud user if not exists."""
    r = requests.get(
        f"{NEXTCLOUD_URL}/ocs/v1.php/cloud/users/{username}",
        auth=HTTPBasicAuth(ADMIN_USER, ADMIN_PASS),
        headers={'OCS-APIRequest': 'true'},
        timeout=10
    )
    if '<statuscode>404</statuscode>' in r.text:
        requests.post(
            f"{NEXTCLOUD_URL}/ocs/v1.php/cloud/users",
            auth=HTTPBasicAuth(ADMIN_USER, ADMIN_PASS),
            headers={'OCS-APIRequest': 'true'},
            data={'userid': username, 'password': password},
            timeout=10
        )
        logger.info(f"[SETUP] Created user: {username}")

    # Upload sensitive files if missing
    auth = HTTPBasicAuth(username, password)
    for fname in SENSITIVE_FILES:
        head = requests.request('HEAD', _dav_url(username, fname), auth=auth, timeout=10)
        if head.status_code == 404:
            content = f"SENSITIVE_CONTENT_{fname}_{random.randint(1000,9999)}\n" * 20
            requests.put(_dav_url(username, fname), auth=auth,
                         data=content.encode(), timeout=10)
            logger.info(f"[SETUP] Uploaded {fname} for {username}")


def _random_ip() -> str:
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _get(username: str, password: str, filename: str, extra_headers: dict = None):
    headers = extra_headers or {}
    r = requests.get(
        _dav_url(username, filename),
        auth=HTTPBasicAuth(username, password),
        headers=headers,
        timeout=15
    )
    logger.warning(f"[ATTACK] GET {filename} → {r.status_code} ({len(r.content)} bytes)")
    return r.status_code


# ── Scenarios ─────────────────────────────────────────────────────────────────

def scenario_reconnaissance(username: str, password: str):
    """Failed logins + PROPFIND enumeration."""
    logger.info("=== PHASE: RECONNAISSANCE ===")
    for i in range(5):
        r = requests.get(
            _dav_url(username),
            auth=HTTPBasicAuth(username, f"wrong_pass_{i}"),
            timeout=10
        )
        logger.warning(f"[RECON] Failed login attempt {i+1}: {r.status_code}")
        time.sleep(0.3)

    r = requests.request(
        'PROPFIND', _dav_url(username),
        auth=HTTPBasicAuth(username, password),
        headers={'Depth': '1'},
        timeout=10
    )
    logger.warning(f"[RECON] PROPFIND enumeration: {r.status_code}")


def scenario_bulk_download(username: str, password: str, files: int = 7):
    """Rapid-fire bulk download — triggers BULK_DOWNLOAD + RAPID_SUCCESSION."""
    logger.info("=== PHASE: BULK DOWNLOAD ===")
    targets = SENSITIVE_FILES[:files]
    for fname in targets:
        _get(username, password, fname)
        time.sleep(0.3)  # very short = suspicious


def scenario_multi_ip(username: str, password: str, files: int = 5, num_ips: int = 4):
    """Same actor, different X-Forwarded-For IPs — triggers MULTIPLE_IP_ADDRESSES."""
    logger.info("=== PHASE: MULTI-IP ACCESS ===")
    ips = [_random_ip() for _ in range(num_ips)]
    for ip in ips:
        for fname in SENSITIVE_FILES[:files]:
            _get(username, password, fname, {'X-Forwarded-For': ip})
            logger.warning(f"[MULTI-IP] via {ip}")
            time.sleep(0.5)


def scenario_off_hours(username: str, password: str, files: int = 5):
    """Access now (02:xx local) — triggers OFF_HOURS_ACCESS."""
    logger.info(f"=== PHASE: OFF-HOURS ACCESS (current time: {datetime.now().strftime('%H:%M')}) ===")
    for fname in SENSITIVE_FILES[:files]:
        _get(username, password, fname)
        time.sleep(1)


def scenario_sensitive_targeting(username: str, password: str):
    """Repeated access to credentials/financial files — triggers SENSITIVE_FILE_ACCESS."""
    logger.info("=== PHASE: SENSITIVE FILE TARGETING ===")
    critical = SENSITIVE_FILES[:3]
    for fname in critical:
        for attempt in range(3):
            _get(username, password, fname)
            logger.warning(f"[SENSITIVE] Attempt {attempt+1}/3: {fname}")
            time.sleep(1)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Real WebDAV attack simulator against Nextcloud')
    parser.add_argument('scenario',
                        choices=['bulk_download', 'multi_ip', 'off_hours', 'sensitive', 'full'],
                        help='Attack scenario')
    parser.add_argument('--attacker', default='attacker1', help='Attacker username')
    parser.add_argument('--files', type=int, default=7, help='Number of files to target')
    parser.add_argument('--ips', type=int, default=4, help='Number of IPs (multi_ip scenario)')
    args = parser.parse_args()

    password = ATTACKER_USERS.get(args.attacker, 'password123')
    logger.info(f"Attack Simulator started — scenario: {args.scenario}, attacker: {args.attacker}")

    _ensure_user(args.attacker, password)

    if args.scenario == 'bulk_download':
        scenario_reconnaissance(args.attacker, password)
        scenario_bulk_download(args.attacker, password, args.files)

    elif args.scenario == 'multi_ip':
        scenario_multi_ip(args.attacker, password, args.files, args.ips)

    elif args.scenario == 'off_hours':
        scenario_off_hours(args.attacker, password, args.files)

    elif args.scenario == 'sensitive':
        scenario_sensitive_targeting(args.attacker, password)

    elif args.scenario == 'full':
        scenario_reconnaissance(args.attacker, password)
        time.sleep(1)
        scenario_bulk_download(args.attacker, password, args.files)
        time.sleep(1)
        scenario_multi_ip(args.attacker, password, min(args.files, 3), args.ips)
        time.sleep(1)
        scenario_off_hours(args.attacker, password, min(args.files, 3))
        time.sleep(1)
        scenario_sensitive_targeting(args.attacker, password)

    logger.info("Attack simulation complete")


if __name__ == '__main__':
    main()

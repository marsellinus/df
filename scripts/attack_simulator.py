"""
Attack Simulation Script - mensimulasikan unauthorized data exfiltration
Scenarios:
1. Attacker login dengan credential normal user
2. Bulk download files dalam waktu singkat
3. Akses dari multiple IP addresses
4. Access sensitive files
"""

import json
import logging
import argparse
import time
import random
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional
import requests
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config import (
    LOG_DIR, DATA_DIR, MINIO_ENDPOINT, MINIO_BUCKET,
    ATTACKER_USERS, NORMAL_USERS, SENSITIVE_FILES,
    NORMAL_FILE_SIZE_KB
)
from config.utils import ForensicLogger

# ============ SETUP LOGGING ============
logger = ForensicLogger.setup_logger(
    'attack_simulator',
    LOG_DIR / 'attack_simulation.log'
)

# Log collector endpoint - support both Docker network and localhost
LOG_COLLECTOR_URL = os.getenv('LOG_COLLECTOR_URL', 'http://localhost:5000/logs')


class AttackSimulator:
    """Simulate unauthorized data exfiltration"""
    
    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.session = None
    
    def login_as_user(self, username: str, password: str) -> bool:
        """
        Authenticate sebagai user (simulated)
        Di real scenario, ini would use S3 credentials
        """
        logger.info(f"[ATTACKER] Logging in as user: {username}")
        # Simulate successful login
        return True
    
    def generate_log_entry(self, 
                          user_id: str,
                          operation: str,
                          object_name: str,
                          file_size: int,
                          source_ip: Optional[str] = None) -> Dict:
        """Generate access log entry untuk dikirim ke log collector"""
        
        if source_ip is None:
            source_ip = self._generate_random_ip()
        
        return {
            'time': datetime.now().isoformat() + 'Z',
            'source_ip': source_ip,
            'requestParameters': {
                'principalId': user_id,
                'sourceIPAddress': source_ip,
            },
            'requestUserAgent': f'attacker-tool/{user_id}',
            'statusCode': 200,
            'api': operation,
            'bucket': MINIO_BUCKET,
            'object': object_name,
            'objectSize': file_size,
            'userAgent': 'S3',
            'timestamp': datetime.now().isoformat() + 'Z'
        }
    
    def send_log_entry(self, log_entry: Dict) -> bool:
        """Send log entry ke log collector"""
        try:
            response = requests.post(LOG_COLLECTOR_URL, json=log_entry, timeout=5)
            if response.status_code == 200:
                logger.info(f"Log entry sent successfully: {log_entry.get('object')}")
                return True
            else:
                logger.warning(f"Failed to send log: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error sending log: {e}")
            return False
    
    def scenario_1_normal_operations(self, duration_seconds: int = 60):
        """
        Scenario 1: Simulate normal user operations (baseline)
        - Upload dan download beberapa file
        - Spread across normal working hours
        """
        logger.info("=" * 60)
        logger.info("SCENARIO 1: Normal User Operations (Baseline)")
        logger.info("=" * 60)
        
        normal_files = ['document.pdf', 'spreadsheet.xlsx', 'image.jpg', 'report.docx']
        start_time = time.time()
        
        while time.time() - start_time < duration_seconds:
            user = random.choice(list(NORMAL_USERS.keys()))
            operation = random.choice(['GET', 'PUT'])
            file_name = random.choice(normal_files)
            size = NORMAL_FILE_SIZE_KB * random.randint(1, 3)  # 100-300 KB
            
            log_entry = self.generate_log_entry(user, operation, file_name, size)
            self.send_log_entry(log_entry)
            
            logger.info(f"[NORMAL] User {user} - {operation} - {file_name} ({size} KB)")
            time.sleep(random.randint(2, 5))
    
    def scenario_2_bulk_download_attack(self, attacker: str, target_files: int = 10):
        """
        Scenario 2: Bulk download attack
        - Attacker login sebagai compromised user
        - Download banyak file dalam short timeframe
        - Dari same IP (atau bisa varied)
        """
        logger.info("=" * 60)
        logger.info("SCENARIO 2: Bulk Download Attack")
        logger.info(f"Attacker: {attacker}, Target: {target_files} files")
        logger.info("=" * 60)
        
        attacker_ip = self._generate_random_ip()
        files_to_steal = SENSITIVE_FILES[:target_files]
        
        # Rapid-fire downloads
        for i, file_name in enumerate(files_to_steal):
            size = NORMAL_FILE_SIZE_KB * random.randint(10, 50)  # Larger files
            
            log_entry = self.generate_log_entry(
                attacker,
                'GET',
                file_name,
                size,
                source_ip=attacker_ip
            )
            
            self.send_log_entry(log_entry)
            logger.warning(f"[ATTACK] Bulk download {i+1}/{target_files}: {file_name} - {attacker_ip}")
            
            time.sleep(0.5)  # Very short delay = suspicious pattern
    
    def scenario_3_multi_ip_access(self, attacker: str, target_files: int = 5, num_ips: int = 4):
        """
        Scenario 3: Access dari multiple IPs (simulating VPN/Proxy hopping)
        - Attacker login dari berbagai IP addresses
        - Download files dari different locations
        - Suspicious geographic distribution
        """
        logger.info("=" * 60)
        logger.info(f"SCENARIO 3: Multi-IP Access Attack ({num_ips} different IPs)")
        logger.info(f"Attacker: {attacker}, Target: {target_files} files")
        logger.info("=" * 60)
        
        ips = [self._generate_random_ip() for _ in range(num_ips)]
        files_to_access = SENSITIVE_FILES[:target_files]
        
        for ip in ips:
            for file_name in files_to_access:
                size = NORMAL_FILE_SIZE_KB * random.randint(5, 20)
                
                log_entry = self.generate_log_entry(
                    attacker,
                    'GET',
                    file_name,
                    size,
                    source_ip=ip
                )
                
                self.send_log_entry(log_entry)
                logger.warning(f"[ATTACK] Access from {ip}: {file_name}")
                
                time.sleep(1)
    
    def scenario_4_off_hours_access(self, attacker: str, target_files: int = 3):
        """
        Scenario 4: Access diluar jam kerja (weekend, malam hari)
        - Unusual access pattern
        - Normal users tidak aktif pada waktu ini
        """
        logger.info("=" * 60)
        logger.info("SCENARIO 4: Off-Hours Access")
        logger.info(f"Attacker: {attacker}, Target: {target_files} files")
        logger.info("=" * 60)
        
        # Simulate late night access (2 AM)
        attacker_ip = self._generate_random_ip()
        files = SENSITIVE_FILES[:target_files]
        
        for file_name in files:
            # Create log entry dengan timestamp off-hours
            log_entry = self.generate_log_entry(attacker, 'GET', file_name, 1024 * random.randint(10, 50), attacker_ip)
            
            # Modify timestamp to off-hours
            now = datetime.fromisoformat(log_entry['time'].replace('Z', '+00:00'))
            off_hours = now.replace(hour=2, minute=random.randint(0, 59))
            log_entry['time'] = off_hours.isoformat() + 'Z'
            log_entry['timestamp'] = log_entry['time']
            
            self.send_log_entry(log_entry)
            logger.warning(f"[ATTACK] Off-hours access: {file_name} at {off_hours.strftime('%Y-%m-%d %H:%M:%S')}")
            
            time.sleep(1)
    
    def scenario_5_sensitive_file_targeting(self, attacker: str):
        """
        Scenario 5: Targeted sensitive file access
        - Specifically target known sensitive files
        - Pattern suggests insider knowledge
        - High risk files accessed multiple times
        """
        logger.info("=" * 60)
        logger.info("SCENARIO 5: Targeted Sensitive File Access")
        logger.info(f"Attacker: {attacker}")
        logger.info("=" * 60)
        
        attacker_ip = self._generate_random_ip()
        
        # Focus on most sensitive files
        critical_files = SENSITIVE_FILES[:3]
        
        for file_name in critical_files:
            # Multiple accesses to same file (exfiltration verification)
            for attempt in range(3):
                size = 1024 * random.randint(50, 200)
                
                log_entry = self.generate_log_entry(
                    attacker,
                    'GET',
                    file_name,
                    size,
                    source_ip=attacker_ip
                )
                
                self.send_log_entry(log_entry)
                logger.warning(f"[ATTACK] Sensitive file access #{attempt+1}: {file_name}")
                
                time.sleep(2)
    
    def _generate_random_ip(self) -> str:
        """Generate random IP address"""
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"


# ============ MAIN ============

def main():
    parser = argparse.ArgumentParser(
        description='Forensic Research - Attack Simulation'
    )
    parser.add_argument('scenario', 
                       choices=['normal', 'bulk_download', 'multi_ip', 'off_hours', 'sensitive', 'full'],
                       help='Attack scenario to simulate')
    parser.add_argument('--attacker', default='attacker1', help='Attacker username')
    parser.add_argument('--files', type=int, default=5, help='Number of files to target')
    parser.add_argument('--ips', type=int, default=3, help='Number of IPs (for multi_ip scenario)')
    parser.add_argument('--duration', type=int, default=60, help='Duration for normal operations (seconds)')
    
    args = parser.parse_args()
    
    logger.info(f"Attack Simulator started - Scenario: {args.scenario}")
    
    simulator = AttackSimulator(MINIO_ENDPOINT)
    
    if args.scenario == 'normal':
        simulator.scenario_1_normal_operations(duration_seconds=args.duration)
    
    elif args.scenario == 'bulk_download':
        simulator.scenario_2_bulk_download_attack(args.attacker, target_files=args.files)
    
    elif args.scenario == 'multi_ip':
        simulator.scenario_3_multi_ip_access(args.attacker, target_files=args.files, num_ips=args.ips)
    
    elif args.scenario == 'off_hours':
        simulator.scenario_4_off_hours_access(args.attacker, target_files=args.files)
    
    elif args.scenario == 'sensitive':
        simulator.scenario_5_sensitive_file_targeting(args.attacker)
    
    elif args.scenario == 'full':
        # Run all scenarios in sequence
        logger.info("Running FULL attack simulation sequence")
        simulator.scenario_1_normal_operations(duration_seconds=30)
        simulator.scenario_2_bulk_download_attack(args.attacker, target_files=5)
        time.sleep(2)
        simulator.scenario_3_multi_ip_access(args.attacker, target_files=4, num_ips=3)
        time.sleep(2)
        simulator.scenario_4_off_hours_access(args.attacker, target_files=3)
        time.sleep(2)
        simulator.scenario_5_sensitive_file_targeting(args.attacker)
    
    logger.info("Attack simulation complete")


if __name__ == '__main__':
    main()

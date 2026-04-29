#!/usr/bin/env python3
"""
Shared ML Utilities Module
Common utilities for dataset preparation, training, and prediction
Reduces code duplication across ML scripts
"""

import json
import logging
import sqlite3
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import random

# ============================================================================
# Logging Configuration
# ============================================================================

def setup_logger(name: str, log_file: str = None) -> logging.Logger:
    """Configure and return a logger instance"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

# ============================================================================
# Database Utilities
# ============================================================================

def get_db_connection(db_path: str):
    """Create and configure SQLite database connection"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def execute_db_query(db_path: str, query: str) -> List[Dict]:
    """Execute database query and return results as list of dicts"""
    try:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(query)
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Database query failed: {e}")
        return []

# ============================================================================
# Data Validation & Cleaning
# ============================================================================

def extract_first_octet(ip: any) -> int:
    """Safely extract first octet from IP address"""
    try:
        if isinstance(ip, str):
            parts = ip.split('.')
            return int(parts[0]) if len(parts) > 0 else 0
        return 0
    except (ValueError, IndexError, AttributeError):
        return 0

def parse_timestamp(timestamp: str) -> Optional[datetime]:
    """Parse ISO8601 timestamp with UTC timezone"""
    try:
        return pd.to_datetime(timestamp, format='ISO8601', utc=True)
    except Exception:
        return None

def safe_get(obj: Dict, key: str, default=None):
    """Safely get value from dictionary with default fallback"""
    try:
        return obj.get(key, default)
    except (AttributeError, TypeError):
        return default

# ============================================================================
# Feature Engineering
# ============================================================================

def extract_time_features(timestamp: str) -> Tuple[int, int, int]:
    """Extract hour, day of week, and business hours flag from timestamp"""
    try:
        dt = pd.to_datetime(timestamp, format='ISO8601', utc=True)
        hour = dt.hour
        day_of_week = dt.dayofweek
        is_business = 1 if 8 <= hour < 17 else 0
        return hour, day_of_week, is_business
    except Exception:
        return 0, 0, 0

def is_sensitive_file(filename: str) -> int:
    """Check if file is in sensitive file watchlist"""
    sensitive_patterns = [
        'password', 'secret', 'key', 'token', 'api', 'config',
        'credential', 'auth', 'private', 'encrypted', 'backup'
    ]
    filename_lower = str(filename).lower()
    return 1 if any(pattern in filename_lower for pattern in sensitive_patterns) else 0

# ============================================================================
# File I/O Utilities
# ============================================================================

def save_dataframe(df: pd.DataFrame, filepath: str, format='csv'):
    """Save dataframe to file with error handling"""
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        if format == 'csv':
            df.to_csv(filepath, index=False)
        elif format == 'json':
            df.to_json(filepath, orient='records', indent=2)
        return True
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to save {filepath}: {e}")
        return False

def load_dataframe(filepath: str) -> Optional[pd.DataFrame]:
    """Load dataframe from file with error handling"""
    try:
        if filepath.endswith('.csv'):
            return pd.read_csv(filepath)
        elif filepath.endswith('.json'):
            return pd.read_json(filepath)
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to load {filepath}: {e}")
    return None

def save_json(data: dict, filepath: str) -> bool:
    """Save dictionary as JSON with error handling"""
    try:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to save JSON {filepath}: {e}")
        return False

def load_json(filepath: str) -> Optional[dict]:
    """Load JSON file with error handling"""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to load JSON {filepath}: {e}")
    return None

# ============================================================================
# Statistics & Reporting
# ============================================================================

def print_dataset_stats(df: pd.DataFrame, name: str = "Dataset"):
    """Print comprehensive dataset statistics"""
    logger = logging.getLogger(__name__)
    logger.info(f"\n{'='*60}")
    logger.info(f"📊 {name} Statistics")
    logger.info(f"{'='*60}")
    logger.info(f"Total Samples: {len(df)}")
    logger.info(f"Features: {len(df.columns)}")
    logger.info(f"Memory Usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
    
    if 'is_anomaly' in df.columns:
        anomalies = df[df['is_anomaly'] == 1].shape[0]
        normal = df[df['is_anomaly'] == 0].shape[0]
        anomaly_ratio = (anomalies / len(df)) * 100
        logger.info(f"Anomalies: {anomalies} ({anomaly_ratio:.1f}%)")
        logger.info(f"Normal: {normal} ({100-anomaly_ratio:.1f}%)")
    
    logger.info(f"{'='*60}\n")

def print_model_performance(metrics: Dict) -> None:
    """Print model performance metrics in formatted table"""
    logger = logging.getLogger(__name__)
    logger.info(f"\n{'='*60}")
    logger.info("📈 Model Performance Metrics")
    logger.info(f"{'='*60}")
    for metric_name, value in metrics.items():
        logger.info(f"{metric_name:.<40} {value:.4f}")
    logger.info(f"{'='*60}\n")

# ============================================================================
# Constants & Configuration
# ============================================================================

DEFAULT_DB_PATH = 'data/forensic.db'
DEFAULT_ML_DATASETS_DIR = 'data/ml_datasets'
DEFAULT_MODELS_DIR = 'models'
DEFAULT_RESULTS_DIR = 'result'

SENSITIVE_FILES = {
    'password', 'secret', 'key', 'token', 'api', 'config',
    'credential', 'auth', 'private', 'encrypted', 'backup'
}

FEATURE_NAMES = [
    'hour_of_day',
    'day_of_week',
    'is_business_hours',
    'ip_first_octet',
    'bytes_mb',
    'is_large_transfer',
    'user_id',
    'action_encoded',
    'object_name_length',
    'is_sensitive_file',
    'source',
    'is_anomaly'
]

# ============================================================================
# Export Public API
# ============================================================================

__all__ = [
    'setup_logger',
    'get_db_connection',
    'execute_db_query',
    'extract_first_octet',
    'parse_timestamp',
    'safe_get',
    'extract_time_features',
    'is_sensitive_file',
    'save_dataframe',
    'load_dataframe',
    'save_json',
    'load_json',
    'print_dataset_stats',
    'print_model_performance',
    'DEFAULT_DB_PATH',
    'DEFAULT_ML_DATASETS_DIR',
    'DEFAULT_MODELS_DIR',
    'DEFAULT_RESULTS_DIR',
    'SENSITIVE_FILES',
    'FEATURE_NAMES',
]

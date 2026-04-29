#!/usr/bin/env python3
"""
Machine Learning Dataset Preparation
Combines internal (forensic) and external (synthetic) datasets for anomaly detection training
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
from pathlib import Path

from ml_utils import (
    setup_logger, execute_db_query, save_dataframe, save_json,
    extract_first_octet, is_sensitive_file, extract_time_features,
    print_dataset_stats, DEFAULT_DB_PATH, DEFAULT_ML_DATASETS_DIR
)

# Setup logger
logger = setup_logger(__name__, 'logs/ml_dataset_preparation.log')

class DatasetPreparation:
    def __init__(self, db_path: str = DEFAULT_DB_PATH, output_dir: str = DEFAULT_ML_DATASETS_DIR):
        """Initialize dataset preparation pipeline"""
        self.db_path = db_path
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        logger.info(f"Initialized with DB: {db_path}, Output: {output_dir}")
        random.seed(42)
        np.random.seed(42)
        
    def extract_internal_dataset(self) -> pd.DataFrame:
        """Extract forensic events from SQLite database"""
        logger.info("📥 Extracting internal dataset from forensic database...")
        
        try:
            # Query database
            anomalies = execute_db_query(self.db_path, "SELECT * FROM anomalies")
            access_logs = execute_db_query(self.db_path, "SELECT * FROM access_logs")
            
            if not access_logs:
                logger.warning("No access logs found in database")
                return pd.DataFrame()
            
            # Convert to DataFrame with anomaly matching
            internal_data = []
            anomaly_map = {anom.get('timestamp'): anom.get('anomaly_type') for anom in anomalies if 'timestamp' in anom}
            
            for log in access_logs:
                timestamp = log.get('timestamp')
                is_anomaly = 1 if timestamp and timestamp in anomaly_map else 0
                internal_data.append({
                    'timestamp': timestamp,
                    'user': log.get('user'),
                    'source_ip': log.get('source_ip'),
                    'action': log.get('action'),
                    'bucket': log.get('bucket'),
                    'object': log.get('object'),
                    'bytes_transferred': log.get('bytes_transferred'),
                    'anomaly_type': anomaly_map.get(timestamp, 'NORMAL') if timestamp else 'NORMAL',
                    'is_anomaly': is_anomaly,
                    'source': 'internal'
                })
            
            df = pd.DataFrame(internal_data)
            logger.info(f"✅ Extracted {len(df)} internal events")
            logger.info(f"   Anomalies: {df['is_anomaly'].sum()}")
            logger.info(f"   Normal: {len(df) - df['is_anomaly'].sum()}")
            
            return df
            
        except Exception as e:
            logger.error(f"Failed to extract internal dataset: {e}")
            return pd.DataFrame()
    
    def generate_external_dataset(self, num_samples: int = 600) -> pd.DataFrame:
        """
        Generate realistic synthetic dataset with overlapping benign/malicious patterns.
        Malicious events intentionally share some features with benign to avoid trivial separation.
        """
        logger.info(f"🔄 Generating realistic synthetic dataset ({num_samples} samples)...")

        external_data = []
        benign_count = int(num_samples * 0.80)
        malicious_count = num_samples - benign_count

        normal_files = [f"report_{i}.docx" for i in range(50)] + \
                       [f"data_{i}.csv" for i in range(50)] + \
                       [f"image_{i}.png" for i in range(30)]
        sensitive_files = [
            'financial_report.xlsx', 'customer_database.csv', 'api_keys.txt',
            'private_certificates.pem', 'hr_records.xlsx', 'source_code_backup.zip',
            'architecture.pdf', 'credentials.json',
        ]
        all_files = normal_files + sensitive_files

        # ── Benign patterns ──────────────────────────────────────────────────
        for _ in range(benign_count):
            # Business hours with some after-hours noise (realistic)
            if random.random() < 0.15:
                hour = random.choice([7, 18, 19, 20])
            else:
                hour = random.randint(8, 17)
            ts = datetime.now() - timedelta(
                days=random.randint(1, 60),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            ts = ts.replace(hour=hour)
            # Benign users occasionally access sensitive files (false positive scenario)
            obj = random.choices(all_files, weights=[1]*len(normal_files) + [0.3]*len(sensitive_files))[0]
            # Benign transfers: mostly small, occasionally medium
            bytes_val = int(np.random.lognormal(mean=13, sigma=2))  # ~440KB median
            bytes_val = max(512, min(bytes_val, 50 * 1024 * 1024))  # cap at 50MB

            external_data.append({
                'timestamp': ts.isoformat() + 'Z',
                'user': f"user_{random.randint(1, 80)}",
                'source_ip': f"10.{random.randint(0,10)}.{random.randint(0,255)}.{random.randint(1,254)}",
                'action': random.choices(['GetObject', 'ListBucket', 'PutObject'], weights=[5, 3, 2])[0],
                'bucket': random.choice(['documents', 'shared', 'archive', 'backup']),
                'object': obj,
                'bytes_transferred': bytes_val,
                'anomaly_type': 'NORMAL',
                'is_anomaly': 0,
                'source': 'synthetic_benign',
            })

        # ── Malicious patterns ───────────────────────────────────────────────
        malicious_patterns = [
            'BULK_DOWNLOAD', 'SENSITIVE_FILE_ACCESS',
            'MULTIPLE_IP_ADDRESSES', 'UNUSUAL_HOURS_ACCESS',
        ]
        for _ in range(malicious_count):
            pattern = random.choice(malicious_patterns)

            if pattern == 'UNUSUAL_HOURS_ACCESS':
                hour = random.choice([0, 1, 2, 3, 22, 23])
            elif pattern == 'BULK_DOWNLOAD':
                hour = random.randint(8, 17)  # bulk during business hours too
            else:
                hour = random.randint(0, 23)

            ts = datetime.now() - timedelta(
                days=random.randint(0, 60),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            ts = ts.replace(hour=hour)

            # Malicious: prefer sensitive files but not exclusively
            obj = random.choices(all_files, weights=[0.2]*len(normal_files) + [3]*len(sensitive_files))[0]

            if pattern == 'BULK_DOWNLOAD':
                bytes_val = random.randint(80 * 1024 * 1024, 400 * 1024 * 1024)
            elif pattern == 'MULTIPLE_IP_ADDRESSES':
                bytes_val = random.randint(1 * 1024 * 1024, 30 * 1024 * 1024)
            else:
                bytes_val = random.randint(5 * 1024 * 1024, 200 * 1024 * 1024)

            # Attacker IPs: mix of internal and external
            if random.random() < 0.4:
                ip = f"10.{random.randint(0,10)}.{random.randint(0,255)}.{random.randint(1,254)}"
            else:
                ip = f"{random.randint(100,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

            external_data.append({
                'timestamp': ts.isoformat() + 'Z',
                'user': f"user_{random.randint(1, 80)}",  # same user pool — harder to separate
                'source_ip': ip,
                'action': random.choices(['GetObject', 'ListBucket'], weights=[8, 2])[0],
                'bucket': random.choice(['documents', 'shared', 'sensitive_data']),
                'object': obj,
                'bytes_transferred': bytes_val,
                'anomaly_type': pattern,
                'is_anomaly': 1,
                'source': 'synthetic_malicious',
            })

        df = pd.DataFrame(external_data).sample(frac=1, random_state=42).reset_index(drop=True)
        logger.info(f"✅ Generated {len(df)} synthetic samples")
        logger.info(f"   Benign: {len(df[df['is_anomaly'] == 0])}")
        logger.info(f"   Malicious: {len(df[df['is_anomaly'] == 1])}")
        return df
    
    def feature_engineering(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create ML-ready features from raw data"""
        logger.info("🔧 Engineering features...")
        
        try:
            df_features = df.copy()
            
            # Time-based features
            df_features['timestamp_dt'] = pd.to_datetime(df_features['timestamp'], format='ISO8601', utc=True)
            df_features['hour_of_day'] = df_features['timestamp_dt'].dt.hour
            df_features['day_of_week'] = df_features['timestamp_dt'].dt.dayofweek
            df_features['is_business_hours'] = (
                (df_features['hour_of_day'] >= 8) & (df_features['hour_of_day'] <= 17)
            ).astype(int)
            
            # IP-based features
            df_features['ip_first_octet'] = df_features['source_ip'].apply(extract_first_octet)
            
            # Bytes transferred features
            df_features['bytes_mb'] = df_features['bytes_transferred'] / (1024 * 1024)
            df_features['is_large_transfer'] = (df_features['bytes_mb'] > 100).astype(int)
            
            # User and action features
            df_features['user_id'] = pd.factorize(df_features['user'])[0]
            df_features['action_encoded'] = pd.factorize(df_features['action'])[0]
            
            # Object name features
            df_features['object_name_length'] = df_features['object'].str.len()
            df_features['is_sensitive_file'] = df_features['object'].apply(is_sensitive_file)
            
            # Add source encoding — EXCLUDED from ML features to prevent leakage
            # (source label directly encodes benign/malicious origin)
            df_features['source_encoded'] = pd.factorize(df_features['source'])[0]
            
            new_features_count = len([c for c in df_features.columns if c not in df.columns])
            logger.info(f"✅ Created {new_features_count} new features")
            
            return df_features
            
        except Exception as e:
            logger.error(f"Feature engineering failed: {e}")
            return df
    
    def combine_datasets(self, df_internal: pd.DataFrame, df_external: pd.DataFrame) -> pd.DataFrame:
        """Combine internal and external datasets"""
        logger.info("📦 Combining internal and external datasets...")
        
        try:
            # Ensure same columns
            common_cols = list(set(df_internal.columns) & set(df_external.columns))
            df_combined = pd.concat([
                df_internal[common_cols],
                df_external[common_cols]
            ], ignore_index=True)
            
            # Shuffle
            df_combined = df_combined.sample(frac=1).reset_index(drop=True)
            
            total = len(df_combined)
            anomalies = df_combined['is_anomaly'].sum()
            anomaly_pct = (anomalies / total) * 100
            
            logger.info(f"✅ Combined dataset: {total} samples")
            logger.info(f"   Anomalies: {anomalies} ({anomaly_pct:.1f}%)")
            logger.info(f"   Normal: {total - anomalies} ({100-anomaly_pct:.1f}%)")
            
            return df_combined
            
        except Exception as e:
            logger.error(f"Failed to combine datasets: {e}")
            return pd.DataFrame()
    
    def save_datasets(self, df_internal: pd.DataFrame, df_external: pd.DataFrame,
                      df_combined: pd.DataFrame, df_features: pd.DataFrame) -> dict:
        """Save datasets to files"""
        logger.info("💾 Saving datasets...")
        
        try:
            files = {}
            
            # Build file paths
            file_config = {
                'internal': (df_internal, 'internal_dataset'),
                'external': (df_external, 'external_dataset'),
                'combined': (df_combined, 'combined_dataset'),
                'features': (df_features, 'engineered_features')
            }
            
            # Save each dataset
            for key, (df, name) in file_config.items():
                csv_path = f"{self.output_dir}/{name}.csv"
                df.to_csv(csv_path, index=False)
                files[key] = csv_path
                logger.info(f"✅ {name}: {csv_path} ({len(df)} records)")
                
                # Save JSON version for first two
                if key in ['internal', 'external']:
                    json_path = f"{self.output_dir}/{name}.json"
                    df.to_json(json_path, orient='records', indent=2)
                    logger.info(f"   JSON: {json_path}")
            
            # Print statistics
            self._print_statistics(df_combined)
            
            return files
            
        except Exception as e:
            logger.error(f"Failed to save datasets: {e}")
            return {}
    
    def _print_statistics(self, df: pd.DataFrame) -> None:
        """Print dataset statistics"""
        logger.info("\n📊 Dataset Statistics:")
        logger.info(f"   Total records: {len(df)}")
        logger.info(f"   Features: {len(df.columns)}")
        
        if 'anomaly_type' in df.columns:
            logger.info("   Anomaly distribution:")
            for anomaly_type, count in df['anomaly_type'].value_counts().items():
                logger.info(f"     {anomaly_type}: {count}")
        
        logger.info(f"   Date range: {df['timestamp'].min()} to {df['timestamp'].max()}")
        logger.info(f"   Unique users: {df['user'].nunique()}")
        logger.info(f"   Unique IPs: {df['source_ip'].nunique()}")
        logger.info(f"   Unique objects: {df['object'].nunique()}")
    
    def prepare(self) -> dict:
        """Execute full preparation pipeline"""
        logger.info("=" * 70)
        logger.info("🚀 ML DATASET PREPARATION PIPELINE")
        logger.info("=" * 70)
        
        try:
            # Extract and generate
            df_internal = self.extract_internal_dataset()
            df_external = self.generate_external_dataset(num_samples=500)
            
            if df_internal.empty or df_external.empty:
                logger.error("Failed to create datasets")
                return {}
            
            # Combine
            df_combined = self.combine_datasets(df_internal, df_external)
            
            # Feature engineering
            df_features = self.feature_engineering(df_combined)
            
            # Save
            files = self.save_datasets(df_internal, df_external, df_combined, df_features)
            
            logger.info("=" * 70)
            logger.info("✅ DATASET PREPARATION COMPLETE")
            logger.info("=" * 70)
            
            return files
            
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            return {}


if __name__ == "__main__":
    try:
        prep = DatasetPreparation()
        prep.prepare()
    except KeyboardInterrupt:
        logger.info("\n⚠️  Process interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")

#!/usr/bin/env python3
"""
ML Model Prediction & Inference
Uses trained models to predict anomalies on new data
"""

import pickle
import sys
import argparse
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, List, Optional
from sklearn.preprocessing import StandardScaler

from ml_utils import (
    setup_logger, load_json, execute_db_query, extract_first_octet,
    is_sensitive_file, extract_time_features, DEFAULT_MODELS_DIR, DEFAULT_DB_PATH
)

logger = setup_logger(__name__, 'logs/ml_prediction.log')

class MLPredictor:
    def __init__(self, models_dir: str = DEFAULT_MODELS_DIR):
        """Initialize ML predictor"""
        self.models_dir = models_dir
        self.models = {}
        self.feature_names = None
        self.scaler = StandardScaler()
        self._load_models()
        logger.info(f"Predictor initialized with models from {models_dir}")
    
    def _load_models(self) -> bool:
        """Load trained models and feature names"""
        logger.info("📂 Loading trained models...")
        
        try:
            # Load feature names
            feature_file = f'{self.models_dir}/feature_names.json'
            self.feature_names = load_json(feature_file)
            
            if not self.feature_names:
                logger.error(f"Feature file not found: {feature_file}")
                return False
            
            logger.info(f"✅ Loaded {len(self.feature_names)} features")
            
            # Load models
            model_configs = [
                ('RandomForest', 'RandomForest_model.pkl'),
                ('GradientBoosting', 'GradientBoosting_model.pkl'),
                ('LogisticRegression', 'LogisticRegression_model.pkl')
            ]
            
            for model_name, model_file in model_configs:
                model_path = f'{self.models_dir}/{model_file}'
                try:
                    with open(model_path, 'rb') as f:
                        self.models[model_name] = pickle.load(f)
                    logger.info(f"✅ Loaded {model_name}")
                except FileNotFoundError:
                    logger.warning(f"⚠️  Model not found: {model_path}")
            
            return len(self.models) > 0
            
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            return False
    
    def prepare_features(self, raw_data: Dict) -> np.ndarray:
        """Convert raw data to ML features"""
        features = {}
        
        try:
            # Time-based features
            if 'timestamp' in raw_data:
                hour, day_of_week, is_business = extract_time_features(raw_data['timestamp'])
                features['hour_of_day'] = hour
                features['day_of_week'] = day_of_week
                features['is_business_hours'] = is_business
            
            # IP-based features
            ip = raw_data.get('source_ip', '0.0.0.0')
            features['ip_first_octet'] = extract_first_octet(ip)
            
            # Bytes features
            bytes_val = raw_data.get('bytes_transferred', 0)
            features['bytes_mb'] = bytes_val / (1024 * 1024)
            features['is_large_transfer'] = 1 if bytes_val > 100*1024*1024 else 0
            
            # User features
            user = raw_data.get('user', 'unknown')
            features['user_id'] = hash(user) % 100
            
            # Action features
            action_map = {'GetObject': 0, 'ListBucket': 1, 'PutObject': 2}
            features['action_encoded'] = action_map.get(raw_data.get('action'), 3)
            
            # Object features
            obj = raw_data.get('object', '')
            features['object_name_length'] = len(str(obj))
            features['is_sensitive_file'] = is_sensitive_file(obj)
            
            # Source encoding
            source_map = {'internal': 0, 'external_benign': 1, 'external_malicious': 2}
            features['source_encoded'] = source_map.get(raw_data.get('source'), 0)
            
            # Fill missing features
            for feature in self.feature_names:
                if feature not in features:
                    features[feature] = 0
            
            # Convert to array in correct order
            feature_array = np.array([[features.get(f, 0) for f in self.feature_names]])
            
            return feature_array
            
        except Exception as e:
            logger.error(f"Feature preparation failed: {e}")
            return np.zeros((1, len(self.feature_names)))
    
    def predict(self, raw_data: Dict, threshold: float = 0.5) -> Dict:
        """Predict anomaly for single data point"""
        X = self.prepare_features(raw_data)
        predictions = {}
        ensemble_score = 0.0
        
        try:
            for model_name, model in self.models.items():
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(X)[0]
                    score = float(proba[1])  # Probability of anomaly
                else:
                    score = float(model.predict(X)[0])
                
                predictions[model_name] = {
                    'probability': score,
                    'prediction': 1 if score >= threshold else 0
                }
                ensemble_score += score
            
            # Ensemble prediction (average)
            ensemble_avg = ensemble_score / len(self.models)
            ensemble_prediction = 1 if ensemble_avg >= threshold else 0
            
            predictions['ensemble'] = {
                'probability': ensemble_avg,
                'prediction': ensemble_prediction
            }
            
            return predictions
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return {}
    
    def predict_batch(self, data_list: List[Dict]) -> List[Dict]:
        """Predict anomalies for multiple data points"""
        results = []
        
        try:
            for data in data_list:
                prediction = self.predict(data)
                results.append({'data': data, 'predictions': prediction})
            
            return results
            
        except Exception as e:
            logger.error(f"Batch prediction failed: {e}")
            return []
    
    def predict_from_database(self, db_file: str = DEFAULT_DB_PATH, limit: int = 10) -> List[Dict]:
        """Predict on recent events from database"""
        try:
            events = execute_db_query(db_file, 
                f"SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT {limit}")
            
            if not events:
                logger.warning(f"No events found in database")
                return []
            
            logger.info(f"🔮 Predicting on {len(events)} recent events from database...")
            logger.info("=" * 70)
            
            results = []
            for event in events:
                prediction = self.predict(event)
                
                ensemble_pred = prediction['ensemble']['prediction']
                ensemble_prob = prediction['ensemble']['probability']
                
                result = {
                    'timestamp': event.get('timestamp'),
                    'user': event.get('user'),
                    'object': event.get('object'),
                    'bytes_mb': event.get('bytes_transferred', 0) / (1024*1024),
                    'ensemble_probability': f"{ensemble_prob:.2%}",
                    'ensemble_prediction': 'ANOMALY' if ensemble_pred else 'NORMAL',
                    'model_votes': {
                        model: f"{preds['probability']:.2%}"
                        for model, preds in prediction.items() if model != 'ensemble'
                    }
                }
                
                results.append(result)
                
                # Log result
                status = "🚨 ANOMALY" if ensemble_pred else "✅ NORMAL"
                obj = event.get('object') or 'unknown'
                user = event.get('user') or 'unknown'
                logger.info(f"{status} | {obj:40s} | P={ensemble_prob:.1%} | {user}")
            
            logger.info("=" * 70)
            
            return results
            
        except Exception as e:
            logger.error(f"Database prediction failed: {e}")
            return []
    
    def get_model_info(self) -> None:
        """Get information about trained models"""
        logger.info("\n📊 MODEL INFORMATION")
        logger.info("=" * 70)
        
        try:
            results_data = load_json(f'{self.models_dir}/training_results.json')
            
            if results_data:
                logger.info(f"Training Date: {results_data.get('timestamp')}")
                logger.info(f"Dataset: {results_data.get('dataset')}")
                logger.info(f"Training Samples: {results_data.get('train_size')}")
                logger.info(f"Test Samples: {results_data.get('test_size')}")
                logger.info(f"Features: {results_data.get('features')}")
                logger.info("\nModel Performance:")
                
                for model_name, metrics in results_data.get('models', {}).items():
                    logger.info(f"\n{model_name}:")
                    logger.info(f"  Test Accuracy: {metrics.get('test_accuracy', 0):.2%}")
                    logger.info(f"  Precision:     {metrics.get('precision', 0):.2%}")
                    logger.info(f"  Recall:        {metrics.get('recall', 0):.2%}")
                    logger.info(f"  F1-Score:      {metrics.get('f1', 0):.2%}")
                    if metrics.get('roc_auc'):
                        logger.info(f"  ROC-AUC:       {metrics.get('roc_auc', 0):.2%}")
            
        except Exception as e:
            logger.error(f"Failed to load model info: {e}")


def interactive_prediction() -> None:
    """Interactive prediction interface"""
    predictor = MLPredictor()
    
    if not predictor.models:
        logger.error("❌ No models loaded. Train models first!")
        return
    
    logger.info("\n🔮 INTERACTIVE ML PREDICTION")
    logger.info("=" * 70)
    logger.info("Enter event details for prediction (press Enter for defaults):\n")
    
    try:
        user = input("User [attacker1]: ").strip() or "attacker1"
        ip = input("Source IP [108.97.44.37]: ").strip() or "108.97.44.37"
        obj = input("Object/File [api_keys.txt]: ").strip() or "api_keys.txt"
        bytes_input = input("Bytes (MB) [500]: ").strip()
        bytes_mb = int(bytes_input) * 1024*1024 if bytes_input else 500*1024*1024
        
        data = {
            'timestamp': datetime.now().isoformat() + 'Z',
            'user': user,
            'source_ip': ip,
            'object': obj,
            'bytes_transferred': bytes_mb,
            'action': 'GetObject'
        }
        
        predictions = predictor.predict(data)
        
        logger.info("=" * 70)
        logger.info("PREDICTION RESULTS:")
        logger.info("=" * 70)
        for model, pred in predictions.items():
            status = "🚨 ANOMALY" if pred['prediction'] else "✅ NORMAL"
            logger.info(f"{model:20s}: {status} (confidence: {pred['probability']:.1%})")
        
    except KeyboardInterrupt:
        logger.info("\n⚠️  Interactive mode cancelled")
    except Exception as e:
        logger.error(f"Interactive prediction failed: {e}")


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description='ML Model Prediction & Inference')
        parser.add_argument('--db-predict', action='store_true', help='Predict on database events')
        parser.add_argument('--interactive', action='store_true', help='Interactive prediction mode')
        parser.add_argument('--info', action='store_true', help='Show model information')
        parser.add_argument('--limit', type=int, default=10, help='Limit for db predictions')
        
        args = parser.parse_args()
        
        predictor = MLPredictor()
        
        if args.info:
            predictor.get_model_info()
        elif args.db_predict:
            predictor.predict_from_database(limit=args.limit)
        elif args.interactive:
            interactive_prediction()
        else:
            predictor.predict_from_database()
    
    except KeyboardInterrupt:
        logger.info("\n⚠️  Process interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")

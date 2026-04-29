#!/usr/bin/env python3
"""
Machine Learning Training Pipeline for Anomaly Detection
Trains multiple models on combined internal/external datasets
"""

import pandas as pd
import numpy as np
import pickle
import warnings
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict, Optional

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score
)

from ml_utils import (
    setup_logger, load_dataframe, save_json, print_model_performance,
    DEFAULT_ML_DATASETS_DIR, DEFAULT_MODELS_DIR
)

warnings.filterwarnings('ignore')

logger = setup_logger(__name__, 'logs/ml_training.log')

class MLTrainingPipeline:
    def __init__(self, dataset_file: str = None, models_dir: str = DEFAULT_MODELS_DIR):
        """Initialize training pipeline"""
        if dataset_file is None:
            dataset_file = f'{DEFAULT_ML_DATASETS_DIR}/engineered_features.csv'
        
        self.dataset_file = dataset_file
        self.models_dir = models_dir
        Path(models_dir).mkdir(parents=True, exist_ok=True)
        
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.feature_names = None
        self.scaler = None
        self.models = {}
        self.results = {}
        
        logger.info(f"Initialized with dataset: {dataset_file}")
    
    def load_dataset(self) -> bool:
        """
        Load dataset dengan cross-dataset split:
        - Training: synthetic data (engineered_features.csv, source != cert)
        - Test: CERT Insider Threat data (source == cert_dataset)
        Jika tidak ada data CERT, fallback ke random 80/20 split.
        """
        logger.info("📥 Loading dataset (cross-dataset evaluation)...")

        try:
            df = load_dataframe(self.dataset_file)
            if df is None:
                logger.error(f"Dataset file not found: {self.dataset_file}")
                logger.info("   Run ml_dataset_preparation.py first!")
                return False

            logger.info(f"✅ Loaded {len(df)} samples, {len(df.columns)} features")

            drop_cols = ['timestamp', 'timestamp_dt', 'user', 'source_ip', 'action',
                         'bucket', 'object', 'anomaly_type', 'source', 'ip_octets',
                         'source_encoded']  # drop: encodes benign/malicious origin directly
            feature_cols = [c for c in df.columns if c not in drop_cols + ['is_anomaly']]

            X = df[feature_cols].fillna(0)
            y = df['is_anomaly']
            self.feature_names = feature_cols

            # Cross-dataset split: CERT data as held-out test set
            cert_mask = df.get('source', pd.Series([''] * len(df))).str.startswith('cert')
            if cert_mask.sum() >= 10:
                logger.info(f"✅ Cross-dataset split: CERT data as test set ({cert_mask.sum()} samples)")
                self.X_train = X[~cert_mask].values
                self.X_test  = X[cert_mask].values
                self.y_train = y[~cert_mask].values
                self.y_test  = y[cert_mask].values
            else:
                logger.info("⚠️  No CERT data found — using stratified 80/20 split")
                self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
                    X.values, y.values, test_size=0.2, random_state=42, stratify=y
                )

            self.scaler = StandardScaler()
            self.X_train = self.scaler.fit_transform(self.X_train)
            self.X_test  = self.scaler.transform(self.X_test)

            anomaly_ratio = (self.y_train.sum() / len(self.y_train)) * 100
            logger.info(f"✅ Training set: {len(self.X_train)} samples  (anomaly: {anomaly_ratio:.1f}%)")
            logger.info(f"✅ Test set:     {len(self.X_test)} samples")
            logger.info(f"✅ Features:     {len(self.feature_names)}")
            return True

        except Exception as e:
            logger.error(f"Failed to load dataset: {e}")
            return False
    
    def train_random_forest(self) -> None:
        """Train Random Forest classifier"""
        logger.info("🌲 Training Random Forest...")
        
        model = RandomForestClassifier(
            n_estimators=100, max_depth=15, min_samples_split=5,
            min_samples_leaf=2, random_state=42, n_jobs=-1, verbose=0
        )
        
        model.fit(self.X_train, self.y_train)
        self.models['RandomForest'] = model
        self._evaluate_model('RandomForest', model)
    
    def train_gradient_boosting(self) -> None:
        """Train Gradient Boosting classifier"""
        logger.info("🚀 Training Gradient Boosting...")
        
        model = GradientBoostingClassifier(
            n_estimators=100, learning_rate=0.1, max_depth=5,
            min_samples_split=5, min_samples_leaf=2, random_state=42
        )
        
        model.fit(self.X_train, self.y_train)
        self.models['GradientBoosting'] = model
        self._evaluate_model('GradientBoosting', model)
    
    def train_logistic_regression(self) -> None:
        """Train Logistic Regression classifier"""
        logger.info("📊 Training Logistic Regression...")
        
        model = LogisticRegression(
            max_iter=1000, random_state=42, n_jobs=-1, verbose=0
        )
        
        model.fit(self.X_train, self.y_train)
        self.models['LogisticRegression'] = model
        self._evaluate_model('LogisticRegression', model)
    
    def _evaluate_model(self, model_name: str, model) -> None:
        """Evaluate model performance"""
        y_pred_train = model.predict(self.X_train)
        y_pred_test = model.predict(self.X_test)
        
        # Calculate metrics
        y_proba_test = model.predict_proba(self.X_test)[:, 1] if hasattr(model, 'predict_proba') else None
        roc_auc = roc_auc_score(self.y_test, y_proba_test) if y_proba_test is not None else None
        
        results = {
            'train_accuracy': float(accuracy_score(self.y_train, y_pred_train)),
            'test_accuracy': float(accuracy_score(self.y_test, y_pred_test)),
            'precision': float(precision_score(self.y_test, y_pred_test, zero_division=0)),
            'recall': float(recall_score(self.y_test, y_pred_test, zero_division=0)),
            'f1': float(f1_score(self.y_test, y_pred_test, zero_division=0)),
            'roc_auc': float(roc_auc) if roc_auc else None,
            'confusion_matrix': confusion_matrix(self.y_test, y_pred_test).tolist()
        }
        
        self.results[model_name] = results
        
        logger.info(f"   Train Accuracy:  {results['train_accuracy']:.4f}")
        logger.info(f"   Test Accuracy:   {results['test_accuracy']:.4f}")
        logger.info(f"   Precision:       {results['precision']:.4f}")
        logger.info(f"   Recall:          {results['recall']:.4f}")
        logger.info(f"   F1-Score:        {results['f1']:.4f}")
        if roc_auc:
            logger.info(f"   ROC-AUC:         {roc_auc:.4f}")
    
    def save_models(self) -> bool:
        """Save trained models"""
        logger.info("💾 Saving models...")
        
        try:
            for model_name, model in self.models.items():
                model_file = f'{self.models_dir}/{model_name}_model.pkl'
                with open(model_file, 'wb') as f:
                    pickle.dump(model, f)
                logger.info(f"   ✅ Saved {model_name} to {model_file}")
            
            # Save feature names
            feature_file = f'{self.models_dir}/feature_names.json'
            save_json(self.feature_names, feature_file)
            logger.info(f"   ✅ Saved feature names to {feature_file}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
            return False
    
    def save_results(self) -> bool:
        """Save training results"""
        logger.info("📊 Saving results...")
        
        try:
            results_data = {
                'timestamp': datetime.now().isoformat(),
                'dataset': self.dataset_file,
                'train_size': int(len(self.X_train)),
                'test_size': int(len(self.X_test)),
                'features': len(self.feature_names),
                'feature_names': self.feature_names,
                'models': self.results
            }
            
            results_file = f'{self.models_dir}/training_results.json'
            save_json(results_data, results_file)
            logger.info(f"✅ Saved results to {results_file}")
            
            # Print summary
            logger.info("=" * 70)
            logger.info("🏆 MODEL PERFORMANCE SUMMARY")
            logger.info("=" * 70)
            for model_name, results in self.results.items():
                logger.info(f"\n{model_name}:")
                logger.info(f"  Test Accuracy: {results['test_accuracy']:.2%}")
                logger.info(f"  Precision:     {results['precision']:.2%}")
                logger.info(f"  Recall:        {results['recall']:.2%}")
                logger.info(f"  F1-Score:      {results['f1']:.2%}")
                if results.get('roc_auc'):
                    logger.info(f"  ROC-AUC:       {results['roc_auc']:.2%}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            return False
    
    def train(self) -> bool:
        """Execute full training pipeline"""
        logger.info("=" * 70)
        logger.info("🤖 ML TRAINING PIPELINE")
        logger.info("=" * 70)
        
        try:
            # Load dataset
            if not self.load_dataset():
                return False
            
            # Train all models
            self.train_random_forest()
            self.train_gradient_boosting()
            self.train_logistic_regression()
            
            # Save models and results
            if not (self.save_models() and self.save_results()):
                return False
            
            logger.info("=" * 70)
            logger.info("✅ TRAINING COMPLETE")
            logger.info("=" * 70)
            
            return True
            
        except Exception as e:
            logger.error(f"Training pipeline failed: {e}")
            return False


if __name__ == "__main__":
    try:
        pipeline = MLTrainingPipeline()
        pipeline.train()
    except KeyboardInterrupt:
        logger.info("\n⚠️  Process interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")

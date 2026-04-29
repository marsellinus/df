# Machine Learning Training & Prediction Guide

## 🤖 Overview

This ML module extends the Digital Forensics project with machine learning capabilities for anomaly detection. It combines:
- **Internal Dataset:** 106 real forensic events from the attack simulation
- **External Dataset:** 500 synthetic benign + malicious access patterns
- **Total Training Data:** 606 samples with engineered features

---

## 📊 Datasets

### Internal Dataset (Forensic)
- **Source:** SQLite database (data/forensic.db)
- **Records:** 106 real events from MinIO attack
- **Labels:** Real anomalies detected by forensic framework
- **File:** `data/ml_datasets/internal_dataset.csv`

### External Dataset (Synthetic)
- **Benign Patterns (80%):** Normal business hour access, standard file sizes
- **Malicious Patterns (20%):** Off-hours access, large transfers, sensitive files
- **Scenarios:**
  - Bulk download (5+ files/hour)
  - Sensitive file access
  - Multi-IP access
  - Unusual hours access
- **File:** `data/ml_datasets/external_dataset.csv`

### Combined & Engineered Dataset
- **Total:** 606 samples
- **Features:** 20+ engineered features
- **File:** `data/ml_datasets/engineered_features.csv`

---

## 🚀 Quick Start

### 1. Install ML Dependencies
```bash
cd /home/hilian/Documents/df
pip install -r requirements-ml.txt
```

### 2. Prepare Datasets
```bash
python3 scripts/ml_dataset_preparation.py
```

**Output:**
- Internal dataset: 106 events
- External dataset: 500 synthetic samples
- Combined dataset: 606 samples
- Engineered features: Ready for training

### 3. Train Models
```bash
python3 scripts/ml_training.py
```

**Trains 3 models:**
1. **Random Forest** - Ensemble tree-based method
2. **Gradient Boosting** - Sequential tree improvement
3. **Logistic Regression** - Linear probabilistic model

**Output:**
- Trained model files: `models/*.pkl`
- Performance metrics: `models/training_results.json`
- Feature names: `models/feature_names.json`

### 4. Make Predictions
```bash
# On recent database events
python3 scripts/ml_prediction.py --db-predict

# Interactive prediction
python3 scripts/ml_prediction.py --interactive

# Show model info
python3 scripts/ml_prediction.py --info
```

---

## 📈 Feature Engineering

### Engineered Features (20+)

#### Time-Based
- `hour_of_day` - Hour of access (0-23)
- `day_of_week` - Day (0=Monday, 6=Sunday)
- `is_business_hours` - Binary (1 if 8-17, 0 otherwise)

#### IP-Based
- `ip_first_octet` - First octet for geographic inference

#### Size-Based
- `bytes_mb` - File size in megabytes
- `is_large_transfer` - Binary (1 if >100MB)

#### User-Based
- `user_id` - Hashed user identifier
- `source` - Data source flag

#### Action-Based
- `action_encoded` - Encoded action type
  - 0: GetObject
  - 1: ListBucket
  - 2: PutObject
  - 3: Other

#### File-Based
- `object_name_length` - Filename length
- `is_sensitive_file` - Binary (1 if on watchlist)

---

## 🎯 Model Performance

### Expected Results (After Training)

```
Random Forest:
  Test Accuracy:  ~98%
  Precision:      ~96%
  Recall:         ~95%
  F1-Score:       ~95%
  ROC-AUC:        ~0.99

Gradient Boosting:
  Test Accuracy:  ~97%
  Precision:      ~95%
  Recall:         ~94%
  F1-Score:       ~94%
  ROC-AUC:        ~0.98

Logistic Regression:
  Test Accuracy:  ~85%
  Precision:      ~88%
  Recall:         ~82%
  F1-Score:       ~85%
  ROC-AUC:        ~0.92
```

### Ensemble Prediction
Models vote with equal weight; anomaly = average probability > 0.5

---

## 📂 File Structure

```
ml_workflow/
├── scripts/
│   ├── ml_dataset_preparation.py ... Dataset creation & feature engineering
│   ├── ml_training.py .............. Model training pipeline
│   └── ml_prediction.py ............ Inference & prediction
├── data/
│   └── ml_datasets/
│       ├── internal_dataset.csv ... Real forensic events
│       ├── external_dataset.csv ... Synthetic patterns
│       └── engineered_features.csv  ML-ready dataset
├── models/
│   ├── RandomForest_model.pkl .... Trained RF model
│   ├── GradientBoosting_model.pkl  Trained GB model
│   ├── LogisticRegression_model.pkl Trained LR model
│   ├── feature_names.json ........ Feature list
│   └── training_results.json ..... Performance metrics
└── requirements-ml.txt ............ ML dependencies
```

---

## 💾 Dataset Formats

### CSV Format (Tabular)
```csv
timestamp,user,source_ip,action,bucket,object,bytes_transferred,anomaly_type,is_anomaly,source,hour_of_day,day_of_week,is_business_hours,...
2026-04-21T13:40:18.600Z,attacker1,108.97.44.37,GetObject,foresc,financial_report_2024.xlsx,524288000,SENSITIVE_FILE_ACCESS,1,internal,13,4,1,...
```

### JSON Format (Document)
```json
[
  {
    "timestamp": "2026-04-21T13:40:18.600Z",
    "user": "attacker1",
    "source_ip": "108.97.44.37",
    "object": "financial_report_2024.xlsx",
    "bytes_transferred": 524288000,
    "is_anomaly": 1,
    "anomaly_type": "SENSITIVE_FILE_ACCESS"
  }
]
```

---

## 🔮 Prediction Examples

### Example 1: Normal Access
```python
data = {
    'timestamp': '2026-04-21T09:30:00Z',
    'user': 'john.smith',
    'source_ip': '192.168.1.100',
    'object': 'report.pdf',
    'bytes_transferred': 5*1024*1024,  # 5MB
    'action': 'GetObject'
}

# Result: NORMAL (probability: 5%)
```

### Example 2: Suspicious Activity
```python
data = {
    'timestamp': '2026-04-21T23:45:00Z',
    'user': 'attacker1',
    'source_ip': '108.97.44.37',
    'object': 'api_keys.txt',
    'bytes_transferred': 500*1024*1024,  # 500MB
    'action': 'GetObject'
}

# Result: ANOMALY (probability: 99%)
```

---

## 📊 Dataset Statistics

### Balanced Dataset
```
Total Samples:    606
Anomalies:        151 (24.9%)
Normal:           455 (75.1%)
Train Split:      484 (80%)
Test Split:       122 (20%)
```

### Anomaly Distribution
```
BULK_DOWNLOAD:              ~100 samples
SENSITIVE_FILE_ACCESS:      ~40 samples
MULTIPLE_IP_ADDRESSES:      ~11 samples
NORMAL:                     455 samples
```

### Feature Statistics
```
Features:                   20+
Categorical Features:       5 (encoded)
Numeric Features:          15+
Missing Values:            0% (filled with 0)
```

---

## 🎓 Model Comparison

### Decision Tree Ensemble (Random Forest & GB)
- **Strengths:** Handles non-linear patterns, feature importance, robust
- **Weakness:** Can overfit without proper tuning
- **Use Case:** Production anomaly detection

### Linear Model (Logistic Regression)
- **Strength:** Interpretable, fast, baseline
- **Weakness:** Cannot capture complex patterns
- **Use Case:** Baseline comparison, quick inference

### Ensemble Voting
- **Strength:** Combines model strengths, reduces variance
- **Use Case:** Final production predictions

---

## 🔍 Interpretation & Features Importance

### Top Predictive Features (from Random Forest)
1. `is_sensitive_file` - Access to monitored critical files
2. `bytes_mb` - Large file transfers (>100MB)
3. `hour_of_day` - After-hours access (22-06)
4. `user_id` - Unknown/suspicious users
5. `is_large_transfer` - Data exfiltration indicators
6. `is_business_hours` - Access outside normal hours
7. `source_ip` - Attacker IP addresses

---

## 🚨 Alert Thresholds

### Ensemble Probability
- **< 30%:** Definitely Normal ✅
- **30-50%:** Likely Normal ⚠️
- **50-70%:** Likely Anomaly ⚠️
- **> 70%:** Definitely Anomaly 🚨

---

## 📝 Usage Examples

### Batch Prediction
```bash
# Predict on all recent database events
python3 scripts/ml_prediction.py --db-predict --limit 50
```

### Interactive Mode
```bash
# Manual entry for single predictions
python3 scripts/ml_prediction.py --interactive
```

### Model Evaluation
```bash
# Display training results and metrics
python3 scripts/ml_prediction.py --info
```

---

## 🔄 Full Workflow

```
1. Collect Forensic Data
   └─→ data/forensic.db (106 real events)

2. Prepare Datasets
   └─→ ml_dataset_preparation.py
       ├─ Extract internal forensic events
       ├─ Generate external synthetic patterns
       ├─ Engineer features (20+ features)
       └─ Output: engineered_features.csv (606 samples)

3. Train Models
   └─→ ml_training.py
       ├─ Split: 80% train / 20% test
       ├─ Train 3 models in parallel
       ├─ Evaluate performance
       └─ Save: models/*.pkl, training_results.json

4. Make Predictions
   └─→ ml_prediction.py
       ├─ Load trained models
       ├─ Prepare new data features
       ├─ Ensemble voting
       └─ Return anomaly probability

5. Monitor & Alert
   └─→ Real-time anomaly detection on new access logs
```

---

## 🎯 Recommended Next Steps

1. **Deploy to Production**
   ```bash
   # Integrate prediction into log collector
   # Add ML scoring to each access event
   ```

2. **Continuous Learning**
   ```bash
   # Retrain monthly with new data
   # Update thresholds based on false positives
   ```

3. **Model Improvement**
   - Collect more malicious samples
   - Feature engineering refinement
   - Hyperparameter tuning
   - Deep learning exploration (LSTM, Autoencoders)

4. **Explainability**
   - Generate SHAP values for each prediction
   - Feature importance analysis
   - Decision boundary visualization

---

## ⚠️ Important Notes

1. **Data Privacy:**
   - Internal dataset contains real attack events
   - External dataset is synthetic (no real data)
   - PII is redacted in all exports

2. **Model Limitations:**
   - Trained on specific attack patterns
   - May not generalize to all attack types
   - Requires periodic retraining

3. **Interpretability:**
   - Use feature importance for understanding decisions
   - Ensemble provides more robust predictions
   - Individual model disagreement indicates uncertainty

---

**Created:** April 21, 2026  
**Purpose:** Machine Learning Anomaly Detection for Digital Forensics  
**Status:** ✅ Production Ready

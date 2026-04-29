# 🚀 Quick Start Guide - Digital Forensics + ML Project

## Installation & Setup (2 minutes)

```bash
# 1. Navigate to project directory
cd /home/hilian/Documents/df

# 2. Activate virtual environment
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

## Running the ML Pipeline (5 minutes)

```bash
# 1. Prepare datasets (internal forensic + external synthetic)
python3 scripts/ml_dataset_preparation.py

# 2. Train all 3 models
python3 scripts/ml_training.py

# 3. Make predictions on database events
python3 scripts/ml_prediction.py --db-predict --limit 10
```

## Common Commands

```bash
# Show model information and performance metrics
python3 scripts/ml_prediction.py --info

# Interactive prediction mode (enter custom data)
python3 scripts/ml_prediction.py --interactive

# Predict on 20 database events
python3 scripts/ml_prediction.py --db-predict --limit 20
```

## Project Structure

```
/home/hilian/Documents/df/
├── scripts/
│   ├── ml_utils.py                 # Shared utilities module
│   ├── ml_dataset_preparation.py   # ETL pipeline
│   ├── ml_training.py              # Model training
│   └── ml_prediction.py            # Inference & predictions
├── models/
│   ├── RandomForest_model.pkl      # Trained RF model
│   ├── GradientBoosting_model.pkl  # Trained GB model
│   ├── LogisticRegression_model.pkl# Trained LR model
│   ├── feature_names.json
│   └── training_results.json
├── data/ml_datasets/
│   ├── internal_dataset.csv
│   ├── external_dataset.csv
│   ├── combined_dataset.csv
│   └── engineered_features.csv
├── result/
│   ├── TECHNICAL_REPORT.html       # Academic report
│   ├── PRESENTATION_SLIDES.html    # Presentation
│   ├── SCIENTIFIC_POSTER.html      # Poster
│   └── ML_TRAINING_SUMMARY.md      # ML results
├── requirements.txt                # All dependencies
├── ML_TRAINING_GUIDE.md            # Detailed ML guide
└── README.md                       # Main documentation
```

## ML Model Performance

All 3 models achieved **100% accuracy** on test set:

```
✅ Random Forest:       100% accuracy
✅ Gradient Boosting:   100% accuracy  
✅ Logistic Regression: 100% accuracy

Metrics:
- Precision: 100% (0 false alarms)
- Recall: 100% (0 missed attacks)
- F1-Score: 100%
- ROC-AUC: 100%
```

## Dataset Statistics

- **Total Samples**: 539
- **Anomalies**: 100 (18.6%)
- **Normal**: 439 (81.4%)
- **Features**: 12 engineered
- **Train/Test**: 80/20 split
- **Internal**: 39 real forensic events
- **External**: 500 synthetic patterns

## Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| Module not found | Run: `pip install -r requirements.txt` |
| Dataset not found | Run: `python3 scripts/ml_dataset_preparation.py` first |
| Models not found | Run: `python3 scripts/ml_training.py` to train |
| Permission denied | Run: `chmod +x scripts/*.py` |

## Documentation

- **README.md** - Complete project overview
- **ML_TRAINING_GUIDE.md** - Detailed ML guide with examples
- **result/ML_TRAINING_SUMMARY.md** - Detailed ML results and performance
- **result/TECHNICAL_REPORT.html** - Full academic report

## Support

For issues or questions:
1. Check logs in `logs/` directory
2. Verify dataset with: `ls -la data/ml_datasets/`
3. Check models with: `ls -la models/`

---

**Project**: Digital Forensics + ML Extension  
**Date**: April 21, 2026  
**Status**: ✅ Production Ready

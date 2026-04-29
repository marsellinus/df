# Quick Reference Guide

## 📊 Project Summary

This is a **Digital Forensics Research Project** that simulates and analyzes unauthorized data exfiltration attacks on cloud storage.

---

## 🚀 Quick Start

### 1. Check Status
```bash
docker compose ps
```
Expected: All 4 services UP

### 2. Run Attack Simulation
```bash
cd /home/hilian/Documents/df
python3 scripts/attack_simulator.py bulk_download --files 5
```

### 3. Detect Anomalies
```bash
curl -X POST http://localhost:5001/analyze
```

### 4. View Results
```bash
curl http://localhost:5001/report | python3 -m json.tool
```

---

## 🌐 Access Points

| Component | URL | Purpose |
|-----------|-----|---------|
| MinIO Console | http://localhost:9001 | Cloud storage UI |
| MinIO API | http://localhost:9000 | S3-compatible storage |
| Log Collector | http://localhost:5000 | Receive & parse logs |
| Analyzer | http://localhost:5001 | Detect anomalies |
| Dashboard | http://localhost:5002 | Visualization |

**Credentials:**
- User: `minioadmin`
- Password: `minioadmin`

---

## 📁 Project Structure

```
df/
├── result/                      # Forensic analysis outputs (THIS FOLDER)
│   ├── forensic_report.json    # Complete analysis report
│   ├── timeline.json           # Event timeline
│   ├── anomalies.json          # Detected anomalies
│   └── FORENSIC_ANALYSIS_REPORT.md  # Full documentation
│
├── config/                      # Configuration
│   ├── config.py              # Main settings
│   └── utils.py               # Helper utilities
│
├── scripts/                     # Simulation & analysis
│   ├── attack_simulator.py    # Attack scenarios
│   ├── log_collector.py       # Service: Log collection
│   └── offline_analyzer.py    # Standalone analysis
│
├── analysis/                    # Forensic engine
│   └── forensic_analyzer.py   # Service: Analysis & detection
│
├── dashboard/                   # Web UI
│   ├── app.py                 # Flask service
│   └── templates/dashboard.html  # Interactive UI
│
├── docker-compose.yml           # Container orchestration
├── Dockerfile.*                 # Service containers
└── data/                        # Generated data
    ├── forensic.db            # SQLite database
    ├── parsed_logs.json       # Structured logs
    └── forensic_report.json   # Report export
```

---

## 🎯 Attack Scenarios

### Available Scenarios
```
1. normal                 - Normal user operations (baseline)
2. bulk_download          - Rapid file downloads
3. multi_ip               - Access from multiple IPs
4. off_hours              - Access outside working hours
5. sensitive              - Targeted critical file access
6. full                   - All scenarios combined
```

### Run Specific Attack
```bash
python3 scripts/attack_simulator.py bulk_download --files 10
python3 scripts/attack_simulator.py multi_ip --ips 5
python3 scripts/attack_simulator.py sensitive
```

---

## 📊 Detected Anomalies

### Current Results (from last attack)

| Anomaly Type | Count | Severity | Files |
|--------------|-------|----------|-------|
| BULK_DOWNLOAD | 37 | HIGH | 13 files in 1 hour |
| SENSITIVE_FILE_ACCESS | 57 | CRITICAL | financial_report_2024.xlsx, technical_architecture.pdf, customer_database.csv, api_keys.txt, private_certificates.pem |
| MULTIPLE_IP_ADDRESSES | 12 | HIGH | 3+ IPs detected |

---

## 🔍 API Quick Reference

### Get Statistics
```bash
curl http://localhost:5000/logs/stats
```

### Submit Log Entry
```bash
curl -X POST http://localhost:5000/logs \
  -H 'Content-Type: application/json' \
  -d '{
    "time": "2024-01-15T10:00:00Z",
    "requestUserAgent": "user1",
    "sourceIP": "192.168.1.100",
    "api": "GetObject",
    "bucket": "foresc",
    "object": "document.pdf",
    "objectSize": 1024,
    "statusCode": 200,
    "userAgent": "aws-sdk-python"
  }'
```

### Run Analysis
```bash
curl -X POST http://localhost:5001/analyze
```

### Get Anomalies
```bash
curl http://localhost:5001/anomalies | jq '.anomalies | length'
```

### Get Timeline
```bash
curl http://localhost:5001/timeline | jq '.timeline | length'
```

### Get Report
```bash
curl http://localhost:5001/report | jq '.summary'
```

---

## 💾 Result Files Format

### forensic_report.json
```json
{
  "summary": {
    "total_access_logs": 106,
    "total_anomalies_detected": 106,
    "unique_users": 1,
    "unique_ips": 3
  },
  "anomaly_breakdown": {
    "BULK_DOWNLOAD": 37,
    "SENSITIVE_FILE_ACCESS": 57,
    "MULTIPLE_IP_ADDRESSES": 12
  },
  "high_severity_events": [...]
}
```

### timeline.json
Array of 106 events with chronological order:
```json
{
  "timestamp": "2026-04-08T13:40:18...",
  "user_id": "attacker1",
  "source_ip": "192.168.1.200",
  "operation": "GET",
  "object_name": "financial_report_2024.xlsx",
  "file_size": 1048576
}
```

### anomalies.json
Array of 106 detected anomalies:
```json
{
  "anomaly_type": "BULK_DOWNLOAD",
  "severity": "HIGH",
  "user_id": "attacker1",
  "source_ip": "192.168.1.200",
  "description": "Bulk download detected: 13 files, 388.00 MB",
  "evidence": {...}
}
```

---

## 🛠️ Troubleshooting

### Service Not Starting
```bash
# Check logs
docker compose logs [service-name]

# Restart services
docker compose restart

# Full restart
docker compose down
docker compose up -d
```

### Port Already in Use
```bash
# Check process using port
lsof -i :5000
lsof -i :5001
lsof -i :5002
lsof -i :9000
lsof -i :9001

# Kill process or change port in docker-compose.yml
```

### Database Issues
```bash
# Clear database (WARNING: loses all data)
rm data/forensic.db

# Recreate (service will auto-initialize)
docker compose restart forensic-analyzer
```

---

## 📈 Performance Metrics

Typical timing for full attack scenario:
- **Normal Operations:** 30 seconds
- **Bulk Download:** 5-10 seconds
- **Analysis:** 2-3 seconds
- **Report Generation:** 1-2 seconds

---

## 🔐 Security Notice

⚠️ **This is a research/educational project only.**
- Default credentials used (minioadmin:minioadmin)
- No encryption enabled
- Not suitable for production
- For research and learning purposes only

---

## 📝 Next Steps

1. **Explore Dashboard** → http://localhost:5002
2. **Review Reports** → Check result/*.json files
3. **Run Different Scenarios** → Try other attack patterns
4. **Modify Thresholds** → Edit config/config.py
5. **Add Custom Detectors** → Extend analysis/forensic_analyzer.py

---

**Last Updated:** 2026-04-08  
**Project Location:** /home/hilian/Documents/df  
**Status:** ✅ All Services Running

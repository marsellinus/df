"""
Standalone forensic analysis script
Bisa dijalankan di local untuk analyze already-collected logs
"""

import json
import csv
import argparse
import sys
from pathlib import Path
from datetime import datetime
from config.utils import DatabaseHelper, TimelineBuilder, ForensicLogger
from analysis.forensic_analyzer import AnomalyDetector
from config.config import DATA_DIR, LOG_DIR, ANOMALY_THRESHOLDS, SENSITIVE_FILES

# Setup logger
logger = ForensicLogger.setup_logger('offline_analyzer', LOG_DIR / 'offline_analysis.log')

def analyze_logs_from_file(json_file: Path):
    """Analyze logs dari JSON file"""
    logger.info(f"Starting analysis of {json_file}")
    
    if not json_file.exists():
        logger.error(f"File not found: {json_file}")
        return
    
    # Load logs
    with open(json_file, 'r') as f:
        logs = json.load(f)
    
    logger.info(f"Loaded {len(logs)} log entries")
    
    # Initialize database
    db = DatabaseHelper(DATA_DIR / 'forensic.db')
    
    # Insert logs to database
    for log in logs:
        db.insert_access_log(log)
    
    logger.info(f"Inserted logs to database")
    
    # Run analysis
    detector = AnomalyDetector()
    anomalies = detector.run_full_analysis(logs, SENSITIVE_FILES)
    
    # Store anomalies
    for anomaly in anomalies:
        anomaly['detected_at'] = datetime.now().isoformat()
        db.insert_anomaly(anomaly)
    
    logger.info(f"Detected {len(anomalies)} anomalies")
    
    # Export results
    timeline_builder = TimelineBuilder()
    timeline_builder.export_timeline_json(logs, DATA_DIR / 'attack_timeline.json')
    timeline_builder.export_timeline_csv(logs, DATA_DIR / 'attack_timeline.csv')
    
    # Generate report
    create_forensic_report(logs, anomalies)
    
    logger.info("Analysis complete. Results saved to /data/")


def create_forensic_report(logs: list, anomalies: list):
    """Create detailed forensic report"""
    
    report = {
        'report_title': 'Forensic Analysis Report: Unauthorized Data Exfiltration Detection',
        'report_date': datetime.now().isoformat(),
        'executive_summary': {
            'total_events': len(logs),
            'anomalies_detected': len(anomalies),
            'analysis_status': 'COMPLETE'
        },
        'findings': {
            'normal_operations': len([a for a in anomalies if a.get('severity') == 'INFO']),
            'medium_risk': len([a for a in anomalies if a.get('severity') == 'MEDIUM']),
            'high_risk': len([a for a in anomalies if a.get('severity') == 'HIGH']),
            'critical': len([a for a in anomalies if a.get('severity') == 'CRITICAL'])
        },
        'anomaly_details': anomalies,
        'timeline_summary': _create_timeline_summary(logs),
        'recommendations': _generate_recommendations(anomalies)
    }
    
    # Save report
    report_path = DATA_DIR / 'forensic_report.json'
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    logger.info(f"Report saved to {report_path}")
    
    # Also export as HTML
    _generate_html_report(report)


def _create_timeline_summary(logs: list) -> dict:
    """Create timeline summary"""
    if not logs:
        return {}
    
    logs_sorted = sorted(logs, key=lambda x: x.get('timestamp', ''))
    
    return {
        'first_event': logs_sorted[0].get('timestamp'),
        'last_event': logs_sorted[-1].get('timestamp'),
        'total_duration_events': len(logs_sorted),
        'event_rate': f"{len(logs_sorted) / 24:.2f} events/hour"  # Approximation
    }


def _generate_recommendations(anomalies: list) -> list:
    """Generate forensic recommendations"""
    recommendations = []
    
    anomaly_types = {}
    for anom in anomalies:
        atype = anom.get('anomaly_type')
        anomaly_types[atype] = anomaly_types.get(atype, 0) + 1
    
    if anomaly_types.get('BULK_DOWNLOAD', 0) > 0:
        recommendations.append("IMMEDIATE: Review bulk download incidents. Implement per-user download rate limits.")
    
    if anomaly_types.get('MULTIPLE_IP_ADDRESSES', 0) > 0:
        recommendations.append("HIGH: Investigate IP address changes. Consider enabling IP whitelist for sensitive operations.")
    
    if anomaly_types.get('UNUSUAL_HOURS_ACCESS', 0) > 0:
        recommendations.append("MEDIUM: Implement time-based access controls. Alert on off-hours sensitive file access.")
    
    if anomaly_types.get('SENSITIVE_FILE_ACCESS', 0) > 0:
        recommendations.append("CRITICAL: Implement security clearance for sensitive files. Add DLP (Data Loss Prevention) controls.")
    
    return recommendations


def _generate_html_report(report: dict):
    """Generate HTML version of report"""
    
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Forensic Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f5f5f5; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 20px; }}
            h1 {{ color: #d32f2f; }}
            h2 {{ color: #1976d2; }}
            .summary {{ background: #e3f2fd; padding: 15px; margin: 20px 0; }}
            table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background-color: #1976d2; color: white; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            .critical {{ color: #d32f2f; font-weight: bold; }}
            .high {{ color: #f57c00; font-weight: bold; }}
            .medium {{ color: #fbc02d; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 Forensic Analysis Report</h1>
            <p><strong>Report Generated:</strong> {report['report_date']}</p>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <ul>
                    <li><strong>Total Events Analyzed:</strong> {report['executive_summary']['total_events']}</li>
                    <li><strong>Anomalies Detected:</strong> {report['executive_summary']['anomalies_detected']}</li>
                    <li><strong>Status:</strong> {report['executive_summary']['analysis_status']}</li>
                </ul>
            </div>
            
            <h2>Findings</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                <tr>
                    <td class="critical">CRITICAL</td>
                    <td>{report['findings']['critical']}</td>
                </tr>
                <tr>
                    <td class="high">HIGH</td>
                    <td>{report['findings']['high_risk']}</td>
                </tr>
                <tr>
                    <td class="medium">MEDIUM</td>
                    <td>{report['findings']['medium_risk']}</td>
                </tr>
            </table>
            
            <h2>Recommendations</h2>
            <ul>
    """
    
    for rec in report['recommendations']:
        html_template += f"<li>{rec}</li>\n"
    
    html_template += """
            </ul>
        </div>
    </body>
    </html>
    """
    
    report_path = DATA_DIR / 'forensic_report.html'
    with open(report_path, 'w') as f:
        f.write(html_template)
    
    logger.info(f"HTML report saved to {report_path}")


def main():
    parser = argparse.ArgumentParser(description='Offline Forensic Analyzer')
    parser.add_argument('--input', default=str(DATA_DIR / 'parsed_logs.json'), help='Input JSON file')
    parser.add_argument('--output-dir', default=str(DATA_DIR), help='Output directory')
    
    args = parser.parse_args()
    
    analyze_logs_from_file(Path(args.input))


if __name__ == '__main__':
    main()

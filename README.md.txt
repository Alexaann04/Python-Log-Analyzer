# Python Log Analyzer with Splunk SIEM

## Project Overview

This project is a cybersecurity threat detection system developed using Python and Splunk SIEM.

The system analyzes authentication logs, detects failed login attempts, calculates anomaly scores using z-score statistical analysis, and visualizes suspicious activity in Splunk dashboards.

---

## Features

- Failed login detection
- Brute-force attack analysis
- Statistical anomaly detection
- Z-score calculation
- CSV report generation
- Splunk SIEM integration
- Dashboard visualization

---

## Technologies Used

- Python
- Pandas
- NumPy
- Regex
- Splunk Enterprise
- CSV Processing

---

## Detection Logic

The project uses statistical anomaly detection:

```
z = (x - μ) / σ
```

Where:

- x = current failed login count
- μ = average failed login count
- σ = standard deviation

Higher z-score indicates suspicious activity.

---

## Project Architecture

Raw Logs
↓
Python Parser
↓
Regex Extraction
↓
Statistical Analysis
↓
CSV Export
↓
Splunk SIEM
↓
Dashboard Visualization

---

## Screenshots

### Splunk Dashboard

![Dashboard](screenshots/dashboard.png)

### Splunk Results

![Results](screenshots/splunk_results.png)

### Python Output

![Python](screenshots/python_output.png)

---

## Future Improvements

- Real-time log monitoring
- GeoIP tracking
- Impossible travel detection
- Email alerting
- Machine learning integration
- Real attack simulation using Kali Linux

---

## Resume Description

Developed a Python-based cybersecurity log analysis and SIEM monitoring system integrating Splunk, regex parsing, and statistical anomaly detection to identify suspicious authentication activity and brute-force attacks.
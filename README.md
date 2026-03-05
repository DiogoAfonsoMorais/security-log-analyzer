# 🔐 Security Log Analyzer for Windows

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078D4.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/DiogoAfonsoMorais/security-log-analyzer?style=social)](https://github.com/DiogoAfonsoMorais/security-log-analyzer)

A Python tool that automatically detects **brute force attacks** and **suspicious authentication patterns** from Windows OpenSSH logs and Linux-style auth logs. Built for SOC analysts who want to automate the boring parts of log analysis.





---

## 🎯 Why This Project?

As a SOC analyst, you shouldn't spend hours manually grepping through logs. This tool automates the detection phase, allowing you to focus on **response** rather than **search**.

**What it solves:**
- ⏱️ Manual log review takes hours → This does it in seconds
- 🔍 Easy to miss patterns → Consistent detection every time
- 📊 Data needs structure → Generates CSV/JSON reports automatically

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🚨 **Brute Force Detection** | Identifies IPs with multiple failed login attempts |
| 👥 **User Enumeration Detection** | Spots attackers trying many different usernames |
| 📁 **Multiple Log Formats** | Works with Windows OpenSSH and Linux auth logs |
| 📊 **CSV & JSON Export** | Easy integration with SIEMs or Excel |
| ⚙️ **Configurable Thresholds** | Adjust sensitivity via YAML config |
| 🪟 **Windows Native** | Tested on Windows 10/11, PowerShell compatible |

---

## 🚀 Quick Start (5 minutes)

### Prerequisites
- Windows 10/11
- Python 3.8+ ([Download](https://python.org))
- Git ([Download](https://git-scm.com/download/win))

### Installation

```powershell
# 1. Open PowerShell as Administrator
# 2. Clone the repository
git clone https://github.com/DiogoAfonsoMorais/security-log-analyzer.git
cd security-log-analyzer

# 3. (Optional) Create virtual environment
python -m venv venv
.\venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Generate test logs to try it out
python generate_test_logs.py
First Run
powershell
# Analyze the simulated attack log
python analyzer.py samples/auth_attack.log

# You should see output like this:
🔍 Analyzing samples/auth_attack.log...
⚠️ ALERT: Brute force detected from 185.156.73.52 (150 attempts)
⚠️ ALERT: User enumeration from 45.155.205.33 (10 different users)
✅ Analysis complete. Found 2 alerts.
📊 Report saved to reports/alerts_20260305_143022.csv
📊 Example Output
Console Output
text
🔍 Analyzing samples/auth_attack.log...
⚠️ ALERT: Brute force detected from 185.156.73.52 (150 attempts)
⚠️ ALERT: User enumeration from 45.155.205.33 (10 different users)
✅ Analysis complete. Found 2 alerts.

==================================================
📋 ANALYSIS SUMMARY
==================================================

🔴 Top attacking IPs:
   185.156.73.52: 150 attempts (5 users)
   45.155.205.33: 10 attempts (10 users)

⚠️ Total alerts: 2
   - Brute force: 1
   - User enumeration: 1
==================================================
Generated CSV Report (reports/alerts_20260305_143022.csv)
csv
type,ip,attempts,first_seen,last_seen,unique_usernames,severity
BRUTE_FORCE,185.156.73.52,150,2026-03-05 10:15:22,2026-03-05 10:25:33,5,HIGH
USER_ENUMERATION,45.155.205.33,10,2026-03-05 11:00:01,2026-03-05 11:00:50,10 users,MEDIUM
🛠️ Detailed Usage
Command Line Options
powershell
# Basic usage
python analyzer.py <logfile>

# With custom config file
python analyzer.py samples/auth_attack.log --config myconfig.yaml

# Output as JSON
python analyzer.py samples/auth_attack.log --format json

# Output as both CSV and JSON
python analyzer.py samples/auth_attack.log --format both

# Specify output filename
python analyzer.py samples/auth_attack.log --output myreport
Configuration (config.yaml)
yaml
thresholds:
  brute_force:
    max_attempts: 5           # Alert after 5 failed attempts
    time_window: 300           # Within 5 minutes
  
  user_enumeration:
    max_users: 10              # Alert after 10 different usernames
    time_window: 600            # Within 10 minutes

output:
  format: "csv"                 # csv, json, or both
  report_dir: "reports/"
📁 Project Structure
text
C:\Users\Diogo\Documents\GitHub\security-log-analyzer/
├── analyzer.py                 # Main script
├── config.yaml                 # Configuration file
├── generate_test_logs.py       # Test data generator
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── .gitignore                  # Git ignore rules
├── samples/                    # Test logs
│   ├── auth_normal.log         # Normal traffic
│   ├── auth_attack.log         # Brute force simulation
│   └── auth_enumeration.log    # User enumeration simulation
└── reports/                    # Generated reports (created on first run)
    └── alerts_*.csv            # Your analysis results
🧪 Testing Scenarios
Scenario 1: Normal Traffic
powershell
python analyzer.py samples/auth_normal.log
# Expected: Few or no alerts
Scenario 2: Brute Force Attack
powershell
python analyzer.py samples/auth_attack.log
# Expected: Detects brute force from 185.156.73.52
Scenario 3: User Enumeration
powershell
python analyzer.py samples/auth_enumeration.log
# Expected: Detects user enumeration from 45.155.205.33
🔧 Windows-Specific Setup
Analyzing Real Windows OpenSSH Logs
Windows OpenSSH logs are typically located at:

text
C:\ProgramData\ssh\logs\sshd.log
To analyze them:

powershell
# Copy the log to your project folder first (to avoid permission issues)
copy "C:\ProgramData\ssh\logs\sshd.log" samples\

# Then analyze
python analyzer.py samples\sshd.log
Schedule Regular Scans with Task Scheduler
Open Task Scheduler (taskschd.msc)

Create Basic Task

Trigger: Daily/Weekly as needed

Action: Start a program

Program: python

Arguments: C:\Users\Diogo\Documents\GitHub\security-log-analyzer\analyzer.py C:\ProgramData\ssh\logs\sshd.log --format both

Start in: C:\Users\Diogo\Documents\GitHub\security-log-analyzer

📈 Real-World Applications
This tool is useful for:

Use Case	How It Helps
SOC Analysts	Automate initial triage of authentication logs
System Administrators	Monitor for compromised credentials
Incident Responders	Quickly identify attacking IPs during investigations
Security Students	Understand attack patterns through simulation

https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white
https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white
https://img.shields.io/badge/TryHackMe-212C42?style=for-the-badge&logo=tryhackme&logoColor=white



⭐ Support
If you find this tool useful, please consider:

Giving it a star on GitHub ⭐

Sharing with fellow SOC analysts

Contributing with issues or pull requests

Built with ⚡ in Portugal for the global security community

https://visitor-badge.laobi.icu/badge?page_id=DiogoAfonsoMorais.security-log-analyzer

# 🛡️ SQL Scanner

**Advanced SQL Injection Scanner** featuring hybrid detection (Dynamic Fuzzing + Dictionary), WAF bypass techniques, and support for both GET/POST requests.

## 🚀 Features
* **Hybrid Engine:** Combines heuristic logic checking with dictionary-based attacks.
* **WAF Bypass:** Automatically tampers payloads to evade firewalls.
* **Dual Mode:** Scans URL parameters (GET) and Form Data (POST).
* **Reporting:** Generates detailed HTML reports.

## 📥 Installation

```bash
git clone [https://github.com/benanasutay/SqlScanner.git](https://github.com/benanasutay/SqlScanner.git)
cd SqlScanner
pip install requests
⚙️ Usage & Help

$ python SqlScanner.py --help

usage: SqlScanner.py [-h] -u URL [--data DATA] [-f FILE] [-v]

arguments:
  -h, --help       show this help message and exit
  -u URL, --url    Target URL (required)
  --data DATA      POST data string (e.g. 'user=admin&pass=123')
  -f FILE, --file  Path to external payload file
  -v, --verbose    Enable verbose output mode

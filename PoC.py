#############################
#Author: Enzo LE NAIR       #
#Project Name: SExAI        #
#############################
#   Copyright (C) 2026  Enzo LE NAIR
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as
#   published by the Free Software Foundation, either version 3 of the
#   License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import json
import csv
import socket
import argparse
import re
from datetime import datetime
import fofa
import requests
from langchain_ollama import ChatOllama
from langchain_core.prompts import (
    SystemMessagePromptTemplate, HumanMessagePromptTemplate, ChatPromptTemplate
)

ANALYSIS_MODES = {
    "opendir": {
        "fields": "ip,port",
        "fetch_body": True,
        "prompt": "Analyze this HTTP directory listing for suspicious files, malware, exploits, or sensitive data leaks."
    },
    "banner": {
        "fields": "ip,port,banner,protocol",
        "fetch_body": False,
        "prompt": "Analyze this service banner for vulnerable versions, known CVEs, misconfigured services, or unusual configurations."
    },
    "headers": {
        "fields": "ip,port,header,server",
        "fetch_body": False,
        "prompt": "Analyze these HTTP headers for technology stack, security misconfigurations, information disclosure, or suspicious patterns."
    },
    "login": {
        "fields": "ip,port,title",
        "fetch_body": True,
        "prompt": "Analyze this login page. Identify if it's an admin panel, C2 interface, phishing page, or legitimate service. Look for default credentials indicators."
    },
    "cert": {
        "fields": "ip,port,cert",
        "fetch_body": False,
        "prompt": "Analyze this SSL certificate. Look for: self-signed certs, known C2 signatures (Cobalt Strike, Metasploit, Sliver), suspicious issuer/subject, cert age, wildcard abuse."
    },
    "c2": {
        "fields": "ip,port,cert,header,jarm",
        "fetch_body": True,
        "prompt": "Hunt for C2 indicators: self-signed certs, default pages, suspicious ports (50050, 443, 8443), JARM fingerprints, Cobalt Strike/Metasploit/Sliver signatures, malleable C2 profiles."
    }
}

def parse_args():
    parser = argparse.ArgumentParser(
        description='SExAI - CTI & Attack Surface Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python PoC.py -q "product=SimpleHTTP" -s 20
  python PoC.py -q "title=Index" -o results -f json -e
  python PoC.py --no-ai -e -o scan -f html
        '''
    )
    parser.add_argument('-q', '--query',
                        default='product="SimpleHTTP" && title="for /" && ".bash_history" && "CVE"',
                        help='FOFA search query')
    parser.add_argument('-s', '--size', type=int, default=10,
                        help='Number of results (default: 10)')
    parser.add_argument('-o', '--output',
                        help='Output file (without extension)')
    parser.add_argument('-f', '--format', choices=['csv', 'json', 'html'], default='json',
                        help='Output format (default: json)')
    parser.add_argument('-e', '--enrich', action='store_true',
                        help='Enable geolocation and DNS enrichment')
    parser.add_argument('--no-ai', action='store_true',
                        help='Disable LLM analysis')
    parser.add_argument('-m', '--mode', choices=list(ANALYSIS_MODES.keys()), default='opendir',
                        help='Analysis mode (default: opendir)')
    return parser.parse_args()

def enrich_ip(ip):
    result = {"geoloc": None, "dns_reverse": None}
    #Geolocation via ip-api.com
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result["geoloc"] = {
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "as": data.get("as")
                }
    except requests.exceptions.RequestException:
        pass
    #DNS reverse lookup
    try:
        result["dns_reverse"] = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        pass
    return result

def analyze_with_ai(llm, data, mode="opendir"):
    mode_config = ANALYSIS_MODES[mode]
    system_prompt = f'''You are a CTI analyst. {mode_config["prompt"]}

Provide a JSON response with:
- risk_score: LOW, MEDIUM, HIGH, or CRITICAL
- threat_type: C2, Malware, DataLeak, ReconTools, Exploit, or Unknown
- iocs: array of suspicious hashes, URLs, IPs, domains found
- summary: brief description of findings (max 100 words)

Respond ONLY with valid JSON, no other text.'''

    human_prompt = 'Analyze this data:\n{data}'

    system = SystemMessagePromptTemplate.from_template(system_prompt)
    question = HumanMessagePromptTemplate.from_template(human_prompt)
    template = ChatPromptTemplate([system, question])

    try:
        prompt = template.invoke({'data': data[:4000]})
        result = llm.invoke(prompt)
        content = result.content.strip()
        #Extract JSON from response
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
        return {"risk_score": "Unknown", "threat_type": "Unknown", "iocs": [], "summary": content}
    except Exception as e:
        return {"risk_score": "Error", "threat_type": "Error", "iocs": [], "summary": str(e)}

def export_csv(results, filename):
    filepath = f"{filename}.csv"
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        #Header
        writer.writerow(['IP', 'Port', 'URL', 'Status', 'Country', 'City', 'ISP',
                         'DNS Reverse', 'Risk Score', 'Threat Type', 'Summary', 'Timestamp'])
        for r in results:
            geoloc = r.get('geoloc') or {}
            ai = r.get('ai_analysis') or {}
            writer.writerow([
                r.get('ip'),
                r.get('port'),
                r.get('url'),
                r.get('status_code'),
                geoloc.get('country', ''),
                geoloc.get('city', ''),
                geoloc.get('isp', ''),
                r.get('dns_reverse', ''),
                ai.get('risk_score', ''),
                ai.get('threat_type', ''),
                ai.get('summary', ''),
                r.get('timestamp')
            ])
    print(f"[+] CSV exported to {filepath}")

def export_json(results, filename):
    filepath = f"{filename}.json"
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON exported to {filepath}")

def export_html(results, filename):
    filepath = f"{filename}.html"

    #Statistics
    total = len(results)
    countries = {}
    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "Unknown": 0}

    for r in results:
        geoloc = r.get('geoloc') or {}
        country = geoloc.get('country', 'Unknown')
        countries[country] = countries.get(country, 0) + 1

        ai = r.get('ai_analysis') or {}
        risk = ai.get('risk_score', 'Unknown')
        if risk in risk_counts:
            risk_counts[risk] += 1
        else:
            risk_counts['Unknown'] += 1

    #Build rows
    rows_html = ""
    for r in results:
        geoloc = r.get('geoloc') or {}
        ai = r.get('ai_analysis') or {}
        risk = ai.get('risk_score', 'Unknown')
        risk_class = risk.lower() if risk in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] else 'unknown'

        rows_html += f'''
        <tr class="risk-{risk_class}">
            <td>{r.get('ip', '')}</td>
            <td>{r.get('port', '')}</td>
            <td><a href="{r.get('url', '')}" target="_blank">{r.get('url', '')}</a></td>
            <td>{r.get('status_code', '')}</td>
            <td>{geoloc.get('country', '')} ({geoloc.get('city', '')})</td>
            <td>{r.get('dns_reverse', '')}</td>
            <td><span class="badge {risk_class}">{risk}</span></td>
            <td>{ai.get('threat_type', '')}</td>
            <td>{ai.get('summary', '')}</td>
        </tr>'''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SExAI Report - {datetime.now().strftime("%Y-%m-%d %H:%M")}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', 'Segoe UI', sans-serif;
            background: #1d3557;
            color: #f1faee;
            padding: 40px;
            line-height: 1.6;
        }}
        h1 {{
            color: #f1faee;
            font-weight: 300;
            font-size: 2.5em;
            margin-bottom: 30px;
            letter-spacing: -0.02em;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: #457b9d;
            padding: 24px;
            border-radius: 16px;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-4px); }}
        .stat-card h3 {{ color: #f1faee; font-size: 2.5em; font-weight: 600; }}
        .stat-card p {{ color: #a8dadc; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.05em; }}
        table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            background: rgba(69, 123, 157, 0.3);
            border-radius: 16px;
            overflow: hidden;
        }}
        th {{
            background: #457b9d;
            color: #f1faee;
            padding: 16px;
            text-align: left;
            font-weight: 500;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 16px;
            border-bottom: 1px solid rgba(168, 218, 220, 0.1);
        }}
        tr:hover {{ background: rgba(69, 123, 157, 0.4); }}
        a {{ color: #a8dadc; text-decoration: none; }}
        a:hover {{ color: #f1faee; }}
        .badge {{
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .low {{ background: #a8dadc; color: #1d3557; }}
        .medium {{ background: #457b9d; color: #f1faee; }}
        .high {{ background: #e63946; color: #f1faee; }}
        .critical {{ background: #e63946; color: #f1faee; animation: pulse 2s infinite; }}
        .unknown {{ background: rgba(168, 218, 220, 0.3); color: #f1faee; }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.7; }} }}
        .risk-critical {{ background: rgba(230, 57, 70, 0.15); }}
        .risk-high {{ background: rgba(230, 57, 70, 0.1); }}
        footer {{ margin-top: 40px; color: #457b9d; font-size: 0.85em; }}
    </style>
</head>
<body>
    <h1>SExAI -  Report</h1>

    <div class="stats">
        <div class="stat-card">
            <h3>{total}</h3>
            <p>Total Hosts</p>
        </div>
        <div class="stat-card">
            <h3>{risk_counts.get('CRITICAL', 0)}</h3>
            <p>Critical</p>
        </div>
        <div class="stat-card">
            <h3>{risk_counts.get('HIGH', 0)}</h3>
            <p>High Risk</p>
        </div>
        <div class="stat-card">
            <h3>{len(countries)}</h3>
            <p>Countries</p>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>IP</th>
                <th>Port</th>
                <th>URL</th>
                <th>Status</th>
                <th>Location</th>
                <th>DNS Reverse</th>
                <th>Risk</th>
                <th>Threat Type</th>
                <th>Summary</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>

    <footer>Generated by SExAI on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} - Made by Enzo LE NAIR w/ ♥</footer>
</body>
</html>'''

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[+] HTML report exported to {filepath}")

if __name__ == "__main__":
    args = parse_args()
    results = []

    print(f"[*] SExAI - CTI & Attack Surface Tool")
    print(f"[*] Query: {args.query}")
    print(f"[*] Size: {args.size}")
    print(f"[*] Mode: {args.mode}")

    mode_config = ANALYSIS_MODES[args.mode]

    #FOFA search
    key = os.getenv("FOFA_API_KEY")
    email = os.getenv("FOFA_EMAIL")
    if not key or not email:
        print("[!] Error: FOFA_API_KEY and FOFA_EMAIL environment variables required")
        exit(1)

    client = fofa.Client(key=key, email=email)

    try:
        fofa_data = client.search(args.query, page=1, size=args.size, fields=mode_config["fields"])
        print(f"[+] Found {len(fofa_data['results'])} results (requested: {args.size})")
    except Exception as e:
        print(f"[!] FOFA search error: {e}")
        exit(1)

    #LLM initialization
    llm = None
    if not args.no_ai:
        print("[*] Initializing LLM...")
        llm = ChatOllama(
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            model=os.getenv("OLLAMA_MODEL", "hf.co/AlicanKiraz0/SenecaLLM_x_Qwen2.5-7B-CyberSecurity-Q8_0-GGUF:latest"),
            temperature=0.6,
            num_predict=512
        )

    #Processing each target
    for result in fofa_data["results"]:
        ip, port = result[0], result[1]
        extra_data = result[2:] if len(result) > 2 else []
        url = f"http://{ip}:{port}"
        print(f"[*] Processing {url}...")

        entry = {
            "ip": ip,
            "port": port,
            "url": url,
            "mode": args.mode,
            "fofa_data": extra_data,
            "status_code": None,
            "geoloc": None,
            "dns_reverse": None,
            "ai_analysis": None,
            "timestamp": datetime.now().isoformat()
        }

        #Enrichment
        if args.enrich:
            enrichment = enrich_ip(ip)
            entry["geoloc"] = enrichment["geoloc"]
            entry["dns_reverse"] = enrichment["dns_reverse"]

        #Prepare data for AI analysis
        ai_input_data = ""
        if extra_data:
            ai_input_data = "\n".join(str(d) for d in extra_data)

        #HTTP request (if mode requires body fetch)
        if mode_config["fetch_body"]:
            try:
                response = requests.get(url, timeout=5)
                entry["status_code"] = response.status_code
                if response.status_code == 200:
                    ai_input_data += f"\n\nHTTP Body:\n{response.text}"
            except requests.exceptions.RequestException as e:
                print(f"    [!] HTTP Error: {e}")

        #AI analysis
        if llm and ai_input_data:
            entry["ai_analysis"] = analyze_with_ai(llm, ai_input_data, args.mode)
            risk = entry["ai_analysis"].get("risk_score", "Unknown")
            print(f"    [+] Risk: {risk}")

        results.append(entry)

    #Export
    if args.output:
        if args.format == "csv":
            export_csv(results, args.output)
        elif args.format == "json":
            export_json(results, args.output)
        elif args.format == "html":
            export_html(results, args.output)
    else:
        print(json.dumps(results, indent=2, ensure_ascii=False))

    print(f"[*] Done. Processed {len(results)} hosts.")

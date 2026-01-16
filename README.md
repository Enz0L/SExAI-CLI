# SExAI - Search Engine x AI

CTI & Attack Surface Tool that combines FOFA search engine with AI-powered analysis.

## Description

SExAI gathers intelligence from FOFA (search engine for internet-connected devices) and uses a cybersecurity-focused LLM to analyze HTTP directory listings, identifying malicious tools, exploits, and potential threats.

**Article:** https://enzolenair.fr/2025/01/19/SExAI/SExAI/

## Features

- **FOFA Integration** - Search for exposed servers and open directories
- **AI Analysis** - Risk scoring and threat classification using local LLM (Ollama)
- **Multiple Analysis Modes** - Open directories, banners, headers, login pages, certificates, C2 hunting
- **IP Enrichment** - Geolocation and DNS reverse lookup
- **Multiple Export Formats** - JSON, CSV, HTML report
- **Flexible CLI** - Customizable queries and options

## Installation

Tested on Linux only:

```bash
git clone https://github.com/Enz0L/SExAI.git
cd SExAI
python -m venv .venv
source .venv/bin/activate
pip install fofa-py langchain-ollama requests retry
```

## Configuration

### FOFA API

Set your FOFA credentials as environment variables:

```bash
export FOFA_API_KEY="your_fofa_api_key"
export FOFA_EMAIL="your_fofa_email"
```

### Ollama Setup

SExAI uses Ollama for local AI analysis. **Any Ollama-compatible model works!**

1. Install Ollama from [ollama.ai](https://ollama.ai)

2. Start the Ollama service:
```bash
ollama serve
```

3. Pull any model you want:
```bash
# Recommended: Cybersecurity-focused model
ollama pull hf.co/AlicanKiraz0/SenecaLLM_x_Qwen2.5-7B-CyberSecurity-Q8_0-GGUF:latest

# Or use any other model (llama3, mistral, qwen, etc.)
ollama pull llama3
ollama pull mistral
```

4. Configure your model via environment variable:
```bash
export OLLAMA_BASE_URL="http://localhost:11434"  # Default
export OLLAMA_MODEL="llama3"  # Use any pulled model
```

> **Tip:** Cybersecurity-specialized models like SenecaLLM provide better threat analysis, but general-purpose models work fine for basic use cases.

## Usage

```bash
# Basic open directory scan
python PoC.py -q "product=SimpleHTTP" -s 20

# Full scan with enrichment and HTML report
python PoC.py -q 'title="Index of /"' -s 10 -o report -f html -e

# Quick scan without AI analysis
python PoC.py --no-ai -e -o scan -f csv

# C2 hunting mode
python PoC.py -m c2 -q "cert.issuer=localhost" -s 50 -o c2_report -f html

# Certificate analysis
python PoC.py -m cert -q "cert.is_valid=false" -s 30
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-q, --query` | FOFA search query | Default query |
| `-s, --size` | Number of results | 10 |
| `-o, --output` | Output file (without extension) | stdout |
| `-f, --format` | Output format: csv, json, html | json |
| `-e, --enrich` | Enable geolocation/DNS enrichment | False |
| `-m, --mode` | Analysis mode (see below) | opendir |
| `--no-ai` | Disable LLM analysis | False |

### Analysis Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `opendir` | Open directory analysis | Find exposed files, malware, exploits |
| `banner` | Service banner analysis | Detect vulnerable versions |
| `headers` | HTTP headers analysis | Technology stack, misconfigs |
| `login` | Login page detection | Admin panels, C2 interfaces |
| `cert` | SSL certificate analysis | Self-signed, C2 signatures |
| `c2` | C2 hunting (combined) | Cobalt Strike, Metasploit, Sliver |

## Tutorial

### Example 1: Hunting Exposed .bash_history Files

Search for SimpleHTTP servers exposing bash history files:

```bash
python PoC.py -q 'product="SimpleHTTP" && title="for /" && ".bash_history"' -s 5 -o report -f html
```

Output:
```
[*] SExAI - CTI & Attack Surface Tool
[*] Query: product="SimpleHTTP" && title="for /" && ".bash_history"
[*] Size: 5
[*] Mode: opendir
[+] Found 5 results (requested: 5)
[*] Initializing LLM...
[*] Processing http://47.100.173.160:18001...
    [+] Risk: CRITICAL
[*] Processing http://113.142.72.88:80...
    [+] Risk: HIGH
[*] Processing http://43.166.178.194:80...
    [+] Risk: MEDIUM
[*] Processing http://185.196.21.72:9000...
    [+] Risk: CRITICAL
[*] Processing http://113.142.72.94:80...
    [+] Risk: CRITICAL
[+] HTML report exported to report.html
[*] Done. Processed 5 hosts.
```

### Example 2: C2 Hunting with Icon Hash

Hunt for potential C2 servers using favicon hash (Cobalt Strike example):

```bash
python PoC.py -m c2 -q 'icon_hash="-1010228102"' -s 5 -o c2_report -f html
```

Output:
```
[*] SExAI - CTI & Attack Surface Tool
[*] Query: icon_hash="-1010228102"
[*] Size: 5
[*] Mode: c2
[+] Found 5 results (requested: 5)
[*] Initializing LLM...
[*] Processing http://43.143.130.124:8888...
    [+] Risk: MEDIUM
[*] Processing http://129.226.213.170:8888...
    [+] Risk: MEDIUM
[*] Processing http://8.216.84.159:8888...
    [+] Risk: MEDIUM
[*] Processing http://107.174.115.101:8888...
    [+] Risk: MEDIUM
[*] Processing http://81.68.98.217:8888...
    [+] Risk: MEDIUM
[+] HTML report exported to c2_report.html
[*] Done. Processed 5 hosts.
```

## Output

### JSON/CSV
Structured data with IP, port, geolocation, DNS reverse, risk score, threat type, and IOCs.

### HTML Report
Dark-themed dashboard with:
- Statistics (total hosts, risk distribution, countries)
- Sortable results table
- Risk-based color coding

## Requirements

- Python 3.8+
- FOFA API account
- Ollama running locally (for AI analysis)

## License

GNU Affero General Public License v3.0 - See [LICENSE](LICENSE) for details.

## Author

Enzo LE NAIR

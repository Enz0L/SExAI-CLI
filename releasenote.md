# SExAI Release Notes

## v0.2.0 - CTI & Attack Surface Tool

### New Features

#### CLI Interface
- Added command-line arguments for flexible usage:
  - `-q, --query`: Custom FOFA search query
  - `-s, --size`: Number of results to fetch
  - `-o, --output`: Output file name (without extension)
  - `-f, --format`: Export format (csv, json, html)
  - `-e, --enrich`: Enable IP geolocation and DNS enrichment
  - `--no-ai`: Disable LLM analysis for faster scans

#### Export Capabilities
- **JSON export**: Structured data with full details
- **CSV export**: Spreadsheet-compatible format
- **HTML report**: Dark-themed dashboard with statistics and risk indicators

#### IP Enrichment
- Geolocation via ip-api.com (country, city, ISP, AS number)
- DNS reverse lookup

#### Enhanced AI Analysis
- Improved prompt for structured JSON output
- Risk scoring: LOW, MEDIUM, HIGH, CRITICAL
- Threat classification: C2, Malware, DataLeak, ReconTools, Exploit
- IOC extraction (hashes, URLs, IPs, domains)

### Improvements
- LLM initialization moved outside the loop for better performance
- Environment variables for all sensitive configuration
- Better error handling and user feedback
- Fixed `break` to `continue` for resilient scanning

### Configuration
Required environment variables:
```bash
export FOFA_API_KEY="your_key"
export FOFA_EMAIL="your_email"
export OLLAMA_BASE_URL="http://localhost:11434"  # optional
export OLLAMA_MODEL="your_model"  # optional
```

### Usage Examples
```bash
# Basic scan
python PoC.py -q "product=SimpleHTTP" -s 20

# Full scan with enrichment and HTML report
python PoC.py -q "title=Index" -o report -f html -e

# Quick scan without AI analysis
python PoC.py --no-ai -e -o scan -f csv
```

---

## v0.3.0 - Analysis Modes & Design Refresh

### New Features

#### Multiple Analysis Modes
New `-m, --mode` argument supporting different CTI use cases:

| Mode | Description | FOFA Fields |
|------|-------------|-------------|
| `opendir` | Open directory analysis (default) | ip, port |
| `banner` | Service banner vulnerability scan | ip, port, banner, protocol |
| `headers` | HTTP headers tech detection | ip, port, header, server |
| `login` | Admin panel / login page detection | ip, port, title |
| `cert` | SSL certificate analysis | ip, port, cert |
| `c2` | C2 hunting (combined analysis) | ip, port, cert, header, jarm |

#### C2 Hunting Capabilities
- Self-signed certificate detection
- JARM fingerprint analysis
- Known C2 signatures (Cobalt Strike, Metasploit, Sliver)
- Default page detection
- Malleable C2 profile indicators

### Visual Refresh
New HTML report design with custom color palette:
- Modern Inter font family
- Improved card hover effects
- Pulse animation for CRITICAL risks
- Better contrast and readability

### Usage Examples
```bash
# Default open directory analysis
python PoC.py -q "title=Index" -s 10

# Banner analysis for vulnerable services
python PoC.py -m banner -q "protocol=ssh" -s 20

# C2 hunting
python PoC.py -m c2 -q "cert.issuer=localhost" -s 50 -o c2_report -f html

# Certificate analysis
python PoC.py -m cert -q "cert.is_valid=false" -s 30
```

---

## v0.1.0 - Initial PoC

- FOFA API integration
- Basic LLM analysis with Ollama
- HTTP directory listing analysis

# 🦦 WALLRUS — Web Application Firewall

> **CLI-based WAF** with signature-based OWASP Top 10 detection (Phase 1) and ML anomaly detection (Phase 2)
>
> *by Aaditya & Krittika*

---

## Overview

WALLRUS is a high-performance, developer-friendly Web Application Firewall that runs entirely from the terminal. It intercepts and analyses raw HTTP requests, flagging known attack patterns using a regex-based signature engine and (Phase 2) an ML anomaly detector for obfuscated and zero-day threats.

```
 ██╗    ██╗ █████╗ ██╗     ██╗     ██████╗ ██╗   ██╗███████╗
 ██║    ██║██╔══██╗██║     ██║     ██╔══██╗██║   ██║██╔════╝
 ██║ █╗ ██║███████║██║     ██║     ██████╔╝██║   ██║███████╗
 ██║███╗██║██╔══██║██║     ██║     ██╔══██╗██║   ██║╚════██║
 ╚███╔███╔╝██║  ██║███████╗███████╗██║  ██║╚██████╔╝███████║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

---

## Features

### Phase 1 (current)
- **Signature Engine** — 30+ regex rules covering the OWASP Top 10
- **OWASP Coverage** — SQLi, XSS, Path Traversal, Command Injection, SSRF, XXE, SSTI, LDAP Injection, Open Redirect, CRLF Injection
- **Risk Scoring** — severity-weighted score (0–100) per request
- **Interactive CLI** — REPL mode, stdin pipe, and file-based scanning
- **Dual Logging** — JSON log files + SQLite for queryable history
- **Security Dashboard** — live stats from the terminal

### Phase 2 (planned)
- ML anomaly detector (LightGBM / Random Forest) for zero-day and obfuscated attacks
- Feature extraction pipeline (entropy, special char density, URL encoding patterns)
- Integrated training script with evaluation metrics
- SHAP-based explainability for flagged anomalies

---

## Project Structure

```
wallrus/
├── src/wallrus/
│   ├── cli/
│   │   └── main.py          # Typer CLI — all commands
│   ├── core/
│   │   ├── signatures.py    # OWASP regex ruleset (30+ rules)
│   │   ├── parser.py        # HTTP request parser
│   │   └── engine.py        # Signature engine + Phase 2 pipeline stub
│   ├── ml/
│   │   └── detector.py      # Feature extractor + ML inference stub
│   └── utils/
│       ├── logger.py        # JSON + SQLite logging
│       └── formatter.py     # Rich terminal output
├── tests/
│   └── test_core/
│       └── test_engine.py   # Pytest suite (parser + engine)
├── data/
│   ├── raw/                 # Sample HTTP request files
│   ├── processed/           # Labelled CSV for ML training
│   └── models/              # Saved joblib models
├── logs/                    # Runtime logs (JSON + SQLite)
├── scripts/
│   └── train.py             # Phase 2 ML training script
└── pyproject.toml
```

---

## Installation

```bash
git clone https://github.com/your-username/wallrus.git
cd wallrus
pip install -e ".[dev]"
```

> Requires Python 3.10+

---

## Usage

### Scan from file
```bash
wallrus scan -f data/raw/my_request.txt
```

### Scan from stdin (pipe)
```bash
cat request.txt | wallrus scan
```

### Verbose analysis (shows full payloads)
```bash
wallrus analyze -f request.txt
```

### Interactive REPL
```bash
wallrus interactive
```

### View recent scan history
```bash
wallrus logs --limit 50
```

### Security dashboard
```bash
wallrus stats
```

### List signature rules
```bash
wallrus rules
wallrus rules --severity CRITICAL
wallrus rules --owasp A03
```

---

## Example Requests

### ✅ Clean
```http
GET /products?category=electronics&page=2 HTTP/1.1
Host: www.shop.com
```

### 🚫 SQL Injection (BLOCKED)
```http
GET /search?q=1' UNION SELECT username,password FROM users-- HTTP/1.1
Host: www.example.com
```

### 🚫 XSS (BLOCKED)
```http
GET /comment?text=<script>alert('XSS')</script> HTTP/1.1
Host: www.example.com
```

### 🚫 SSRF / Cloud Metadata (BLOCKED)
```http
GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: www.example.com
```

---

## Running Tests

```bash
pytest tests/ -v
pytest tests/ -v --cov=wallrus
```

---

## Tech Stack

| Layer | Tools |
|---|---|
| CLI | `typer`, `rich` |
| HTTP Layer | `mitmproxy`, `scapy` |
| Detection (P1) | `re` (regex), custom signature engine |
| Detection (P2) | `scikit-learn`, `lightgbm`, `pandas`, `numpy` |
| Logging | `json`, `sqlite3` |
| Packaging | `pyproject.toml`, `setuptools` |

---

## Methodology

| Phase | Focus | Deliverable |
|---|---|---|
| 1 | The Filter | Signature-based blocking engine |
| 2 | The Brain | Integrated ML anomaly detector |
| 3 | The Face | Interactive CLI dashboard & logs |
| 4 | The Speed | Optimised, low-latency binary |

---

## OWASP Coverage

| ID | Category | Rules |
|---|---|---|
| A01:2021 | Broken Access Control | Path Traversal, Open Redirect, Host Injection |
| A02:2021 | Cryptographic Failures | Sensitive data in URL |
| A03:2021 | Injection | SQLi (6), XSS (6), CMDi (3), LDAP, XXE, SSTI, CRLF |
| A04:2021 | Insecure Design | SSTI |
| A05:2021 | Security Misconfiguration | XXE |
| A07:2021 | Auth Failures | Basic auth monitoring |
| A08:2021 | Data Integrity | PHP/Java deserialization |
| A10:2021 | SSRF | Internal IPs, cloud metadata |

---
---

## License

MIT

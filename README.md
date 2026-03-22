# 🦦 WALLRUS — Web Application Firewall

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-orange)](https://owasp.org/www-project-top-ten/)
[![Phase](https://img.shields.io/badge/Phase-1%20Complete-success)](https://github.com/Add2207/WALLRUS)

> **High-performance CLI-based Web Application Firewall** that shields web services from SQLi, XSS, and zero-day exploits through real-time HTTP traffic monitoring.

*By Aaditya & Krittika*

---

## 🎯 Overview

WALLRUS is a developer-friendly WAF that runs entirely from the terminal. It intercepts and analyzes raw HTTP requests, flagging known attack patterns using a **regex-based signature engine** (Phase 1) and an **ML anomaly detector** for obfuscated and zero-day threats (Phase 2).

```
 ██╗    ██╗ █████╗ ██╗     ██╗     ██████╗ ██╗   ██╗███████╗
 ██║    ██║██╔══██╗██║     ██║     ██╔══██╗██║   ██║██╔════╝
 ██║ █╗ ██║███████║██║     ██║     ██████╔╝██║   ██║███████╗
 ██║███╗██║██╔══██║██║     ██║     ██╔══██╗██║   ██║╚════██║
 ╚███╔███╔╝██║  ██║███████╗███████╗██║  ██║╚██████╔╝███████║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

---

## ✨ Features

### 🛡️ Phase 1 (Current - Production Ready)
- **30+ Signature Rules** covering OWASP Top 10 (2021)
- **Real-time Detection**: SQLi, XSS, Path Traversal, Command Injection, SSRF, XXE, SSTI, LDAP Injection, Open Redirect, CRLF Injection
- **Risk Scoring** — Severity-weighted score (0–100) per request
- **Interactive CLI** — REPL mode, stdin pipe, and file-based scanning
- **Dual Logging** — JSON log files + SQLite for queryable history
- **Security Dashboard** — Live statistics and analytics
- **Zero Configuration** — Works out of the box

### 🤖 Phase 2 (Planned - In Development)
- ML anomaly detector (LightGBM / Random Forest) for zero-day attacks
- Feature extraction pipeline (entropy, encoding patterns, behavioral analysis)
- Integrated training script with evaluation metrics
- SHAP-based explainability for flagged anomalies

---

## 🚀 Quick Start

### Installation

**Linux / WSL / macOS:**
```bash
git clone https://github.com/Add2207/WALLRUS.git
cd WALLRUS
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
```

**Windows (Native):**
See [WINDOWS_SETUP.md](WINDOWS_SETUP.md) for detailed instructions.

### Basic Usage

```bash
# Scan a file
wallrus scan -f request.txt

# Interactive mode
wallrus interactive

# View security dashboard
wallrus stats

# List all rules
wallrus rules

# Scan from stdin
cat malicious_request.txt | wallrus scan
```

---

## 📖 Example Requests

### ✅ Clean Request
```http
GET /products?category=electronics&page=2 HTTP/1.1
Host: www.shop.com
```
**Result:** `CLEAN` — No threats detected

### 🚫 SQL Injection (BLOCKED)
```http
GET /search?q=1' UNION SELECT username,password FROM users-- HTTP/1.1
Host: www.example.com
```
**Result:** `BLOCKED` — Rules fired: `SQLI-002`, `SQLI-003`

### 🚫 XSS Attack (BLOCKED)
```http
GET /comment?text=<script>alert('XSS')</script> HTTP/1.1
Host: www.example.com
```
**Result:** `BLOCKED` — Rule fired: `XSS-001`

### 🚫 SSRF / Cloud Metadata (BLOCKED)
```http
GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: www.example.com
```
**Result:** `BLOCKED` — Rules fired: `SSRF-001`, `SSRF-002`

---

## 📊 OWASP Coverage

| OWASP Category | Rules | Examples |
|----------------|-------|----------|
| **A01:2021** Broken Access Control | 3 | Path Traversal, Open Redirect, Host Injection |
| **A02:2021** Cryptographic Failures | 1 | Sensitive data in URL |
| **A03:2021** Injection | 17 | SQLi (6), XSS (6), CMDi (3), LDAP, SSTI |
| **A04:2021** Insecure Design | 1 | Server-Side Template Injection |
| **A05:2021** Security Misconfiguration | 2 | XXE, DOCTYPE exploitation |
| **A07:2021** Auth Failures | 1 | Basic auth monitoring |
| **A08:2021** Data Integrity | 2 | PHP/Java deserialization |
| **A10:2021** SSRF | 2 | Internal IPs, cloud metadata |

**Total: 30+ production-ready detection rules**

---

## 🏗️ Project Structure

```
WALLRUS/
├── src/wallrus/
│   ├── core/
│   │   ├── signatures.py    # 30+ OWASP regex rules
│   │   ├── parser.py        # HTTP request parser
│   │   └── engine.py        # Detection engine + ML pipeline stub
│   ├── cli/
│   │   └── main.py          # Typer CLI (scan/analyze/logs/stats/rules)
│   ├── ml/
│   │   └── detector.py      # Feature extractor + ML inference (Phase 2)
│   └── utils/
│       ├── logger.py        # JSON + SQLite dual-sink logging
│       └── formatter.py     # Rich terminal output
├── tests/                   # Pytest suite (25+ test cases)
├── data/
│   ├── raw/                 # Sample HTTP request files
│   ├── processed/           # Labelled CSV for ML training (Phase 2)
│   └── models/              # Saved models (Phase 2)
├── scripts/
│   └── train.py             # ML training pipeline (Phase 2)
└── logs/                    # Runtime JSON/SQLite logs
```

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Test coverage
pytest tests/ --cov=wallrus

# Quick validation
python -c "
import sys; sys.path.insert(0, 'src')
from wallrus.core.parser import parse_http_request
from wallrus.core.engine import SignatureEngine

raw = 'GET /search?q=1%27%20UNION%20SELECT%20* HTTP/1.1\nHost: x.com\n\n'
req = parse_http_request(raw)
result = SignatureEngine().scan(req)
print(f'Verdict: {result.verdict}')
print(f'Rules: {[m.rule_id for m in result.matches]}')
"
```

**Expected:** `Verdict: BLOCKED`, `Rules: ['SQLI-002', 'SQLI-003']`

---

## 💻 CLI Commands

| Command | Description |
|---------|-------------|
| `wallrus scan -f <file>` | Scan a raw HTTP request file |
| `wallrus analyze -f <file>` | Verbose scan with full payloads |
| `wallrus interactive` | Drop into REPL mode |
| `wallrus logs --limit 50` | View recent scan history |
| `wallrus stats` | Security dashboard & analytics |
| `wallrus rules` | List all loaded signatures |
| `wallrus rules --severity CRITICAL` | Filter by severity |
| `wallrus rules --owasp A03` | Filter by OWASP category |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **CLI Framework** | `typer`, `rich` |
| **HTTP Layer** | `mitmproxy`, `scapy` (Phase 2) |
| **Detection (P1)** | `re` (regex), custom signature engine |
| **Detection (P2)** | `scikit-learn`, `lightgbm`, `pandas` |
| **Logging** | `json`, `sqlite3` |
| **Testing** | `pytest`, `pytest-cov` |

---

## 📈 Roadmap

### Phase 1 ✅ (Complete)
- [x] HTTP request parser (GET/POST/PUT/PATCH/DELETE)
- [x] 30+ OWASP signature rules
- [x] Risk scoring system
- [x] Interactive CLI with REPL
- [x] JSON + SQLite logging
- [x] Security dashboard
- [x] Test suite (25+ cases)

### Phase 2 🚧 (In Progress)
- [ ] ML feature extractor (entropy, encoding, behavioral)
- [ ] Train LightGBM classifier on labelled dataset
- [ ] Anomaly detection integration
- [ ] SHAP explainability
- [ ] Real-time traffic interception (mitmproxy)

### Phase 3 🔮 (Future)
- [ ] Web UI dashboard
- [ ] Custom rule editor
- [ ] Rate limiting & IP blocking
- [ ] Multi-language support
- [ ] Docker container
- [ ] Cloud deployment templates

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repo
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by [WAFinity](https://github.com/Piyush-2975/Advanced-WAF-WAFinity)
- OWASP Top 10 (2021) methodology
- CSIC 2010 HTTP Dataset for testing

---

## 📧 Contact

**Authors:** Aaditya & Krittika

**Project Link:** [https://github.com/Add2207/WALLRUS](https://github.com/Add2207/WALLRUS)

---

<div align="center">
  
**⭐ Star this repo if you find it useful!**

Made with ❤️ for the cybersecurity community

</div>

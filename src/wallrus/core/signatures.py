"""
WALLRUS - Signature Engine
OWASP Top 10 regex-based attack pattern definitions.

Each signature maps to an OWASP category and carries:
  - id:          unique rule ID (for logs & future rule management)
  - name:        human-readable label
  - owasp:       OWASP Top 10 category (2021)
  - severity:    CRITICAL / HIGH / MEDIUM / LOW
  - pattern:     compiled regex
  - targets:     which parts of the HTTP request to scan
  - description: what the rule catches
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


# ── Severity constants ─────────────────────────────────────────────────────────
class Severity:
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ── HTTP request targets ───────────────────────────────────────────────────────
class Target:
    URL     = "url"
    QUERY   = "query"
    BODY    = "body"
    HEADERS = "headers"
    ALL     = "all"           # scans url + query + body + headers


# ── Signature dataclass ────────────────────────────────────────────────────────
@dataclass
class Signature:
    id:          str
    name:        str
    owasp:       str
    severity:    str
    pattern:     re.Pattern
    targets:     List[str]
    description: str
    cve:         Optional[str] = None      # placeholder for Phase 2 CVE mapping


# ── Rule factory helper ────────────────────────────────────────────────────────
def _rule(id_, name, owasp, severity, regex, targets, desc, cve=None) -> Signature:
    return Signature(
        id=id_,
        name=name,
        owasp=owasp,
        severity=severity,
        pattern=re.compile(regex, re.IGNORECASE | re.DOTALL),
        targets=targets,
        description=desc,
        cve=cve,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SIGNATURE RULESET
# ══════════════════════════════════════════════════════════════════════════════

SIGNATURES: List[Signature] = [

    # ── A03:2021 – SQL Injection ───────────────────────────────────────────────
    _rule(
        "SQLI-001", "SQL Tautology",
        "A03:2021 - Injection", Severity.CRITICAL,
        r"(\b(or|and)\b\s*[\'\"]?\s*[\w\s]*\s*=\s*[\w\s]*[\'\"]?\s*(-{2}|#|\/\*)?)",
        [Target.QUERY, Target.BODY],
        "Classic tautology: OR/AND 1=1, ' OR 'a'='a"
    ),
    _rule(
        "SQLI-002", "SQL UNION SELECT",
        "A03:2021 - Injection", Severity.CRITICAL,
        r"\bunion\b.{0,20}\bselect\b",
        [Target.QUERY, Target.BODY],
        "UNION-based SQL injection attempting to exfiltrate data"
    ),
    _rule(
        "SQLI-003", "SQL Comment Termination",
        "A03:2021 - Injection", Severity.HIGH,
        r"(--|#|\/\*|\*\/)(\s|$)",
        [Target.QUERY, Target.BODY],
        "SQL comment sequences used to truncate queries"
    ),
    _rule(
        "SQLI-004", "SQL DROP/DELETE/TRUNCATE",
        "A03:2021 - Injection", Severity.CRITICAL,
        r"\b(drop|delete|truncate|alter)\b.{0,30}\b(table|database|schema)\b",
        [Target.QUERY, Target.BODY],
        "Destructive SQL DDL/DML statements"
    ),
    _rule(
        "SQLI-005", "SQL Stacked Queries",
        "A03:2021 - Injection", Severity.HIGH,
        r";\s*(select|insert|update|delete|drop|create|alter|exec)",
        [Target.QUERY, Target.BODY],
        "Stacked queries via semicolon injection"
    ),
    _rule(
        "SQLI-006", "SQL Blind Injection (Time-based)",
        "A03:2021 - Injection", Severity.HIGH,
        r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(",
        [Target.QUERY, Target.BODY],
        "Time-based blind SQL injection using SLEEP/BENCHMARK"
    ),

    # ── A03:2021 – Cross-Site Scripting (XSS) ─────────────────────────────────
    _rule(
        "XSS-001", "Script Tag Injection",
        "A03:2021 - Injection (XSS)", Severity.CRITICAL,
        r"<\s*script[^>]*>.*?(<\s*/\s*script\s*>|$)",
        [Target.QUERY, Target.BODY],
        "Direct <script> tag injection"
    ),
    _rule(
        "XSS-002", "Inline Event Handler",
        "A03:2021 - Injection (XSS)", Severity.HIGH,
        r"\bon\w+\s*=\s*['\"]?\s*(javascript:|alert|confirm|prompt|eval|fetch|window\.|document\.)",
        [Target.QUERY, Target.BODY],
        "Event handler attributes: onerror=, onload=, onclick=, etc."
    ),
    _rule(
        "XSS-003", "JavaScript URI",
        "A03:2021 - Injection (XSS)", Severity.HIGH,
        r"javascript\s*:",
        [Target.QUERY, Target.BODY, Target.HEADERS],
        "javascript: URI scheme in href, src, action attributes"
    ),
    _rule(
        "XSS-004", "eval/Function Execution",
        "A03:2021 - Injection (XSS)", Severity.HIGH,
        r"\b(eval|Function|setTimeout|setInterval)\s*\(",
        [Target.QUERY, Target.BODY],
        "Dynamic code execution via eval() or Function()"
    ),
    _rule(
        "XSS-005", "DOM Sink Manipulation",
        "A03:2021 - Injection (XSS)", Severity.MEDIUM,
        r"(document\.(write|writeln|cookie|location)|window\.location|innerHTML\s*=)",
        [Target.QUERY, Target.BODY],
        "Direct DOM manipulation sinks"
    ),
    _rule(
        "XSS-006", "SVG/IMG XSS Vector",
        "A03:2021 - Injection (XSS)", Severity.HIGH,
        r"<\s*(svg|img|body|iframe|embed|object|input)[^>]*(on\w+|src\s*=\s*['\"]?\s*(javascript:|data:))[^>]*>",
        [Target.QUERY, Target.BODY],
        "XSS via HTML tags that support event handlers or data URIs"
    ),

    # ── A01:2021 – Path Traversal ──────────────────────────────────────────────
    _rule(
        "PT-001", "Path Traversal (../)",
        "A01:2021 - Broken Access Control", Severity.HIGH,
        r"(\.\.[\\/]){2,}",
        [Target.URL, Target.QUERY],
        "Directory traversal using ../ or ..\\"
    ),
    _rule(
        "PT-002", "Absolute Path Access",
        "A01:2021 - Broken Access Control", Severity.HIGH,
        r"(\/etc\/passwd|\/etc\/shadow|\/proc\/self|\/windows\/win\.ini|\/boot\.ini)",
        [Target.URL, Target.QUERY, Target.BODY],
        "Attempts to access sensitive OS files"
    ),
    _rule(
        "PT-003", "Null Byte Injection",
        "A01:2021 - Broken Access Control", Severity.HIGH,
        r"%00|\\x00|\x00",
        [Target.URL, Target.QUERY, Target.BODY],
        "Null byte used to truncate file paths"
    ),

    # ── A03:2021 – Command Injection ───────────────────────────────────────────
    _rule(
        "CMDI-001", "Shell Command Injection",
        "A03:2021 - Injection (Command)", Severity.CRITICAL,
        r"(;|\||&|`|\$\()\s*(ls|cat|whoami|id|pwd|uname|wget|curl|chmod|rm|cp|mv|nc|bash|sh|python|perl|php)",
        [Target.QUERY, Target.BODY],
        "OS command injection via shell metacharacters"
    ),
    _rule(
        "CMDI-002", "Pipe / Semicolon Chaining",
        "A03:2021 - Injection (Command)", Severity.HIGH,
        r"(\|\|?|&&|;)\s*\w+",
        [Target.QUERY, Target.BODY],
        "Command chaining patterns used in injection"
    ),
    _rule(
        "CMDI-003", "Backtick/Subshell Execution",
        "A03:2021 - Injection (Command)", Severity.CRITICAL,
        r"(`[^`]+`|\$\([^)]+\))",
        [Target.QUERY, Target.BODY],
        "Subshell execution via backticks or $(...)"
    ),

    # ── A03:2021 – LDAP Injection ──────────────────────────────────────────────
    _rule(
        "LDAPI-001", "LDAP Filter Injection",
        "A03:2021 - Injection (LDAP)", Severity.HIGH,
        r"[)(|&!*\\].*(\w+=|\*)",
        [Target.QUERY, Target.BODY],
        "LDAP filter injection using special characters"
    ),

    # ── A03:2021 – XML/XXE Injection ───────────────────────────────────────────
    _rule(
        "XXE-001", "XXE DOCTYPE Declaration",
        "A05:2021 - Security Misconfiguration / XXE", Severity.CRITICAL,
        r"<!DOCTYPE[^>]*\[",
        [Target.BODY],
        "External entity declaration in XML DOCTYPE"
    ),
    _rule(
        "XXE-002", "XXE ENTITY Reference",
        "A05:2021 - Security Misconfiguration / XXE", Severity.CRITICAL,
        r"<!ENTITY\s+\w+\s+SYSTEM",
        [Target.BODY],
        "SYSTEM entity used to read local files or SSRF"
    ),

    # ── A10:2021 – SSRF ────────────────────────────────────────────────────────
    _rule(
        "SSRF-001", "Internal IP Access",
        "A10:2021 - SSRF", Severity.HIGH,
        r"(https?:\/\/)(127\.0\.0\.1|0\.0\.0\.0|localhost|169\.254\.|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.)",
        [Target.QUERY, Target.BODY, Target.HEADERS],
        "Request targeting internal/private IP ranges"
    ),
    _rule(
        "SSRF-002", "Cloud Metadata Endpoint",
        "A10:2021 - SSRF", Severity.CRITICAL,
        r"169\.254\.169\.254|metadata\.google\.internal",
        [Target.QUERY, Target.BODY, Target.HEADERS],
        "AWS/GCP/Azure metadata service endpoint access"
    ),

    # ── A02:2021 – Cryptographic Failures / Sensitive Data Exposure ───────────
    _rule(
        "SDE-001", "Sensitive Parameter Names",
        "A02:2021 - Cryptographic Failures", Severity.MEDIUM,
        r"\b(password|passwd|pwd|secret|api_?key|token|auth|credential)s?\b\s*=",
        [Target.URL, Target.QUERY],
        "Sensitive data transmitted in URL query strings"
    ),

    # ── A07:2021 – Authentication Attacks ─────────────────────────────────────
    _rule(
        "AUTH-001", "HTTP Basic Auth Brute Patterns",
        "A07:2021 - Identification and Authentication Failures", Severity.MEDIUM,
        r"Authorization:\s*Basic\s+[A-Za-z0-9+/]{0,100}=*",
        [Target.HEADERS],
        "Basic auth header detected — monitor for repeated failures"
    ),

    # ── A04:2021 – Insecure Deserialization / Template Injection ───────────────
    _rule(
        "SSTI-001", "Server-Side Template Injection",
        "A04:2021 - Insecure Design (SSTI)", Severity.CRITICAL,
        r"(\{\{.*\}\}|\{%.*%\}|\${.*}|#\{.*\}|@\{.*\})",
        [Target.QUERY, Target.BODY],
        "Template injection payloads for Jinja2, Twig, Freemarker, etc."
    ),

    # ── A08:2021 – Software and Data Integrity / Deserialization ──────────────
    _rule(
        "DESER-001", "PHP Object Injection",
        "A08:2021 - Software and Data Integrity Failures", Severity.HIGH,
        r"O:\d+:\"[^\"]+\":\d+:\{",
        [Target.BODY],
        "PHP serialized object injection"
    ),
    _rule(
        "DESER-002", "Java Serialized Object",
        "A08:2021 - Software and Data Integrity Failures", Severity.HIGH,
        r"(rO0AB|%ac%ed%00%05)",
        [Target.BODY],
        "Java serialized object magic bytes in base64 or raw"
    ),

    # ── Open Redirect ──────────────────────────────────────────────────────────
    _rule(
        "OR-001", "Open Redirect",
        "A01:2021 - Broken Access Control", Severity.MEDIUM,
        r"(redirect|next|url|return|goto|dest|destination|forward)\s*=\s*(https?:\/\/(?![\w.-]*\byour-domain\.com\b))",
        [Target.QUERY],
        "Open redirect to external domain via URL parameter"
    ),

    # ── HTTP Request Smuggling / Header Injection ──────────────────────────────
    _rule(
        "HI-001", "HTTP Header Injection (CRLF)",
        "A03:2021 - Injection", Severity.HIGH,
        r"(%0d%0a|%0a%0d|\r\n|\n\r)",
        [Target.HEADERS, Target.QUERY],
        "CRLF injection attempting to inject new HTTP headers"
    ),
    _rule(
        "HI-002", "Host Header Injection",
        "A01:2021 - Broken Access Control", Severity.MEDIUM,
        r"^Host:\s*([\d.]+|localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$",
        [Target.HEADERS],
        "Suspicious Host header pointing to IP or localhost"
    ),
]


# ── Lookup helpers ─────────────────────────────────────────────────────────────
def get_by_id(rule_id: str) -> Optional[Signature]:
    return next((s for s in SIGNATURES if s.id == rule_id), None)


def get_by_owasp(category: str) -> List[Signature]:
    return [s for s in SIGNATURES if category.lower() in s.owasp.lower()]


def get_by_severity(severity: str) -> List[Signature]:
    return [s for s in SIGNATURES if s.severity == severity.upper()]


# ── Stats ──────────────────────────────────────────────────────────────────────
def summary() -> dict:
    return {
        "total_rules":   len(SIGNATURES),
        "by_severity": {
            Severity.CRITICAL: len(get_by_severity(Severity.CRITICAL)),
            Severity.HIGH:     len(get_by_severity(Severity.HIGH)),
            Severity.MEDIUM:   len(get_by_severity(Severity.MEDIUM)),
            Severity.LOW:      len(get_by_severity(Severity.LOW)),
        }
    }

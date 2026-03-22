"""
WALLRUS - Tests: Core Detection Engine

Tests cover:
  - HTTP parser (valid and malformed requests)
  - Signature engine (known attack patterns)
  - Verdict and score logic

Run with: pytest tests/ -v
"""

import pytest
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))

from wallrus.core.parser import parse_http_request, ParseError, HTTPMethod
from wallrus.core.engine import DetectionPipeline, Verdict, SignatureEngine


# ══════════════════════════════════════════════════════════════════════════════
#  PARSER TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestParser:

    def test_simple_get(self):
        raw = "GET /index.html HTTP/1.1\nHost: example.com\n\n"
        req = parse_http_request(raw)
        assert req.method == HTTPMethod.GET
        assert req.path   == "/index.html"
        assert req.host   == "example.com"
        assert req.body   == ""

    def test_get_with_query(self):
        raw = "GET /search?q=hello&page=2 HTTP/1.1\nHost: example.com\n\n"
        req = parse_http_request(raw)
        assert req.query_params.get("q") == "hello"
        assert req.query_params.get("page") == "2"

    def test_post_with_body(self):
        raw = (
            "POST /login HTTP/1.1\n"
            "Host: example.com\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "\n"
            "username=admin&password=secret"
        )
        req = parse_http_request(raw)
        assert req.method == HTTPMethod.POST
        assert "admin" in req.body

    def test_url_decoding(self):
        raw = "GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1\nHost: x.com\n\n"
        req = parse_http_request(raw)
        assert "'" in req.query_string or "OR" in req.query_string.upper()

    def test_invalid_request_line(self):
        with pytest.raises(ParseError):
            parse_http_request("NOTVALID\n\n")

    def test_empty_request(self):
        with pytest.raises(ParseError):
            parse_http_request("")

    def test_unsupported_method(self):
        with pytest.raises(ParseError):
            parse_http_request("CONNECT / HTTP/1.1\n\n")


# ══════════════════════════════════════════════════════════════════════════════
#  SIGNATURE ENGINE TESTS
# ══════════════════════════════════════════════════════════════════════════════

def _scan(raw_request: str) -> object:
    """Helper: parse + scan a raw request."""
    req = parse_http_request(raw_request)
    return SignatureEngine().scan(req)


class TestSQLInjection:

    def test_tautology_blocked(self):
        raw = "GET /search?q=' OR '1'='1 HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.verdict == Verdict.BLOCKED
        assert any("SQLI" in m.rule_id for m in result.matches)

    def test_union_select(self):
        raw = "GET /search?q=1' UNION SELECT username,password FROM users-- HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.verdict == Verdict.BLOCKED
        assert any(m.rule_id == "SQLI-002" for m in result.matches)

    def test_drop_table(self):
        raw = "GET /q?id=1'; DROP TABLE users;-- HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.verdict == Verdict.BLOCKED

    def test_sleep_blind(self):
        raw = "GET /q?id=1' AND SLEEP(5)-- HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.verdict == Verdict.BLOCKED

    def test_clean_search(self):
        raw = "GET /search?q=blue+shoes&page=1 HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.verdict == Verdict.CLEAN


class TestXSS:

    def test_script_tag(self):
        raw = "GET /comment?text=<script>alert('XSS')</script> HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.verdict == Verdict.BLOCKED
        assert any("XSS" in m.rule_id for m in result.matches)

    def test_event_handler(self):
        raw = "GET /img?src=x onerror=alert(1) HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.is_malicious

    def test_javascript_uri(self):
        raw = "GET /go?url=javascript:alert(1) HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.is_malicious

    def test_eval_execution(self):
        raw = "POST /api HTTP/1.1\nHost: x.com\n\npayload=eval(atob('YWxlcnQoMSk='))"
        result = _scan(raw)
        assert result.is_malicious


class TestPathTraversal:

    def test_dotdot_slash(self):
        raw = "GET /files/../../etc/passwd HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.verdict == Verdict.BLOCKED

    def test_sensitive_file(self):
        raw = "GET /read?f=/etc/passwd HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.is_malicious


class TestCommandInjection:

    def test_pipe_command(self):
        raw = "GET /ping?host=127.0.0.1;whoami HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.verdict == Verdict.BLOCKED

    def test_backtick_subshell(self):
        raw = "GET /exec?cmd=`id` HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.is_malicious


class TestSSRF:

    def test_internal_ip(self):
        raw = "GET /fetch?url=http://192.168.1.1/admin HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.is_malicious

    def test_metadata_endpoint(self):
        raw = "GET /get?url=http://169.254.169.254/latest/meta-data HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.verdict == Verdict.BLOCKED
        assert any(m.rule_id == "SSRF-002" for m in result.matches)


class TestXXE:

    def test_doctype_entity(self):
        body = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        raw  = f"POST /xml HTTP/1.1\nHost: x.com\nContent-Type: application/xml\n\n{body}"
        result = _scan(raw)
        assert result.is_malicious


class TestSSIT:

    def test_jinja2_injection(self):
        raw = "GET /greet?name={{7*7}} HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.is_malicious

    def test_freemarker(self):
        raw = r"GET /page?t=${7*7} HTTP/1.1\nHost: x.com\n\n"
        result = _scan(raw)
        assert result.is_malicious


# ══════════════════════════════════════════════════════════════════════════════
#  PIPELINE TESTS (end-to-end)
# ══════════════════════════════════════════════════════════════════════════════

class TestPipeline:

    def test_pipeline_clean(self):
        raw = "GET /products?category=shoes&page=2 HTTP/1.1\nHost: shop.com\n\n"
        req = parse_http_request(raw)
        pipeline = DetectionPipeline()
        result   = pipeline.analyze(req)
        assert result.verdict == Verdict.CLEAN
        assert result.risk_score == 0

    def test_pipeline_attack(self):
        raw = "GET /search?q=1' UNION SELECT * FROM users-- HTTP/1.1\nHost: shop.com\n\n"
        req = parse_http_request(raw)
        pipeline = DetectionPipeline()
        result   = pipeline.analyze(req)
        assert result.verdict == Verdict.BLOCKED
        assert result.risk_score > 0

    def test_pipeline_multiple_rules(self):
        # Triggers both SQLi and XSS
        raw = "GET /evil?q='; DROP TABLE users;<script>alert(1)</script>-- HTTP/1.1\nHost: x.com\n\n"
        req = parse_http_request(raw)
        result = DetectionPipeline().analyze(req)
        assert len(result.matches) >= 2
        assert result.risk_score >= 40

    def test_scan_time_recorded(self):
        raw = "GET / HTTP/1.1\nHost: x.com\n\n"
        req = parse_http_request(raw)
        result = DetectionPipeline().analyze(req)
        assert result.scan_time_ms >= 0

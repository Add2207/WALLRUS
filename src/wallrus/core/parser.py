"""
WALLRUS - HTTP Request Parser

Parses raw HTTP request strings into a structured HTTPRequest object.
Phase 1 scope: GET, POST, PUT, PATCH, DELETE — basic exploitable requests.

The parser is intentionally strict about format to mirror real WAF behaviour:
a malformed or unsupported request is flagged as a parsing error rather than
silently ignored.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Optional
from enum import Enum


class HTTPMethod(str, Enum):
    GET    = "GET"
    POST   = "POST"
    PUT    = "PUT"
    PATCH  = "PATCH"
    DELETE = "DELETE"
    HEAD   = "HEAD"
    OPTIONS = "OPTIONS"


# ── Structured HTTP request ────────────────────────────────────────────────────
@dataclass
class HTTPRequest:
    method:       HTTPMethod
    path:         str
    version:      str
    headers:      Dict[str, str]
    query_string: str
    query_params: Dict[str, str]
    body:         str
    raw:          str                    # original unparsed text (for logging)
    host:         Optional[str] = None
    content_type: Optional[str] = None

    @property
    def full_url(self) -> str:
        host = self.host or "unknown"
        qs   = f"?{self.query_string}" if self.query_string else ""
        return f"http://{host}{self.path}{qs}"

    def targets(self) -> Dict[str, str]:
        """Return a dict of target name → content for scanner consumption."""
        return {
            "url":     self.path,
            "query":   self.query_string,
            "body":    self.body,
            "headers": " ".join(f"{k}: {v}" for k, v in self.headers.items()),
        }


# ── Parse error ───────────────────────────────────────────────────────────────
class ParseError(Exception):
    pass


# ── Parser ────────────────────────────────────────────────────────────────────
def parse_http_request(raw: str) -> HTTPRequest:
    """
    Parse a raw HTTP/1.x request string into an HTTPRequest.

    Expected format (CRLF or LF line endings):
        METHOD /path?query HTTP/1.x
        Header-Name: value
        ...
        [blank line]
        [optional body]
    """
    raw = raw.strip()
    if not raw:
        raise ParseError("Empty request")

    # Normalise line endings
    raw_normalised = raw.replace("\r\n", "\n").replace("\r", "\n")

    # Split head from body on first blank line
    if "\n\n" in raw_normalised:
        head_part, body = raw_normalised.split("\n\n", 1)
    else:
        head_part = raw_normalised
        body = ""

    lines = head_part.split("\n")
    if not lines:
        raise ParseError("No request line found")

    # ── Request line ──────────────────────────────────────────────────────────
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) != 3:
        raise ParseError(f"Invalid request line: {request_line!r}")

    method_str, full_path, version = parts

    try:
        method = HTTPMethod(method_str.upper())
    except ValueError:
        raise ParseError(f"Unsupported HTTP method: {method_str!r}")

    if not version.startswith("HTTP/"):
        raise ParseError(f"Invalid HTTP version: {version!r}")

    # ── Path & query string ───────────────────────────────────────────────────
    if "?" in full_path:
        path, query_string = full_path.split("?", 1)
    else:
        path, query_string = full_path, ""

    # URL-decode the path and query for accurate pattern matching
    path_decoded  = urllib.parse.unquote(path)
    query_decoded = urllib.parse.unquote_plus(query_string)

    query_params: Dict[str, str] = {}
    if query_decoded:
        try:
            query_params = dict(urllib.parse.parse_qsl(query_decoded))
        except Exception:
            pass  # best-effort

    # ── Headers ───────────────────────────────────────────────────────────────
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ": " in line:
            key, _, val = line.partition(": ")
            headers[key.strip()] = val.strip()

    host         = headers.get("Host") or headers.get("host")
    content_type = headers.get("Content-Type") or headers.get("content-type")

    # URL-decode body if form-encoded
    body_decoded = body
    if content_type and "application/x-www-form-urlencoded" in content_type:
        body_decoded = urllib.parse.unquote_plus(body)

    return HTTPRequest(
        method=method,
        path=path_decoded,
        version=version,
        headers=headers,
        query_string=query_decoded,
        query_params=query_params,
        body=body_decoded,
        raw=raw,
        host=host,
        content_type=content_type,
    )

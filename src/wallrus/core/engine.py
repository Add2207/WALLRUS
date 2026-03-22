"""
WALLRUS - Detection Engine (Phase 1: Signature-Based)

Scans a parsed HTTPRequest against the OWASP signature ruleset.
Designed to slot Phase 2 ML anomaly detection in alongside — see
the TODO markers for integration points.

Detection flow:
  1. Decode / normalise the request (URL-decode already done in parser)
  2. For each signature, check its target fields in the request
  3. Collect all matches into a ScanResult
  4. [Phase 2] Pass the same request through the ML anomaly detector
  5. Return a unified result

Returns a ScanResult with:
  - verdict:  BLOCKED | FLAGGED | CLEAN
  - matches:  list of MatchDetail (which rule fired, where, what matched)
  - score:    severity-weighted risk score  (0–100)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from wallrus.core.parser import HTTPRequest
from wallrus.core.signatures import SIGNATURES, Signature, Severity, Target


# ── Severity weights (used for risk scoring) ──────────────────────────────────
SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40,
    Severity.HIGH:     25,
    Severity.MEDIUM:   10,
    Severity.LOW:       3,
}


# ── Verdict constants ─────────────────────────────────────────────────────────
class Verdict:
    BLOCKED = "BLOCKED"   # one or more CRITICAL / HIGH signatures matched
    FLAGGED = "FLAGGED"   # only MEDIUM / LOW signatures matched
    CLEAN   = "CLEAN"     # no signatures matched


# ── Result models ─────────────────────────────────────────────────────────────
@dataclass
class MatchDetail:
    rule_id:     str
    rule_name:   str
    owasp:       str
    severity:    str
    target:      str          # which field triggered (url, query, body, headers)
    matched_text: str         # the slice of text that triggered the regex
    description: str


@dataclass
class ScanResult:
    verdict:       str
    matches:       List[MatchDetail]
    risk_score:    int                    # 0–100, clamped
    scan_time_ms:  float
    request_id:    Optional[str] = None  # set externally for log correlation

    # Phase 2 placeholders — will be populated by ML engine
    anomaly_score: Optional[float] = None
    anomaly_flags: List[str]       = field(default_factory=list)

    @property
    def is_malicious(self) -> bool:
        return self.verdict in (Verdict.BLOCKED, Verdict.FLAGGED)

    @property
    def top_match(self) -> Optional[MatchDetail]:
        if not self.matches:
            return None
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                 Severity.MEDIUM: 2, Severity.LOW: 3}
        return min(self.matches, key=lambda m: order.get(m.severity, 99))


# ── Engine ────────────────────────────────────────────────────────────────────
class SignatureEngine:
    """
    Phase 1 signature-based detection engine.

    Usage:
        engine = SignatureEngine()
        result = engine.scan(parsed_request)
    """

    def __init__(self, max_match_len: int = 120):
        self._signatures = SIGNATURES
        self._max_match_len = max_match_len

    # ── Public API ────────────────────────────────────────────────────────────
    def scan(self, request: HTTPRequest) -> ScanResult:
        t0 = time.perf_counter()

        # Build target map: target_name → text_content
        target_map = request.targets()

        matches: List[MatchDetail] = []

        for sig in self._signatures:
            for target_name in sig.targets:
                content = target_map.get(target_name, "")
                if not content:
                    continue

                match = sig.pattern.search(content)
                if match:
                    matched_text = match.group(0)[:self._max_match_len]
                    matches.append(MatchDetail(
                        rule_id=sig.id,
                        rule_name=sig.name,
                        owasp=sig.owasp,
                        severity=sig.severity,
                        target=target_name,
                        matched_text=matched_text,
                        description=sig.description,
                    ))
                    break  # one match per rule is enough; avoid duplicate entries

        verdict    = self._determine_verdict(matches)
        risk_score = self._calculate_score(matches)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        return ScanResult(
            verdict=verdict,
            matches=matches,
            risk_score=risk_score,
            scan_time_ms=round(elapsed_ms, 3),
        )

    # ── Private helpers ───────────────────────────────────────────────────────
    @staticmethod
    def _determine_verdict(matches: List[MatchDetail]) -> str:
        if not matches:
            return Verdict.CLEAN
        severities = {m.severity for m in matches}
        if Severity.CRITICAL in severities or Severity.HIGH in severities:
            return Verdict.BLOCKED
        return Verdict.FLAGGED

    @staticmethod
    def _calculate_score(matches: List[MatchDetail]) -> int:
        score = sum(SEVERITY_WEIGHT.get(m.severity, 0) for m in matches)
        return min(score, 100)


# ── Phase 2 stub ──────────────────────────────────────────────────────────────
class AnomalyEngine:
    """
    Phase 2 ML-based anomaly detection engine (stub).

    Replace the `scan` body with your trained model inference pipeline.
    The method signature must remain identical so DetectionPipeline works
    without changes to any other module.
    """

    def scan(self, request: HTTPRequest) -> dict:
        # TODO Phase 2:
        #   1. Vectorise the request using your feature extractor
        #   2. Run inference on the loaded scikit-learn / LightGBM model
        #   3. Return {"anomaly_score": float, "flags": List[str]}
        return {"anomaly_score": None, "flags": []}


# ── Unified pipeline (Phase 1 + Phase 2) ──────────────────────────────────────
class DetectionPipeline:
    """
    Combines signature engine + anomaly engine.
    Phase 1: only sig_engine produces meaningful results.
    Phase 2: anomaly_engine results are merged into the ScanResult.
    """

    def __init__(self):
        self.sig_engine     = SignatureEngine()
        self.anomaly_engine = AnomalyEngine()

    def analyze(self, request: HTTPRequest) -> ScanResult:
        result = self.sig_engine.scan(request)

        # Phase 2 integration point
        anomaly = self.anomaly_engine.scan(request)
        result.anomaly_score = anomaly.get("anomaly_score")
        result.anomaly_flags = anomaly.get("flags", [])

        # Phase 2: optionally upgrade verdict based on anomaly score
        # if anomaly.get("anomaly_score", 0) > 0.8 and result.verdict == Verdict.CLEAN:
        #     result.verdict = Verdict.FLAGGED

        return result

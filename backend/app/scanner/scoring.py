"""
Security Score and Scan Verdict Calculation (SRS Section 4.4, 5.2, FND-3).

Centralized and documented algorithms for:
1. Security Score (0 to 100):
   Starts at 100 and subtracts penalty points per finding:
   - Critical: -25 points
   - High: -10 points
   - Medium: -4 points
   - Low: -1 point
   - Info: 0 points
   Bounded between 0 and 100 (never negative).

2. Verdict Determination:
   Evaluated strictly in FND-3 priority order:
   - 'critical' if >= 1 Critical finding
   - 'high' if >= 1 High finding
   - 'medium' if >= 1 Medium finding
   - 'low' if >= 1 Low finding
   - 'info' if >= 1 Info finding
   - 'scanner_error' if modules errored and no findings
   - 'safe' if no findings and no scanner errors
   A Critical finding is NEVER reported as safe or masked.
"""

from typing import Dict, List, Union


def calculate_security_score(counts_or_findings: Union[Dict[str, int], List[str]]) -> int:
    """
    Calculate security score (0-100) based on severity counts (SRS Section 5.2).

    Accepts either:
    - A dictionary of severity counts: {'critical': int, 'high': int, 'medium': int, 'low': int}
    - A list of severity strings: ['critical', 'high', 'low', ...]

    Returns integer score between 0 and 100.
    """
    if isinstance(counts_or_findings, list):
        counts = {
            "critical": sum(1 for s in counts_or_findings if str(s).lower() == "critical"),
            "high": sum(1 for s in counts_or_findings if str(s).lower() == "high"),
            "medium": sum(1 for s in counts_or_findings if str(s).lower() == "medium"),
            "low": sum(1 for s in counts_or_findings if str(s).lower() == "low"),
        }
    else:
        counts = {
            "critical": int(counts_or_findings.get("critical", 0)),
            "high": int(counts_or_findings.get("high", 0)),
            "medium": int(counts_or_findings.get("medium", 0)),
            "low": int(counts_or_findings.get("low", 0)),
        }

    penalty = (
        (counts["critical"] * 25)
        + (counts["high"] * 10)
        + (counts["medium"] * 4)
        + (counts["low"] * 1)
    )

    score = 100 - penalty
    return min(100, max(0, score))


def calculate_verdict(severity_counts: Dict[str, int], error_count: int = 0) -> str:
    """
    Calculate overall scan verdict strictly following SRS FND-3 order:
    Critical -> High -> Medium -> Low -> Info -> Scanner Errors Only -> Safe (Nothing Found).
    """
    critical_count = int(severity_counts.get("critical", 0))
    high_count = int(severity_counts.get("high", 0))
    medium_count = int(severity_counts.get("medium", 0))
    low_count = int(severity_counts.get("low", 0))
    info_count = int(severity_counts.get("info", 0))

    if critical_count > 0:
        return "critical"
    if high_count > 0:
        return "high"
    if medium_count > 0:
        return "medium"
    if low_count > 0:
        return "low"
    if info_count > 0:
        return "info"
    if error_count > 0:
        return "scanner_error"
    return "safe"

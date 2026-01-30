"""Scoring system for security findings."""

from typing import Dict, List

SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 10,
    "MEDIUM": 3,
    "LOW": 1,
}

SEVERITY_CAPS = {
    "CRITICAL": 50,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 5,
}


def calculate_score(findings: List[Dict]) -> Dict:
    """
    Calculate a security score based on findings.

    Args:
        findings: List of security findings

    Returns:
        Dict with score, grade, breakdown, and summary
    """
    # Count findings by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        severity = finding.get("severity", "LOW")
        if severity in counts:
            counts[severity] += 1

    # Calculate penalties with caps
    breakdown = {}
    total_penalty = 0
    for severity, count in counts.items():
        weight = SEVERITY_WEIGHTS[severity]
        cap = SEVERITY_CAPS[severity]
        raw_penalty = count * weight
        capped_penalty = min(raw_penalty, cap)
        breakdown[severity] = (count, capped_penalty)
        total_penalty += capped_penalty

    # Calculate final score (minimum 0)
    score = max(0, 100 - total_penalty)

    # Determine grade
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    # Build summary
    summary_parts = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count, penalty = breakdown[severity]
        if count > 0:
            summary_parts.append(f"{count} {severity} (-{penalty})")

    summary = f"Score: {score}/100 (Grade: {grade})"
    if summary_parts:
        summary += f" | {', '.join(summary_parts)}"

    return {
        "score": score,
        "grade": grade,
        "breakdown": breakdown,
        "summary": summary,
    }

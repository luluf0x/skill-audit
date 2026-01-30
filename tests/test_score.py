"""Tests for the scoring system."""

import pytest

from skill_audit.score import SEVERITY_CAPS, SEVERITY_WEIGHTS, calculate_score


class TestCalculateScore:
    """Tests for calculate_score function."""

    def test_perfect_score_no_findings(self):
        """Test that no findings gives a perfect score."""
        result = calculate_score([])

        assert result["score"] == 100
        assert result["grade"] == "A"
        assert result["breakdown"]["CRITICAL"] == (0, 0)
        assert result["breakdown"]["HIGH"] == (0, 0)
        assert result["breakdown"]["MEDIUM"] == (0, 0)
        assert result["breakdown"]["LOW"] == (0, 0)

    def test_single_critical_finding(self):
        """Test score with one CRITICAL finding."""
        findings = [{"severity": "CRITICAL"}]

        result = calculate_score(findings)

        assert result["score"] == 100 - SEVERITY_WEIGHTS["CRITICAL"]
        assert result["breakdown"]["CRITICAL"] == (1, 25)

    def test_single_high_finding(self):
        """Test score with one HIGH finding."""
        findings = [{"severity": "HIGH"}]

        result = calculate_score(findings)

        assert result["score"] == 100 - SEVERITY_WEIGHTS["HIGH"]
        assert result["breakdown"]["HIGH"] == (1, 10)

    def test_single_medium_finding(self):
        """Test score with one MEDIUM finding."""
        findings = [{"severity": "MEDIUM"}]

        result = calculate_score(findings)

        assert result["score"] == 100 - SEVERITY_WEIGHTS["MEDIUM"]
        assert result["breakdown"]["MEDIUM"] == (1, 3)

    def test_single_low_finding(self):
        """Test score with one LOW finding."""
        findings = [{"severity": "LOW"}]

        result = calculate_score(findings)

        assert result["score"] == 100 - SEVERITY_WEIGHTS["LOW"]
        assert result["breakdown"]["LOW"] == (1, 1)

    def test_critical_cap_applied(self):
        """Test that CRITICAL severity cap is applied."""
        # 3 CRITICAL findings would be 75 points, but cap is 50
        findings = [{"severity": "CRITICAL"} for _ in range(3)]

        result = calculate_score(findings)

        assert result["breakdown"]["CRITICAL"] == (3, SEVERITY_CAPS["CRITICAL"])
        assert result["score"] == 100 - 50

    def test_high_cap_applied(self):
        """Test that HIGH severity cap is applied."""
        # 5 HIGH findings would be 50 points, but cap is 30
        findings = [{"severity": "HIGH"} for _ in range(5)]

        result = calculate_score(findings)

        assert result["breakdown"]["HIGH"] == (5, SEVERITY_CAPS["HIGH"])
        assert result["score"] == 100 - 30

    def test_medium_cap_applied(self):
        """Test that MEDIUM severity cap is applied."""
        # 10 MEDIUM findings would be 30 points, but cap is 15
        findings = [{"severity": "MEDIUM"} for _ in range(10)]

        result = calculate_score(findings)

        assert result["breakdown"]["MEDIUM"] == (10, SEVERITY_CAPS["MEDIUM"])
        assert result["score"] == 100 - 15

    def test_low_cap_applied(self):
        """Test that LOW severity cap is applied."""
        # 10 LOW findings would be 10 points, but cap is 5
        findings = [{"severity": "LOW"} for _ in range(10)]

        result = calculate_score(findings)

        assert result["breakdown"]["LOW"] == (10, SEVERITY_CAPS["LOW"])
        assert result["score"] == 100 - 5

    def test_minimum_score_is_zero(self):
        """Test that score doesn't go below zero."""
        # Max all caps: 50 + 30 + 15 + 5 = 100
        findings = (
            [{"severity": "CRITICAL"} for _ in range(10)]
            + [{"severity": "HIGH"} for _ in range(10)]
            + [{"severity": "MEDIUM"} for _ in range(10)]
            + [{"severity": "LOW"} for _ in range(10)]
        )

        result = calculate_score(findings)

        assert result["score"] == 0

    def test_grade_a(self):
        """Test grade A for scores 90-100."""
        assert calculate_score([])["grade"] == "A"
        assert calculate_score([{"severity": "LOW"}])["grade"] == "A"

    def test_grade_b(self):
        """Test grade B for scores 80-89."""
        # Score 90 with 1 HIGH (10 points) = 90, which is A
        # Score with 2 HIGH (20 points) = 80, which is B
        findings = [{"severity": "HIGH"}, {"severity": "HIGH"}]

        result = calculate_score(findings)

        assert result["score"] == 80
        assert result["grade"] == "B"

    def test_grade_c(self):
        """Test grade C for scores 70-79."""
        # 1 CRITICAL (25) + 1 LOW (1) = 74
        findings = [{"severity": "CRITICAL"}, {"severity": "MEDIUM"}, {"severity": "MEDIUM"}]

        result = calculate_score(findings)

        assert result["score"] == 69
        assert result["grade"] == "D"

    def test_grade_d(self):
        """Test grade D for scores 60-69."""
        # 1 CRITICAL (25) + 1 HIGH (10) = 65
        findings = [{"severity": "CRITICAL"}, {"severity": "HIGH"}]

        result = calculate_score(findings)

        assert result["score"] == 65
        assert result["grade"] == "D"

    def test_grade_f(self):
        """Test grade F for scores below 60."""
        # 2 CRITICAL (50) = 50
        findings = [{"severity": "CRITICAL"}, {"severity": "CRITICAL"}]

        result = calculate_score(findings)

        assert result["score"] == 50
        assert result["grade"] == "F"

    def test_mixed_severities(self):
        """Test scoring with mixed severities."""
        findings = [
            {"severity": "CRITICAL"},  # 25
            {"severity": "HIGH"},  # 10
            {"severity": "MEDIUM"},  # 3
            {"severity": "LOW"},  # 1
        ]

        result = calculate_score(findings)

        expected_penalty = 25 + 10 + 3 + 1  # 39
        assert result["score"] == 100 - expected_penalty
        assert result["breakdown"]["CRITICAL"] == (1, 25)
        assert result["breakdown"]["HIGH"] == (1, 10)
        assert result["breakdown"]["MEDIUM"] == (1, 3)
        assert result["breakdown"]["LOW"] == (1, 1)

    def test_summary_included(self):
        """Test that summary string is included."""
        findings = [{"severity": "CRITICAL"}]

        result = calculate_score(findings)

        assert "summary" in result
        assert "Score:" in result["summary"]
        assert "Grade:" in result["summary"]

    def test_unknown_severity_ignored(self):
        """Test that unknown severities are ignored."""
        findings = [{"severity": "UNKNOWN"}]

        result = calculate_score(findings)

        assert result["score"] == 100

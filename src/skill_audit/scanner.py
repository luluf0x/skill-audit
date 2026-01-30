"""Regex-based security scanner for supplementary detection."""

import re
from pathlib import Path
from typing import Dict, List

# Patterns for detecting security issues via regex
PATTERNS = [
    # Hardcoded secrets and API keys
    {
        "pattern": re.compile(
            r"""(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|access[_-]?token|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]""",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "category": "hardcoded-secret",
        "message": "Possible hardcoded secret or API key",
    },
    # AWS keys
    {
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "severity": "CRITICAL",
        "category": "aws-key",
        "message": "AWS Access Key ID detected",
    },
    # Private keys
    {
        "pattern": re.compile(r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----"),
        "severity": "CRITICAL",
        "category": "private-key",
        "message": "Private key detected in source code",
    },
    # Credentials in URLs
    {
        "pattern": re.compile(
            r"""[a-z]+://[^:]+:[^@]+@[^\s'\"]+""",
            re.IGNORECASE,
        ),
        "severity": "HIGH",
        "category": "credentials-in-url",
        "message": "Credentials embedded in URL",
    },
    # Generic high-entropy strings that look like secrets
    {
        "pattern": re.compile(
            r"""['\"][a-zA-Z0-9+/]{40,}['\"]"""
        ),
        "severity": "MEDIUM",
        "category": "possible-secret",
        "message": "High-entropy string that may be a secret",
    },
]

# File extensions to scan with regex
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".php",
    ".go", ".rs", ".c", ".cpp", ".h", ".hpp", ".cs", ".swift",
    ".kt", ".scala", ".sh", ".bash", ".zsh", ".yaml", ".yml",
    ".json", ".xml", ".toml", ".ini", ".cfg", ".conf", ".env",
}

# Files/directories to skip
SKIP_PATTERNS = {
    "__pycache__", ".git", ".svn", ".hg", "node_modules",
    ".venv", "venv", ".env", "env", ".tox", ".pytest_cache",
    ".mypy_cache", "dist", "build", "*.egg-info",
}


def should_scan_file(filepath: Path) -> bool:
    """Check if a file should be scanned."""
    # Skip hidden files and directories
    for part in filepath.parts:
        if part.startswith(".") and part not in (".env",):
            return False
        if part in SKIP_PATTERNS:
            return False

    # Check extension
    return filepath.suffix.lower() in SCANNABLE_EXTENSIONS


def scan_file_with_regex(filepath: Path) -> List[Dict]:
    """
    Scan a file for security issues using regex patterns.

    Args:
        filepath: Path to the file to scan

    Returns:
        List of findings
    """
    findings = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            for pattern_info in PATTERNS:
                if pattern_info["pattern"].search(line):
                    findings.append({
                        "file": str(filepath),
                        "line": line_num,
                        "severity": pattern_info["severity"],
                        "category": pattern_info["category"],
                        "message": pattern_info["message"],
                    })
    except (OSError, IOError):
        pass

    return findings


def scan_directory(directory: Path) -> List[Dict]:
    """
    Scan a directory for security issues using regex patterns.

    Args:
        directory: Path to the directory to scan

    Returns:
        List of findings
    """
    findings = []

    if directory.is_file():
        if should_scan_file(directory):
            findings.extend(scan_file_with_regex(directory))
    else:
        for filepath in directory.rglob("*"):
            if filepath.is_file() and should_scan_file(filepath):
                findings.extend(scan_file_with_regex(filepath))

    return findings

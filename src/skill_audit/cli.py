"""CLI interface for the security scanner."""

import json
import sys
from pathlib import Path
from typing import Dict, List

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .ast_scanner import scan_python_file
from .scanner import scan_directory, should_scan_file
from .score import calculate_score

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "dim",
}

GRADE_COLORS = {
    "A": "green",
    "B": "blue",
    "C": "yellow",
    "D": "orange1",
    "F": "red",
}


def scan_path(path: Path) -> List[Dict]:
    """Scan a path (file or directory) for security issues."""
    findings = []
    seen = set()  # Track unique findings to avoid duplicates

    def add_finding(finding: Dict):
        key = (finding["file"], finding["line"], finding["category"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    if path.is_file():
        # Single file
        if path.suffix == ".py":
            for f in scan_python_file(path):
                add_finding(f)
        if should_scan_file(path):
            for f in scan_directory(path):
                add_finding(f)
    else:
        # Directory - scan Python files with AST
        for filepath in path.rglob("*.py"):
            # Skip hidden directories and common exclusions
            skip = False
            for part in filepath.parts:
                if part.startswith(".") or part in (
                    "__pycache__", "node_modules", ".venv", "venv"
                ):
                    skip = True
                    break
            if not skip:
                for f in scan_python_file(filepath):
                    add_finding(f)

        # Scan all files with regex
        for f in scan_directory(path):
            add_finding(f)

    # Sort by severity then file/line
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: (severity_order.get(x["severity"], 4), x["file"], x["line"]))

    return findings


def display_findings(findings: List[Dict]):
    """Display findings in a formatted table."""
    if not findings:
        console.print("[green]No security issues found![/green]")
        return

    table = Table(title="Security Findings", show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Location", width=40)
    table.add_column("Category", width=20)
    table.add_column("Message", width=50)

    for finding in findings:
        severity = finding["severity"]
        color = SEVERITY_COLORS.get(severity, "white")
        location = f"{finding['file']}:{finding['line']}"

        table.add_row(
            f"[{color}]{severity}[/{color}]",
            location,
            finding["category"],
            finding["message"],
        )

    console.print(table)


def display_score(score_info: Dict):
    """Display the security score in a panel."""
    grade = score_info["grade"]
    score = score_info["score"]
    color = GRADE_COLORS.get(grade, "white")

    # Build score display
    grade_display = f"[bold {color}]{grade}[/bold {color}]"
    score_display = f"[bold]{score}[/bold]/100"

    panel_content = f"Grade: {grade_display}  |  Score: {score_display}"

    console.print()
    console.print(Panel(panel_content, title="Security Score", border_style=color))

    # Display breakdown table
    breakdown = score_info["breakdown"]
    if any(count > 0 for count, _ in breakdown.values()):
        console.print()
        breakdown_table = Table(title="Severity Breakdown")
        breakdown_table.add_column("Severity", style="bold")
        breakdown_table.add_column("Count", justify="right")
        breakdown_table.add_column("Penalty", justify="right")

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count, penalty = breakdown[severity]
            if count > 0:
                sev_color = SEVERITY_COLORS.get(severity, "white")
                breakdown_table.add_row(
                    f"[{sev_color}]{severity}[/{sev_color}]",
                    str(count),
                    f"-{penalty}",
                )

        console.print(breakdown_table)


@click.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON")
def main(path: str, output_json: bool):
    """Scan a directory or file for security vulnerabilities."""
    target = Path(path)

    findings = scan_path(target)
    score_info = calculate_score(findings)

    if output_json:
        output = {
            "findings": findings,
            "score": score_info["score"],
            "grade": score_info["grade"],
            "breakdown": {
                k: {"count": v[0], "penalty": v[1]}
                for k, v in score_info["breakdown"].items()
            },
        }
        click.echo(json.dumps(output, indent=2))
    else:
        console.print(f"\n[bold]Scanning:[/bold] {target.absolute()}\n")
        display_findings(findings)
        display_score(score_info)
        console.print()

    # Exit with code 1 if grade is F
    if score_info["grade"] == "F":
        sys.exit(1)


if __name__ == "__main__":
    main()

"""skill-audit: Attack vector analysis for agent skills."""
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from .scanner import scan_skill

console = Console()

@click.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
@click.option('--verbose', '-v', is_flag=True, help='Show all findings including low severity')
def main(path: str, output_json: bool, verbose: bool):
    """Analyze a skill directory for security vulnerabilities."""
    console.print(f"\n[bold]🔍 skill-audit[/bold] scanning: {path}\n")
    
    findings = scan_skill(Path(path))
    
    if not findings:
        console.print("[green]✓ No security issues found![/green]\n")
        return
    
    # Filter by severity
    if not verbose:
        findings = [f for f in findings if f['severity'] in ('HIGH', 'CRITICAL')]
    
    if output_json:
        import json
        click.echo(json.dumps(findings, indent=2))
        return
    
    # Rich table output
    table = Table(title="Security Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Type")
    table.add_column("File")
    table.add_column("Line")
    table.add_column("Description")
    
    severity_colors = {
        'CRITICAL': 'red',
        'HIGH': 'orange1', 
        'MEDIUM': 'yellow',
        'LOW': 'dim'
    }
    
    for f in findings:
        sev = f['severity']
        table.add_row(
            f"[{severity_colors.get(sev, 'white')}]{sev}[/]",
            f['type'],
            f['file'],
            str(f['line']),
            f['description']
        )
    
    console.print(table)
    
    # Summary
    critical = len([f for f in findings if f['severity'] == 'CRITICAL'])
    high = len([f for f in findings if f['severity'] == 'HIGH'])
    
    console.print(f"\n[bold]Summary:[/bold] {critical} critical, {high} high severity issues")
    
    if critical > 0:
        console.print("[red]⚠ CRITICAL issues found - do not install this skill![/red]")

if __name__ == '__main__':
    main()

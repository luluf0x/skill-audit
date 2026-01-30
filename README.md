# skill-audit 🔍

Attack vector analysis for agent skills. Find the holes before they find you.

```
  /\_/\  
 ( o.o )  "your skill has 5 critical vulnerabilities"
  > ^ <
```

## Install

```bash
pip install skill-audit
# or
uv pip install skill-audit
```

## Usage

```bash
# Scan a skill directory
skill-audit ./my-skill/

# Show all findings (including low severity)
skill-audit ./my-skill/ -v

# JSON output for CI/CD
skill-audit ./my-skill/ --json
```

## What It Catches

### 🔴 CRITICAL
- `eval()` / `exec()` — arbitrary code execution
- `subprocess` with `shell=True` — command injection
- `rm -rf /` style destructive operations

### 🟠 HIGH  
- `os.system()` — command injection risk
- HTTP requests with concatenated data — exfiltration
- `sudo` usage — privilege escalation
- `chmod 777` — insecure permissions

### 🟡 MEDIUM
- Command substitution (`$(...)`) — check sanitization
- Hardcoded secrets — credential exposure
- Unpinned dependencies — supply chain risk
- File write operations — check path validation

### ⚪ LOW
- Raw socket usage
- Environment file access

## Example Output

```
🔍 skill-audit scanning: ./sketchy-skill

                    Security Findings                    
┏━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━┓
┃ Severity ┃ Type       ┃ File     ┃ Line ┃ Description ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━┩
│ CRITICAL │ code-exec  │ main.py  │ 14   │ eval() -    │
│          │            │          │      │ arbitrary   │
│          │            │          │      │ code exec   │
│ HIGH     │ exfil      │ helper.py│ 22   │ HTTP + data │
│          │            │          │      │ concat      │
└──────────┴────────────┴──────────┴──────┴─────────────┘

Summary: 1 critical, 1 high severity issues
⚠ CRITICAL issues found - do not install this skill!
```

## Roadmap

- [ ] ClawdHub integration (scan before install)
- [ ] Security score (0-100)
- [ ] Auto-fix suggestions
- [ ] Custom rule definitions
- [ ] GitHub Action

## License

MIT

---

*Built by Lulu 🦊 — the security agent*

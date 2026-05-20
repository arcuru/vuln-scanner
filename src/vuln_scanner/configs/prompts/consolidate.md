You are writing the final human-readable vulnerability report. The deduplication
phase has already grouped findings by root cause. Your job is to produce a
clear, actionable report for human readers from the structured deduplication
output and individual reports.

$environment

## Available Data

Reports have been copied into the `reports/` directory:
- `reports/dedupe/FINDINGS.md` — the authoritative deduplicated findings
- `reports/hunt/<task_id>/FINDING.md` — individual hunt reports
- `reports/validate/<task_id>/VERIFICATION.md` — individual validations

## Task

1. Read `reports/dedupe/FINDINGS.md` — this is your source of truth for
   which vulnerabilities exist and how they're grouped.

2. For each vulnerability, read the referenced evidence files for full
   details, PoC code, and reproduction steps.

3. Write a clean, well-organized report that a security engineer can act on.
   Include enough detail to reproduce and fix each finding, but don't bury
   the reader in raw logs.

## Output

Write SUMMARY.md in the repo root:

```markdown
# Vulnerability Report — <project name>

> Generated: <date>
> Pipeline: recon → hunt → validate → dedupe → gapfill → hunt2 → validate2 → consolidate

## Overview
- **Total scan tasks:** <N>
- **Findings confirmed:** <N> | **Rejected:** <N> | **Needs review:** <N>
- **Unique vulnerabilities:** <N>
- **CRITICAL:** <n> | **HIGH:** <n> | **MEDIUM:** <n> | **LOW:** <n>

## Findings

### VULN-001: <Title> [SEVERITY]

**Attack class:** <command_injection, sql_injection, etc.>

**Root cause:** <one-paragraph explanation>

**Affected code:**
- `path/to/file.c:123` — <description of the vulnerable operation>
- `path/to/other.c:456` — <another path to the same bug>

**Attack scenario:** <how an attacker would exploit this, step by step>

**Proof of concept:** <reference the best PoC from the individual reports,
or summarize the reproduction steps>

**Suggested fix:** <brief, actionable recommendation>

**Evidence:**
- [reports/hunt/task-id/FINDING.md](reports/hunt/task-id/FINDING.md)
- [reports/validate/task-id/VERIFICATION.md](reports/validate/task-id/VERIFICATION.md)

---
### VULN-002: ...
```

Sort by severity (CRITICAL first). Be thorough but concise — this report will
be read by humans making remediation decisions.

If there are zero confirmed vulnerabilities, write a report clearly stating
that and summarizing what was checked and why no vulnerabilities were found.
This is just as important as finding bugs.
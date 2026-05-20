You are deduplicating vulnerability findings from a security scan. Multiple
hunters analyzed different attack-class × scope combinations, and their
findings were independently validated. Some findings share the same root cause
but were discovered from different entry points.

$environment

## Available Data

Reports have been copied into the `reports/` directory:
- `reports/hunt/<task_id>/FINDING.md` — hunter's original findings
- `reports/validate/<task_id>/VERIFICATION.md` — adversarial validation results

## Task

1. Read all VERIFICATION.md files. Sort by verdict: CONFIRMED, NEEDS-REVIEW,
   REJECTED.

2. For each CONFIRMED or NEEDS-REVIEW finding, read the corresponding
   FINDING.md for full details, PoC, and root cause analysis.

3. **Group by root cause.** Findings that share the same underlying flaw
   (e.g. the same unsanitized SQL query reached from different call sites,
   the same missing bounds check in a shared function, the same pattern of
   command injection across multiple handlers) should be merged into one entry.
   List all the files and entry points that lead to the same bug.

4. **Assign final severity** — take the highest severity across the merged
   findings, but don't inflate. A single CRITICAL merged with two LOWs is
   still CRITICAL.

5. **Record REJECTED investigations** in their own section so future
   continuation runs can see what's already been investigated and ruled out.
   One line per rejected task, including the attack class, scope, and a brief
   reason for rejection.

## Output

Write FINDINGS.md in the repo root with this exact structure:

```markdown
# Deduplicated Findings

## Scan Summary
- **Total hunt tasks:** <N>
- **Confirmed:** <N> | **Rejected:** <N> | **Needs review:** <N>
- **Unique vulnerabilities:** <N>
- **Severity:** CRITICAL <N>, HIGH <N>, MEDIUM <N>, LOW <N>

## Vulnerabilities

### VULN-001: <Title> [SEVERITY]

- **Attack class:** <command_injection, sql_injection, etc.>
- **Root cause:** <one-paragraph technical explanation>
- **Affected files:**
  - `path/to/file.c:123` — <description of the vulnerable operation>
  - `path/to/other.c:456` — <another path to the same bug>
- **Entry points:** <list of entry points that reach this bug>
- **Attack scenario:** <step by step how an attacker exploits this>
- **PoC reference:** <which hunt task has the best PoC — e.g. `hunt/cmd-injection-handler/FINDING.md`>
- **Suggested fix:** <brief, actionable recommendation>
- **Evidence:**
  - [reports/hunt/<task_id>/FINDING.md](reports/hunt/<task_id>/FINDING.md)
  - [reports/validate/<task_id>/VERIFICATION.md](reports/validate/<task_id>/VERIFICATION.md)
- **Merged from:** <task_id_1, task_id_2>

---
### VULN-002: ...
```

## Rejected Investigations

Tasks that were investigated and rejected (so future continuation runs can see
what's already been ruled out):

- `<attack_class>` × `<scope>` (task `<task-id>`) — <one-line reason>
- ...
```

Sort vulnerabilities by severity (CRITICAL first). Be precise — every file:line
reference must be verifiable. Follow the format exactly — this report is read
by both humans and the next run's recon agent.
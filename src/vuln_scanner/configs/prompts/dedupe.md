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

1. Read all VERIFICATION.md files. Only consider findings with verdict
   CONFIRMED or NEEDS-REVIEW. Skip REJECTED findings.

2. For each confirmed finding, read the corresponding FINDING.md for full
   details, PoC, and root cause analysis.

3. **Group by root cause.** Findings that share the same underlying flaw
   (e.g. the same unsanitized SQL query reached from different call sites,
   the same missing bounds check in a shared function, the same pattern of
   command injection across multiple handlers) should be merged into one entry.
   List all the files and entry points that lead to the same bug.

4. **Assign final severity** — take the highest severity across the merged
   findings, but don't inflate. A single CRITICAL merged with two LOWs is
   still CRITICAL.

5. **Identify coverage gaps for gapfill.** For each scope that was scanned,
   note which attack classes WEREN'T checked but COULD apply. This will feed
   the gapfill phase.

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

## Coverage Gaps

The following (attack_class × scope) combinations were NOT covered but may be
worth investigating:

- **`<attack_class>` in `<scope>`** — <why this might be worth checking>
- ...

If there are no meaningful gaps, write "None identified — all high-priority
combinations were covered."
```

Sort vulnerabilities by severity (CRITICAL first). Be precise — every file:line
reference must be verifiable. This report will be read by both humans and the
gapfill agent, so follow the format exactly.
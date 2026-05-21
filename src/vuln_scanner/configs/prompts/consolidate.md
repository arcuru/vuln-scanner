You are writing the **cumulative** human-readable vulnerability report for an
ongoing investigation. The deduplication phase has grouped this run's findings
by root cause. Your job is to merge them with prior runs' findings into a
single report that reflects the current state of the investigation across all
runs to date.

$environment

## Available Data

Reports for this run have been copied into the `reports/` directory:
- `reports/dedupe/FINDINGS.md` — this run's deduplicated findings (authoritative
  for the current run, includes a Rejected Investigations section)
- `reports/hunt/<task_id>/FINDING.md` — this run's hunt reports
- `reports/validate/<task_id>/VERIFICATION.md` — this run's validations

Prior runs are at `$prior_runs_path` (empty for the first run). When non-empty:
- `<prior_runs_path>/<run-id>/SUMMARY.md` — the cumulative report from each
  prior run. The most recent one is the best starting point — its findings are
  already tagged with NEW / PERSISTS / FIXED / REGRESSED.
- `<prior_runs_path>/<run-id>/manifest.toml` — `target_sha` of that run.

## Task

1. Read `reports/dedupe/FINDINGS.md` — this run's findings.

2. If this is a continuation run, read the most recent prior run's
   `SUMMARY.md` to see prior findings and their last-known state.

3. **Reconcile each finding** with prior state and tag it:
   - **NEW** — first surfaced in this run
   - **PERSISTS** — present in a prior run, still confirmed at this run's SHA
   - **FIXED** — present in a prior run, no longer reproducible at this SHA
     (either the target code changed and the bug is gone, or this run's
     adversarial validation REJECTED what was previously CONFIRMED)
   - **REGRESSED** — was FIXED in some intermediate run, has returned

   Use natural-language matching by attack class + scope + root cause. There
   is no stable cross-run vuln identifier — the agent does the matching.

4. For each finding, read evidence files (this run's, and prior runs' if
   relevant) for full details, PoC code, and reproduction steps.

5. Write a clean, well-organized report that a security engineer can act on.

## Output

Write SUMMARY.md in the repo root:

```markdown
# Vulnerability Report — <project name>

> Run: <this run-id>
> Target SHA: <this run's target SHA>
> Prior runs considered: <N>  (most recent: <prior run-id> at <prior SHA>)

## Overview
- **This run's tasks:** <N>  (confirmed <N>, rejected <N>, needs-review <N>, failed <N>)
- **Cumulative unique vulnerabilities:** <N>
  (NEW: <n>, PERSISTS: <n>, FIXED: <n>, REGRESSED: <n>)
- **By severity (active only — NEW + PERSISTS + REGRESSED):**
  CRITICAL <n>, HIGH <n>, MEDIUM <n>, LOW <n>

## Findings

### VULN-001: <Title> [SEVERITY] [STATUS]

**Status:** NEW | PERSISTS | FIXED | REGRESSED
**First seen:** <run-id> (target SHA <sha>)
**Last confirmed:** <run-id> (target SHA <sha>)  *omit if status is FIXED*

**Attack class:** <command_injection, sql_injection, etc.>

**Root cause:** <one-paragraph explanation>

**Affected code:**
- `path/to/file.c:123` — <description of the vulnerable operation>
- `path/to/other.c:456` — <another path to the same bug>

**Attack scenario:** <how an attacker would exploit this, step by step>

**Proof of concept:** <reference the best PoC from this or prior runs>

**Suggested fix:** <brief, actionable recommendation>

**Evidence:**
- [reports/hunt/task-id/FINDING.md](reports/hunt/task-id/FINDING.md)
- [reports/validate/task-id/VERIFICATION.md](reports/validate/task-id/VERIFICATION.md)
- (prior runs:) [<prior-run-id>/SUMMARY.md](../<prior-run-id>/SUMMARY.md)

---
### VULN-002: ...

## Failed Investigations (this run)

Carry forward the "Failed Investigations" section from
`reports/dedupe/FINDINGS.md` verbatim if present, so the cumulative SUMMARY.md
makes clear which codepaths this run did NOT clear. Continuation runs read
this section to know what to re-attempt. Omit the heading entirely if no
tasks failed.
```

Sort by status (NEW + REGRESSED first, then PERSISTS, then FIXED), then by
severity within each group. Be thorough but concise.

If this run found zero new vulnerabilities and nothing changed in prior
findings' status, write a brief report stating that explicitly. Failed
investigations still get listed — they are not a "no findings" outcome.
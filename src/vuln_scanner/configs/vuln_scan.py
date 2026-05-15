"""Vulnerability scan config for claude-sweep.

Config files are plain Python modules. They must define:
  BRANCH_PREFIX, PHASE1_OUTPUT, PHASE2_OUTPUT, phase1_prompt(), phase2_prompt()
Optional: phase3_prompt(output_dir), PHASE3_OUTPUT
"""

from pathlib import Path

BRANCH_PREFIX = "vuln-scan"
PHASE1_OUTPUT = "VULN-REPORT.md"
PHASE2_OUTPUT = "VULN-VERIFIED.md"
PHASE3_OUTPUT = "SUMMARY.md"

PRIORITY_PROMPT = """\
You are selecting files for a CTF vulnerability scan. Prioritize:
- Code that handles user input (HTTP handlers, form processing, CLI arg parsing)
- Authentication and authorization logic
- Database access layers, ORM models, raw SQL
- File I/O, path construction, file uploads
- Deserialization, template rendering, eval/exec usage
- Cryptography, token generation, session management
- Code flagged in GitHub issues as buggy or security-related

Read the README and any security docs first to understand the attack surface."""


ENVIRONMENT_CONTEXT = """\
## Environment

You are running inside an isolated git worktree — a full, independent copy of
the repository. You can modify any file, install packages, compile, run tests,
execute the application, write exploit code, and do anything else you need.
Nothing you do here affects the original repo or any other worker. Your changes
will be committed and preserved on a dedicated branch after you finish.

You have full shell access with no permission restrictions. Use it freely."""


def phase1_prompt(rel_path: str) -> str:
    return f"""\
I'm competing in a CTF. Find me an exploitable vulnerability in this project.

{ENVIRONMENT_CONTEXT}

## Task

Start your analysis with: {rel_path}
But you have the full repo — trace call chains, check configs, build and run
the code, write a PoC, whatever you need.

Approach this methodically:
1. Read and understand the target file and its role in the project
2. Trace data flows — where does user input enter? Where is it used unsafely?
3. Check for common vulnerability classes (injection, auth bypass, memory safety,
   deserialization, path traversal, SSRF, etc.)
4. If you find something promising, build and run a proof of concept
5. If the PoC works, document it. If it doesn't, explain why the mitigation holds.

When done, write your vulnerability report to VULN-REPORT.md in the repo root.
Include:
- Vulnerability type and severity (CRITICAL / HIGH / MEDIUM / LOW)
- Affected file(s) and line numbers
- Root cause analysis
- Proof of concept (code or reproduction steps you actually tested)
- Suggested fix

If you don't find anything exploitable in or related to this file, write
VULN-REPORT.md anyway explaining what you checked and why it's not vulnerable."""


def phase2_prompt(rel_path: str) -> str:
    return f"""\
I got an inbound vulnerability report. Your job is to independently verify
whether it is actually exploitable.

{ENVIRONMENT_CONTEXT}

The original investigator worked in this same repo before you. Their
modifications, PoC scripts, and any other artifacts are preserved in the git
history of this worktree — check `git log` and `git diff HEAD~1` to see what
they did.

## Task

Read the vulnerability report in VULN-REPORT.md, then:

1. Understand the claimed vulnerability and root cause
2. Read the relevant source code yourself — don't trust the report blindly
3. If the reporter wrote a PoC, run it. If they didn't, write your own.
4. Check whether the vulnerability is reachable from actual user input
5. Check for mitigations the reporter may have missed (sanitization, type
   checking, sandboxing, permission checks, etc.)

Write your verification result to VULN-VERIFIED.md. Include:
- Verdict: CONFIRMED or REJECTED or NEEDS-REVIEW
- Your independent reproduction steps and results
- If rejected: specifically what the original report got wrong
- If confirmed: severity assessment and realistic attack scenario
- If needs-review: what you couldn't determine and why"""


def phase3_prompt(output_dir: Path) -> str:
    """Build the consolidation prompt. Reports are in the worktree, not the prompt."""
    # Just build a manifest so Claude knows what to read
    phase2_dir = output_dir / "phase2"
    files = sorted(
        str(f.relative_to(phase2_dir)).removesuffix(".md")
        for f in phase2_dir.rglob("*.md")
    )
    manifest = "\n".join(f"- {f}" for f in files)

    return f"""\
You are consolidating the results of a vulnerability scan. Multiple independent
analysts each examined a different source file in the same project. Many of them
found the same underlying vulnerabilities from different entry points.

{ENVIRONMENT_CONTEXT}

## Available Data

Individual reports have been copied into the `reports/` directory:
- `reports/phase1/<file>.md` — original vulnerability report for each file
- `reports/phase2/<file>.md` — independent verification of each report

Files analyzed ({len(files)} total):
{manifest}

## Task

1. Read through the verification reports in `reports/phase2/`. Focus on reports
   with CONFIRMED or NEEDS-REVIEW verdicts — skip REJECTED ones.
2. For each confirmed finding, read the corresponding `reports/phase1/` report
   for the full details, PoC, and root cause analysis.
3. **Group duplicates.** Multiple reports about the same root cause (e.g. the
   same unsanitized SQL query reached from different call sites) should be
   merged into one finding. List all the files/entry points that lead to it.
4. **Assign a final severity** (CRITICAL / HIGH / MEDIUM / LOW).
5. Write the consolidated report to SUMMARY.md.

## Output Format (SUMMARY.md)

```markdown
# Vulnerability Report

## Overview
<total unique findings, severity breakdown>

## Findings

### 1. <Title> [SEVERITY]

**Root cause:** <one-paragraph explanation>

**Affected code:**
- `path/to/file.c:123` — <description>
- `path/to/other.c:456` — <another entry point to the same bug>

**Attack scenario:** <how an attacker would exploit this>

**Proof of concept:** <reference the best PoC from the individual reports,
or summarize the reproduction steps>

**Suggested fix:** <brief recommendation>

**Evidence:**
- [reports/phase1/path-to-file.c.md](reports/phase1/path-to-file.c.md)
- [reports/phase2/path-to-file.c.md](reports/phase2/path-to-file.c.md)
- ...

---
### 2. ...
```

Sort findings by severity (CRITICAL first). Be thorough but concise — this is
the report that will be read by humans."""

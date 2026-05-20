"""Vulnerability scan config — recon → hunt → validate → dedupe → gapfill → hunt2 → validate2 → consolidate.

Config files are plain Python modules. Required:
  recon_prompt() -> str
  hunt_prompt(*, attack_class, scope, function, entry_point,
               rationale, arch_summary) -> str
  validate_prompt() -> str
Optional: dedupe_prompt(), gapfill_prompt(), consolidate_prompt()
"""

from __future__ import annotations

from pathlib import Path

BRANCH_PREFIX = "vuln-scan"

# Agent backend: "claude" (default) or "pi"
AGENT = "claude"
# Extra flags passed verbatim to the agent command.
# Prefer setting models via the TOML [agent.models] section; use this for
# backend-specific knobs (e.g. "--thinking high").
AGENT_FLAGS = ""
# Default task timeout in seconds (0 = no timeout)
TASK_TIMEOUT = 0
# Per-phase timeout overrides (phase_name -> seconds)
# e.g. {"hunt": 900, "validate": 600, "hunt2": 900, "validate2": 600}
TASK_TIMEOUTS: dict[str, int] = {}

# ---------------------------------------------------------------------------
# Per-phase model overrides (None = use Claude Code's configured default)
# Set these to use different models per phase for model diversity.
# ---------------------------------------------------------------------------

RECON_MODEL = None       # e.g. "claude-sonnet-4-6"
HUNT_MODEL = None        # e.g. "claude-sonnet-4-6"
VALIDATE_MODEL = None    # e.g. "claude-opus-4-7" (different model for adversarial review)
GAPFILL_MODEL = None
HUNT2_MODEL = None       # defaults to HUNT_MODEL if None
VALIDATE2_MODEL = None   # defaults to VALIDATE_MODEL if None
DEDUPE_MODEL = None
CONSOLIDATE_MODEL = None

# ---------------------------------------------------------------------------
# Attack classes — the full catalog. The recon phase assigns relevant ones per scope.
# ---------------------------------------------------------------------------

ATTACK_CLASSES = [
    "command_injection",
    "sql_injection",
    "path_traversal",
    "authentication_bypass",
    "authorization_bypass",
    "buffer_overflow",
    "use_after_free",
    "format_string",
    "integer_overflow",
    "deserialization",
    "ssrf",
    "xxe",
    "xss",
    "open_redirect",
    "race_condition",
    "crypto_misuse",
    "information_disclosure",
]

# ---------------------------------------------------------------------------
# Output filenames
# ---------------------------------------------------------------------------

RECON_OUTPUT = "HUNT_QUEUE.json"
HUNT_OUTPUT = "FINDING.md"
VALIDATE_OUTPUT = "VERIFICATION.md"
DEDUPE_OUTPUT = "FINDINGS.md"
GAPFILL_OUTPUT = "HUNT_QUEUE_2.json"
CONSOLIDATE_OUTPUT = "SUMMARY.md"

# ---------------------------------------------------------------------------
# Shared context injected into every prompt
# ---------------------------------------------------------------------------

ENVIRONMENT_CONTEXT = """\
## Environment

You are running inside an isolated git worktree — a full, independent copy of
the repository. You can modify any file, install packages, compile, run tests,
execute the application, write exploit code, and do anything else you need.
Nothing you do here affects the original repo or any other worker. Your changes
will be committed and preserved on a dedicated branch after you finish.

You have full shell access with no permission restrictions. Use it freely."""

# ---------------------------------------------------------------------------
# Phase 1 — Reconnaissance
# ---------------------------------------------------------------------------


def recon_prompt() -> str:
    return f"""\
You are performing a security reconnaissance pass over a codebase. Your job is
to understand the project's architecture and produce a structured hunt queue
that downstream agents will use to find vulnerabilities.

{ENVIRONMENT_CONTEXT}

## Task

1. **Read the project top-down.** Start with the README, build files
   (Makefile, CMakeLists.txt, Cargo.toml, package.json, etc.), and top-level
   directory structure. Understand:
   - What the project does
   - How it's built and run
   - Major subsystems and how they connect
   - Which languages are used where

2. **Map trust boundaries.** For each subsystem, identify:
   - **Entry points** — where does external input enter? (HTTP handlers, CLI
     args, config files, network sockets, file reads, IPC, environment
     variables, etc.)
   - **Trust boundaries** — where does data cross from untrusted → trusted
     context? (user input → application logic, network → local, etc.)
   - **Sensitive operations** — auth checks, database queries, file writes,
     command execution, memory management, crypto operations

3. **Generate hunt tasks.** For each entry point that crosses a trust boundary,
   identify which attack classes are relevant and produce a hunt task. Each
   task pairs ONE attack class with ONE scope. A single entry point should
   generate multiple tasks — one per relevant attack class.

   Available attack classes: {', '.join(ATTACK_CLASSES)}

   Be specific. Bad: "Look for injection in src/handler.c"
   Good: "Look for command injection in parse_filename() at src/handler.c:142,
   where user-supplied multipart filename is passed to system()"

## Output

Write a file called HUNT_QUEUE.json in the repo root with this structure:

```json
{{
  "architecture_summary": "<2-3 paragraph overview of the project, its trust boundaries, and key subsystems>",
  "trust_boundaries": [
    {{
      "name": "<e.g. Public HTTP API>",
      "entry_points": ["<e.g. POST /upload, GET /search>"],
      "description": "<how input crosses this boundary>"
    }}
  ],
  "tasks": [
    {{
      "id": "<unique kebab-case id, e.g. cmd-injection-upload-handler>",
      "attack_class": "<from the list above>",
      "scope": "<file path or subsystem name>",
      "function": "<specific function name, or empty if subsystem-wide>",
      "entry_point": "<how attacker input reaches this code>",
      "rationale": "<why this attack class is relevant to this scope — one sentence>"
    }}
  ]
}}
```

Requirements:
- Every attack class you assign MUST be from the list above
- Every task MUST pair exactly ONE attack class with ONE scope
- Cover every entry point you find — an entry point with no tasks is a gap
- Produce at least 10 tasks for a non-trivial project. More is better.
- If the project is very large, focus on the highest-risk areas first
  (auth, input handling, network-facing code, crypto)
- Do NOT include attack classes that are structurally impossible
  (e.g. don't assign buffer_overflow to a Python project)

Write HUNT_QUEUE.json and nothing else — the architecture understanding is
captured in the queue file itself."""


# ---------------------------------------------------------------------------
# Phase 2 — Hunt
# ---------------------------------------------------------------------------


def hunt_prompt(
    *,
    attack_class: str,
    scope: str,
    function: str,
    entry_point: str,
    rationale: str,
    arch_summary: str,
) -> str:
    function_hint = f"\n**Target function:** `{function}`" if function else ""

    return f"""\
You are hunting for a specific class of vulnerability in a specific part of
this codebase. Your scope is NARROW — stay focused.

{ENVIRONMENT_CONTEXT}

## Architecture Context

{arch_summary}

## Hunt Target

- **Attack class:** {attack_class}
- **Scope:** {scope}{function_hint}
- **Entry point:** {entry_point}
- **Rationale:** {rationale}

## Approach

1. **Read the target code** — understand exactly what {scope} does and how
   data flows from {entry_point} through this code.

2. **Look for the specific vulnerability class** — do NOT wander into other
   classes. If you're assigned `command_injection`, look for shell command
   construction with user input. If you're assigned `sql_injection`, look for
   query building. Stay on target.

3. **Trace the full data path** — from entry point to the potentially
   vulnerable operation. Is the input sanitized anywhere along the way?
   Is there a guard that would block an attacker?

4. **Build a proof of concept.** If you find something suspicious, you MUST
   attempt to prove exploitability through the loop below.

## Proof of Concept Loop (CRITICAL)

You MUST run this loop when you find a potential vulnerability. Document every
attempt.

**Attempt 1:**
1. Write exploit code / test harness that would trigger the vulnerability
2. Compile it. If compilation fails, fix errors and recompile.
3. Run it against the target (build and run the application if needed)
4. Evaluate:
   - **SUCCESS** → the vulnerability is confirmed. Document the working PoC.
   - **FAILURE** → read the output carefully. Why didn't it work?

**Attempt 2 through 5:**
- Adjust your approach based on what you learned from the previous failure
- Try a different payload, a different input path, a different triggering
  condition
- Compile → run → evaluate again

**After 5 attempts:**
- If you got it working → CONFIRMED. Write up the complete finding.
- If it never worked → explain SPECIFICALLY what mitigation blocked you and
  why you believe it holds. This is still a valuable finding.

**Important:** Do NOT skip the loop. Do NOT claim exploitability without a
working PoC. Do NOT give up after one failure — adjust and try again.

## Output

Write FINDING.md in the repo root:

```markdown
# Hunt Result: {attack_class} in {scope}

**Verdict:** CONFIRMED / LIKELY / CLEAN

## Summary
<one paragraph — what you found or why it's clean>

## Data Flow
<Trace from entry point to potentially vulnerable operation. Include file:line
references for every step.>

## Proof of Concept (if CONFIRMED or LIKELY)
<The exploit code you wrote and ran, with output showing it worked.>

## Attempt Log
<For each attempt: what you tried, what happened, what you changed.>

## Mitigation (if CLEAN)
<What prevents exploitation — sanitization, type safety, sandboxing, etc.>

## Coverage
- [x] {attack_class} — CHECKED
- [ ] Other attack classes — NOT IN SCOPE
```

State the verdict clearly. CONFIRMED with a working PoC is the goal. LIKELY
means you found a plausible vector but couldn't get a clean PoC. CLEAN means
you verified the code is safe for this attack class — write a good explanation
of why, as this is just as valuable as finding a bug.

Write FINDING.md and nothing else."""


# ---------------------------------------------------------------------------
# Phase 3 — Adversarial Validation
# ---------------------------------------------------------------------------


def validate_prompt() -> str:
    return f"""\
You are an adversarial reviewer. Your job is to DISPROVE vulnerability findings.
Assume every finding is a false positive until you can demonstrate otherwise.

{ENVIRONMENT_CONTEXT}

A hunter previously analyzed this codebase and wrote a vulnerability report in
FINDING.md. The hunter's modifications, PoC scripts, and artifacts are
preserved in the git history — check `git log` and `git diff HEAD~1` to see
their work.

## Task

Read FINDING.md, then:

1. **Assume the finding is wrong.** Your default posture is SKEPTICAL. The
   hunter may have:
   - Misunderstood the code flow
   - Missed a sanitization or validation step
   - Wrongly assumed attacker control of input
   - Written a PoC that only works under unrealistic conditions

2. **Read the code yourself.** Do not trust the hunter's analysis. Read every
   file and function in the reported data path independently.

3. **Run the hunter's PoC.** Does it actually work? Does it produce the
   claimed result? If it doesn't work as claimed, the finding is REJECTED.

4. **Check for missed mitigations:**
   - Input validation / sanitization earlier in the call chain
   - Type constraints that prevent the exploit
   - Permission checks, sandboxing, containerization
   - Compiler mitigations (stack canaries, ASLR, CFI, etc.)
   - Runtime guards (e.g., prepared statements, parameterized queries)

5. **Try to break it anyway.** Even if the hunter's PoC works, try to find the
   condition that WOULD block it. If you can find a realistic scenario where
   the exploit can't reach the vulnerable code, that's a rejection.

## Output

Write VERIFICATION.md in the repo root:

```markdown
# Validation: {{{{attack_class}}}} in {{{{scope}}}}

**Verdict:** CONFIRMED / REJECTED / NEEDS-REVIEW

## Independent Analysis
<Your own understanding of the code, from scratch. Do not paraphrase the
hunter's report.>

## PoC Reproduction
<Ran the hunter's PoC? What happened? If you wrote your own, show it.>

## Missed Mitigations (if REJECTED)
<Specifically what the hunter got wrong or missed. Be precise — file:line.>

## Attack Feasibility (if CONFIRMED)
<How realistic is exploitation? What would an attacker need? Is it remotely
triggerable or local-only?>

## Severity Assessment (if CONFIRMED)
CRITICAL / HIGH / MEDIUM / LOW — with one-sentence justification.
```

**IMPORTANT:** You may ONLY validate the finding in FINDING.md. Do NOT report
new vulnerabilities. Do NOT expand the scope. If you find something the hunter
missed, note it in a single sentence at the end of your report but do NOT
treat it as a finding.

Write VERIFICATION.md and nothing else."""


# ---------------------------------------------------------------------------
# Phase 4 — Deduplication
# ---------------------------------------------------------------------------


def dedupe_prompt() -> str:
    return f"""\
You are deduplicating vulnerability findings from a security scan. Multiple
hunters analyzed different attack-class × scope combinations, and their
findings were independently validated. Some findings share the same root cause
but were discovered from different entry points.

{ENVIRONMENT_CONTEXT}

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
gapfill agent, so follow the format exactly."""


# ---------------------------------------------------------------------------
# Phase 5 — Gapfill
# ---------------------------------------------------------------------------


def gapfill_prompt() -> str:
    return f"""\
You are identifying coverage gaps in a security scan. The initial recon phase
generated a hunt queue, but not every (attack_class × scope) combination was
covered. Your job is to find what was missed and create a second hunt queue
for the gaps.

{ENVIRONMENT_CONTEXT}

## Available Data

Reports have been copied into the `reports/` directory:
- `reports/recon/HUNT_QUEUE.json` — original hunt queue + architecture summary
- `reports/dedupe/FINDINGS.md` — deduplicated findings with coverage gaps section
- `reports/hunt/<task_id>/FINDING.md` — individual hunt results
- Full source code of the repository

Available attack classes: {', '.join(ATTACK_CLASSES)}

## Task

1. **Read the deduplication output** — `reports/dedupe/FINDINGS.md` has a
   "Coverage Gaps" section identifying (attack_class × scope) combos suggested
   by the deduplication agent.

2. **Read individual hunt results** — each `reports/hunt/<task_id>/FINDING.md`
   has a "Coverage" section. Aggregate what was and wasn't checked.

3. **Review the original hunt queue** — `reports/recon/HUNT_QUEUE.json` shows
   what was originally assigned. Compare against what was actually completed.

4. **Scan the codebase for unscanned areas** — are there entire files or
   subsystems that weren't touched by any hunt task? Are there high-risk
   patterns (auth logic, crypto, network I/O, file operations) that were
   missed entirely?

5. **Create a gap-filling hunt queue.** Only include tasks that are genuinely
   worth investigating. Don't pad — a small gapfill queue with high-signal
   tasks is better than a large one with noise.

## Output

Write HUNT_QUEUE_2.json in the repo root — same format as the original
HUNT_QUEUE.json:

```json
{{
  "architecture_summary": "<same as original, or updated if you discover new context>",
  "generation_note": "<1-2 sentences explaining what gaps this queue fills>",
  "tasks": [
    {{
      "id": "<unique kebab-case id>",
      "attack_class": "<from the list above>",
      "scope": "<file path or subsystem name>",
      "function": "<specific function name, or empty if subsystem-wide>",
      "entry_point": "<how attacker input reaches this code>",
      "rationale": "<why this gap matters>"
    }}
  ]
}}
```

If there are no meaningful gaps, write HUNT_QUEUE_2.json with an empty tasks
array and a generation_note explaining why the initial scan was sufficient.

Write HUNT_QUEUE_2.json and nothing else."""


# ---------------------------------------------------------------------------
# Phase 8 — Consolidation (final report)
# ---------------------------------------------------------------------------


def consolidate_prompt(output_dir: Path) -> str | None:
    """Build the consolidation prompt. Reports are in the worktree, not the prompt."""
    dedupe_dir = output_dir / "dedupe"
    if not dedupe_dir.is_dir():
        return None

    findings_path = dedupe_dir / "FINDINGS.md"
    if not findings_path.exists():
        return None

    return f"""\
You are writing the final human-readable vulnerability report. The deduplication
phase has already grouped findings by root cause. Your job is to produce a
clear, actionable report for human readers from the structured deduplication
output and individual reports.

{ENVIRONMENT_CONTEXT}

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
This is just as important as finding bugs."""

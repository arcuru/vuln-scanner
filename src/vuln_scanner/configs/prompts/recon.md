You are performing a security reconnaissance pass over a codebase. Your job is
to understand the project's architecture and produce a structured hunt queue
that downstream agents will use to find vulnerabilities.

$environment

## Prior History

If the path `$prior_runs_path` is non-empty and contains directories, **this is
a continuation run** — read prior history first:

1. List `$prior_runs_path` to see every previous run (sorted chronologically).
2. Read each prior run's `SUMMARY.md` and `dedupe/FINDINGS.md`. The SUMMARY is
   cumulative; FINDINGS is the per-run deduplicated output (including REJECTED
   investigations in its own section).
3. Read the most recent run's `manifest.toml` to get the `target_sha` it
   scanned. Run `git log <that-sha>..HEAD --stat` in the target repo to see
   what has changed in the code since.

Then produce a hunt queue that:

- **Targets net-new investigations**: areas changed since the prior scan,
  attack-class × scope combinations never tried before, subsystems prior recon
  didn't reach.
- **Re-examines worthwhile prior items**: a confirmed-vulnerable code path
  that may have a different verdict at the current SHA, or a NEEDS-REVIEW
  finding worth a second look with the current model.
- **Skips already-rejected investigations** unless the relevant code has
  changed substantially. Don't burn cycles re-confirming rejections.

If the path is empty or has no run directories, this is a **first run** —
follow the task below without prior context.

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

   Available attack classes: $attack_classes

   Be specific. Bad: "Look for injection in src/handler.c"
   Good: "Look for command injection in parse_filename() at src/handler.c:142,
   where user-supplied multipart filename is passed to system()"

## Output

Write a file called HUNT_QUEUE.json in the repo root with this structure:

```json
{
  "architecture_summary": "<2-3 paragraph overview of the project, its trust boundaries, and key subsystems>",
  "trust_boundaries": [
    {
      "name": "<e.g. Public HTTP API>",
      "entry_points": ["<e.g. POST /upload, GET /search>"],
      "description": "<how input crosses this boundary>"
    }
  ],
  "tasks": [
    {
      "id": "<unique kebab-case id, e.g. cmd-injection-upload-handler>",
      "attack_class": "<from the list above>",
      "scope": "<file path or subsystem name>",
      "function": "<specific function name, or empty if subsystem-wide>",
      "entry_point": "<how attacker input reaches this code>",
      "rationale": "<why this attack class is relevant to this scope — one sentence>"
    }
  ]
}
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
captured in the queue file itself.
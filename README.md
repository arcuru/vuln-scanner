# vuln-scanner

LLM-driven vulnerability scanner that builds up an **investigation directory**
per scan target, accumulating history across runs as the target evolves and
models improve.

```
recon → hunt → validate → dedupe → consolidate     (per run)
```

> **Status:** experimental personal project. Expect false positives and
> meaningful token spend — every hunt task is an independent agent run. Treat
> findings as leads to validate manually, not as audit output.

## Prerequisites

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) for dependency and environment management
- `git` on `$PATH`
- An agent CLI for the chosen backend, authenticated:
  - [`claude`](https://github.com/anthropics/claude-code) — default backend
  - [`pi`](https://github.com/anthropics/oh-my-pi) — alternative backend
  - Anything else you wire up via a custom `[agent.backends.*]` entry

## Install

```bash
# Run from a checkout without installing globally
uv run vuln-scanner --help

# Or install as a uv tool (puts `vuln-scanner` on $PATH)
uv tool install .
```

## Quick start

Create a folder for the investigation, scaffold it against a target, run a
scan, check status.

```bash
mkdir cool-project-scan && cd cool-project-scan

# Clone the target into ./target/, write vuln-scanner.toml + MANIFEST.toml
uv run vuln-scanner init https://github.com/user/cool-project

# Run a scan (uses target's current HEAD; pass --sha to pin a commit)
uv run vuln-scanner run -j 8

# Re-run later (target may have new commits, or a newer model is available);
# the next recon reads prior runs and proposes net-new investigations
uv run vuln-scanner run --sha <newer-sha>

# See the run history
uv run vuln-scanner status
```

The investigation folder is self-contained. Move it, archive it, commit it to
its own git repo — it stays consistent.

## Investigation directory

`init` scaffolds, `run` produces an immutable per-run directory, `SUMMARY.md`
at the top always points at the latest run:

```
my-investigation/
  vuln-scanner.toml            # config (committed)
  MANIFEST.toml                # target URL, latest-run pointer
  target/                      # cloned scan target (gitignored)
  worktrees/                   # ephemeral worktrees (gitignored)
  .vuln-scanner.lock           # concurrency guard
  runs/
    2026-05-20T14-30-abc1234/  # ISO timestamp + short target SHA
      manifest.toml            # tool version, models used, target SHA, status
      recon/HUNT_QUEUE.json
      hunt/<task-id>/FINDING.md
      validate/<task-id>/VERIFICATION.md
      dedupe/FINDINGS.md
      SUMMARY.md               # cumulative across all runs
  SUMMARY.md  →  runs/<latest>/SUMMARY.md
```

The `.gitignore` written by `init` covers `target/`, `worktrees/`, and the
lockfile — so you can run `git init` in the investigation folder and track
the config + runs without dragging the target's full history with you.

## How it works

Each phase runs in its own git worktree off `target/`, isolating agent
artifacts per task:

1. **recon** — one task. Maps architecture and produces `HUNT_QUEUE.json`. On
   continuation runs, also reads prior runs' `SUMMARY.md` and the git diff
   since the prior target SHA, then produces a queue of net-new
   investigations and worthwhile revisits.
2. **hunt** — fan-out from the queue. Each entry is one attack class in one
   scope. Produces `FINDING.md` per task.
3. **validate** — fan-out from hunt tasks. Adversarial review of each finding.
   Produces `VERIFICATION.md` per task.
4. **dedupe** — one task. Groups confirmed findings by root cause, records
   rejected investigations so future recon can skip them. Produces
   `FINDINGS.md`.
5. **consolidate** — one task. Produces the cumulative `SUMMARY.md` with each
   finding tagged **NEW** / **PERSISTS** / **FIXED** / **REGRESSED** relative
   to prior runs.

Each run resumes from `.done` sentinels — if interrupted, re-running `run`
(without `--sha`) picks up where it left off in the same run directory.
Concurrent `run` invocations in the same investigation folder are refused via
the lockfile.

If recon decides there's nothing new to investigate (continuation run on an
unchanged target), it writes an empty queue and the pipeline bails early.

## Configuration

Two layers: a **prompt profile** (Python module with prompt functions, plus
markdown bodies) and a **TOML config** (settings overlay).

### Prompt profile (Python + markdown)

The built-in profile is `vuln-scan` (in `src/vuln_scanner/configs/vuln_scan.py`).
The prompt bodies live alongside it in `src/vuln_scanner/configs/prompts/` —
one `.md` per phase, with `$variable` placeholders substituted at render time:

```
configs/
  vuln_scan.py          # settings + glue (loads + renders the .md files)
  prompts/
    _environment.md     # shared snippet injected into every prompt
    recon.md            # uses $prior_runs_path for continuation runs
    hunt.md             # uses $attack_class, $scope, $entry_point, …
    validate.md
    dedupe.md
    consolidate.md      # uses $prior_runs_path
```

To tweak what the agents are told, edit the markdown — no Python changes
needed. Required prompt functions on the profile module:

- `recon_prompt(*, prior_runs_path: str = "") -> str`
- `hunt_prompt(*, attack_class, scope, function, entry_point, rationale, arch_summary) -> str`
- `validate_prompt() -> str`

Optional: `dedupe_prompt()`, `consolidate_prompt(output_dir, *, prior_runs_path="")`.

Write your own profile by copying `vuln_scan.py` (and the `prompts/` directory)
and pointing `vuln-scanner.toml` at it via `[scan] prompt_profile = "..."`.

### Settings (TOML)

`init` writes a minimal `vuln-scanner.toml` into the investigation folder.
See [`config.example.toml`](config.example.toml) for the full set of options
with comments. Key sections:

| Section | Purpose |
|---|---|
| `attack_classes` (top-level) | Vulnerability categories to scan for |
| `[scan]` | Profile, branch prefix, parallelism, timeouts |
| `[scan.task_timeouts]` | Per-phase timeout overrides (seconds) |
| `[agent]` | Backend name and flags |
| `[agent.models]` | Per-phase model names |
| `[agent.backends.<name>]` | Define custom backends in config |
| `[output]` | Per-phase output filenames |
| `[files]` | File extensions and exclude directories |

### Backends

Built-in backends: `claude` (Claude Code CLI) and `pi` (Oh My Pi). Set via
`[agent] backend = "..."`.

Custom backends can be defined directly in TOML — no Python code needed:

```toml
[agent]
backend = "gemini"

[agent.backends.gemini]
executable = "gemini-cli"
model_flag = "--model"
prompt_flag = "--prompt"
extra_args = ["--yes"]
```

Fields: `executable` (required), `prompt_flag` (required), `model_flag`
(optional), `extra_args` (optional). The resulting command is:

```
gemini-cli --yes --model <name> --prompt <text>
```

For backends needing custom logic beyond flags, implement the `Backend`
protocol in `src/vuln_scanner/claude.py` and add to the `BACKENDS` registry.

### Timeouts

`task_timeout` sets a global default (0 = no timeout). `task_timeouts`
overrides per phase:

```toml
[scan]
task_timeout = 0          # global default: no timeout

[scan.task_timeouts]
hunt = 900                # 15 minutes per hunt task
validate = 600
```

When a timeout is hit, the agent subprocess receives SIGTERM, then SIGKILL
after 5 seconds.

## Development

```bash
# Install dev dependencies
uv sync --extra dev

# Run tests
uv run pytest tests/ -v

# Type check
uv run pyright src/
```

## Credits

The multi-phase recon → hunt → validate → dedupe → consolidate architecture
is adapted from the design Cloudflare describes in
["Cyber frontier models: Claude's strengths in software security"](https://blog.cloudflare.com/cyber-frontier-models/),
which lays out the agentic vulnerability-research pipeline this project
re-implements on top of Claude Code (or any other agent CLI). Cloudflare's
in-process gapfill / hunt2 / validate2 second pass is here realized as
*running the tool again* — the next run's recon reads prior runs' findings
and produces a queue informed by them.

## License

AGPL-3.0-or-later. See [`LICENSE.txt`](LICENSE.txt).

# vuln-scanner

Multi-phase LLM-powered vulnerability scanner over git repos using isolated worktrees.

```
recon → hunt → validate → dedupe → gapfill → hunt2 → validate2 → consolidate
```

> **Status:** experimental personal project. Expect false positives and meaningful
> token spend — every hunt task is an independent agent run. Treat findings as
> leads to validate manually, not as audit output.

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

```bash
# Scan a local repo with the built-in prompt profile
uv run vuln-scanner /path/to/repo -c vuln_scan

# Scan a remote repo (clones automatically)
uv run vuln-scanner https://github.com/user/repo -c config.toml

# Increase parallelism
uv run vuln-scanner /path/to/repo -c vuln_scan -j 8
```

## How it works

Each phase runs in its own git worktree, isolating agent artifacts per task:

1. **recon** — one task. Maps the codebase architecture and produces `HUNT_QUEUE.json`
2. **hunt** — fan-out from the queue. Each entry is one attack class in one scope. Produces `FINDING.md`
3. **validate** — fan-out from hunt tasks. Adversarial review of each finding. Produces `VERIFICATION.md`
4. **dedupe** (optional) — one task. Groups validated findings by root cause.
5. **gapfill** (optional) — one task. Identifies coverage gaps, produces `HUNT_QUEUE_2.json`
6. **hunt2** — fan-out from the gapfill queue. Second hunting pass.
7. **validate2** — fan-out from hunt2 tasks. Second validation pass.
8. **consolidate** (optional) — one task. Merges all findings into `SUMMARY.md`

Output lands in `output/<phase>/` and `output/logs/`.

## Configuration

Two layers: a **prompt profile** (Python module with prompt functions) and a **TOML config** (settings overlay).

### Prompt profile (Python)

The built-in profile is `vuln_scan` (in `src/vuln_scanner/configs/vuln_scan.py`). Required functions:

- `recon_prompt() -> str`
- `hunt_prompt(*, attack_class, scope, function, entry_point, rationale, arch_summary) -> str`
- `validate_prompt() -> str`

Optional: `dedupe_prompt()`, `gapfill_prompt()`, `consolidate_prompt(output_dir)`.

Write your own by copying `vuln_scan.py` and customizing the prompts, then reference it:

```bash
vuln-scanner ./repo -c my_profile.py
```

### Settings (TOML)

See [`config.example.toml`](config.example.toml) for all options with comments. Key sections:

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

Built-in backends: `claude` (Claude Code CLI) and `pi` (Oh My Pi). Set via `[agent] backend`.

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

Fields: `executable` (required), `prompt_flag` (required), `model_flag` (optional), `extra_args` (optional). The resulting command is:

```
gemini-cli --yes --model <name> --prompt <text>
```

For backends requiring custom logic beyond flags, implement the `Backend` protocol in `src/vuln_scanner/claude.py` and add to the `BACKENDS` registry.

### Model fallback

When a phase's model is unset, the fallback chain is:

| Phase | Fallback |
|---|---|
| recon, hunt, validate, dedupe, gapfill, consolidate | agent default |
| hunt2 | hunt2_model → hunt_model → agent default |
| validate2 | validate2_model → validate_model → agent default |

### Timeouts

`task_timeout` sets a global default (0 = no timeout). `task_timeouts` overrides per phase:

```toml
[scan]
task_timeout = 0          # global default: no timeout

[scan.task_timeouts]
hunt  = 900               # 15 minutes per hunt task
hunt2 = 900
```

When a timeout is hit, the agent subprocess receives SIGTERM, then SIGKILL after 5 seconds.

## Resumability

If a scan is interrupted, re-running with the same output directory skips tasks whose outputs already exist. A `.done` sentinel file is written alongside each task's outputs; tasks without the sentinel are re-executed even if output files exist (guarding against partial writes).

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

The multi-phase recon → hunt → validate → dedupe → gapfill loop is adapted
from the architecture Cloudflare describes in
["Cyber frontier models: Claude's strengths in software security"](https://blog.cloudflare.com/cyber-frontier-models/),
which lays out the agentic vulnerability-research pipeline this project
re-implements on top of Claude Code (or any other agent CLI).

## License

AGPL-3.0-or-later. See [`LICENSE.txt`](LICENSE.txt).

"""Vulnerability scan profile.

Pipeline: recon → hunt → validate → dedupe → gapfill → hunt2 → validate2 → consolidate.

Prompt bodies live alongside this file in ``prompts/`` (one ``.md`` per phase,
with ``$variable`` placeholders). This module wires settings + parameterized
substitution; edit the markdown to change what the agents are told.
"""

from __future__ import annotations

from pathlib import Path
from string import Template

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
# Per-phase model overrides (None = use the agent backend's configured default)
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
# Prompt loading — bodies live in prompts/<phase>.md with $variable placeholders
# ---------------------------------------------------------------------------

_PROMPTS_DIR = Path(__file__).parent / "prompts"
_ENVIRONMENT = (_PROMPTS_DIR / "_environment.md").read_text().rstrip()
_ATTACK_CLASSES_STR = ", ".join(ATTACK_CLASSES)


def _render(name: str, **extra: str) -> str:
    """Render prompts/<name>.md with $environment, $attack_classes, plus extras."""
    template = Template((_PROMPTS_DIR / f"{name}.md").read_text())
    return template.substitute(
        environment=_ENVIRONMENT,
        attack_classes=_ATTACK_CLASSES_STR,
        **extra,
    )


# ---------------------------------------------------------------------------
# Prompt functions
# ---------------------------------------------------------------------------


def recon_prompt() -> str:
    return _render("recon")


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
    return _render(
        "hunt",
        attack_class=attack_class,
        scope=scope,
        function_hint=function_hint,
        entry_point=entry_point,
        rationale=rationale,
        arch_summary=arch_summary,
    )


def validate_prompt() -> str:
    return _render("validate")


def dedupe_prompt() -> str:
    return _render("dedupe")


def gapfill_prompt() -> str:
    return _render("gapfill")


def consolidate_prompt(output_dir: Path) -> str | None:
    """Build the consolidation prompt, or None if dedupe didn't produce output."""
    findings_path = output_dir / "dedupe" / "FINDINGS.md"
    if not findings_path.exists():
        return None
    return _render("consolidate")

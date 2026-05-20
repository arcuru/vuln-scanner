"""Config loading — supports Python modules (backward compat) and TOML config files.

Python modules (prompt profiles) define prompt functions.
TOML config files overlay settings on top of a prompt profile.

Required in either form:
    recon_prompt(), hunt_prompt(), validate_prompt()  (from profile)
Optional: dedupe_prompt(), gapfill_prompt(), consolidate_prompt()
"""

from __future__ import annotations

import importlib.util
import logging
import sys
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

from vuln_scanner.files import DEFAULT_EXCLUDE_DIRS, DEFAULT_EXTENSIONS

logger = logging.getLogger("vuln-scanner")

DEFAULT_ATTACK_CLASSES = [
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


class Config:
    """Wraps settings + prompt functions. Built from a Python module, with
    optional TOML overlays.
    """

    def __init__(self, mod: ModuleType) -> None:
        # Agent
        self.agent: str = getattr(mod, "AGENT", "claude")
        self.agent_flags: str = getattr(mod, "AGENT_FLAGS", "")

        # Scan
        self.branch_prefix: str = getattr(mod, "BRANCH_PREFIX", "vuln-scan")
        self.max_tasks: int = getattr(mod, "MAX_TASKS", 0)  # 0 = unlimited
        self.task_timeout: int = getattr(mod, "TASK_TIMEOUT", 0)  # 0 = no timeout
        self.task_timeouts: dict[str, int] = getattr(mod, "TASK_TIMEOUTS", {})

        # Attack classes
        self.attack_classes: list[str] = getattr(
            mod, "ATTACK_CLASSES", DEFAULT_ATTACK_CLASSES,
        )
        self.extensions: str = getattr(mod, "EXTENSIONS", DEFAULT_EXTENSIONS)
        self.exclude_dirs: set[str] = getattr(mod, "EXCLUDE_DIRS", DEFAULT_EXCLUDE_DIRS)

        # Per-phase model overrides
        self.recon_model: str | None = getattr(mod, "RECON_MODEL", None)
        self.hunt_model: str | None = getattr(mod, "HUNT_MODEL", None)
        self.validate_model: str | None = getattr(mod, "VALIDATE_MODEL", None)
        self.hunt2_model: str | None = getattr(mod, "HUNT2_MODEL", None)
        self.validate2_model: str | None = getattr(mod, "VALIDATE2_MODEL", None)
        self.dedupe_model: str | None = getattr(mod, "DEDUPE_MODEL", None)
        self.gapfill_model: str | None = getattr(mod, "GAPFILL_MODEL", None)
        self.consolidate_model: str | None = getattr(mod, "CONSOLIDATE_MODEL", None)

        # Output filenames
        self.recon_output: str = getattr(mod, "RECON_OUTPUT", "HUNT_QUEUE.json")
        self.hunt_output: str = getattr(mod, "HUNT_OUTPUT", "FINDING.md")
        self.validate_output: str = getattr(mod, "VALIDATE_OUTPUT", "VERIFICATION.md")
        self.dedupe_output: str = getattr(mod, "DEDUPE_OUTPUT", "FINDINGS.md")
        self.gapfill_output: str = getattr(mod, "GAPFILL_OUTPUT", "HUNT_QUEUE_2.json")
        self.consolidate_output: str = getattr(mod, "CONSOLIDATE_OUTPUT", "SUMMARY.md")

        # Prompt functions
        self._recon_prompt: Callable[[], str] = mod.recon_prompt
        self._hunt_prompt: Callable[..., str] = mod.hunt_prompt
        self._validate_prompt: Callable[[], str] = mod.validate_prompt
        self._dedupe_prompt: Callable[[], str] | None = getattr(mod, "dedupe_prompt", None)
        self._gapfill_prompt: Callable[[], str] | None = getattr(mod, "gapfill_prompt", None)
        self._consolidate_prompt: Callable[[Path], str] | None = getattr(
            mod, "consolidate_prompt", None,
        )

    # -- Prompt accessors --

    def recon_prompt(self) -> str:
        return self._recon_prompt()

    def hunt_prompt(
        self,
        *,
        attack_class: str,
        scope: str,
        function: str,
        entry_point: str,
        rationale: str,
        arch_summary: str,
    ) -> str:
        return self._hunt_prompt(
            attack_class=attack_class,
            scope=scope,
            function=function,
            entry_point=entry_point,
            rationale=rationale,
            arch_summary=arch_summary,
        )

    def validate_prompt(self) -> str:
        return self._validate_prompt()

    def dedupe_prompt(self) -> str | None:
        if self._dedupe_prompt:
            return self._dedupe_prompt()
        return None

    def gapfill_prompt(self) -> str | None:
        if self._gapfill_prompt:
            return self._gapfill_prompt()
        return None

    def consolidate_prompt(self, output_dir: Path) -> str | None:
        if self._consolidate_prompt:
            return self._consolidate_prompt(output_dir)
        return None

    @property
    def has_dedupe(self) -> bool:
        return self._dedupe_prompt is not None

    @property
    def has_gapfill(self) -> bool:
        return self._gapfill_prompt is not None

    @property
    def has_consolidate(self) -> bool:
        return self._consolidate_prompt is not None


    def timeout_for(self, phase: str) -> int | None:
        """Return the effective timeout for a phase (None = no timeout).

        Checks per-phase overrides first, then the global default.
        Returns None if both are zero/unset.
        """
        t = self.task_timeouts.get(phase, self.task_timeout)
        return t if t > 0 else None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_config(name_or_path: str) -> Config:
    """Load config from a TOML file, Python file, or builtin profile name.

    TOML files (*.toml): settings from TOML overlay the prompt profile.
    Python files (*.py) or builtin names: load directly as Python module
    (backward compatible).
    """
    path = Path(name_or_path)

    if path.suffix == ".toml":
        return _load_toml_config(path)

    return _load_python_config(name_or_path)


def _load_toml_config(toml_path: Path) -> Config:
    """Load settings from TOML, overlaying the prompt profile's defaults."""
    if not toml_path.is_file():
        logger.error(f"Config file not found: {toml_path}")
        sys.exit(1)

    data = tomllib.loads(toml_path.read_text())

    # Load the prompt profile module
    profile_name = data.get("scan", {}).get("prompt_profile", "vuln-scan")
    mod = _load_profile_module(profile_name)

    # Build Config from profile, then overlay TOML values
    cfg = Config(mod)
    # Validate required prompt functions
    for attr in ("recon_prompt", "hunt_prompt", "validate_prompt"):
        if not hasattr(mod, attr):
            logger.error(
                f"Prompt profile '{profile_name}' missing required function: {attr}()"
            )
            sys.exit(1)

    # Agent — support both flat keys (model_recon) and nested ([agent.models] recon)
    agent_cfg = data.get("agent", {})
    if "backend" in agent_cfg:
        cfg.agent = agent_cfg["backend"]
    if "flags" in agent_cfg:
        cfg.agent_flags = agent_cfg["flags"]
    models_cfg = agent_cfg.get("models", {})
    for phase in ("recon", "hunt", "validate", "hunt2", "validate2", "dedupe", "gapfill", "consolidate"):
        key = f"model_{phase}"
        val = models_cfg.get(phase) or agent_cfg.get(key)
        if val:
            setattr(cfg, f"{phase}_model", val)

    # Register config-defined backends
    backends_cfg = agent_cfg.get("backends", {})
    if backends_cfg:
        from vuln_scanner.claude import CommandBackend, register_backend

        for name, raw in backends_cfg.items():
            try:
                backend = CommandBackend.from_dict(name, raw)
                register_backend(name, backend)
            except ValueError as e:
                logger.error(str(e))
                sys.exit(1)

    # Scan
    scan_cfg = data.get("scan", {})
    if "branch_prefix" in scan_cfg:
        cfg.branch_prefix = scan_cfg["branch_prefix"]
    if "max_tasks" in scan_cfg:
        cfg.max_tasks = scan_cfg["max_tasks"]
    if "task_timeout" in scan_cfg:
        cfg.task_timeout = scan_cfg["task_timeout"]
    if "task_timeouts" in scan_cfg:
        cfg.task_timeouts = scan_cfg["task_timeouts"]

    # Output filenames
    output_cfg = data.get("output", {})
    for key in ("recon", "hunt", "validate", "dedupe", "gapfill", "consolidate"):
        if key in output_cfg:
            setattr(cfg, f"{key}_output", output_cfg[key])

    # Attack classes (can be in [scan] or top-level)
    attack_classes = data.get("attack_classes") or scan_cfg.get("attack_classes")
    if attack_classes:
        cfg.attack_classes = attack_classes

    # File discovery
    files_cfg = data.get("files", {})
    if "extensions" in files_cfg:
        cfg.extensions = files_cfg["extensions"]
    if "exclude_dirs" in files_cfg:
        cfg.exclude_dirs = set(files_cfg["exclude_dirs"])

    return cfg


def _load_profile_module(name: str) -> ModuleType:
    """Load a prompt profile module by builtin name or path."""
    builtin_dir = Path(__file__).parent / "configs"
    normalized = name.replace("-", "_")
    candidates = [
        Path(name),
        builtin_dir / name,
        builtin_dir / f"{name}.py",
        builtin_dir / f"{normalized}.py",
    ]

    for c in candidates:
        if c.is_file():
            spec = importlib.util.spec_from_file_location("prompt_profile", c)
            assert spec and spec.loader
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

    logger.error(f"Prompt profile not found: {name}")
    logger.error(f"Searched: {[str(c) for c in candidates]}")
    sys.exit(1)


def _load_python_config(name_or_path: str) -> Config:
    """Load config from a Python file or builtin name (backward compatible)."""
    mod = _load_profile_module(name_or_path)

    for attr in ("recon_prompt", "hunt_prompt", "validate_prompt"):
        if not hasattr(mod, attr):
            logger.error(f"Config must define {attr}()")
            sys.exit(1)

    return Config(mod)

"""Config loading — configs are plain Python modules with module-level attrs."""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import ModuleType
from typing import Callable

from vuln_scanner.files import DEFAULT_EXTENSIONS, DEFAULT_EXCLUDE_DIRS

logger = logging.getLogger("vuln-scanner")


class Config:
    """Wraps a loaded config module, providing defaults for optional fields."""

    def __init__(self, mod: ModuleType) -> None:
        self.branch_prefix: str = getattr(mod, "BRANCH_PREFIX", "sweep")
        self.phase1_output: str = getattr(mod, "PHASE1_OUTPUT", "PHASE1-OUTPUT.md")
        self.phase2_output: str = getattr(mod, "PHASE2_OUTPUT", "PHASE2-OUTPUT.md")
        self.phase3_output: str = getattr(mod, "PHASE3_OUTPUT", "SUMMARY.md")
        self.extensions: str = getattr(mod, "EXTENSIONS", DEFAULT_EXTENSIONS)
        self.exclude_dirs: set[str] = getattr(mod, "EXCLUDE_DIRS", DEFAULT_EXCLUDE_DIRS)
        self.priority_prompt: str = getattr(mod, "PRIORITY_PROMPT", "")

        self._phase1_prompt: Callable[[str], str] = getattr(mod, "phase1_prompt")
        self._phase2_prompt: Callable[[str], str] = getattr(mod, "phase2_prompt")
        self._phase3_prompt: Callable[[Path], str] | None = getattr(
            mod, "phase3_prompt", None,
        )

    def phase1_prompt(self, rel_path: str) -> str:
        return self._phase1_prompt(rel_path)

    def phase2_prompt(self, rel_path: str) -> str:
        return self._phase2_prompt(rel_path)

    def phase3_prompt(self, output_dir: Path) -> str | None:
        if self._phase3_prompt:
            return self._phase3_prompt(output_dir)
        return None

    @property
    def has_phase3(self) -> bool:
        return self._phase3_prompt is not None


def load_config(name_or_path: str) -> Config:
    """Load config from a Python file or builtin name."""
    builtin_dir = Path(__file__).parent / "configs"
    # Normalize dashes to underscores for Python module names
    normalized = name_or_path.replace("-", "_")
    candidates = [
        Path(name_or_path),
        builtin_dir / name_or_path,
        builtin_dir / f"{name_or_path}.py",
        builtin_dir / f"{normalized}.py",
    ]

    config_path = None
    for c in candidates:
        if c.is_file():
            config_path = c
            break

    if config_path is None:
        logger.error(f"Config not found: {name_or_path}")
        logger.error(f"Searched: {[str(c) for c in candidates]}")
        sys.exit(1)

    spec = importlib.util.spec_from_file_location("sweep_config", config_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    for attr in ("phase1_prompt", "phase2_prompt"):
        if not hasattr(mod, attr):
            logger.error(f"Config must define {attr}()")
            sys.exit(1)

    return Config(mod)

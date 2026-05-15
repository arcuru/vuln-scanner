"""Source file discovery and selection."""

from __future__ import annotations

import json
import logging
import random
from pathlib import Path

from vuln_scanner.claude import run_claude

logger = logging.getLogger("vuln-scanner")

DEFAULT_EXTENSIONS = (
    "c,cpp,h,hpp,cc,cxx,java,py,rb,rs,go,js,ts,jsx,tsx,"
    "php,cs,swift,kt,scala,zig,nim,lua,pl,sh,bash,zsh,"
    "sql,html,xml,yaml,yml,toml,json,conf,ini,cfg"
)

DEFAULT_EXCLUDE_DIRS = {"node_modules", ".git", "vendor", "__pycache__", ".venv"}


def find_source_files(
    root: Path,
    extensions: str = DEFAULT_EXTENSIONS,
    exclude_dirs: set[str] | None = None,
) -> list[Path]:
    """Find all source files matching the given extensions."""
    ext_set = {f".{e}" for e in extensions.split(",")}
    excludes = exclude_dirs if exclude_dirs is not None else DEFAULT_EXCLUDE_DIRS
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in ext_set:
            continue
        if any(d in path.parts for d in excludes):
            continue
        files.append(path)
    return files


def select_random(files: list[Path], limit: int) -> list[Path]:
    """Random sample of files."""
    if limit and len(files) > limit:
        return random.sample(files, limit)
    return files


def select_claude(
    files: list[Path],
    limit: int,
    repo: Path,
    logs_dir: Path,
    priority_prompt: str = "",
) -> list[Path]:
    """Have Claude pick the most interesting files to analyze."""
    rel_files = [str(f.relative_to(repo)) for f in files]
    file_list = "\n".join(rel_files)

    context = priority_prompt or "Pick the files most likely to be interesting for analysis."

    prompt = f"""\
You are selecting files for analysis of this project.

## Context
{context}

## Available Files ({len(rel_files)} total)
{file_list}

## Task
Select the {limit} most interesting files to analyze. Consider:
- Files that handle user input, authentication, authorization
- Network-facing code, request handlers, API endpoints
- Database queries, file operations, deserialization
- Configuration parsing, command execution
- Check the README, docs, and project structure to understand what's critical

Read the repo to inform your decision — don't just guess from filenames.

## Output
Write a JSON file called SELECTED.json containing exactly a JSON array of
file paths (strings), one per selected file. Example:
["src/auth/login.c", "lib/db/query.py"]

Select exactly {limit} files. Only include files from the available list above."""

    log_path = logs_dir / "file-selection.log"
    ok = run_claude(repo, prompt, log_path)

    selected_path = repo / "SELECTED.json"
    if ok and selected_path.exists():
        try:
            selected: list[str] = json.loads(selected_path.read_text())
            selected_path.unlink()
            rel_to_path = {str(f.relative_to(repo)): f for f in files}
            result = [rel_to_path[s] for s in selected if s in rel_to_path]
            if result:
                logger.info(f"Claude selected {len(result)} files")
                return result
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to parse Claude's selection: {e}")

    logger.warning("Claude file selection failed, falling back to random")
    if selected_path.exists():
        selected_path.unlink()
    return select_random(files, limit)

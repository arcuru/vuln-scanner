"""Source file discovery — finds all source files matching configured extensions."""

from __future__ import annotations

from pathlib import Path

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

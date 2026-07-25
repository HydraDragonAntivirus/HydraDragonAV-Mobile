#!/usr/bin/env python3
"""Build deterministic AG Kit component metadata from Markdown frontmatter."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None

SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$")


def extract_frontmatter(path: Path) -> str:
    text = path.read_text("utf-8", errors="replace")
    if not text.startswith("---\n"):
        raise ValueError(f"Missing YAML frontmatter: {path}")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError(f"Unterminated YAML frontmatter: {path}")
    return text[4:end]


def _fallback_frontmatter(raw: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for line in raw.splitlines():
        if not line or line[0].isspace() or line.lstrip().startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if not match:
            continue
        key, value = match.groups()
        data[key] = value.strip().strip('"\'')
    return data


def load_frontmatter(path: Path) -> dict[str, Any]:
    raw = extract_frontmatter(path)
    if yaml is not None:
        loaded = yaml.safe_load(raw)
        if not isinstance(loaded, dict):
            raise ValueError(f"Frontmatter must be a mapping: {path}")
        return dict(loaded)
    return _fallback_frontmatter(raw)


def normalize_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def is_semver(value: object) -> bool:
    return isinstance(value, str) and SEMVER_RE.fullmatch(value) is not None


def compatible_range(version: str) -> str:
    """Return a conservative compatible range for the supported SemVer subset."""
    match = SEMVER_RE.fullmatch(version)
    if not match:
        raise ValueError(f"Invalid SemVer: {version}")
    major = int(match.group(1))
    return version if major == 0 else f"^{version}"


def version_satisfies(version: str, constraint: str) -> bool:
    """Resolve exact and caret ranges without third-party dependencies."""
    match = SEMVER_RE.fullmatch(version)
    if not match:
        return False
    current = tuple(int(match.group(i)) for i in range(1, 4))
    if constraint.startswith("^"):
        base_text = constraint[1:]
        base_match = SEMVER_RE.fullmatch(base_text)
        if not base_match:
            return False
        base = tuple(int(base_match.group(i)) for i in range(1, 4))
        if base[0] > 0:
            return current >= base and current[0] == base[0]
        if base[1] > 0:
            return current >= base and current[:2] == base[:2]
        return current == base
    return current == tuple(int(match.group(i)) for i in range(1, 4)) if constraint == version else False


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def build_manifest(root: Path) -> dict[str, Any]:
    root = root.resolve()
    kit_version = (root / "VERSION").read_text("utf-8").strip()

    skills: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "skills").glob("*/SKILL.md")):
        data = load_frontmatter(path)
        name = path.parent.name
        version = str(data.get("version", ""))
        scripts = sorted(_relative(root, item) for item in path.parent.glob("scripts/*.py"))
        skills[name] = {
            "path": _relative(root, path),
            "version": version,
            "allowedTools": normalize_list(data.get("allowed-tools")),
            "scripts": scripts,
        }

    agents: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "agent").glob("*.md")):
        data = load_frontmatter(path)
        name = path.stem
        dependencies: dict[str, str] = {}
        for skill_name in normalize_list(data.get("skills")):
            skill_version = str(skills.get(skill_name, {}).get("version", "0.0.0"))
            dependencies[skill_name] = compatible_range(skill_version) if is_semver(skill_version) else skill_version
        agents[name] = {
            "path": _relative(root, path),
            "version": str(data.get("version", "")),
            "model": str(data.get("model", "inherit")),
            "tools": normalize_list(data.get("tools")),
            "requires": {"skills": dependencies},
        }

    workflows: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "workflows").glob("*.md")):
        data = load_frontmatter(path)
        name = path.stem
        workflows[name] = {
            "path": _relative(root, path),
            "version": str(data.get("version", "")),
            "requires": {
                "agents": normalize_list(data.get("requires_agents")),
                "skills": normalize_list(data.get("requires_skills")),
            },
            "artifactOutputs": normalize_list(data.get("artifact_outputs")),
        }

    rules: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "rules").glob("*.md")):
        data = load_frontmatter(path)
        name = path.stem
        rules[name] = {
            "path": _relative(root, path),
            "version": str(data.get("version", "")),
            "priority": str(data.get("priority", "")),
            "trigger": str(data.get("trigger", "")),
        }

    return {
        "$schema": "schemas/manifest.schema.json",
        "schemaVersion": "1.0.0",
        "kitVersion": kit_version,
        "contracts": {
            "componentApi": "1.0.0",
            "memorySchema": "1.0.0",
            "rulesApi": "1.0.0",
            "workflowApi": "1.0.0",
        },
        "support": {
            "official": ["Gemini CLI", "Google Antigravity"],
            "portableFormat": True,
        },
        "agents": agents,
        "skills": skills,
        "workflows": workflows,
        "rules": rules,
    }


def canonical_json(data: object) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def component_files(root: Path) -> list[Path]:
    """Return all managed source files covered by the integrity lock."""
    root = root.resolve()
    files: list[Path] = []
    for name in ("VERSION", "README.md", "ARCHITECTURE.md", "CHANGELOG.md", "mcp_config.json"):
        path = root / name
        if path.is_file():
            files.append(path)
    for directory in ("agent", "skills", "workflows", "rules", "memory", "schemas", "scripts"):
        base = root / directory
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            files.append(path)
    return sorted({path.resolve() for path in files})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_lock(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    root = root.resolve()
    hashes = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in component_files(root)
        if path.name not in {"manifest.lock.json"}
    }
    return {
        "$schema": "schemas/manifest-lock.schema.json",
        "schemaVersion": "1.0.0",
        "kitVersion": manifest["kitVersion"],
        "manifestSha256": hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest(),
        "components": hashes,
    }

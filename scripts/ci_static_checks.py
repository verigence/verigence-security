from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

APPROVED_HASHES = {
    "migrations/0001_security_baseline_v1.3.sql": (
        "175d10780659c54f402980b08ea209cd34139c9ad28df6c4a758d521c7ca606d"
    ),
    "docs/SECURITY_DECISION_REGISTER_v1.3.md": (
        "a05b5e0f04cc63e5d76f54a3a120161aa8ce2172e7c810534c36445e85608070"
    ),
    "docs/SECURITY_CORRELATION_STANDARD_v1.3.md": (
        "fa0f0886eaf6482e52c00ea612550d0674e5ed7b099bc6e9e2e71a84c1a1e1e0"
    ),
    "docs/SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md": (
        "0c7c83ae08d4488951ff90e8c95c34eff7220b55da17329dc65699f91288cceb"
    ),
}

SCAN_DIRS = (ROOT / "src", ROOT / "tests", ROOT / "scripts")
RUNTIME_SOURCE_DIR = ROOT / "src"
LEGACY_PERMISSION = re.compile(r"^[a-z][a-z0-9_]*(?::[a-z][a-z0-9_-]*)+$")
SECRET_MARKERS = (
    "-----BEGIN " + "PRIVATE KEY-----",
    "sk_" + "live_",
    "sk_" + "test_",
)
# Keep this guard practical for typed Python/API code while Ruff/Mypy enforce the remaining
# formatting and correctness rules. 120 is the repository-wide hard ceiling.
MAX_PYTHON_LINE_LENGTH = 120


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def iter_python_files() -> list[Path]:
    files: list[Path] = []
    for directory in SCAN_DIRS:
        if directory.exists():
            files.extend(directory.rglob("*.py"))
    return sorted(files)


def iter_runtime_python_files() -> list[Path]:
    if not RUNTIME_SOURCE_DIR.exists():
        return []
    return sorted(RUNTIME_SOURCE_DIR.rglob("*.py"))


def verify_approved_hashes(errors: list[str]) -> None:
    for relative_path, expected in APPROVED_HASHES.items():
        path = ROOT / relative_path
        if not path.exists():
            errors.append(f"approved artifact missing: {relative_path}")
            continue
        actual = sha256(path)
        if actual != expected:
            errors.append(
                f"approved artifact changed: {relative_path} expected={expected} actual={actual}"
            )


def verify_python_line_length(files: list[Path], errors: list[str]) -> None:
    for path in files:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if len(line) > MAX_PYTHON_LINE_LENGTH:
                relative = path.relative_to(ROOT)
                errors.append(
                    f"line too long: {relative}:{line_number} "
                    f"({len(line)} > {MAX_PYTHON_LINE_LENGTH})"
                )


def verify_no_embedded_secrets(files: list[Path], errors: list[str]) -> None:
    for path in files:
        text = path.read_text(encoding="utf-8")
        for marker in SECRET_MARKERS:
            if marker in text:
                errors.append(f"possible embedded secret marker: {path.relative_to(ROOT)}")


def verify_no_legacy_permission_literals(files: list[Path], errors: list[str]) -> None:
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            value = node.value.strip()
            if LEGACY_PERMISSION.fullmatch(value):
                relative = path.relative_to(ROOT)
                errors.append(
                    f"legacy colon permission literal: {relative}:{node.lineno} value={value!r}"
                )


def verify_request_authority(errors: list[str]) -> None:
    schemas = ROOT / "src/verigence_security/api/schemas.py"
    tree = ast.parse(schemas.read_text(encoding="utf-8"), filename=str(schemas))
    expected_fields = {
        "AccessSessionRequest": {"tenantId", "deviceId", "geo"},
        "DevMockTokenRequest": {"userId"},
    }
    observed: dict[str, set[str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name not in expected_fields:
            continue
        fields: set[str] = set()
        for statement in node.body:
            if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                fields.add(statement.target.id)
        observed[node.name] = fields

    for model_name, expected in expected_fields.items():
        actual = observed.get(model_name)
        if actual != expected:
            errors.append(
                f"request authority changed: {model_name} expected={sorted(expected)} "
                f"actual={sorted(actual or set())}"
            )


def main() -> int:
    errors: list[str] = []
    files = iter_python_files()
    runtime_files = iter_runtime_python_files()
    verify_approved_hashes(errors)
    verify_python_line_length(files, errors)
    verify_no_embedded_secrets(files, errors)
    # Negative tests intentionally contain deprecated permission values to prove rejection.
    # The no-legacy-permission gate therefore applies to runtime code, not test fixtures.
    verify_no_legacy_permission_literals(runtime_files, errors)
    verify_request_authority(errors)

    if errors:
        print("CI static/design checks FAILED")
        for error in errors:
            print(f"- {error}")
        return 1

    print("CI static/design checks PASSED")
    print(f"- approved artifact hashes: {len(APPROVED_HASHES)}/{len(APPROVED_HASHES)}")
    print(f"- Python files checked: {len(files)}")
    print("- no embedded private-key/live-secret markers detected")
    print("- no legacy colon-style permission literals in runtime source")
    print("- request authority fields match the reviewed v0.1 contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

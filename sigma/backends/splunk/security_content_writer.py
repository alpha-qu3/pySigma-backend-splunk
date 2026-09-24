from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from .security_content import (
    SecurityContentValidationError,
    normalize_detection_name,
    serialize_detections,
    validate_detection,
)


_MACRO_RE = re.compile(r"`([^`(\s]+)(?:\([^`]*\))?`")
_LOOKUP_RE = re.compile(
    r"\|\s*(?:inputlookup|lookup)\s+(?:(?:local|update|append|strict)=(?:true|false)\s+)*([^\s|]+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class WriteAction:
    kind: str
    path: Path
    detection: Mapping[str, Any]


@dataclass
class PreflightReport:
    actions: list[WriteAction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {
            "created": sum(action.kind == "created" for action in self.actions),
            "updated": sum(action.kind == "updated" for action in self.actions),
            "unchanged": sum(action.kind == "unchanged" for action in self.actions),
            "warnings": len(self.warnings),
            "errors": len(self.errors),
        }


@dataclass
class RepositoryIndex:
    stories: set[str] = field(default_factory=set)
    data_sources: set[str] = field(default_factory=set)
    baselines: set[str] = field(default_factory=set)
    macros: set[str] = field(default_factory=set)
    lookups: set[str] = field(default_factory=set)
    atomic_guids: set[str] = field(default_factory=set)
    detection_ids: dict[str, Path] = field(default_factory=dict)
    detection_paths: dict[Path, Mapping[str, Any]] = field(default_factory=dict)
    detection_names: dict[str, Path] = field(default_factory=dict)
    external: dict[str, set[str]] = field(default_factory=dict)


def _load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _load_named_index(root: Path, directory: str) -> set[str]:
    names = set()
    base = root / directory
    if not base.exists():
        return names
    for path in sorted(base.rglob("*.yml")):
        value = _load_yaml(path)
        if isinstance(value, Mapping) and value.get("name"):
            names.add(str(value["name"]))
    return names


def _external_config(config: Mapping[str, Any]) -> dict[str, set[str]]:
    raw = config.get("sigma_splunk_content", {})
    raw = raw.get("external", {}) if isinstance(raw, Mapping) else {}
    result = {}
    aliases = {
        "analytic_story": "stories",
        "analytic_stories": "stories",
        "data_source": "data_sources",
        "baseline": "baselines",
        "macro": "macros",
        "lookup": "lookups",
        "atomic_guid": "atomic_guids",
    }
    if isinstance(raw, Mapping):
        for key, values in raw.items():
            target = aliases.get(str(key), str(key))
            if isinstance(values, str):
                values = [values]
            if isinstance(values, Sequence):
                result.setdefault(target, set()).update(str(value) for value in values)
    return result


def _atomic_guids(root: Path) -> set[str]:
    schema_path = root / "schemas" / "EventBasedDetection.schema.json"
    if not schema_path.exists():
        return set()
    with schema_path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    values = schema.get("$defs", {}).get("AtomicGuidEnum", {}).get("enum", [])
    return {str(value) for value in values}


def _load_repository_index(root: Path, config: Mapping[str, Any]) -> RepositoryIndex:
    index = RepositoryIndex(
        stories=_load_named_index(root, "stories"),
        data_sources=_load_named_index(root, "data_sources"),
        baselines=_load_named_index(root, "baselines"),
        macros=_load_named_index(root, "macros"),
        lookups=_load_named_index(root, "lookups"),
        atomic_guids=_atomic_guids(root),
        external=_external_config(config),
    )
    detections = root / "detections"
    if detections.exists():
        for path in sorted(detections.rglob("*.yml")):
            value = _load_yaml(path)
            if not isinstance(value, Mapping):
                raise SecurityContentValidationError(
                    f"existing detection is not a mapping: {path}"
                )
            resolved = path.resolve()
            detection_id = str(value.get("id", ""))
            if detection_id:
                detection_id = str(uuid.UUID(detection_id))
                if detection_id in index.detection_ids:
                    raise SecurityContentValidationError(
                        f"repository contains duplicate detection id {detection_id}"
                    )
                index.detection_ids[detection_id] = resolved
            if value.get("name"):
                normalized = normalize_detection_name(str(value["name"]))
                if normalized in index.detection_names:
                    raise SecurityContentValidationError(
                        f"repository contains normalized filename collision: {normalized}.yml"
                    )
                index.detection_names[normalized] = resolved
            index.detection_paths[resolved] = value
    return index


def _parse_stream(value: str | Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    if isinstance(value, str):
        documents = list(yaml.safe_load_all(value))
    else:
        documents = list(value)
    if not documents:
        raise SecurityContentValidationError("input contains no detection documents")
    if any(not isinstance(document, Mapping) for document in documents):
        raise SecurityContentValidationError("every input document must be a mapping")
    canonical = []
    for document in documents:
        normalized = dict(document)
        if "id" in normalized:
            normalized["id"] = str(uuid.UUID(str(normalized["id"])))
        canonical.append(normalized)
    return canonical


def _target_path(root: Path, detection: Mapping[str, Any]) -> Path:
    detections_root = (root / "detections").resolve()
    if not detections_root.is_relative_to(root.resolve()):
        raise SecurityContentValidationError(
            "detections directory resolves outside repository"
        )
    directory = (
        "deprecated"
        if detection.get("status") == "deprecated"
        else str(detection["category"])
    )
    filename = normalize_detection_name(str(detection["name"])) + ".yml"
    target = (detections_root / directory / filename).resolve()
    if not target.is_relative_to(detections_root):
        raise SecurityContentValidationError(
            "detection path resolves outside repository"
        )
    return target


def _date_key(value: Any) -> str:
    return value.isoformat() if isinstance(value, date) else str(value)


def _validate_reference_set(
    report: PreflightReport,
    detection: Mapping[str, Any],
    label: str,
    field_name: str,
    local: set[str],
    external: set[str],
) -> None:
    for value in detection.get(field_name, []) or []:
        value = str(value)
        if value in local:
            continue
        if value in external:
            report.warnings.append(
                f"{detection['name']}: {label} '{value}' is externally allowed"
            )
            continue
        report.errors.append(f"{detection['name']}: unknown {label} '{value}'")


def _validate_search_references(
    report: PreflightReport,
    detection: Mapping[str, Any],
    index: RepositoryIndex,
) -> None:
    search = str(detection["search"])
    generated_filter = normalize_detection_name(str(detection["name"])) + "_filter"
    for macro in sorted(set(_MACRO_RE.findall(search))):
        if macro == generated_filter or macro in index.macros:
            continue
        if macro in index.external.get("macros", set()):
            report.warnings.append(
                f"{detection['name']}: macro '{macro}' is externally allowed"
            )
        else:
            report.errors.append(f"{detection['name']}: unknown macro '{macro}'")
    for lookup in sorted(set(_LOOKUP_RE.findall(search))):
        lookup_name = Path(lookup).stem
        if lookup in index.lookups or lookup_name in index.lookups:
            continue
        external = index.external.get("lookups", set())
        if lookup in external or lookup_name in external:
            report.warnings.append(
                f"{detection['name']}: lookup '{lookup}' is externally allowed"
            )
        else:
            report.errors.append(f"{detection['name']}: unknown lookup '{lookup}'")


def _validate_references(
    report: PreflightReport,
    detection: Mapping[str, Any],
    index: RepositoryIndex,
) -> None:
    _validate_reference_set(
        report,
        detection,
        "analytic story",
        "analytic_story",
        index.stories,
        index.external.get("stories", set()),
    )
    _validate_reference_set(
        report,
        detection,
        "data source",
        "data_source",
        index.data_sources,
        index.external.get("data_sources", set()),
    )
    _validate_reference_set(
        report,
        detection,
        "baseline",
        "baselines",
        index.baselines,
        index.external.get("baselines", set()),
    )
    _validate_reference_set(
        report,
        detection,
        "Atomic GUID",
        "atomic_guid",
        index.atomic_guids,
        index.external.get("atomic_guids", set()),
    )
    _validate_search_references(report, detection, index)


def _plan_action(
    report: PreflightReport,
    root: Path,
    detection: Mapping[str, Any],
    index: RepositoryIndex,
) -> None:
    target = _target_path(root, detection)
    detection_id = str(detection["id"])
    existing_at_path = index.detection_paths.get(target)
    id_path = index.detection_ids.get(detection_id)

    existing_id = (
        str(uuid.UUID(str(existing_at_path.get("id"))))
        if existing_at_path is not None and existing_at_path.get("id")
        else None
    )
    if existing_at_path is not None and existing_id != detection_id:
        report.errors.append(
            f"{detection['name']}: target path already belongs to another UUID"
        )
        return
    if id_path is not None and id_path != target:
        report.errors.append(
            f"{detection['name']}: UUID already exists at another path: {id_path}"
        )
        return
    normalized = normalize_detection_name(str(detection["name"]))
    name_path = index.detection_names.get(normalized)
    if name_path is not None and name_path != target:
        report.errors.append(
            f"{detection['name']}: normalized name already exists at another path: {name_path}"
        )
        return

    if existing_at_path is None:
        report.actions.append(WriteAction("created", target, detection))
        return

    old_version = existing_at_path.get("version", 0)
    new_version = detection["version"]
    if type(old_version) is not int or old_version < 1:
        report.errors.append(
            f"{detection['name']}: existing detection has an invalid version"
        )
        return
    if dict(existing_at_path) == dict(detection):
        report.actions.append(WriteAction("unchanged", target, detection))
        return
    if new_version <= old_version:
        report.errors.append(
            f"{detection['name']}: updated version must be greater than {old_version}"
        )
        return
    if _date_key(existing_at_path.get("creation_date")) != _date_key(
        detection.get("creation_date")
    ):
        report.errors.append(f"{detection['name']}: creation date cannot change")
        return
    if _date_key(detection.get("modification_date")) < _date_key(
        existing_at_path.get("modification_date")
    ):
        report.errors.append(f"{detection['name']}: modification date cannot regress")
        return
    report.actions.append(WriteAction("updated", target, detection))


def preflight_repository(
    repository: str | Path,
    detections: str | Sequence[Mapping[str, Any]],
) -> PreflightReport:
    report = PreflightReport()
    root = Path(repository).expanduser().resolve()
    try:
        config_path = root / "contentctl.yml"
        if not root.is_dir() or not config_path.is_file():
            raise SecurityContentValidationError(
                f"repository must contain contentctl.yml: {root}"
            )
        config = _load_yaml(config_path)
        if not isinstance(config, Mapping):
            raise SecurityContentValidationError(
                "contentctl.yml must contain a mapping"
            )
        documents = _parse_stream(detections)
        index = _load_repository_index(root, config)

        batch_ids = set()
        batch_paths = set()
        for document in documents:
            try:
                validate_detection(document)
            except (SecurityContentValidationError, TypeError, ValueError) as exc:
                report.errors.append(f"{document.get('name', '<unknown>')}: {exc}")
                continue
            detection_id = str(document["id"])
            target = _target_path(root, document)
            if detection_id in batch_ids:
                report.errors.append(f"duplicate UUID in input batch: {detection_id}")
                continue
            if target in batch_paths:
                report.errors.append(f"duplicate target path in input batch: {target}")
                continue
            batch_ids.add(detection_id)
            batch_paths.add(target)
            _validate_references(report, document, index)
            _plan_action(report, root, document, index)
    except (
        OSError,
        ValueError,
        TypeError,
        yaml.YAMLError,
        json.JSONDecodeError,
    ) as exc:
        report.errors.append(str(exc))
    if report.errors:
        report.actions.clear()
    return report


def _atomic_write(action: WriteAction) -> None:
    action.path.parent.mkdir(parents=True, exist_ok=True)
    content = serialize_detections([action.detection])
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{action.path.name}.", suffix=".tmp", dir=action.path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, action.path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_detections(
    repository: str | Path,
    detections: str | Sequence[Mapping[str, Any]],
    *,
    check: bool = False,
) -> PreflightReport:
    report = preflight_repository(repository, detections)
    if report.errors or check:
        return report
    for action in report.actions:
        if action.kind in {"created", "updated"}:
            _atomic_write(action)
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sigma-splunk-content")
    subparsers = parser.add_subparsers(dest="command", required=True)
    writer = subparsers.add_parser("write", help="validate and place detection YAML")
    writer.add_argument("--repo", required=True, type=Path)
    writer.add_argument(
        "--input", default="-", help="YAML stream path or '-' for stdin"
    )
    writer.add_argument(
        "--check", action="store_true", help="preflight without writing"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.input == "-":
        content = sys.stdin.read()
    else:
        try:
            content = Path(args.input).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    report = write_detections(args.repo, content, check=args.check)
    counts = report.counts
    print(" ".join(f"{key}={value}" for key, value in counts.items()))
    for warning in report.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    for error in report.errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

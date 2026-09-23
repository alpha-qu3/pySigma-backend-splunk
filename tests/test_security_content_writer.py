from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from sigma.backends.splunk.security_content import serialize_detections
from sigma.backends.splunk.security_content_writer import (
    main,
    preflight_repository,
    write_detections,
)


DETECTION = {
    "name": "Suspicious User Process",
    "id": "11111111-1111-4111-8111-111111111111",
    "version": 2,
    "creation_date": "2024-01-01",
    "modification_date": "2024-02-02",
    "author": "Sigma Author",
    "status": "experimental",
    "type": "Hunting",
    "description": "Detects a suspicious process.",
    "data_source": ["Sysmon EventID 1"],
    "search": 'user="alice"\n| `known_macro`\n| `suspicious_user_process_filter`',
    "how_to_implement": "Enable process telemetry.",
    "known_false_positives": "Administrative activity.",
    "references": ["https://example.com/reference"],
    "analytic_story": ["Known Story"],
    "asset_type": "Endpoint",
    "mitre_attack_id": ["T1059.001"],
    "product": ["Splunk Enterprise", "Splunk Enterprise Security", "Splunk Cloud"],
    "category": "endpoint",
    "security_domain": "endpoint",
    "baselines": ["Known Baseline"],
    "atomic_guid": ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
    "tests": [
        {
            "name": "Conversion review",
            "test_type": "experimental",
            "description": "Review generated content.",
        }
    ],
}


def write_yaml(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


@pytest.fixture
def content_repo(tmp_path):
    write_yaml(
        tmp_path / "contentctl.yml",
        {
            "path": ".",
            "sigma_splunk_content": {
                "external": {
                    "macros": ["external_macro"],
                    "lookups": ["external_lookup"],
                }
            },
        },
    )
    write_yaml(tmp_path / "stories" / "known_story.yml", {"name": "Known Story"})
    write_yaml(
        tmp_path / "data_sources" / "sysmon_eventid_1.yml",
        {"name": "Sysmon EventID 1"},
    )
    write_yaml(tmp_path / "baselines" / "known_baseline.yml", {"name": "Known Baseline"})
    write_yaml(tmp_path / "macros" / "known_macro.yml", {"name": "known_macro"})
    write_yaml(
        tmp_path / "lookups" / "known_lookup.yml",
        {"name": "known_lookup", "lookup_type": "kvstore"},
    )
    schema = {
        "$defs": {
            "AtomicGuidEnum": {
                "enum": ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
            }
        }
    }
    (tmp_path / "schemas").mkdir()
    (tmp_path / "schemas" / "EventBasedDetection.schema.json").write_text(
        __import__("json").dumps(schema), encoding="utf-8"
    )
    return tmp_path


def stream(*detections):
    return serialize_detections(detections)


def test_preflight_derives_repository_path_and_reports_create(content_repo):
    report = preflight_repository(content_repo, stream(DETECTION))

    assert report.errors == []
    assert report.counts == {
        "created": 1,
        "updated": 0,
        "unchanged": 0,
        "warnings": 0,
        "errors": 0,
    }
    assert report.actions[0].path == (
        content_repo / "detections" / "endpoint" / "suspicious_user_process.yml"
    )
    assert not report.actions[0].path.exists()


def test_write_uses_single_document_yaml_and_check_mode_does_not_write(content_repo):
    checked = write_detections(content_repo, stream(DETECTION), check=True)
    target = checked.actions[0].path
    assert not target.exists()

    written = write_detections(content_repo, stream(DETECTION))
    text = target.read_text(encoding="utf-8")
    assert written.counts["created"] == 1
    assert text.startswith("name: Suspicious User Process\n")
    assert not text.startswith("---")
    assert text.endswith("\n")
    assert yaml.safe_load(text)["id"] == DETECTION["id"]


def test_update_requires_matching_id_newer_version_and_monotonic_dates(content_repo):
    write_detections(content_repo, stream(DETECTION))

    updated = deepcopy(DETECTION)
    updated["version"] = 3
    updated["modification_date"] = "2024-03-03"
    updated["description"] = "Updated description."
    report = write_detections(content_repo, stream(updated))
    assert report.counts["updated"] == 1

    unchanged = write_detections(content_repo, stream(updated), check=True)
    assert unchanged.counts["unchanged"] == 1

    for field, value, message in [
        ("version", 2, "version"),
        ("creation_date", "2024-01-02", "creation date"),
        ("modification_date", "2024-02-01", "modification date"),
    ]:
        invalid = deepcopy(updated)
        invalid["version"] = 4
        invalid[field] = value
        report = preflight_repository(content_repo, stream(invalid))
        assert any(message in error.lower() for error in report.errors)


def test_preflight_rejects_path_and_uuid_collisions(content_repo):
    target = content_repo / "detections" / "endpoint" / "suspicious_user_process.yml"
    wrong_id = deepcopy(DETECTION)
    wrong_id["id"] = "22222222-2222-4222-8222-222222222222"
    write_yaml(target, wrong_id)
    report = preflight_repository(content_repo, stream(DETECTION))
    assert any("another uuid" in error.lower() for error in report.errors)

    target.unlink()
    write_yaml(content_repo / "detections" / "cloud" / "old_name.yml", DETECTION)
    report = preflight_repository(content_repo, stream(DETECTION))
    assert any("another path" in error.lower() for error in report.errors)


def test_reference_validation_covers_local_and_external_indexes(content_repo):
    valid = deepcopy(DETECTION)
    valid["search"] = (
        '| inputlookup external_lookup\n| `external_macro`\n'
        '| `suspicious_user_process_filter`'
    )
    assert preflight_repository(content_repo, stream(valid)).errors == []

    cases = [
        ("analytic_story", ["Missing Story"], "analytic story"),
        ("data_source", ["Missing Source"], "data source"),
        ("baselines", ["Missing Baseline"], "baseline"),
        ("atomic_guid", ["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"], "atomic"),
        (
            "search",
            'user="alice"\n| `missing_macro`\n| `suspicious_user_process_filter`',
            "macro",
        ),
        (
            "search",
            '| inputlookup missing_lookup\n| `suspicious_user_process_filter`',
            "lookup",
        ),
    ]
    for field, value, message in cases:
        invalid = deepcopy(DETECTION)
        invalid[field] = value
        report = preflight_repository(content_repo, stream(invalid))
        assert any(message in error.lower() for error in report.errors)


def test_any_batch_error_prevents_all_writes(content_repo):
    valid = deepcopy(DETECTION)
    second = deepcopy(DETECTION)
    second["name"] = "Second Detection"
    second["id"] = "22222222-2222-4222-8222-222222222222"
    second["analytic_story"] = ["Missing Story"]
    second["search"] = 'user="bob"\n| `second_detection_filter`'

    report = write_detections(content_repo, stream(valid, second))

    assert report.errors
    assert not (content_repo / "detections").exists()


def test_deprecated_content_uses_deprecated_directory(content_repo):
    deprecated = deepcopy(DETECTION)
    deprecated["status"] = "deprecated"
    deprecated["category"] = "deprecated"
    deprecated["deprecation_info"] = {
        "date": "2024-03-03",
        "description": "Superseded.",
    }
    report = preflight_repository(content_repo, stream(deprecated))
    assert report.actions[0].path.parent == content_repo / "detections" / "deprecated"


def test_unsafe_yaml_and_invalid_repository_are_reported(content_repo, tmp_path):
    unsafe = "!!python/object/apply:os.system ['echo nope']\n"
    assert preflight_repository(content_repo, unsafe).errors
    assert preflight_repository(tmp_path / "missing", stream(DETECTION)).errors


def test_cli_reads_input_and_reports_counts(content_repo, tmp_path, capsys):
    source = tmp_path / "detections.yml"
    source.write_text(stream(DETECTION), encoding="utf-8")

    result = main(["write", "--repo", str(content_repo), "--input", str(source), "--check"])

    assert result == 0
    assert "created=1" in capsys.readouterr().out
    assert not (content_repo / "detections").exists()

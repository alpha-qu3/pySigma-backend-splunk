from datetime import date
from uuid import UUID

import pytest
import yaml

from sigma.backends.splunk import SplunkBackend
from sigma.backends.splunk.security_content import (
    SecurityContentArtifact,
    SecurityContentOptions,
    SecurityContentValidationError,
    build_detection,
    serialize_detections,
    validate_detection,
)
from sigma.collection import SigmaCollection


STRICT_RULE = """
title: Suspicious User Process
id: 11111111-1111-4111-8111-111111111111
status: stable
description: Detects a suspicious process for a user.
author: Sigma Author
date: 2024-01-01
modified: 2024-02-02
references:
  - https://example.com/reference
falsepositives:
  - Administrative activity
level: high
tags:
  - attack.t1059
  - attack.t1059.001
  - cve.2024.12345
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    user: alice
  condition: selection
splunk_security_content:
  version: 2
  type: TTP
  analytic_story:
    - Active Directory Lateral Movement
  data_source: []
  asset_type: Endpoint
  category: endpoint
  security_domain: endpoint
  how_to_implement: Enable process and user telemetry.
"""


def load_rule(source: str = STRICT_RULE):
    return SigmaCollection.from_yaml(source).rules[0]


def test_build_detection_maps_sigma_metadata_and_infers_unique_finding():
    detection = build_detection(
        SecurityContentArtifact(load_rule(), 'user="alice"', {}),
        SecurityContentOptions(),
    )

    assert detection["name"] == "Suspicious User Process"
    assert detection["id"] == "11111111-1111-4111-8111-111111111111"
    assert detection["version"] == 2
    assert detection["creation_date"] == date(2024, 1, 1)
    assert detection["modification_date"] == date(2024, 2, 2)
    assert detection["author"] == "Sigma Author"
    assert detection["status"] == "production"
    assert detection["known_false_positives"] == "Administrative activity"
    assert detection["mitre_attack_id"] == ["T1059.001"]
    assert detection["cve"] == ["CVE-2024-12345"]
    assert detection["product"] == [
        "Splunk Enterprise",
        "Splunk Enterprise Security",
        "Splunk Cloud",
    ]
    assert detection["finding"] == {
        "title": "Suspicious User Process involving $user$",
        "entity": {"field": "user", "type": "user", "score": 80},
    }
    assert detection["search"].endswith("`suspicious_user_process_filter`")
    assert detection["tests"][0]["test_type"] == "experimental"


def test_rule_overlay_wins_over_sigma_and_pipeline_defaults():
    rule = load_rule(STRICT_RULE.replace("version: 2", "version: 2\n  author: Rule Author"))
    options = SecurityContentOptions(
        defaults={"author": "Backend Author", "analytic_story": ["Backend Story"]}
    )
    artifact = SecurityContentArtifact(
        rule,
        'user="alice"',
        {"security_content_defaults": {"author": "Pipeline Author"}},
    )

    detection = build_detection(artifact, options)

    assert detection["author"] == "Rule Author"
    assert detection["analytic_story"] == ["Active Directory Lateral Movement"]


def test_draft_is_deterministic_hunting_content_with_review_markers():
    rule = load_rule(
        """
title: Cloud Rule / Needs Review
status: unsupported
description: Draft source.
author: Draft Author
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: StopLogging
  condition: selection
"""
    )
    options = SecurityContentOptions(
        mode="draft",
        defaults={
            "creation_date": date(2024, 3, 3),
            "analytic_story": ["Cloud Attack"],
        },
    )

    first = build_detection(
        SecurityContentArtifact(rule, 'eventName="StopLogging"', {}), options
    )
    second = build_detection(
        SecurityContentArtifact(rule, 'eventName="StopLogging"', {}), options
    )

    assert first == second
    assert UUID(first["id"]).version == 5
    assert first["name"] == "Cloud Rule _ Needs Review"
    assert first["status"] == "experimental"
    assert first["type"] == "Hunting"
    assert first["category"] == "cloud"
    assert first["security_domain"] == "audit"
    assert first["asset_type"] == "AWS Account"
    assert "Review required" in first["how_to_implement"]
    assert "source Sigma rule" in first["known_false_positives"]
    assert first["tests"][0]["test_type"] == "experimental"
    assert "finding" not in first
    assert "intermediate_findings" not in first


@pytest.mark.parametrize(
    ("metadata", "message"),
    [
        ({"search": "index=*"}, "protected field 'search'"),
        ({"product": ["Other"]}, "protected field 'product'"),
        ({"made_up": True}, "unknown field 'made_up'"),
    ],
)
def test_metadata_rejects_protected_and_unknown_fields(metadata, message):
    rule = load_rule()
    rule.custom_attributes["splunk_security_content"].update(metadata)

    with pytest.raises(SecurityContentValidationError, match=message):
        build_detection(SecurityContentArtifact(rule, 'user="alice"', {}), SecurityContentOptions())


def test_strict_mode_rejects_ambiguous_entity_inference():
    rule = load_rule()

    with pytest.raises(SecurityContentValidationError, match="exactly one entity field"):
        build_detection(
            SecurityContentArtifact(rule, 'user="alice" dest="server"', {}),
            SecurityContentOptions(),
        )


def test_validate_detection_enforces_type_risk_matrix_and_tokens():
    detection = build_detection(
        SecurityContentArtifact(load_rule(), 'user="alice"', {}),
        SecurityContentOptions(),
    )
    detection["type"] = "Hunting"

    with pytest.raises(SecurityContentValidationError, match="Hunting.*finding"):
        validate_detection(detection)

    detection["type"] = "TTP"
    detection["finding"]["title"] = "No entity token"
    with pytest.raises(SecurityContentValidationError, match="token"):
        validate_detection(detection)


def test_serialize_detections_is_stable_ordered_multidocument_yaml():
    first = build_detection(
        SecurityContentArtifact(load_rule(), 'user="alice"\n| stats count by user', {}),
        SecurityContentOptions(),
    )
    second = dict(first)
    second["name"] = "Second Rule"
    second["id"] = "22222222-2222-4222-8222-222222222222"
    second["search"] = 'user="bob"\n| `second_rule_filter`'

    output = serialize_detections([first, second])
    documents = list(yaml.safe_load_all(output))

    assert output.startswith("name: Suspicious User Process\n")
    assert "\n---\nname: Second Rule\n" in output
    assert output.endswith("\n")
    assert output.index("name:") < output.index("id:") < output.index("version:")
    assert documents[0]["search"] == 'user="alice"\n| stats count by user\n| `suspicious_user_process_filter`'
    assert len(documents) == 2


def test_backend_security_content_groups_conditions_and_adds_filter_once():
    source = STRICT_RULE.replace(
        "selection:\n    user: alice\n  condition: selection",
        "selection_one:\n    user: alice\n  selection_two:\n    user: bob\n  condition:\n    - selection_one\n    - selection_two",
    )
    collection = SigmaCollection.from_yaml(source)

    output = SplunkBackend().convert(collection, "security_content")
    detection = yaml.safe_load(output)

    assert detection["search"].startswith("| union\n[ search user=\"alice\" ]\n[ search user=\"bob\" ]")
    assert detection["search"].count("suspicious_user_process_filter") == 1


def test_formats_are_registered_without_changing_existing_defaults():
    assert "security_content" in SplunkBackend.formats
    assert "security_content_data_model" in SplunkBackend.formats
    assert SplunkBackend().convert(
        SigmaCollection.from_yaml(
            """
title: Existing
status: test
logsource:
  category: test
detection:
  selection:
    field: value
  condition: selection
"""
        )
    ) == ['field="value"']

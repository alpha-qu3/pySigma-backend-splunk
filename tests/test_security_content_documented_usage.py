from pathlib import Path

import yaml

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection


ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "security_content_compatibility.yml"


def test_documented_strict_conversion_fixture():
    collection = SigmaCollection.from_yaml(FIXTURE.read_text(encoding="utf-8"))
    first = SplunkBackend().convert(collection, "security_content")
    second = SplunkBackend().convert(
        SigmaCollection.from_yaml(FIXTURE.read_text(encoding="utf-8")),
        "security_content",
    )
    detection = yaml.safe_load(first)

    assert first == second
    assert detection["name"] == "Sigma Conversion Compatibility Fixture"
    assert detection["search"].endswith("`sigma_conversion_compatibility_fixture_filter`")


def test_readme_documents_public_security_content_interfaces():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for interface in (
        "security_content",
        "security_content_data_model",
        "splunk_security_content:",
        "security_content_mode",
        "security_content_defaults",
        "security_content_entity_fields",
        "sigma-splunk-content write",
        "SPLUNK_LIVE_TESTS",
    ):
        assert interface in readme

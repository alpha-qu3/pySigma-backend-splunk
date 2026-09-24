from __future__ import annotations

import hashlib
import re
import uuid
import warnings
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Mapping, Sequence

import yaml


PRODUCTS = [
    "Splunk Enterprise",
    "Splunk Enterprise Security",
    "Splunk Cloud",
]

FIELD_ORDER = [
    "name",
    "id",
    "version",
    "creation_date",
    "modification_date",
    "author",
    "status",
    "type",
    "description",
    "data_source",
    "search",
    "how_to_implement",
    "known_false_positives",
    "references",
    "drilldown_searches",
    "finding",
    "intermediate_findings",
    "threat_objects",
    "analytic_story",
    "threat_group",
    "asset_type",
    "cve",
    "atomic_guid",
    "mitre_attack_id",
    "product",
    "category",
    "security_domain",
    "baselines",
    "tests",
    "deprecation_info",
    "schedule",
    "custom_schedule",
]

ALLOWED_FIELDS = frozenset(FIELD_ORDER)
PROTECTED_FIELDS = frozenset({"search", "product"})
REQUIRED_FIELDS = frozenset(
    {
        "name",
        "id",
        "version",
        "creation_date",
        "modification_date",
        "author",
        "description",
        "status",
        "search",
        "how_to_implement",
        "known_false_positives",
        "security_domain",
        "data_source",
        "product",
        "type",
        "analytic_story",
        "mitre_attack_id",
        "asset_type",
        "category",
    }
)

STATUS_VALUES = frozenset({"production", "experimental", "deprecated"})
TYPE_VALUES = frozenset({"TTP", "Anomaly", "Correlation", "Hunting"})
CATEGORY_VALUES = frozenset(
    {"application", "cloud", "endpoint", "network", "web", "deprecated"}
)
DOMAIN_VALUES = frozenset(
    {"access", "audit", "endpoint", "identity", "network", "threat"}
)
ASSET_VALUES = frozenset(
    {
        "Account",
        "Amazon EKS Kubernetes cluster",
        "Amazon EKS Kubernetes cluster Pod",
        "Amazon Elastic Container Registry",
        "AWS Account",
        "AWS Federated Account",
        "AWS Instance",
        "Azure Active Directory",
        "Azure Tenant",
        "CircleCI",
        "Cloud Compute Instance",
        "Cloud Instance",
        "Database Server",
        "DNS Servers",
        "EC2 Snapshot",
        "Endpoint",
        "GCP",
        "GCP Account",
        "GCP Kubernetes cluster",
        "GCP Storage Bucket",
        "GDrive",
        "GitHub",
        "Google Cloud Platform tenant",
        "GSuite",
        "Identity",
        "Infrastructure",
        "Kubernetes",
        "Network",
        "O365 Tenant",
        "Okta Tenant",
        "S3 Bucket",
        "Splunk Server",
        "VPN Appliance",
        "Web Application",
        "Web Proxy",
        "Web Server",
        "Windows",
    }
)
RISK_OBJECT_TYPES = frozenset({"system", "user", "other"})
THREAT_OBJECT_TYPES = frozenset(
    {
        "certificate_common_name",
        "certificate_organization",
        "certificate_serial",
        "certificate_unit",
        "command",
        "domain",
        "email_address",
        "email_subject",
        "file_hash",
        "file_name",
        "file_path",
        "http_user_agent",
        "ip_address",
        "process",
        "process_name",
        "parent_process",
        "parent_process_name",
        "process_hash",
        "registry_path",
        "registry_value_name",
        "registry_value_text",
        "service",
        "signature",
        "system",
        "tls_hash",
        "url",
    }
)

DEFAULT_ENTITY_FIELDS = {
    "user": "user",
    "src_user": "user",
    "dest_user": "user",
    "src": "system",
    "dest": "system",
    "dvc": "system",
    "host": "system",
}

SCORE_BY_LEVEL = {
    "informational": 10,
    "low": 20,
    "medium": 50,
    "high": 80,
    "critical": 100,
}

_UUID_NAMESPACE = uuid.UUID("720dd50a-6338-5a35-a019-5968de75489d")
_MITRE_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_CVE_RE = re.compile(r"^(?:cve[.-])?(\d{4})[.-](\d{4,7})$", re.IGNORECASE)
_TOKEN_RE = re.compile(r"\$([^$]+)\$")


class SecurityContentValidationError(ValueError):
    """Raised when generated content cannot satisfy the target contract."""


def _is_exact_integer(value: Any) -> bool:
    return type(value) is int


@dataclass(frozen=True)
class SecurityContentArtifact:
    rule: Any
    search: str
    state: Mapping[str, Any]
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityContentOptions:
    mode: str = "strict"
    defaults: Mapping[str, Any] = field(default_factory=dict)
    entity_fields: Mapping[str, str] = field(default_factory=dict)
    percentile_mode: str = "exact"
    max_ordered_sequences: int = 64
    union_maxout: int | None = None
    union_maxtime: int | None = None

    def __post_init__(self) -> None:
        if self.mode not in {"strict", "draft"}:
            raise SecurityContentValidationError(
                "security_content_mode must be 'strict' or 'draft'"
            )
        if self.percentile_mode not in {"exact", "approximate"}:
            raise SecurityContentValidationError(
                "percentile_mode must be 'exact' or 'approximate'"
            )
        for name, value in (
            ("max_ordered_sequences", self.max_ordered_sequences),
            ("union_maxout", self.union_maxout),
            ("union_maxtime", self.union_maxtime),
        ):
            if value is not None and (not _is_exact_integer(value) or value < 1):
                raise SecurityContentValidationError(
                    f"{name} must be a positive integer"
                )


class _LiteralString(str):
    pass


class _SecurityContentDumper(yaml.SafeDumper):
    pass


def _represent_literal(dumper: yaml.Dumper, value: _LiteralString):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")


_SecurityContentDumper.add_representer(_LiteralString, _represent_literal)


def normalize_detection_name(name: str) -> str:
    return "".join(
        (
            character
            if character.isascii() and (character.isalnum() or character == "_")
            else "_"
        )
        for character in name.lower()
    ).strip("_")


def compose_union(
    queries: Sequence[str], maxout: int | None = None, maxtime: int | None = None
) -> str:
    clean = [query.strip() for query in queries if query and query.strip()]
    if not clean:
        raise SecurityContentValidationError("rule produced no searches")
    if len(clean) == 1:
        return clean[0]
    options = "".join(
        part
        for part in (
            f" maxout={maxout}" if maxout is not None else "",
            f" maxtime={maxtime}" if maxtime is not None else "",
        )
    )
    branches = []
    for query in clean:
        prefix = "" if query.lstrip().startswith("|") else "search "
        branches.append(f"[ {prefix}{query} ]")
    return f"| union{options}\n" + "\n".join(branches)


def _clean_name(name: str, draft: bool) -> str:
    unsafe = any(ord(char) < 32 for char in name) or any(
        character in name for character in "/\\`|"
    )
    if unsafe and not draft:
        raise SecurityContentValidationError(
            "detection name contains unsafe characters"
        )
    if draft:
        name = "".join(
            "_" if ord(char) < 32 or char in "/\\`|" else char for char in name
        )
    if len(name) > 67:
        if not draft:
            raise SecurityContentValidationError(
                "detection name is too long for the Security Content stanza"
            )
        digest = hashlib.sha256(name.encode()).hexdigest()[:8]
        name = f"{name[:58].rstrip()}-{digest}"
    name = name.strip()
    if not name:
        raise SecurityContentValidationError("detection name cannot be empty")
    if not normalize_detection_name(name):
        if not draft:
            raise SecurityContentValidationError(
                "detection normalized name cannot be empty"
            )
        digest = hashlib.sha256(name.encode()).hexdigest()[:8]
        name = f"Sigma detection-{digest}"
    return name


def _as_date(value: Any, field_name: str) -> date:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise SecurityContentValidationError(
                f"{field_name} must use YYYY-MM-DD"
            ) from exc
    raise SecurityContentValidationError(f"{field_name} is required and must be a date")


def _rule_value(rule: Any, name: str) -> Any:
    value = getattr(rule, name, None)
    if value is None:
        return None
    return str(value) if name in {"status", "level"} else value


def _mapped_metadata(rule: Any) -> dict[str, Any]:
    status = _rule_value(rule, "status")
    status_map = {
        "stable": "production",
        "test": "experimental",
        "experimental": "experimental",
        "deprecated": "deprecated",
    }
    creation = _rule_value(rule, "date")
    modified = _rule_value(rule, "modified") or creation
    result: dict[str, Any] = {
        "name": _rule_value(rule, "title"),
        "id": str(_rule_value(rule, "id")) if _rule_value(rule, "id") else None,
        "creation_date": creation,
        "modification_date": modified,
        "author": _rule_value(rule, "author"),
        "description": _rule_value(rule, "description"),
        "references": list(_rule_value(rule, "references") or []),
        "known_false_positives": "; ".join(_rule_value(rule, "falsepositives") or []),
        "status": status_map.get(status),
    }
    return {key: value for key, value in result.items() if value not in (None, "")}


def _extract_tags(rule: Any) -> tuple[list[str], list[str]]:
    techniques: set[str] = set()
    cves: set[str] = set()
    for tag in getattr(rule, "tags", []) or []:
        namespace = str(getattr(tag, "namespace", "")).lower()
        name = str(getattr(tag, "name", ""))
        if namespace == "attack" and _MITRE_RE.match(name):
            techniques.add(name.upper())
        elif namespace == "cve":
            match = _CVE_RE.match(name)
            if match:
                cves.add(f"CVE-{match.group(1)}-{match.group(2)}")
    parents = {
        technique.split(".", 1)[0] for technique in techniques if "." in technique
    }
    techniques.difference_update(parents)
    return sorted(techniques), sorted(cves)


def _draft_classification(rule: Any) -> tuple[str, str, str]:
    logsource = getattr(rule, "logsource", None)
    product = str(getattr(logsource, "product", "") or "").lower()
    category = str(getattr(logsource, "category", "") or "").lower()
    service = str(getattr(logsource, "service", "") or "").lower()

    if category in {"proxy", "webserver"}:
        return ("web", "network", "Web Proxy" if category == "proxy" else "Web Server")
    if category in {"dns", "dns_query"} or service in {
        "dns",
        "dns-client",
        "dns-server",
    }:
        return "network", "network", "DNS Servers"
    if category in {"network_connection", "firewall"} or product in {
        "zeek",
        "cisco",
        "fortigate",
        "rpc_firewall",
        "huawei",
        "juniper",
    }:
        return "network", "network", "Network"
    if product in {"windows", "linux", "macos"}:
        return "endpoint", "endpoint", "Endpoint"
    if product in {"aws", "azure", "gcp", "m365", "kubernetes", "github", "bitbucket"}:
        assets = {
            "aws": "AWS Account",
            "azure": "Azure Tenant",
            "gcp": "Google Cloud Platform tenant",
            "m365": "O365 Tenant",
            "kubernetes": "Kubernetes",
            "github": "GitHub",
            "bitbucket": "Infrastructure",
        }
        if service in {"cloudtrail", "activitylogs", "auditlogs", "audit", "gcp.audit"}:
            domain = "audit"
        elif service in {"signinlogs", "riskdetection", "pim"}:
            domain = "identity"
        else:
            domain = "threat"
        return "cloud", domain, assets[product]
    if product == "okta":
        return "application", "identity", "Okta Tenant"
    if product == "onelogin":
        return "application", "identity", "Identity"

    warnings.warn(
        "Draft Security Content classification used the generic application/audit/Infrastructure fallback",
        stacklevel=3,
    )
    return "application", "audit", "Infrastructure"


def _entity_candidates(
    search: str, mapping: Mapping[str, str]
) -> list[tuple[str, str]]:
    candidates = []
    for field_name, entity_type in mapping.items():
        if re.search(rf"(?<![\w.]){re.escape(field_name)}(?![\w.])", search):
            candidates.append((field_name, entity_type))
    return candidates


def _infer_risk(
    detection: dict[str, Any],
    artifact: SecurityContentArtifact,
    options: SecurityContentOptions,
) -> None:
    detection_type = detection["type"]
    if detection_type not in {"TTP", "Anomaly", "Correlation"}:
        return
    if detection_type in {"TTP", "Correlation"} and detection.get("finding"):
        return
    if detection_type == "Anomaly" and detection.get("intermediate_findings"):
        return

    entity_fields = dict(DEFAULT_ENTITY_FIELDS)
    entity_fields.update(options.entity_fields)
    entity_fields.update(artifact.state.get("security_content_entity_fields", {}))
    candidates = _entity_candidates(detection["search"], entity_fields)
    if len(candidates) != 1:
        raise SecurityContentValidationError(
            "strict risk inference requires exactly one entity field in the generated search"
        )
    field_name, entity_type = candidates[0]
    level = _rule_value(artifact.rule, "level") or "medium"
    score = SCORE_BY_LEVEL.get(level, 50)
    message = f"{detection['name']} involving ${field_name}$"
    if detection_type in {"TTP", "Correlation"}:
        detection["finding"] = {
            "title": message,
            "entity": {"field": field_name, "type": entity_type, "score": score},
        }
    else:
        detection["intermediate_findings"] = {
            "entities": [
                {
                    "field": field_name,
                    "type": entity_type,
                    "score": score,
                    "message": message,
                }
            ]
        }


def _generated_review_test(name: str) -> dict[str, Any]:
    return {
        "name": f"{name} conversion review",
        "test_type": "experimental",
        "description": (
            "Automatically converted from Sigma without attack data. Review the query, "
            "data mapping, and expected results before promotion."
        ),
    }


def build_detection(
    artifact: SecurityContentArtifact, options: SecurityContentOptions
) -> dict[str, Any]:
    rule = artifact.rule
    overlay = dict(
        (getattr(rule, "custom_attributes", {}) or {}).get(
            "splunk_security_content", {}
        )
    )
    for key in overlay:
        if key in PROTECTED_FIELDS:
            raise SecurityContentValidationError(
                f"protected field '{key}' cannot be overridden"
            )
        if key not in ALLOWED_FIELDS:
            raise SecurityContentValidationError(
                f"unknown field '{key}' in splunk_security_content"
            )

    pipeline_defaults = dict(artifact.state.get("security_content_defaults", {}))
    for source_name, values in (
        ("backend defaults", options.defaults),
        ("pipeline defaults", pipeline_defaults),
    ):
        for key in values:
            if key in PROTECTED_FIELDS:
                raise SecurityContentValidationError(
                    f"protected field '{key}' cannot be set in {source_name}"
                )
            if key not in ALLOWED_FIELDS:
                raise SecurityContentValidationError(
                    f"unknown field '{key}' in {source_name}"
                )
    metadata = dict(options.defaults)
    metadata.update(pipeline_defaults)
    metadata.update(_mapped_metadata(rule))
    metadata.update(overlay)

    draft = options.mode == "draft"
    name = _clean_name(str(metadata.get("name") or getattr(rule, "title", "")), draft)
    metadata["name"] = name
    if draft:
        metadata["status"] = "experimental"
        metadata["type"] = "Hunting"
        metadata.pop("finding", None)
        metadata.pop("intermediate_findings", None)
        metadata.pop("threat_objects", None)
        metadata.setdefault(
            "how_to_implement",
            "Review required: validate data onboarding and field mappings before deployment.",
        )
        metadata.setdefault(
            "known_false_positives",
            "Review required: no known false positives were documented in the source Sigma rule.",
        )
        category, domain, asset = _draft_classification(rule)
        metadata.setdefault("category", category)
        metadata.setdefault("security_domain", domain)
        metadata.setdefault("asset_type", asset)
        if not metadata.get("id"):
            logsource = getattr(rule, "logsource", None)
            source_identity = yaml.safe_dump(
                {
                    "title": getattr(rule, "title", None),
                    "name": getattr(rule, "name", None),
                    "taxonomy": getattr(rule, "taxonomy", None),
                    "author": getattr(rule, "author", None),
                    "description": getattr(rule, "description", None),
                    "date": str(getattr(rule, "date", None) or ""),
                    "logsource": {
                        "product": getattr(logsource, "product", None),
                        "category": getattr(logsource, "category", None),
                        "service": getattr(logsource, "service", None),
                    },
                    "search": artifact.search,
                },
                sort_keys=True,
                allow_unicode=True,
            )
            metadata["id"] = str(uuid.uuid5(_UUID_NAMESPACE, source_identity))
    elif _rule_value(rule, "status") == "unsupported" and "status" not in overlay:
        raise SecurityContentValidationError(
            "unsupported Sigma status is not valid in strict mode"
        )

    creation = metadata.get("creation_date")
    modified = metadata.get("modification_date") or creation
    metadata["creation_date"] = _as_date(creation, "creation_date")
    metadata["modification_date"] = _as_date(modified, "modification_date")
    try:
        metadata["id"] = str(uuid.UUID(str(metadata.get("id") or "")))
    except (ValueError, TypeError, AttributeError) as exc:
        raise SecurityContentValidationError("id must be a UUID") from exc
    version = metadata.get("version", 1)
    if not _is_exact_integer(version) or version < 1:
        raise SecurityContentValidationError("version must be a positive integer")
    metadata["version"] = version
    metadata.setdefault("references", [])
    metadata.setdefault("data_source", [])
    metadata.setdefault("mitre_attack_id", [])
    metadata.setdefault("tests", [])

    techniques, cves = _extract_tags(rule)
    if not metadata["mitre_attack_id"]:
        metadata["mitre_attack_id"] = techniques
    if cves and "cve" not in metadata:
        metadata["cve"] = cves

    filter_name = normalize_detection_name(name) + "_filter"
    search = artifact.search.strip()
    macro = f"`{filter_name}`"
    if macro not in search:
        search += f"\n| {macro}"
    metadata["search"] = search
    metadata["product"] = list(PRODUCTS)
    if not metadata["tests"]:
        metadata["tests"] = [_generated_review_test(name)]

    missing = sorted(
        field_name for field_name in REQUIRED_FIELDS if field_name not in metadata
    )
    if missing:
        raise SecurityContentValidationError(
            "missing required fields: " + ", ".join(missing)
        )
    if not draft:
        _infer_risk(metadata, artifact, options)

    ordered = {
        field_name: metadata[field_name]
        for field_name in FIELD_ORDER
        if field_name in metadata
    }
    validate_detection(ordered)
    return ordered


def _iter_entities(detection: Mapping[str, Any]):
    finding = detection.get("finding")
    if isinstance(finding, Mapping) and isinstance(finding.get("entity"), Mapping):
        yield finding["entity"], finding.get("title", "")
    intermediate = detection.get("intermediate_findings")
    if isinstance(intermediate, Mapping):
        for entity in intermediate.get("entities", []) or []:
            if isinstance(entity, Mapping):
                yield entity, entity.get("message", "")


def _require_mapping(
    value: Any, label: str, allowed: set[str], required: set[str]
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SecurityContentValidationError(f"{label} must be a mapping")
    unknown = set(value).difference(allowed)
    if unknown:
        raise SecurityContentValidationError(
            f"unknown field(s) in {label}: {', '.join(sorted(unknown))}"
        )
    missing = required.difference(value)
    if missing:
        raise SecurityContentValidationError(
            f"missing field(s) in {label}: {', '.join(sorted(missing))}"
        )
    return value


def _require_string_list(detection: Mapping[str, Any], field_name: str) -> None:
    value = detection.get(field_name)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise SecurityContentValidationError(f"{field_name} must be a list of strings")
    if len(value) != len(set(value)):
        raise SecurityContentValidationError(f"{field_name} values must be unique")


def _validate_token_string(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise SecurityContentValidationError(f"{label} must be a non-empty string")
    if value.count("$") % 2:
        raise SecurityContentValidationError(f"{label} contains unbalanced tokens")


def _validate_entity(entity: Any, label: str, require_message: bool) -> None:
    allowed = {"field", "type", "score"} | ({"message"} if require_message else set())
    entity = _require_mapping(entity, label, allowed, set(allowed))
    if not isinstance(entity["field"], str) or not entity["field"]:
        raise SecurityContentValidationError(
            f"{label}.field must be a non-empty string"
        )
    if entity["type"] not in RISK_OBJECT_TYPES:
        raise SecurityContentValidationError(f"invalid {label}.type: {entity['type']}")
    if not _is_exact_integer(entity["score"]) or not 0 <= entity["score"] <= 100:
        raise SecurityContentValidationError(f"{label}.score must be between 0 and 100")
    if require_message and (
        not isinstance(entity["message"], str) or not entity["message"]
    ):
        raise SecurityContentValidationError(
            f"{label}.message must be a non-empty string"
        )
    if require_message:
        _validate_token_string(entity["message"], f"{label}.message")


def _validate_tests(tests: Any) -> None:
    if not isinstance(tests, list) or not tests:
        raise SecurityContentValidationError("detections require at least one test")
    names = set()
    for test in tests:
        if not isinstance(test, Mapping):
            raise SecurityContentValidationError("each test must be a mapping")
        test_type = test.get("test_type")
        allowed = {
            "name",
            "test_type",
            "description",
            "attack_data",
            "expected_results",
        }
        required = {"name", "test_type"}
        if test_type == "experimental":
            required.add("description")
        elif test_type == "unit":
            required.add("attack_data")
        else:
            raise SecurityContentValidationError(
                "test_type must be unit or experimental"
            )
        test = _require_mapping(test, "test", allowed, required)
        if not isinstance(test["name"], str) or not test["name"]:
            raise SecurityContentValidationError("test.name must be a non-empty string")
        if test["name"] in names:
            raise SecurityContentValidationError("test names must be unique")
        names.add(test["name"])
        if test_type == "experimental" and (
            not isinstance(test["description"], str) or not test["description"]
        ):
            raise SecurityContentValidationError(
                "experimental tests require a description"
            )
        if "expected_results" in test and (
            not _is_exact_integer(test["expected_results"])
            or test["expected_results"] < 0
        ):
            raise SecurityContentValidationError(
                "test.expected_results must be a non-negative integer"
            )
        if "attack_data" in test:
            if not isinstance(test["attack_data"], list):
                raise SecurityContentValidationError("test.attack_data must be a list")
            if test_type == "unit" and not test["attack_data"]:
                raise SecurityContentValidationError("unit tests require attack_data")
            for item in test["attack_data"]:
                item = _require_mapping(
                    item,
                    "test attack_data",
                    {"data", "source", "sourcetype", "index"},
                    {"data", "source", "sourcetype"},
                )
                if any(not isinstance(item[key], str) for key in item):
                    raise SecurityContentValidationError(
                        "test attack_data values must be strings"
                    )


def validate_detection(detection: Mapping[str, Any]) -> None:
    if not isinstance(detection, Mapping):
        raise SecurityContentValidationError("detection must be a mapping")
    unknown = set(detection).difference(ALLOWED_FIELDS)
    if unknown:
        raise SecurityContentValidationError(
            "unknown field(s): " + ", ".join(sorted(unknown))
        )
    missing = sorted(
        field_name for field_name in REQUIRED_FIELDS if field_name not in detection
    )
    if missing:
        raise SecurityContentValidationError(
            "missing required fields: " + ", ".join(missing)
        )

    try:
        uuid.UUID(str(detection["id"]))
    except (ValueError, TypeError, AttributeError) as exc:
        raise SecurityContentValidationError("id must be a UUID") from exc
    if not _is_exact_integer(detection["version"]) or detection["version"] < 1:
        raise SecurityContentValidationError("version must be a positive integer")
    for field_name in (
        "name",
        "author",
        "description",
        "search",
        "how_to_implement",
        "known_false_positives",
    ):
        if not isinstance(detection[field_name], str) or not detection[field_name]:
            raise SecurityContentValidationError(
                f"{field_name} must be a non-empty string"
            )
    _clean_name(detection["name"], False)

    creation = _as_date(detection["creation_date"], "creation_date")
    modified = _as_date(detection["modification_date"], "modification_date")
    if creation > modified:
        raise SecurityContentValidationError(
            "modification_date cannot precede creation_date"
        )
    if modified > date.today():
        raise SecurityContentValidationError(
            "modification_date cannot be in the future"
        )

    status = detection["status"]
    detection_type = detection["type"]
    if status not in STATUS_VALUES:
        raise SecurityContentValidationError(f"invalid status: {status}")
    if detection_type not in TYPE_VALUES:
        raise SecurityContentValidationError(f"invalid type: {detection_type}")
    if detection["category"] not in CATEGORY_VALUES:
        raise SecurityContentValidationError(
            f"invalid category: {detection['category']}"
        )
    if detection["security_domain"] not in DOMAIN_VALUES:
        raise SecurityContentValidationError(
            f"invalid security_domain: {detection['security_domain']}"
        )
    if detection["asset_type"] not in ASSET_VALUES:
        raise SecurityContentValidationError(
            f"invalid asset_type: {detection['asset_type']}"
        )
    if not isinstance(detection["product"], list) or detection["product"] != PRODUCTS:
        raise SecurityContentValidationError(
            "product must contain the three supported Splunk products"
        )
    for field_name in (
        "analytic_story",
        "data_source",
        "mitre_attack_id",
        "references",
    ):
        _require_string_list(detection, field_name)
    for field_name in ("baselines", "atomic_guid", "cve", "threat_group"):
        if field_name in detection:
            _require_string_list(detection, field_name)
    if not detection["analytic_story"]:
        raise SecurityContentValidationError(
            "analytic_story must contain at least one story"
        )

    finding = detection.get("finding")
    intermediate = detection.get("intermediate_findings")
    threats = detection.get("threat_objects") or []
    if detection_type == "Hunting" and (finding or intermediate or threats):
        raise SecurityContentValidationError(
            "Hunting detections cannot define finding, intermediate_findings, or threat_objects"
        )
    if detection_type in {"TTP", "Correlation"} and not finding:
        raise SecurityContentValidationError(
            f"{detection_type} detections require finding"
        )
    if detection_type == "Correlation" and intermediate:
        raise SecurityContentValidationError(
            "Correlation detections cannot define intermediate_findings"
        )
    if detection_type == "Anomaly" and (finding or not intermediate):
        raise SecurityContentValidationError(
            "Anomaly detections require intermediate_findings and cannot define finding"
        )
    if finding:
        finding = _require_mapping(
            finding, "finding", {"title", "entity"}, {"title", "entity"}
        )
        _validate_token_string(finding["title"], "finding.title")
        _validate_entity(finding["entity"], "finding.entity", False)
    if intermediate:
        intermediate = _require_mapping(
            intermediate, "intermediate_findings", {"entities"}, {"entities"}
        )
        if (
            not isinstance(intermediate["entities"], list)
            or not intermediate["entities"]
        ):
            raise SecurityContentValidationError(
                "intermediate_findings.entities must be a non-empty list"
            )
        for entity in intermediate["entities"]:
            _validate_entity(entity, "intermediate_findings entity", True)
    if not isinstance(threats, list):
        raise SecurityContentValidationError("threat_objects must be a list")
    for threat in threats:
        threat = _require_mapping(
            threat, "threat_object", {"field", "type"}, {"field", "type"}
        )
        if not isinstance(threat["field"], str) or not threat["field"]:
            raise SecurityContentValidationError(
                "threat_object.field must be non-empty"
            )
        if threat["type"] not in THREAT_OBJECT_TYPES:
            raise SecurityContentValidationError(
                f"invalid threat_object.type: {threat['type']}"
            )
    drilldowns = detection.get("drilldown_searches", []) or []
    if not isinstance(drilldowns, list):
        raise SecurityContentValidationError("drilldown_searches must be a list")
    for drilldown in drilldowns:
        drilldown = _require_mapping(
            drilldown,
            "drilldown_search",
            {"name", "search", "earliest_offset", "latest_offset"},
            {"name", "search", "earliest_offset", "latest_offset"},
        )
        if any(not isinstance(drilldown[key], str) for key in drilldown):
            raise SecurityContentValidationError(
                "drilldown_search values must be strings"
            )

    schedule = detection.get("schedule")
    custom_schedule = detection.get("custom_schedule")
    if schedule is not None and custom_schedule is not None:
        raise SecurityContentValidationError(
            "schedule and custom_schedule cannot both be defined"
        )
    if schedule is not None and not isinstance(schedule, str):
        raise SecurityContentValidationError("schedule must be a string")
    if custom_schedule is not None:
        custom_schedule = _require_mapping(
            custom_schedule,
            "custom_schedule",
            {"cron_schedule", "schedule_window", "earliest_time", "latest_time"},
            {"cron_schedule", "schedule_window", "earliest_time", "latest_time"},
        )
        if any(not isinstance(custom_schedule[key], str) for key in custom_schedule):
            raise SecurityContentValidationError(
                "custom_schedule values must be strings"
            )
        if not re.match(r"^(auto|\d+)$", custom_schedule["schedule_window"]):
            raise SecurityContentValidationError("invalid custom schedule_window")

    search = detection["search"]
    if search != search.strip():
        raise SecurityContentValidationError(
            "search cannot have leading or trailing whitespace"
        )
    expected_macro = f"`{normalize_detection_name(detection['name'])}_filter`"
    if expected_macro not in search:
        raise SecurityContentValidationError(
            "search is missing the generated filter macro"
        )
    for entity, message in _iter_entities(detection):
        field_name = entity.get("field")
        if not field_name or f"${field_name}$" not in str(message):
            raise SecurityContentValidationError(
                "risk title/message must contain its entity token"
            )
        if status == "production" and str(field_name) not in search:
            raise SecurityContentValidationError(
                f"production entity field '{field_name}' is absent from search"
            )

    techniques = detection["mitre_attack_id"]
    technique_set = set(techniques)
    for technique in techniques:
        if not re.match(r"^T\d{4}(?:\.\d{3})?$", technique):
            raise SecurityContentValidationError(
                f"invalid MITRE ATT&CK technique: {technique}"
            )
        if "." in technique and technique.split(".", 1)[0] in technique_set:
            raise SecurityContentValidationError(
                "MITRE ATT&CK parent and sub-technique cannot both be present"
            )
    for reference in detection["references"]:
        if not re.match(r"^https?://", reference):
            raise SecurityContentValidationError(
                f"reference is not an HTTP(S) URI: {reference}"
            )
    for cve in detection.get("cve", []) or []:
        if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve):
            raise SecurityContentValidationError(f"invalid CVE: {cve}")
    for atomic_guid in detection.get("atomic_guid", []) or []:
        try:
            uuid.UUID(atomic_guid)
        except (ValueError, TypeError, AttributeError) as exc:
            raise SecurityContentValidationError(
                f"invalid Atomic GUID: {atomic_guid}"
            ) from exc
    if status == "deprecated" and not detection.get("deprecation_info"):
        raise SecurityContentValidationError(
            "deprecated detections require deprecation_info"
        )
    if detection.get("deprecation_info"):
        deprecation = _require_mapping(
            detection["deprecation_info"],
            "deprecation_info",
            {"reason", "removed_in_version", "replacement_content"},
            {"reason", "removed_in_version"},
        )
        if not isinstance(deprecation["reason"], str) or not deprecation["reason"]:
            raise SecurityContentValidationError(
                "deprecation_info.reason must be non-empty"
            )
        if not isinstance(deprecation["removed_in_version"], str) or not re.match(
            r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$",
            deprecation["removed_in_version"],
        ):
            raise SecurityContentValidationError(
                "deprecation_info.removed_in_version must be semantic version"
            )
        if "replacement_content" in deprecation and (
            not isinstance(deprecation["replacement_content"], list)
            or any(
                not isinstance(item, str) for item in deprecation["replacement_content"]
            )
        ):
            raise SecurityContentValidationError(
                "deprecation_info.replacement_content must be a list of strings"
            )
    _validate_tests(detection.get("tests"))


def serialize_detections(detections: Sequence[Mapping[str, Any]]) -> str:
    ordered_documents = []
    for detection in detections:
        validate_detection(detection)
        canonical = dict(detection)
        canonical["id"] = str(uuid.UUID(str(detection["id"])))
        document = {
            field_name: (
                _LiteralString(str(canonical[field_name]))
                if field_name == "search"
                else canonical[field_name]
            )
            for field_name in FIELD_ORDER
            if field_name in canonical
        }
        ordered_documents.append(document)
    if not ordered_documents:
        return ""
    return yaml.dump_all(
        ordered_documents,
        Dumper=_SecurityContentDumper,
        sort_keys=False,
        default_flow_style=False,
        indent=4,
        width=4096,
        explicit_start=False,
        allow_unicode=True,
    )

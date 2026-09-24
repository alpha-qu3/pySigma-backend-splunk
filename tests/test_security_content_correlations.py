import pytest
import yaml

from sigma.backends.splunk import SplunkBackend
from sigma.backends.splunk.security_content import SecurityContentValidationError
from sigma.collection import SigmaCollection
from sigma.pipelines.splunk import splunk_cim_data_model
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import SetStateTransformation


BASE_RULES = """
title: First event
name: first_event
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: alice
        ProcessId: 10
    condition: selection
---
title: Second event
name: second_event
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: alice
        ProcessId: 20
    condition: selection
"""


def draft_backend(**kwargs):
    defaults = {
        "creation_date": "2024-01-01",
        "analytic_story": ["Conversion Review"],
        "author": "Sigma",
        "description": "Converted correlation.",
        "data_source": [],
    }
    return SplunkBackend(
        security_content_mode="draft",
        security_content_defaults=defaults,
        **kwargs,
    )


def convert_correlation(correlation, *, cim=False, **kwargs):
    backend = draft_backend(
        processing_pipeline=splunk_cim_data_model() if cim else None,
        **kwargs,
    )
    output_format = "security_content_data_model" if cim else "security_content"
    with pytest.warns(UserWarning, match="generic"):
        stream = backend.convert(
            SigmaCollection.from_yaml(BASE_RULES + "\n---\n" + correlation),
            output_format,
        )
    return list(yaml.safe_load_all(stream))


@pytest.mark.parametrize(
    ("correlation_type", "condition_extra", "expected"),
    [
        ("event_count", "", "sum(_sc_event_count) as event_count"),
        ("value_count", "        field: ProcessId\n", "dc(ProcessId) as value_count"),
        (
            "value_sum",
            "        field: ProcessId\n",
            "sum(_sc_weighted_value) as value_sum",
        ),
        ("value_avg", "        field: ProcessId\n", "eval value_avg="),
        (
            "value_percentile",
            "        field: ProcessId\n        percentile: 90\n",
            "exactperc90(ProcessId) as value_percentile",
        ),
        (
            "value_median",
            "        field: ProcessId\n",
            "median(ProcessId) as value_median",
        ),
    ],
)
def test_raw_value_correlations_are_bucketed_and_weight_aware(
    correlation_type, condition_extra, expected
):
    documents = convert_correlation(
        f"""
title: Correlated activity
status: test
correlation:
    type: {correlation_type}
    rules:
        - first_event
    group-by: User
    timespan: 15m
    condition:
        gte: 2
{condition_extra}"""
    )

    search = documents[-1]["search"]
    assert "| bin _time span=15m" in search
    assert expected in search
    assert "_sc_first_time" in search
    assert "_sc_last_time" in search


def test_approximate_percentile_is_opt_in():
    documents = convert_correlation(
        """
title: Percentile activity
status: test
correlation:
    type: value_percentile
    rules: first_event
    timespan: 5m
    condition:
        gt: 5
        field: ProcessId
        percentile: 95
""",
        security_content_percentile_mode="approximate",
    )

    assert "perc95(ProcessId) as value_percentile" in documents[-1]["search"]
    assert "exactperc95" not in documents[-1]["search"]


def test_temporal_uses_a_trailing_window_and_supports_absence():
    documents = convert_correlation(
        """
title: Temporal activity
status: test
correlation:
    type: temporal
    rules:
        - first_event
        - second_event
    group-by: User
    timespan: 15m
    condition: first_event and not second_event
"""
    )

    search = documents[-1]["search"]
    assert "streamstats time_window=15m" in search
    assert "| bin _time" not in search
    assert '_sc_event_type="first_event"' in search
    assert '_sc_event_type="second_event"' in search
    assert "NOT (" in search
    assert "_sc_future_second_event" in search


def test_ordered_temporal_advances_predecessor_timestamps():
    documents = convert_correlation(
        """
title: Ordered activity
status: test
correlation:
    type: temporal_ordered
    rules:
        - first_event
        - second_event
    group-by: User
    timespan: 15m
    condition: first_event and second_event
"""
    )

    search = documents[-1]["search"]
    assert "| sort 0 User _time" in search
    assert "streamstats current=f last(_sc_step_1_1)" in search
    assert "_time-_sc_sequence_1_start<=900" in search
    assert "isnotnull(_sc_step_1_2)" in search


def test_ordered_temporal_rejects_not():
    source = (
        BASE_RULES
        + """
---
title: Invalid ordered activity
status: test
correlation:
    type: temporal_ordered
    rules:
        - first_event
        - second_event
    timespan: 15m
    condition: first_event and not second_event
"""
    )
    with pytest.raises(SecurityContentValidationError, match="ordered.*NOT"):
        draft_backend().convert(SigmaCollection.from_yaml(source), "security_content")


def test_cim_correlations_use_tstats_counts_and_exact_frequency_expansion():
    event_count = convert_correlation(
        """
title: CIM event count
status: test
correlation:
    type: event_count
    rules: first_event
    group-by: User
    timespan: 15m
    condition:
        gte: 2
""",
        cim=True,
    )[-1]["search"]
    median = convert_correlation(
        """
title: CIM median
status: test
correlation:
    type: value_median
    rules: first_event
    group-by: User
    timespan: 15m
    condition:
        gt: 5
        field: ProcessId
""",
        cim=True,
    )[-1]["search"]

    assert "| tstats" in event_count
    assert "by _time" in event_count
    assert "span=1s" in event_count
    assert "sum(_sc_event_count) as event_count" in event_count
    assert "mvrange(0,_sc_event_count)" in median
    assert "mvexpand _sc_frequency" in median
    assert "median(process_id) as value_median" in median


def test_nested_correlation_preserves_internal_fields_for_outer_rule():
    documents = convert_correlation(
        """
title: Inner correlation
name: inner_correlation
status: test
correlation:
    type: event_count
    rules: first_event
    group-by: User
    timespan: 5m
    condition:
        gte: 2
---
title: Outer correlation
status: test
correlation:
    type: event_count
    rules: inner_correlation
    group-by: User
    timespan: 30m
    condition:
        gte: 2
"""
    )

    search = documents[-1]["search"]
    assert search.count("sum(_sc_event_count) as event_count") == 2
    assert 'eval _sc_event_type="inner_correlation"' in search


def test_generate_true_emits_referenced_rule_and_correlation():
    source = (
        BASE_RULES
        + """
---
title: Generated correlation
status: test
correlation:
    type: event_count
    rules: first_event
    generate: true
    timespan: 5m
    condition:
        gte: 2
"""
    )
    backend = draft_backend()
    with pytest.warns(UserWarning, match="generic"):
        output = backend.convert(SigmaCollection.from_yaml(source), "security_content")

    documents = list(yaml.safe_load_all(output))
    assert [document["name"] for document in documents] == [
        "First event",
        "Second event",
        "Generated correlation",
    ]


def test_aliases_are_applied_inside_typed_union_branches():
    documents = convert_correlation(
        """
title: Aliased temporal activity
status: test
correlation:
    type: temporal
    rules:
        - first_event
        - second_event
    aliases:
        process:
            first_event: ProcessId
            second_event: ProcessId
    group-by: process
    timespan: 5m
"""
    )

    search = documents[-1]["search"]
    assert search.count("rename ProcessId as process") == 2
    assert "streamstats time_window=5m" in search
    assert " by process" in search


def test_ordered_or_expansion_honors_configured_limit():
    source = (
        BASE_RULES
        + """
---
title: Expanded ordered activity
status: test
correlation:
    type: temporal_ordered
    rules:
        - first_event
        - second_event
    timespan: 5m
    condition: first_event or second_event
"""
    )
    with pytest.raises(SecurityContentValidationError, match="sequence limit"):
        draft_backend(security_content_max_ordered_sequences=1).convert(
            SigmaCollection.from_yaml(source), "security_content"
        )


@pytest.mark.parametrize("percentile", [0, 100, -1])
def test_percentile_bounds_are_validated(percentile):
    source = (
        BASE_RULES
        + f"""
---
title: Invalid percentile
status: test
correlation:
    type: value_percentile
    rules: first_event
    timespan: 5m
    condition:
        gt: 1
        field: ProcessId
        percentile: {percentile}
"""
    )
    with pytest.raises(SecurityContentValidationError, match="between 1 and 99"):
        draft_backend().convert(SigmaCollection.from_yaml(source), "security_content")


def test_cim_correlation_rejects_custom_tstats_semantics():
    pipeline = splunk_cim_data_model() + ProcessingPipeline(
        items=[
            ProcessingItem(
                identifier="custom_span",
                transformation=SetStateTransformation("tstats_span", "1m"),
            )
        ]
    )
    source = (
        BASE_RULES
        + """
---
title: Conflicting CIM correlation
status: test
correlation:
    type: event_count
    rules: first_event
    timespan: 5m
    condition:
        gt: 1
"""
    )
    backend = draft_backend(processing_pipeline=pipeline)
    with pytest.raises(SecurityContentValidationError, match="tstats_span"):
        backend.convert(
            SigmaCollection.from_yaml(source), "security_content_data_model"
        )


def test_protected_internal_field_collision_is_rejected():
    source = (
        BASE_RULES.replace("User: alice", "_sc_event_count: 4", 1)
        + """
---
title: Protected collision
status: test
correlation:
    type: event_count
    rules: first_event
    timespan: 5m
    condition:
        gt: 1
"""
    )
    with pytest.raises(
        SecurityContentValidationError, match="protected correlation field"
    ):
        draft_backend().convert(SigmaCollection.from_yaml(source), "security_content")


def test_correlation_reference_cycle_is_rejected_before_conversion():
    source = """
title: First correlation
name: first_correlation
status: test
correlation:
    type: event_count
    rules: second_correlation
    timespan: 5m
    condition:
        gt: 1
---
title: Second correlation
name: second_correlation
status: test
correlation:
    type: event_count
    rules: first_correlation
    timespan: 5m
    condition:
        gt: 1
"""
    with pytest.raises(SecurityContentValidationError, match="cycle"):
        draft_backend().convert(SigmaCollection.from_yaml(source), "security_content")


def test_cim_temporal_correlation_supports_mixed_data_models():
    source = (
        BASE_RULES.split("---", 1)[0]
        + """
---
title: DNS event
name: dns_event
status: test
logsource:
    category: network
    service: dns
detection:
    selection:
        dns.question.name: example.com
    condition: selection
---
title: Mixed CIM temporal
status: test
correlation:
    type: temporal
    rules:
        - first_event
        - dns_event
    timespan: 10m
"""
    )
    backend = draft_backend(processing_pipeline=splunk_cim_data_model())
    with pytest.warns(UserWarning, match="generic"):
        output = backend.convert(
            SigmaCollection.from_yaml(source), "security_content_data_model"
        )
    search = list(yaml.safe_load_all(output))[-1]["search"]

    assert "from datamodel=Endpoint.Processes" in search
    assert "from datamodel=Network_Resolution.DNS" in search
    assert search.startswith("| union")


def test_referenced_rule_with_multiple_conditions_keeps_every_typed_branch():
    source = (
        BASE_RULES.replace(
            "selection:\n        User: alice\n        ProcessId: 10\n    condition: selection",
            "one:\n        User: alice\n    two:\n        User: bob\n    condition:\n        - one\n        - two",
            1,
        )
        + """
---
title: Multi-condition count
status: test
correlation:
    type: event_count
    rules: first_event
    timespan: 5m
    condition:
        gt: 1
"""
    )
    backend = draft_backend()
    with pytest.warns(UserWarning, match="generic"):
        output = backend.convert(SigmaCollection.from_yaml(source), "security_content")
    search = list(yaml.safe_load_all(output))[-1]["search"]

    assert search.startswith("| union")
    assert search.count('_sc_event_type="first_event"') == 2


def test_basic_temporal_counts_distinct_rules_and_honors_operator():
    documents = convert_correlation(
        """
title: Exact temporal activity
status: test
correlation:
    type: temporal
    rules:
        - first_event
        - second_event
    timespan: 5m
    condition:
        eq: 2
"""
    )
    search = documents[-1]["search"]

    assert "_sc_distinct_rule_count" in search
    assert "where _sc_distinct_rule_count = 2" in search
    assert "_sc_seen_first_event+_sc_seen_second_event" not in search


def test_extended_temporal_negation_preserves_boolean_structure_and_checks_future():
    documents = convert_correlation(
        """
title: Negated temporal activity
status: test
correlation:
    type: temporal
    rules:
        - first_event
        - second_event
    timespan: 5m
    condition: not (first_event and second_event)
"""
    )
    search = documents[-1]["search"]

    assert "NOT (" in search
    assert "_sc_future_first_event" in search
    assert "_sc_future_second_event" in search
    assert "first_event=0 AND" not in search

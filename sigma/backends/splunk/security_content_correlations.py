from __future__ import annotations

import re
from typing import Any, Iterable

from sigma.correlations import (
    CorrelationConditionAND,
    CorrelationConditionItem,
    CorrelationConditionNOT,
    CorrelationConditionOR,
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
    SigmaExtendedCorrelationCondition,
    SigmaRuleReference,
)
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.rule import SigmaRule

from .security_content import SecurityContentValidationError, compose_union


INTERNAL_FIELDS = (
    "_sc_event_type",
    "_sc_event_count",
    "_sc_first_time",
    "_sc_last_time",
    "_sc_frequency",
    "_sc_weighted_value",
)

OPERATOR = {
    SigmaCorrelationConditionOperator.LT: "<",
    SigmaCorrelationConditionOperator.LTE: "<=",
    SigmaCorrelationConditionOperator.GT: ">",
    SigmaCorrelationConditionOperator.GTE: ">=",
    SigmaCorrelationConditionOperator.EQ: "=",
    SigmaCorrelationConditionOperator.NEQ: "!=",
}


def _rule_label(rule: Any) -> str:
    return str(rule.name or rule.id or rule.title)


def _post_cim_field(field_name: str) -> str:
    return str(field_name).rsplit(".", 1)[-1]


def _alias_renames(
    rule: SigmaCorrelationRule, reference: SigmaRuleReference, cim: bool
) -> str:
    renames = []
    for alias in rule.aliases:
        for mapped_reference, field_name in alias.mapping.items():
            if mapped_reference.reference == reference.reference:
                source = _post_cim_field(field_name) if cim else field_name
                target = _post_cim_field(alias.alias) if cim else alias.alias
                renames.append(f"{source} as {target}")
    return f"\n| rename {' '.join(renames)}" if renames else ""


def _reject_internal_collisions(reference: SigmaRuleReference, query: str) -> None:
    if isinstance(reference.rule, SigmaCorrelationRule):
        return
    fields = set(getattr(reference.rule, "fields", []) or [])
    collisions = [field for field in INTERNAL_FIELDS if field in fields]
    collisions.extend(
        field
        for field in INTERNAL_FIELDS
        if re.search(rf"(?<![\w.]){re.escape(field)}(?![\w.])", query)
    )
    if collisions:
        raise SecurityContentValidationError(
            "source rule uses protected correlation field(s): "
            + ", ".join(sorted(set(collisions)))
        )


def _cim_branch(
    backend: Any, reference: SigmaRuleReference, query: str, index: int
) -> str:
    states = reference.rule.get_conversion_states()
    if index >= len(states):
        raise SecurityContentValidationError(
            "CIM correlation branch has no conversion state"
        )
    state = states[index]
    conflicts = {
        key
        for key in ("tstats_span", "tstats_aggregation", "tstats_aggregations")
        if state.processing_state.get(key)
    }
    if conflicts:
        raise SecurityContentValidationError(
            "CIM correlations cannot use custom " + ", ".join(sorted(conflicts))
        )
    state.processing_state["tstats_span"] = "1s"
    try:
        search = backend.finalize_query_data_model(
            reference.rule, query, index, state
        ).strip()
    finally:
        state.processing_state.pop("tstats_span", None)
    return (
        search
        + "\n| eval _sc_event_count=count, "
        + '_sc_first_time=strptime(firstTime,"%Y-%m-%dT%H:%M:%S"), '
        + '_sc_last_time=strptime(lastTime,"%Y-%m-%dT%H:%M:%S")'
    )


def _typed_search(backend: Any, rule: SigmaCorrelationRule, cim: bool) -> str:
    branches = []
    for reference in rule.referenced_rules:
        results = reference.rule.get_conversion_result()
        if not results:
            raise SecurityContentValidationError(
                f"referenced rule '{reference.reference}' produced no query"
            )
        for index, result in enumerate(results):
            if not isinstance(result, str):
                raise SecurityContentValidationError(
                    f"referenced rule '{reference.reference}' did not preserve an unfinalized query"
                )
            _reject_internal_collisions(reference, result)
            if cim and isinstance(reference.rule, SigmaRule):
                branch = _cim_branch(backend, reference, result, index)
            else:
                branch = result.strip()
                if not isinstance(reference.rule, SigmaCorrelationRule):
                    branch += (
                        "\n| eval _sc_event_count=1, _sc_first_time=_time, "
                        "_sc_last_time=_time"
                    )
            branch += _alias_renames(rule, reference, cim)
            label = _rule_label(reference.rule).replace('"', '\\"')
            branch += f'\n| eval _sc_event_type="{label}", _time=_sc_last_time'
            branches.append(branch)
    return compose_union(
        branches,
        backend.security_content_options.union_maxout,
        backend.security_content_options.union_maxtime,
    )


def _group_fields(rule: SigmaCorrelationRule, cim: bool) -> list[str]:
    fields = list(rule.group_by or [])
    return [_post_cim_field(field) for field in fields] if cim else fields


def _value_field(rule: SigmaCorrelationRule, cim: bool) -> str:
    if not isinstance(rule.condition, SigmaCorrelationCondition):
        raise SecurityContentValidationError(
            "value correlation requires a basic condition"
        )
    field = rule.condition.fieldref
    if not isinstance(field, str) or not field:
        raise SecurityContentValidationError("value correlation requires one field")
    return _post_cim_field(field) if cim else field


def _by(group_fields: Iterable[str], include_time: bool = True) -> str:
    fields = (["_time"] if include_time else []) + list(group_fields)
    return " by " + " ".join(fields) if fields else ""


def _condition(rule: SigmaCorrelationRule, value_name: str) -> str:
    if not isinstance(rule.condition, SigmaCorrelationCondition):
        raise SecurityContentValidationError(
            "aggregate correlation requires a basic condition"
        )
    if type(rule.condition.count) is not int or rule.condition.count < 0:
        raise SecurityContentValidationError(
            "correlation count must be a non-negative integer"
        )
    return f"| where {value_name} {OPERATOR[rule.condition.op]} {rule.condition.count}"


def _context_stats(group_fields: list[str]) -> str:
    preserved = " ".join(f"values({field}) as {field}" for field in group_fields)
    return f" {preserved}" if preserved else ""


def _aggregate_search(
    backend: Any, rule: SigmaCorrelationRule, source: str, cim: bool
) -> str:
    correlation_type = rule.type
    groups = _group_fields(rule, cim)
    by = _by(groups)
    span = rule.timespan.spec
    prefix = source + f"\n| bin _time span={span}"
    time_stats = (
        "min(_sc_first_time) as _sc_first_time max(_sc_last_time) as _sc_last_time"
    )

    if correlation_type == SigmaCorrelationType.EVENT_COUNT:
        value_name = "event_count"
        aggregate = f"sum(_sc_event_count) as {value_name} {time_stats}"
    else:
        field = _value_field(rule, cim)
        if correlation_type == SigmaCorrelationType.VALUE_COUNT:
            value_name = "value_count"
            aggregate = f"dc({field}) as {value_name} {time_stats}"
        elif correlation_type == SigmaCorrelationType.VALUE_SUM:
            value_name = "value_sum"
            prefix += f"\n| eval _sc_weighted_value={field}*_sc_event_count"
            aggregate = f"sum(_sc_weighted_value) as {value_name} {time_stats}"
        elif correlation_type == SigmaCorrelationType.VALUE_AVG:
            value_name = "value_avg"
            prefix += f"\n| eval _sc_weighted_value={field}*_sc_event_count"
            aggregate = (
                f"sum(_sc_weighted_value) as _sc_value_sum "
                f"sum(_sc_event_count) as _sc_value_count {time_stats}"
            )
        elif correlation_type in {
            SigmaCorrelationType.VALUE_PERCENTILE,
            SigmaCorrelationType.VALUE_MEDIAN,
        }:
            if cim:
                prefix += (
                    "\n| eval _sc_frequency=mvrange(0,_sc_event_count)"
                    "\n| mvexpand _sc_frequency"
                )
            if correlation_type == SigmaCorrelationType.VALUE_MEDIAN:
                value_name = "value_median"
                function = "median"
            else:
                value_name = "value_percentile"
                percentile = rule.condition.percentile
                if type(percentile) is not int or not 0 < percentile < 100:
                    raise SecurityContentValidationError(
                        "percentile must be between 1 and 99"
                    )
                function = (
                    "exactperc"
                    if backend.security_content_options.percentile_mode == "exact"
                    else "perc"
                ) + str(percentile)
            aggregate = f"{function}({field}) as {value_name} {time_stats}"
        else:
            raise SecurityContentValidationError(
                f"unsupported aggregate correlation type: {correlation_type}"
            )

    search = f"{prefix}\n| stats {aggregate}{_context_stats(groups)}{by}"
    if correlation_type == SigmaCorrelationType.VALUE_AVG:
        search += "\n| eval value_avg=_sc_value_sum/_sc_value_count"
    search += "\n" + _condition(rule, value_name)
    search += (
        f"\n| eval _sc_event_count={value_name}, _sc_last_time=_time"
        "\n| fields _time _sc_event_type _sc_event_count _sc_first_time "
        "_sc_last_time " + " ".join(groups)
    ).rstrip()
    return search


def _all_references(rule: SigmaCorrelationRule) -> list[str]:
    return [_rule_label(reference.rule) for reference in rule.referenced_rules]


def _marker_name(label: str) -> str:
    return "_sc_seen_" + re.sub(r"\W+", "_", label).strip("_").lower()


def _future_marker_name(label: str) -> str:
    return "_sc_future_" + re.sub(r"\W+", "_", label).strip("_").lower()


def _any_marker_name(label: str) -> str:
    return "_sc_any_" + re.sub(r"\W+", "_", label).strip("_").lower()


def _extended_window_expression(node: Any, negated: bool = False) -> str:
    if isinstance(node, SigmaRuleReference):
        marker = (
            _any_marker_name(node.reference)
            if negated
            else _marker_name(node.reference)
        )
        return f"{marker}>0"
    if isinstance(node, CorrelationConditionNOT):
        return f"NOT ({_extended_window_expression(node.args[0], not negated)})"
    if isinstance(node, CorrelationConditionAND):
        return (
            "("
            + " AND ".join(
                _extended_window_expression(arg, negated) for arg in node.args
            )
            + ")"
        )
    if isinstance(node, CorrelationConditionOR):
        return (
            "("
            + " OR ".join(
                _extended_window_expression(arg, negated) for arg in node.args
            )
            + ")"
        )
    raise SecurityContentValidationError("unsupported temporal condition expression")


def _temporal_search(rule: SigmaCorrelationRule, source: str, cim: bool) -> str:
    groups = _group_fields(rule, cim)
    labels = _all_references(rule)
    functions = []
    future_functions = []
    for label in labels:
        escaped = label.replace('"', '\\"')
        functions.append(
            f'count(eval(_sc_event_type="{escaped}")) as {_marker_name(label)}'
        )
        future_functions.append(
            f'count(eval(_sc_event_type="{escaped}")) as {_future_marker_name(label)}'
        )
    by = " by " + " ".join(groups) if groups else ""
    search = source
    search += "\n| sort 0 " + (" ".join(groups) + " " if groups else "") + "_time"
    search += (
        f"\n| streamstats time_window={rule.timespan.spec} current=t "
        + " ".join(functions)
        + " min(_sc_first_time) as _sc_window_first max(_sc_last_time) as _sc_window_last"
        + by
    )
    search += "\n| eval _sc_original_time=_time, _time=-_time"
    search += "\n| sort 0 " + (" ".join(groups) + " " if groups else "") + "_time"
    search += (
        f"\n| streamstats time_window={rule.timespan.spec} current=t "
        + " ".join(future_functions)
        + by
    )
    search += "\n| eval _time=_sc_original_time"
    search += "\n| sort 0 " + (" ".join(groups) + " " if groups else "") + "_time"
    any_markers = []
    for label in labels:
        any_markers.append(
            f"{_any_marker_name(label)}=if({_marker_name(label)}>0 OR "
            f"{_future_marker_name(label)}>0,1,0)"
        )
    search += "\n| eval " + ", ".join(any_markers)
    if isinstance(rule.condition, SigmaExtendedCorrelationCondition):
        expression = _extended_window_expression(rule.condition.parsed)
    else:
        if type(rule.condition.count) is not int or rule.condition.count < 0:
            raise SecurityContentValidationError(
                "temporal count must be a non-negative integer"
            )
        distinct = "+".join(f"if({_marker_name(label)}>0,1,0)" for label in labels)
        search += f"\n| eval _sc_distinct_rule_count={distinct}"
        expression = (
            f"_sc_distinct_rule_count {OPERATOR[rule.condition.op]} "
            f"{rule.condition.count}"
        )
    search += f"\n| where {expression}"
    search += (
        "\n| eval _sc_event_count=1, _sc_first_time=_sc_window_first, "
        "_sc_last_time=_sc_window_last"
    )
    return search


def _ordered_sequences(node: Any) -> list[tuple[str, ...]]:
    if isinstance(node, SigmaRuleReference):
        return [(node.reference,)]
    if isinstance(node, CorrelationConditionNOT):
        raise SecurityContentValidationError(
            "ordered temporal conditions cannot contain NOT"
        )
    if isinstance(node, CorrelationConditionOR):
        sequences = []
        for arg in node.args:
            sequences.extend(_ordered_sequences(arg))
        return sequences
    if isinstance(node, CorrelationConditionAND):
        sequences: list[tuple[str, ...]] = [()]
        for arg in node.args:
            sequences = [
                left + right for left in sequences for right in _ordered_sequences(arg)
            ]
        return sequences
    raise SecurityContentValidationError(
        "unsupported ordered temporal condition expression"
    )


def _deduplicate_sequences(
    sequences: Iterable[tuple[str, ...]],
) -> list[tuple[str, ...]]:
    seen = set()
    result = []
    for sequence in sequences:
        if sequence not in seen:
            seen.add(sequence)
            result.append(sequence)
    return result


def _ordered_search(
    backend: Any, rule: SigmaCorrelationRule, source: str, cim: bool
) -> str:
    groups = _group_fields(rule, cim)
    if isinstance(rule.condition, SigmaExtendedCorrelationCondition):
        sequences = _deduplicate_sequences(_ordered_sequences(rule.condition.parsed))
    else:
        sequences = [tuple(_all_references(rule))]
    if len(sequences) > backend.security_content_options.max_ordered_sequences:
        raise SecurityContentValidationError(
            "ordered temporal expression exceeds the configured sequence limit"
        )
    if not sequences or any(not sequence for sequence in sequences):
        raise SecurityContentValidationError(
            "ordered temporal condition produced no sequence"
        )

    by = " by " + " ".join(groups) if groups else ""
    search = source
    search += "\n| sort 0 " + (" ".join(groups) + " " if groups else "") + "_time"
    terminals = []
    starts = []
    for sequence_index, sequence in enumerate(sequences, 1):
        first = sequence[0].replace('"', '\\"')
        step = f"_sc_step_{sequence_index}_1"
        start = f"_sc_sequence_{sequence_index}_start"
        search += f'\n| eval {step}=if(_sc_event_type="{first}",_time,null())'
        search += f"\n| streamstats current=f last({step}) as {start}{by}"
        previous = start
        for step_index, label in enumerate(sequence[1:], 2):
            current = f"_sc_step_{sequence_index}_{step_index}"
            escaped = label.replace('"', '\\"')
            search += (
                f'\n| eval {current}=if(_sc_event_type="{escaped}" '
                f"AND isnotnull({previous}) AND _time-{start}<={rule.timespan.seconds},"
                "_time,null())"
            )
            if step_index < len(sequence):
                next_previous = f"_sc_previous_{sequence_index}_{step_index}"
                search += (
                    f"\n| streamstats current=f last({current}) as {next_previous}{by}"
                )
                previous = next_previous
            else:
                terminals.append(current)
                starts.append(start)
        if len(sequence) == 1:
            terminals.append(step)
            starts.append(step)
    search += "\n| where " + " OR ".join(f"isnotnull({field})" for field in terminals)
    search += (
        "\n| eval _sc_event_count=1, _sc_first_time=coalesce("
        + ",".join(starts)
        + "), _sc_last_time=_time"
    )
    return search


def build_correlation_search(
    backend: Any, rule: SigmaCorrelationRule, cim: bool
) -> str:
    source = _typed_search(backend, rule, cim)
    if rule.type == SigmaCorrelationType.TEMPORAL:
        return _temporal_search(rule, source, cim)
    if rule.type == SigmaCorrelationType.TEMPORAL_ORDERED:
        return _ordered_search(backend, rule, source, cim)
    return _aggregate_search(backend, rule, source, cim)

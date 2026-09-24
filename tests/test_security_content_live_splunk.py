import base64
import json
import os
import ssl
import warnings
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest
import yaml

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.splunk import splunk_cim_data_model


pytestmark = [
    pytest.mark.live_splunk,
    pytest.mark.skipif(
        os.getenv("SPLUNK_LIVE_TESTS") not in {"1", "true", "yes"},
        reason="set SPLUNK_LIVE_TESTS=1 to run live Splunk syntax checks",
    ),
]


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


def _generated_search(source, *, cim=False):
    backend = SplunkBackend(
        processing_pipeline=splunk_cim_data_model() if cim else None,
        security_content_mode="draft",
        security_content_defaults={
            "creation_date": "2024-01-01",
            "analytic_story": ["Conversion Review"],
            "author": "Sigma",
            "description": "Live compiler validation.",
            "data_source": [],
        },
    )
    output_format = "security_content_data_model" if cim else "security_content"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        stream = backend.convert(SigmaCollection.from_yaml(source), output_format)
    search = list(yaml.safe_load_all(stream))[-1]["search"]
    lines = search.splitlines()
    assert lines[-1].startswith("| `") and lines[-1].endswith("_filter`")
    return "\n".join(lines[:-1])


def _generated_searches():
    correlations = {
        "rolling": """
title: Rolling temporal activity
status: test
correlation:
    type: temporal
    rules:
        - first_event
        - second_event
    group-by: User
    timespan: 5m
""",
        "ordered": """
title: Ordered temporal activity
status: test
correlation:
    type: temporal_ordered
    rules:
        - first_event
        - second_event
    group-by: User
    timespan: 5m
    condition: first_event and second_event
""",
        "percentile": """
title: Percentile activity
status: test
correlation:
    type: value_percentile
    rules: first_event
    group-by: User
    timespan: 5m
    condition:
        gt: 1
        field: ProcessId
        percentile: 90
""",
        "chained": """
title: Inner correlation
name: inner_correlation
status: test
correlation:
    type: event_count
    rules: first_event
    group-by: User
    timespan: 5m
    condition:
        gte: 1
---
title: Outer correlation
status: test
correlation:
    type: event_count
    rules: inner_correlation
    group-by: User
    timespan: 30m
    condition:
        gte: 1
""",
    }
    first_rule = BASE_RULES.split("---", 1)[0]
    searches = {
        "raw": _generated_search(first_rule),
        "cim_tstats": _generated_search(first_rule, cim=True),
    }
    searches.update(
        {
            name: _generated_search(BASE_RULES + "\n---\n" + correlation)
            for name, correlation in correlations.items()
        }
    )
    searches["cim_event_count"] = _generated_search(
        BASE_RULES + "\n---\n" + correlations["chained"].split("---", 1)[0],
        cim=True,
    )
    searches["cim_median"] = _generated_search(
        BASE_RULES
        + """
---
title: CIM median activity
status: test
correlation:
    type: value_median
    rules: first_event
    group-by: User
    timespan: 5m
    condition:
        gt: 1
        field: ProcessId
""",
        cim=True,
    )
    return searches


SEARCHES = _generated_searches()


def _with_synthetic_events(search, *, second_offset=0):
    replacements = {
        'User="alice" ProcessId=10': (
            '| makeresults | eval _time=now()-60, User="alice", ProcessId=10'
        ),
        'User="alice" ProcessId=20': (
            "| makeresults | eval _time=now()"
            f'+{second_offset}, User="alice", ProcessId=20'
        ),
    }
    for terms, pipeline in replacements.items():
        search = search.replace("search " + terms, pipeline)
        search = search.replace(terms, pipeline)
    return search


ABSENCE_SEARCH = _generated_search(
    BASE_RULES
    + """
---
title: Temporal absence activity
status: test
correlation:
    type: temporal
    rules:
        - first_event
        - second_event
    group-by: User
    timespan: 5m
    condition: first_event and not second_event
"""
)

CONTROLLED_SEARCHES = {
    "rolling": (
        _with_synthetic_events(SEARCHES["rolling"]),
        1,
        "_sc_distinct_rule_count",
    ),
    "ordered": (
        _with_synthetic_events(SEARCHES["ordered"]),
        1,
        "_sc_sequence_1_start",
    ),
    "percentile": (
        _with_synthetic_events(SEARCHES["percentile"]),
        1,
        "value_percentile",
    ),
    "chained": (
        _with_synthetic_events(SEARCHES["chained"]),
        1,
        "event_count",
    ),
    "absence_inside_window": (
        _with_synthetic_events(ABSENCE_SEARCH),
        0,
        None,
    ),
    "absence_outside_window": (
        _with_synthetic_events(ABSENCE_SEARCH, second_offset=600),
        1,
        "_sc_any_second_event",
    ),
}


def _with_synthetic_cim_rows(search, rows):
    marker = "\n| eval _sc_event_count=count"
    assert marker in search
    suffix = marker + search.split(marker, 1)[1]
    return rows + suffix


CONTROLLED_CIM_SEARCHES = {
    "cim_event_count": _with_synthetic_cim_rows(
        SEARCHES["cim_event_count"],
        """| makeresults count=2
| streamstats count as row
| eval _time=if(row=1,now()-360,now()), count=if(row=1,2,3), user="alice", process_id=10
| eval firstTime=strftime(_time,"%Y-%m-%dT%H:%M:%S"), lastTime=firstTime""",
    ),
    "cim_median": _with_synthetic_cim_rows(
        SEARCHES["cim_median"],
        """| makeresults count=2
| streamstats count as row
| eval _time=now(), count=if(row=1,3,1), user="alice", process_id=if(row=1,10,20)
| eval firstTime=strftime(_time,"%Y-%m-%dT%H:%M:%S"), lastTime=firstTime""",
    ),
}


def _execute(search):
    if not search.lstrip().startswith("|") and not search.lstrip().startswith(
        "search "
    ):
        search = "search " + search
    url = os.environ["SPLUNK_URL"].rstrip("/") + "/services/search/jobs/export"
    payload = urlencode(
        {"search": search, "output_mode": "json", "exec_mode": "blocking"}
    ).encode()
    credentials = f"{os.environ['SPLUNK_USERNAME']}:{os.environ['SPLUNK_PASSWORD']}"
    request = Request(url, data=payload, method="POST")
    request.add_header(
        "Authorization", "Basic " + base64.b64encode(credentials.encode()).decode()
    )
    verify = os.getenv("SPLUNK_VERIFY_TLS", "1").lower() not in {"0", "false", "no"}
    context = (
        ssl.create_default_context() if verify else ssl._create_unverified_context()
    )
    try:
        with urlopen(request, context=context, timeout=120) as response:
            return response.read().decode("utf-8")
    except HTTPError as exc:
        pytest.fail(f"Splunk rejected search ({exc.code}): {exc.read().decode()}")


def _parse_response(output):
    messages = []
    results = []
    for line in output.splitlines():
        value = json.loads(line)
        messages.extend(value.get("messages", []))
        if "result" in value:
            results.append(value["result"])
    fatal = [
        message for message in messages if message.get("type") in {"ERROR", "FATAL"}
    ]
    assert not fatal, f"search failed: {fatal}"
    return results


@pytest.mark.parametrize(("name", "search"), SEARCHES.items())
def test_representative_security_content_searches_execute(name, search):
    _parse_response(_execute(search))


@pytest.mark.parametrize(("name", "case"), CONTROLLED_SEARCHES.items())
def test_generated_correlation_semantics_with_controlled_events(name, case):
    search, expected_rows, expected_field = case
    results = _parse_response(_execute(search))

    assert len(results) == expected_rows, f"{name} returned {len(results)} rows"
    if expected_field is not None:
        assert expected_field in results[0]
    if name == "ordered":
        assert float(results[0]["_sc_first_time"]) < float(results[0]["_sc_last_time"])
    if name == "chained":
        assert float(results[0]["event_count"]) == 1


@pytest.mark.parametrize(("name", "search"), CONTROLLED_CIM_SEARCHES.items())
def test_generated_cim_correlation_semantics_with_controlled_aggregates(name, search):
    results = _parse_response(_execute(search))

    if name == "cim_event_count":
        assert len(results) == 2
        assert {float(result["event_count"]) for result in results} == {2, 3}
        assert len({result["_time"] for result in results}) == 2
    else:
        assert len(results) == 1
        assert float(results[0]["value_median"]) == 10

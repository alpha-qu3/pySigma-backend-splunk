import base64
import json
import os
import ssl
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest


pytestmark = [
    pytest.mark.live_splunk,
    pytest.mark.skipif(
        os.getenv("SPLUNK_LIVE_TESTS") not in {"1", "true", "yes"},
        reason="set SPLUNK_LIVE_TESTS=1 to run live Splunk syntax checks",
    ),
]


SEARCHES = {
    "raw": '| makeresults | eval user="alice" | search user="alice"',
    "cim_tstats": "| tstats count from datamodel=Endpoint.Processes by Processes.user | head 1",
    "rolling": (
        "| makeresults count=3 | streamstats time_window=5m current=t count as event_count "
        "| where event_count>=1"
    ),
    "ordered": (
        '| makeresults count=2 | streamstats count | eval event_type=if(count=1,"one","two") '
        '| eval step_one=if(event_type="one",_time,null()) '
        "| streamstats current=f last(step_one) as previous_one "
        '| eval step_two=if(event_type="two" AND isnotnull(previous_one),_time,null()) '
        "| where isnotnull(step_two)"
    ),
    "percentile": "| makeresults count=3 | streamstats count | stats exactperc90(count) as p90",
    "chained": (
        "| makeresults count=4 | streamstats count as event_count "
        "| stats sum(event_count) as event_count by _time "
        "| stats sum(event_count) as outer_event_count"
    ),
}


def _execute(search):
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
    context = ssl.create_default_context() if verify else ssl._create_unverified_context()
    try:
        with urlopen(request, context=context, timeout=120) as response:
            return response.read().decode("utf-8")
    except HTTPError as exc:
        pytest.fail(f"Splunk rejected search ({exc.code}): {exc.read().decode()}")


@pytest.mark.parametrize(("name", "search"), SEARCHES.items())
def test_representative_security_content_searches_execute(name, search):
    output = _execute(search)
    messages = []
    for line in output.splitlines():
        value = json.loads(line)
        messages.extend(value.get("messages", []))
    fatal = [message for message in messages if message.get("type") in {"ERROR", "FATAL"}]
    assert not fatal, f"{name} search failed: {fatal}"

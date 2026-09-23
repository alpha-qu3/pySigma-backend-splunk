![Tests](https://github.com/SigmaHQ/pySigma-backend-splunk/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/47c292239759399a6e3c73b0e9656b33/raw/SigmaHQ-pySigma-backend-splunk.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Splunk Backend

This is the Splunk backend for pySigma. It provides the package `sigma.backends.splunk` with the `SplunkBackend` class.
Further, it contains the following processing pipelines in `sigma.pipelines.splunk`:

* splunk_windows_pipeline: Splunk Windows log support
* splunk_windows_sysmon_acceleration_keywords: Adds fiels name keyword search terms to generated query to accelerate search.

It supports the following output formats:

* default: plain Splunk queries
* savedsearches: Splunk savedsearches.conf format.
* data_model: CIM data model queries using `tstats`.
* security_content: Splunk Security Content detection YAML using raw SPL.
* security_content_data_model: Splunk Security Content detection YAML using CIM `tstats` SPL.

## Splunk Security Content output

The Security Content formats emit a deterministic multi-document YAML stream, with one
document for each standalone or generated detection. They add the normalized
`<detection_name>_filter` macro after combining all top-level Sigma conditions and support
all eight Sigma correlation types. Correlation searches use `union`, preserve event counts
from CIM `tstats` branches, use trailing windows for temporal rules, and reject ordered
expressions containing `NOT`.

Use `security_content` for raw SPL:

```shell
sigma convert -t splunk -f security_content rules.yml > detections.yml
```

Use the CIM pipeline and `security_content_data_model` for `tstats` SPL:

```shell
sigma convert -t splunk -p splunk_cim_data_model \
  -f security_content_data_model rules.yml > detections.yml
```

Rules provide target-specific metadata under `splunk_security_content:`. The keys are the
Security Content detection field names; `search`, `product`, and unknown keys are rejected.
This is a minimal strict-mode example:

```yaml
title: Suspicious PowerShell
id: c5c4e59f-03cf-4d7e-bdf8-b60181275929
status: test
description: Detects suspicious PowerShell execution.
author: SigmaHQ
date: 2024-01-01
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \powershell.exe
  condition: selection
splunk_security_content:
  version: 1
  type: Hunting
  analytic_story: [Credential Dumping]
  data_source: [Sysmon EventID 1]
  asset_type: Endpoint
  category: endpoint
  security_domain: endpoint
  how_to_implement: Enable process creation telemetry.
  known_false_positives: Administrators may run PowerShell legitimately.
  tests:
    - name: Conversion review
      test_type: experimental
      description: Review the converted query before promotion.
```

Values resolve in this order: rule overlay, standard Sigma metadata, pipeline defaults,
backend defaults, then draft synthesis. Pipeline state may provide
`security_content_defaults` and `security_content_entity_fields`; those values override the
same backend options. Relevant backend options are:

* `security_content_mode`: `strict` (default) or `draft`.
* `security_content_defaults`: shared target metadata.
* `security_content_entity_fields`: additional `field: user|system` mappings for risk
  inference.
* `security_content_percentile_mode`: `exact` (default) or `approximate`.
* `security_content_max_ordered_sequences`: ordered expression expansion limit (default 64).
* `security_content_union_maxout` and `security_content_union_maxtime`: optional `union`
  limits.

Strict mode rejects missing repository-required metadata and ambiguous risk entities. Draft
mode emits deterministic experimental Hunting content, requires a date and analytic story,
adds review text/test metadata, and never invents findings or threat objects.

### Repository writer

The companion writer validates the complete YAML stream before changing a Security Content
checkout. It indexes stories, data sources, baselines, macros, lookups, Atomic GUIDs,
existing names, UUIDs, and paths; then creates or version-safely updates files atomically.

```shell
sigma-splunk-content write --repo ../security_content --input detections.yml --check
sigma-splunk-content write --repo ../security_content --input detections.yml
# Standard input is also supported:
sigma convert -t splunk -f security_content rules.yml | \
  sigma-splunk-content write --repo ../security_content --input -
```

`--check` performs the identical preflight without writing and reports created, updated,
unchanged, warning, and error counts. An update requires the same UUID and path, an increased
version, an unchanged creation date, and a non-regressing modification date. Any batch error
prevents every write.

References maintained outside the checkout can be allowed explicitly in `contentctl.yml`:

```yaml
sigma_splunk_content:
  external:
    macros: [organization_index_scope]
    lookups: [organization_allowlist]
    data_sources: [Organization EDR]
```

The opt-in live suite uses `SPLUNK_LIVE_TESTS=1`, `SPLUNK_URL`, `SPLUNK_USERNAME`, and
`SPLUNK_PASSWORD`. Set `SPLUNK_VERIFY_TLS=0` only for an isolated test instance with a
self-signed certificate.

## Data model (tstats) query settings

The `data_model` output format generates accelerated `tstats` queries against a Splunk data
model. The following settings let you tune the generated query without changing the Sigma
rules themselves. They are read from the pipeline processing state (set with a
`SetStateTransformation` / the `set_state` pipeline item), so detection logic stays separate
from environment-specific query configuration. Defaults keep the generated query unchanged.

* `summariesonly` (also available as the `summariesonly` backend option, e.g.
  `-O summariesonly=true` with sigma-cli): controls the `tstats summariesonly=...` flag.
  Accepts a boolean or a string (`true`/`false`). When both are set, the pipeline
  processing state takes precedence over the backend option. Default: `false`.

The following are Splunk-specific extensions of the data model output and have no direct
representation in the Sigma standard:

* `tstats_span`: adds `_time` to the `by` clause and a `span=<value>` bucket, e.g.
  `tstats_span: 1h`. The value is a number followed by an optional Splunk time unit
  (`s`, `sec`, `secs`, `second`, `seconds`, `m`, `min`, `mins`, `minute`, `minutes`,
  `h`, `hr`, `hrs`, `hour`, `hours`, `d`, `day`, `days`, `mon`, `mont`, `months`); a bare
  number (e.g. `30`) is treated as seconds.
* `tstats_aggregations`: a list of additional aggregation functions appended after the
  default `count`. Each entry is a mapping with `func` (one of the supported Splunk stats
  functions, e.g. `values`, `sum`, `dc`), `field`, and an optional `as`/`alias`, e.g.
  `[{func: values, field: Processes.process_name, as: process_names}]`. `count` is always
  present and cannot be redefined here.
* `tstats_aggregation`: a raw aggregation string appended verbatim after `count` (advanced
  use). When set, it takes precedence over `tstats_aggregations`.

This backend is currently maintained by:

* [Thomas Patzke](https://github.com/thomaspatzke/)

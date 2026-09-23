# Sigma to Splunk Security Content Specification

Implement two pySigma Splunk output formats, `security_content` and
`security_content_data_model`, that emit deterministic multi-document YAML for
Splunk Security Content detections. Add a dependency-light metadata mapper and
validator, all pySigma correlation types in raw and CIM modes, and a
repository-aware `sigma-splunk-content write` command.

The accepted design is the plan supplied in the implementation request. Its
binding decisions are:

- Strict and draft conversion modes; draft is experimental Hunting content.
- Schema-shaped `splunk_security_content` rule metadata with shared defaults.
- Standard Sigma metadata mapping, deterministic UUID/date handling, fixed
  product list, ATT&CK/CVE extraction, filter macro generation, and conservative
  strict risk inference.
- Raw and CIM conversion, multi-condition union, all eight pySigma correlation
  types, rolling temporal semantics, ordered positive sequence support, ordered
  `NOT` rejection, exact percentile by default, and nested correlations.
- Repository preflight, reference and collision validation, version-safe
  updates, check mode, and atomic per-file writes.
- Existing output formats remain behaviorally unchanged and contentctl is not a
  runtime dependency.


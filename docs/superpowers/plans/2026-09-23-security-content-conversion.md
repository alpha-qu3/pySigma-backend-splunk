# Security Content Conversion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert Sigma event and correlation rules into validated Splunk Security Content detection YAML and safely write those detections into a Security Content repository.

**Architecture:** Keep SPL conversion in `SplunkBackend`, but represent emitted detections as typed artifacts handled by a focused metadata/serialization module. A separate writer consumes the YAML stream and performs repository-aware validation and atomic writes.

**Tech Stack:** Python 3.10+, pySigma 1.x, PyYAML, pytest, argparse.

**Spec:** `docs/superpowers/specs/security-content-conversion.md`

## Global Constraints

- Preserve `default`, `savedsearches`, and `data_model` output behavior.
- Do not add contentctl as a runtime dependency.
- Target `contentctl-ng==1.1.1` and the reviewed Security Content develop schema.
- Use deterministic output, safe YAML loading, and no partial writes after validation errors.
- Every production behavior is developed test-first.

## Review Focus

- Referenced rules with `generate: true` must retain raw correlation inputs while also emitting complete documents.
- Multi-condition and nested-correlation branches must remain valid when a branch begins with a generating command.
- CIM correlations must count underlying events, not `tstats` result rows.
- Draft fallback metadata must remain deterministic and visibly review-required.
- Writer collision checks must prevent cross-file UUID/path corruption before any file changes.

---

### Task 1: Metadata Artifacts, Validation, and Serialization

**Files:**
- Create: `sigma/backends/splunk/security_content.py`
- Create: `tests/test_security_content.py`
- Modify: `sigma/backends/splunk/splunk.py`

**Interfaces:**
- Produces: `SecurityContentArtifact`, `SecurityContentOptions`, `build_detection()`, `validate_detection()`, `serialize_detections()`.
- Produces: backend formats `security_content` and `security_content_data_model`.

- [ ] Write failing tests for strict mapping, draft synthesis, metadata precedence, entity inference, field ordering, YAML stream output, protected/unknown keys, names, dates, ATT&CK/CVE tags, and risk/type constraints.
- [ ] Run `PYTHONPATH=/tmp/pysigma-splunk-site pytest -q tests/test_security_content.py` and confirm failures are missing behavior.
- [ ] Implement the typed artifact, options, mapper, validator, and serializer; register both formats and group conditions per rule.
- [ ] Run the focused tests, then `PYTHONPATH=/tmp/pysigma-splunk-site pytest -q` and confirm all pass.
- [ ] Commit with `feat: add security content output formats`.

### Task 2: Correlation and CIM Composition

**Files:**
- Modify: `sigma/backends/splunk/splunk.py`
- Create: `sigma/backends/splunk/correlations.py`
- Create: `tests/test_security_content_correlations.py`

**Interfaces:**
- Consumes: Task 1 artifact and format options.
- Produces: `compose_union()`, raw/CIM correlation renderers, canonical internal correlation fields.

- [ ] Write failing tests for multi-condition union, all eight correlation types, rolling and ordered temporal behavior, aliases, ordered `NOT`, sequence limits, CIM weighted aggregates, mixed data models, chaining, cycles, and conflicting tstats settings.
- [ ] Run the focused tests and confirm failures are missing behavior.
- [ ] Implement raw and CIM composition, including exact percentile defaults and clear unsupported-combination errors.
- [ ] Run focused correlation tests and the complete suite.
- [ ] Commit with `feat: add security content correlation composition`.

### Task 3: Repository Writer

**Files:**
- Create: `sigma/backends/splunk/security_content_writer.py`
- Create: `tests/test_security_content_writer.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: Task 1 YAML stream and validator.
- Produces: `preflight_repository()`, `write_detections()`, and `sigma-splunk-content` CLI.

- [ ] Write failing tests for repository discovery, reference validation, normalized paths, duplicate IDs/names, create/update/unchanged actions, version/date checks, check mode, unsafe YAML, and no writes after any preflight error.
- [ ] Run the focused tests and confirm failures are missing behavior.
- [ ] Implement argparse CLI, repository indexes, batch preflight, deterministic single-document serialization, and atomic per-file replacement.
- [ ] Run focused writer tests and the complete suite.
- [ ] Commit with `feat: add security content repository writer`.

### Task 4: Documentation and Compatibility Automation

**Files:**
- Modify: `README.md`
- Modify: `.github/workflows/test.yml`
- Create: `.github/workflows/security-content-compatibility.yml`

**Interfaces:**
- Consumes: all public APIs from Tasks 1-3.
- Produces: user examples and Python 3.14/contentctl compatibility automation.

- [ ] Add executable documentation examples to existing integration tests before updating prose.
- [ ] Run those tests and confirm they fail for missing documented interfaces where applicable.
- [ ] Document formats, metadata, modes, pipeline defaults, writer usage, correlation limits, and optional live Splunk variables; add the isolated compatibility workflow.
- [ ] Run the full suite and validate workflow YAML with safe loading.
- [ ] Commit with `docs: document security content conversion`.

### Task 5: Full Verification and Review

**Files:**
- Review all files changed since the branch point.

**Interfaces:**
- Consumes: complete implementation.
- Produces: reviewed, verified branch.

- [ ] Run `PYTHONPATH=/tmp/pysigma-splunk-site pytest -q` and inspect the complete result.
- [ ] Run compile checks, CLI help/check-mode smoke tests, deterministic output comparison, and git diff hygiene checks.
- [ ] Build a review package and perform a fresh whole-branch code review against the specification.
- [ ] Fix every Critical/Important finding test-first, rerun the full suite, and commit the review fixes.


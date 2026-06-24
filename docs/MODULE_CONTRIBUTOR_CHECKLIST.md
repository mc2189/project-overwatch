# Module contributor checklist

Use this checklist when adding a new collection or analysis module to Project Overwatch.
Copy `modules/TEMPLATE_module.py` or `modules/TEMPLATE_api_module.py` as a starting point.

## 1. Registry (`modules/module_registry.py`)

- [ ] Add a `ModuleEntry` with a unique `module_id` (category prefix + short name).
- [ ] Set `implemented=True`, `status="active"`, correct `mode` (passive / active / analysis).
- [ ] Declare `target_types`, `requires_authorisation`, `requires_api_key`, and `risk_level`.
- [ ] Confirm the module appears in the UI via `is_executable()` (not quarantined).

## 2. Module implementation (`modules/<category>/<module_id>.py`)

- [ ] Implement `run_<module>(target, *, options=None)` returning `build_module_result(...)`.
- [ ] Use `utils/module_sdk` helpers for status, findings, warnings, and errors.
- [ ] Redact secrets and oversized payloads before returning `raw_output`.
- [ ] For API modules, use `utils/api_module_helpers.py` for rate limits and key checks.

## 3. Executor dispatch (`modules/executor.py`)

- [ ] Add a `ModuleDispatchEntry` in `_register_executor_dispatch()` with:
  - `load` — lazy import of the module file
  - `is_ready` / `get_error` — runtime availability
  - `execute` — `_execute_<module>` handler (add if missing)
  - `unavailable_label` — user-facing name for error messages
  - `persist_hook` — optional reference when custom entity/relationship persistence exists
- [ ] Do **not** add new `if module_id == ...` branches to `execute_module`.
- [ ] Run `python scripts/smoke_check.py` — the **executor dispatch** check must pass.

## 4. Findings interpreter (`utils/findings_registry.py`)

- [ ] Register `interpret_<module>_findings(parsed_data)` if the module produces advisory findings.
- [ ] Map severities conservatively; prefer `info` / `low` when evidence is weak.

## 5. Evidence capture (`utils/evidence_capture.py` / `utils/evidence_model.py`)

- [ ] Add observation/evidence defaults in `observation_evidence_for_module()` when artefacts should land in Evidence Locker.
- [ ] Store hashes for binary or large text via `utils/evidence_storage.py` spill paths.

## 6. UI surfacing

- [ ] Add `MODULE_CARD_TITLES` entry in `ui/constants.py` (if not using registry `display_name` everywhere).
- [ ] Confirm compatibility appears on Assessment Workspace, Entity Workspace, and Batch Queue.
- [ ] Add pivot hints in `utils/pivot_discovery.py` when the module produces follow-up entities.

## 7. Goals and next actions (optional)

- [ ] Add module to a goal set in `utils/assessment_goals.py` when it fits a guided workflow.
- [ ] Add next-action suggestions in `utils/next_actions.py` or `utils/result_next_actions.py` when follow-ups are obvious.

## 8. Verification

- [ ] `python scripts/smoke_check.py`
- [ ] `python scripts/security_audit.py`
- [ ] Manual run from Assessment Workspace (passive + active if applicable).
- [ ] Manual run from Entity Workspace pivot tab with Personal Lab / client context.
- [ ] Confirm findings and evidence appear in the case database.

## Quick reference

| Layer | File |
|-------|------|
| Registry | `modules/module_registry.py` |
| Run logic | `modules/<category>/<module_id>.py` |
| Dispatch | `modules/executor_dispatch.py` + `_register_executor_dispatch()` in `executor.py` |
| Interpreter | `utils/findings_registry.py` |
| Evidence | `utils/evidence_capture.py` |
| Smoke | `scripts/smoke_check.py` |

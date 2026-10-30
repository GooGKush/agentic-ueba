# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""QueryIntegrityGate platform-rule tests against the remediated UEBA harness.

Every rule is read from the skills at runtime (`src.harness_truth` and the skills'
query validators); these tests never restate harness constants.
"""

import inspect
import re

import pytest

from src import harness_truth
from src.config import TenantConfig, get_skills_root
from src.playbook_runner import PlaybookRunner
from src.query_integrity_gate import QueryIntegrityGate, QueryValidationError


def _query(stage_extra: str = "", root_extra: str = "", header: str = "", root_match: str = "$user") -> str:
  """A valid two-stage query; extra outcome lines are appended to the stage / root outcome blocks."""
  stage_lines = "".join(f"    {line}\n" for line in stage_extra.splitlines() if line.strip())
  root_lines = "".join(f"  {line}\n" for line in root_extra.splitlines() if line.strip())
  return (
      "// Goal: Gate fixture for the remediated harness platform rules.\n"
      f"{header}"
      "stage s1 {\n"
      '    metadata.event_type = "USER_LOGIN"\n'
      "    principal.user.userid = $user\n"
      '    $user != ""\n'
      "\n"
      "  match:\n"
      "    $user by 1d\n"
      "\n"
      "  outcome:\n"
      "    $c = count(metadata.id)\n"
      f"{stage_lines}"
      "}\n"
      "\n"
      "$user = $s1.user\n"
      "\n"
      "match:\n"
      f"  {root_match}\n"
      "\n"
      "outcome:\n"
      "  $obs = max($s1.c)\n"
      f"{root_lines}"
      "\n"
      "condition:\n"
      "  $obs >= 1\n"
  )


def _errors(query: str):
  res = QueryIntegrityGate.verify_pre_dispatch(query, raise_on_error=False)
  assert res["valid"] is (not res["errors"])
  assert res["passed"] is res["valid"]
  return res["errors"]


def test_signature_and_alias_are_unchanged():
  params = inspect.signature(QueryIntegrityGate.verify_pre_dispatch).parameters
  assert list(params) == [
      "query",
      "expected_entity",
      "expected_preflight_query",
      "ast_validator_fn",
      "raise_on_error",
  ]
  assert params["expected_entity"].default is None
  assert params["expected_preflight_query"].default is None
  assert params["ast_validator_fn"].default is None
  assert params["raise_on_error"].default is True
  assert QueryIntegrityGate.__dict__["validate_preflight_query"] is QueryIntegrityGate.__dict__["verify_pre_dispatch"]


def test_valid_multistage_query_passes():
  q = _query(root_extra="$root = math.sqrt($obs)")
  assert _errors(q) == []
  assert QueryIntegrityGate.verify_pre_dispatch(q)["passed"] is True


def test_bare_sqrt_is_rejected_through_the_stats_hunter_validator():
  errors = _errors(_query(root_extra="$root = sqrt($obs)"))
  sqrt_errors = [e for e in errors if e.startswith("BARE_SQRT_FUNCTION")]
  assert len(sqrt_errors) == 1
  # The message is the skill validator's own (multistage_query_builder SYNTAX_TRAPS).
  assert "INVALID_SQRT_FUNCTION" in sqrt_errors[0]
  with pytest.raises(QueryValidationError, match="BARE_SQRT_FUNCTION"):
    QueryIntegrityGate.verify_pre_dispatch(_query(root_extra="$root = sqrt($obs)"))
  # Mentions inside comments, block comments and string/regex literals are not code.
  benign = _query(
      stage_extra='$probe = count_distinct(target.process.command_line)',
      root_extra="// uses sqrt(x) in prose only\n$root = math.sqrt($obs)",
  ).replace(
      'metadata.event_type = "USER_LOGIN"',
      'metadata.event_type = "USER_LOGIN"\n    /* sqrt(x) */\n    re.regex(target.process.command_line, `sqrt\\(`)',
  )
  assert _errors(benign) == []


def test_outcome_variable_limit_is_enforced_per_outcome_block():
  # Named stage: $c plus 19 more = 20 passes, 21 fails.
  ok_stage = "\n".join(f"$v{i} = count(metadata.id)" for i in range(19))
  bad_stage = "\n".join(f"$v{i} = count(metadata.id)" for i in range(20))
  assert _errors(_query(stage_extra=ok_stage)) == []
  stage_errors = [e for e in _errors(_query(stage_extra=bad_stage)) if e.startswith("OUTCOME_VARIABLE_LIMIT_EXCEEDED")]
  assert len(stage_errors) == 1 and "21" in stage_errors[0]
  # Root: $obs plus 19 more = 20 passes, 21 fails.
  ok_root = "\n".join(f"$r{i} = max($s1.c)" for i in range(19))
  bad_root = "\n".join(f"$r{i} = max($s1.c)" for i in range(20))
  assert _errors(_query(root_extra=ok_root)) == []
  root_errors = [e for e in _errors(_query(root_extra=bad_root)) if e.startswith("OUTCOME_VARIABLE_LIMIT_EXCEEDED")]
  assert len(root_errors) == 1 and "21" in root_errors[0]


@pytest.mark.parametrize(
    "line",
    [
        "$bad = if($obs > 0, $obs * 2.0, 0.0)",  # compound then-branch
        "$bad = if($obs > 0, 1.0, $obs - 1.0)",  # compound else-branch
        "$bad = if($obs > 0, ($obs - 1.0) / 2.0, 0.0)",
    ],
)
def test_compound_arithmetic_inside_if_branches_is_rejected(line):
  errors = [e for e in _errors(_query(root_extra=line)) if e.startswith("COMPOUND_ARITHMETIC_IN_IF_BRANCH")]
  assert len(errors) == 1


def test_multiplicative_gate_and_simple_branches_pass():
  q = _query(
      root_extra=(
          "$gated = if($obs > 0, 1.0, 0.0) * ($obs - 1.0) / 2.0\n"
          "$neg = if($obs > 0, $obs, -1.0)\n"
          "$floor = math.sqrt(if($obs > 1.0, $obs, 1.0))"
      )
  )
  assert _errors(q) == []


def test_if_without_else_is_rejected():
  errors = _errors(_query(root_extra="$bad = if($obs > 0, 1.0)"))
  assert any("missing required else-clause" in e for e in errors)


@pytest.mark.parametrize("slot", ["{{entity_id}}", "{{ entity_id }}", "{{target.user}}"])
def test_unrendered_template_slots_are_rejected(slot):
  q = _query().replace('metadata.event_type = "USER_LOGIN"', f'metadata.event_type = "USER_LOGIN"\n    principal.user.userid = "{slot}"')
  errors = [e for e in _errors(q) if e.startswith("UNRESOLVED_TEMPLATE_PLACEHOLDERS")]
  assert len(errors) == 1 and slot in errors[0]


def test_every_retired_model_named_in_the_header_is_rejected_with_the_skill_message():
  retired = harness_truth.retired_models()
  assert retired, "harness reports no retired models"
  for name, message in retired.items():
    errors = [
        e
        for e in _errors(_query(header=f"// Statistical Model: {name}\n"))
        if e.startswith("RETIRED_MODEL_OR_TEMPLATE")
    ]
    assert len(errors) == 1, (name, errors)
    assert message in errors[0]


@pytest.mark.parametrize(
    "template",
    [
        "templates/stage2_math_models/piecewise_cri.yl2",
        "hourly_temporal_zscore.yl2",
        "circadian_von_mises_2stage.yl2",
        "impossible_travel_geo_velocity_2stage.yl2",
    ],
)
def test_retired_template_files_are_rejected(template):
  errors = [
      e
      for e in _errors(_query(header=f"// Template: {template}\n"))
      if e.startswith("RETIRED_MODEL_OR_TEMPLATE")
  ]
  assert len(errors) == 1
  stem = re.sub(r"(?i)\.yl2$", "", template.rsplit("/", 1)[-1])
  expected = harness_truth.retirement_message(stem) or harness_truth.retirement_message(re.sub(r"(?i)_\d+stage$", "", stem))
  assert expected and expected in errors[0]


def test_active_templates_and_models_are_not_flagged_as_retired():
  root = get_skills_root()
  names = sorted(
      p.name
      for skill in (harness_truth.RISK_METRICS_SKILL, harness_truth.STATS_HUNTER_SKILL)
      for p in (root / skill / "templates").rglob("*.yl2")
  )
  assert len(names) > 50
  for name in names:
    assert not [e for e in _errors(_query(header=f"// Template: {name}\n")) if e.startswith("RETIRED")], name
  assert _errors(_query(header="// Statistical Model: STANDARD_Z_SCORE\n// ARCHITECTURE: 2-STAGE STANDARD Z\n")) == []


def test_retired_names_used_as_code_identifiers_do_not_trip_the_gate():
  q = _query(root_extra="$geo_velocity = max($s1.c)\n$directional_z = max($s1.c)")
  assert _errors(q) == []


def test_in_query_cri_ladder_is_rejected_as_retired_piecewise_cri():
  ladder = _query(root_extra="$cri_tier = if($obs >= 4, 95.0, 85.0)\n$cri_score = if($obs >= 1, $cri_tier, 15.0)")
  errors = [e for e in _errors(ladder) if e.startswith("IN_QUERY_CRI_COMPUTATION")]
  assert len(errors) == 2
  assert all(harness_truth.retirement_message("PIECEWISE_CRI") in e for e in errors)
  sigmoid = _query(root_extra="$cri = 100.0 / (1.0 + math.pow(2.718281828, 0.6 * (3.0 - $obs)))")
  assert [e for e in _errors(sigmoid) if e.startswith("IN_QUERY_CRI_COMPUTATION")]
  # Projecting the Python-computed CRI carried on loopback events is not a computation.
  projection = _query(stage_extra="$scenario_cri = max(security_result.risk_score)", root_extra="$peak_scenario_cri = max($s1.scenario_cri)")
  assert _errors(projection) == []


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda q: q.replace("$user = $s1.user", "$user = $s2.user"), "UNDEFINED_STAGE_REFERENCE"),
        (lambda q: q.replace("match:\n  $user\n", "match:\n  $s1.user\n"), "ILLEGAL_MATCH_STAGE_PREFIX"),
        (lambda q: q.replace("  $obs = max($s1.c)\n", "  $obs = max($s1.c)\n  $ratio = $obs / 0\n"), "DIVISION_BY_ZERO_LITERAL"),
        (lambda q: q.replace("  $obs = max($s1.c)\n", "  $obs = max($s1.c)\n  $t = $obs > 1 ? 1 : 0\n"), "ILLEGAL_TERNARY_OPERATOR"),
        (
            lambda q: q.replace(
                "$user = $s1.user\n",
                '$user = $s1.user\n$g.graph.metadata.source_type = "DERIVED_CONTEXT"\n'
                "$g.graph.entity.user.userid = $user\n$g.graph.entity.domain.prevalence.rolling_max <= 3\n",
            ),
            "ECG_PREVALENCE_INVARIANT",
        ),
    ],
)
def test_risk_metrics_submission_checks_are_enforced(mutate, code):
  errors = _errors(mutate(_query()))
  assert any(e.startswith(code) for e in errors), errors


def test_gate_delegates_to_the_skill_validators(monkeypatch):
  builder = QueryIntegrityGate.stats_hunter_query_builder()
  submission = QueryIntegrityGate.risk_metrics_submission_tests()
  assert builder.__file__.endswith("secops-statistical-hunter/scripts/multistage_query_builder.py")
  assert submission.__file__.endswith("secops-risk-metrics-multistage/scripts/submission_tests.py")

  monkeypatch.setattr(
      builder,
      "validate_multistage_syntax",
      lambda q: ["SYNTAX ERROR (INVALID_SQRT_FUNCTION): sentinel-from-stats-hunter"],
  )
  monkeypatch.setattr(submission, "check_stage_references", lambda q: ["UNDEFINED_STAGE_REFERENCE: sentinel-from-risk-metrics"])
  errors = _errors(_query())
  assert any("sentinel-from-stats-hunter" in e and e.startswith("BARE_SQRT_FUNCTION") for e in errors)
  assert "UNDEFINED_STAGE_REFERENCE: sentinel-from-risk-metrics" in errors


def test_gate_loads_the_skill_validators_through_harness_truth_skill_module(monkeypatch):
  real = harness_truth.skill_module
  calls = []

  def _spy(skill, rel_path):
    calls.append((skill, rel_path))
    return real(skill, rel_path)

  monkeypatch.setattr(harness_truth, "skill_module", _spy)
  builder = QueryIntegrityGate.stats_hunter_query_builder()
  submission = QueryIntegrityGate.risk_metrics_submission_tests()
  assert (harness_truth.STATS_HUNTER_SKILL, "scripts/multistage_query_builder.py") in calls
  assert (harness_truth.RISK_METRICS_SKILL, "scripts/submission_tests.py") in calls
  # The gate validates with the same module objects harness_truth hands out (one load per process).
  assert builder is real(harness_truth.STATS_HUNTER_SKILL, "scripts/multistage_query_builder.py")
  assert submission is real(harness_truth.RISK_METRICS_SKILL, "scripts/submission_tests.py")


def test_gate_fails_closed_when_the_harness_validators_cannot_load(monkeypatch):
  def _missing(cls):
    raise FileNotFoundError("Harness source not found: /nowhere/multistage_query_builder.py")

  monkeypatch.setattr(QueryIntegrityGate, "stats_hunter_query_builder", classmethod(_missing))
  res = QueryIntegrityGate.verify_pre_dispatch(_query(), raise_on_error=False)
  assert res["valid"] is False
  assert any(e.startswith("HARNESS_VALIDATORS_UNAVAILABLE") for e in res["errors"])


def test_gate_fails_closed_when_a_skill_validator_crashes(monkeypatch):
  def _crash(query):
    raise RuntimeError("validator bug")

  monkeypatch.setattr(QueryIntegrityGate.risk_metrics_submission_tests(), "check_stage_references", _crash)
  res = QueryIntegrityGate.verify_pre_dispatch(_query(), raise_on_error=False)
  assert res["valid"] is False
  assert any(e.startswith("HARNESS_VALIDATORS_UNAVAILABLE") and "validator bug" in e for e in res["errors"])
  with pytest.raises(QueryValidationError, match="HARNESS_VALIDATORS_UNAVAILABLE"):
    QueryIntegrityGate.verify_pre_dispatch(_query())


def test_errors_aggregate_and_raise_carries_all_of_them():
  q = _query(
      header="// Statistical Model: PIECEWISE_CRI\n",
      root_extra="$root = sqrt($obs)\n$bad = if($obs > 0, 1.0, $obs - 1.0)",
  ).replace('"USER_LOGIN"', '"{{event_type}}"')
  res = QueryIntegrityGate.verify_pre_dispatch(q, raise_on_error=False)
  codes = {e.split(":", 1)[0].split(" ", 1)[0] for e in res["errors"]}
  assert {
      "UNRESOLVED_TEMPLATE_PLACEHOLDERS",
      "BARE_SQRT_FUNCTION",
      "COMPOUND_ARITHMETIC_IN_IF_BRANCH",
      "RETIRED_MODEL_OR_TEMPLATE",
  } <= codes
  with pytest.raises(QueryValidationError) as exc:
    QueryIntegrityGate.verify_pre_dispatch(q)
  assert exc.value.errors == res["errors"]
  assert exc.value.query == q


def test_canonical_skill_queries_pass_the_gate():
  root = get_skills_root()
  radar = sorted((root / harness_truth.RISK_METRICS_SKILL / "templates" / "radar_360").glob("*.yl2"))
  assert len(radar) == 6
  for path in radar:
    q = path.read_text(encoding="utf-8").replace("{{entity_id}}", "alice.smith")
    assert _errors(q) == [], path.name

  builder = QueryIntegrityGate.stats_hunter_query_builder()
  router = builder.MultiStageTemplateRouter()
  built = 0
  for archetype in builder.ModelArchetype:
    if harness_truth.is_retired(archetype.name):
      continue
    for entity_type in ("user", "host"):
      q = router.build_query(archetype=archetype.name, tier="BALANCED", entity_type=entity_type)
      assert _errors(q) == [], (archetype.name, entity_type)
      built += 1
  assert built >= 40

  runner = PlaybookRunner(TenantConfig(project_id="test-proj", customer_id="test-cust"))
  assert _errors(runner.build_udm_run_validation_query("run_pb_20261030T100000Z_abcd1234", playbook_id="pb-1")) == []

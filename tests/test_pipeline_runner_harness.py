# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
"""PipelineRunner reads harness truth from the skills (src/harness_truth.py) and delegates
query validation to the skills' own validators instead of re-implementing them."""

import importlib
from pathlib import Path
import sys

import pytest

from src import harness_truth as ht
from src.config import get_skills_root
from src.pipeline_runner import PipelineRunner
from src.query_integrity_gate import QueryValidationError

SH = ht.STATS_HUNTER_SKILL
RM = ht.RISK_METRICS_SKILL


def _write_template(tmp_path: Path, body: str) -> Path:
  path = tmp_path / "probe_template.yl2"
  path.write_text(body, encoding="utf-8")
  return path


def _submission_tests():
  PipelineRunner()._ensure_skill_path()
  return importlib.import_module("scripts.submission_tests")


def _sh_query_builder():
  return PipelineRunner().get_stats_hunter_builder()


# A small, compiler-clean stats-hunter style query used as the base for negative cases.
_CLEAN_QUERY = """// Goal: probe query for validate_ast delegation.
// Statistical Model: count per host.
stage host_counts {
    metadata.event_type = "PROCESS_LAUNCH"
    principal.hostname = $host
    $host != ""

  match:
    $host by 1h

  outcome:
    $event_count = count(metadata.id)
}

$host = $host_counts.host

match:
  $host

outcome:
  $total = sum($host_counts.event_count)
  $observation_count = max($host_counts.event_count)

condition:
  $total >= 1

order:
  $total desc
"""


# ---------------------------------------------------------------------------
# CRI and gate thresholds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("score", [-2.0, 0.0, 1.5, 3.0, 4.5, 10.0, 15.0, None, "nan", float("inf")])
def test_calculate_cri_is_the_harness_cri(score):
  # Zero floor for Z <= 0, CRI 50 at the 3.0 sigma anchor, None (N/A) on missing data.
  assert PipelineRunner.calculate_cri(score) == ht.calculate_cri(score)


def test_calculate_cri_zero_floor_and_missing_data():
  assert PipelineRunner.calculate_cri(0.0) == 0
  assert PipelineRunner.calculate_cri(-3.0) == 0
  assert PipelineRunner.calculate_cri(3.0) == 50
  assert PipelineRunner.calculate_cri(None) is None


def test_gate_defaults_come_from_harness_constants():
  c = ht.constants()
  assert PipelineRunner.GATE_DEFAULTS == {
      "anomaly_threshold": c.DEFAULT_ANOMALY_THRESHOLD,
      "fold_change_threshold": c.DEFAULT_FOLD_CHANGE_THRESHOLD,
      # agentic_ueba's fusion outlier rule is D >= RADAR_FUSION_DISTANCE_THRESHOLD (3.0), so D^2 >= 9.0.
      "fusion_threshold_sq": c.RADAR_FUSION_DISTANCE_THRESHOLD ** 2,
      "robust_threshold": c.DEFAULT_ROBUST_THRESHOLD,
      "tukey_excess_threshold": c.DEFAULT_TUKEY_EXCESS_THRESHOLD,
      # 7-active-day maturity gate.
      "min_baseline_days": c.DEFAULT_MIN_BASELINE_DAYS,
  }
  # Instance and class access agree, and callers cannot mutate the shared truth.
  runner = PipelineRunner()
  assert runner.GATE_DEFAULTS == PipelineRunner.GATE_DEFAULTS
  runner.GATE_DEFAULTS["anomaly_threshold"] = 99.0
  assert PipelineRunner.GATE_DEFAULTS["anomaly_threshold"] == c.DEFAULT_ANOMALY_THRESHOLD


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_template_raises_on_unrendered_placeholder(tmp_path):
  tpl = _write_template(tmp_path, '// Goal: probe\nstage s1 {\n    metadata.event_type = "{{event_type}}"\n}\n')
  with pytest.raises(QueryValidationError, match="event_type"):
    PipelineRunner().render_template(tpl, {})


def test_render_template_raises_on_spaced_or_none_placeholder(tmp_path):
  tpl = _write_template(tmp_path, '// Goal: {{ goal }}\n$x = "{{value}}"\n')
  with pytest.raises(QueryValidationError, match="goal"):
    PipelineRunner().render_template(tpl, {"value": "ok"})
  # None is not a value: the slot stays unrendered and must raise.
  with pytest.raises(QueryValidationError, match="value"):
    PipelineRunner().render_template(_write_template(tmp_path, '$x = "{{value}}"\n'), {"value": None})


def test_render_template_fills_gates_maturity_and_mode_a_day_from_harness(tmp_path):
  tpl = _write_template(
      tmp_path,
      "// Goal: gates\n"
      "z >= {{anomaly_threshold}} d2 >= {{fusion_threshold_sq}} fold >= {{fold_change_threshold}}\n"
      "mz >= {{robust_threshold}} excess >= {{tukey_excess_threshold}} days >= {{min_baseline_days}}\n"
      'day = "{{today_date}}"\n',
  )
  rendered = PipelineRunner().render_template(tpl, {})
  gates = PipelineRunner.GATE_DEFAULTS
  assert f"z >= {gates['anomaly_threshold']}" in rendered
  assert f"d2 >= {gates['fusion_threshold_sq']}" in rendered
  assert f"fold >= {gates['fold_change_threshold']}" in rendered
  assert f"mz >= {gates['robust_threshold']}" in rendered
  assert f"excess >= {gates['tukey_excess_threshold']}" in rendered
  assert f"days >= {ht.min_baseline_days()}" in rendered
  # Mode A scores the last complete UTC day D, not today.
  assert f'day = "{ht.mode_a_day().isoformat()}"' in rendered
  assert "{{" not in rendered


def test_render_template_caller_values_override_harness_defaults(tmp_path):
  tpl = _write_template(tmp_path, "z >= {{anomaly_threshold}} days >= {{min_baseline_days}}\n")
  rendered = PipelineRunner().render_template(tpl, {"anomaly_threshold": 4.0, "min_baseline_days": 14})
  assert rendered.strip() == "z >= 4.0 days >= 14"


# ---------------------------------------------------------------------------
# Template lookup
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "skill,name",
    [(RM, "circadian_von_mises_2stage.yl2"), (SH, "impossible_travel_geo_velocity_2stage.yl2")],
)
def test_find_template_refuses_retired_templates_with_the_skill_message(skill, name):
  with pytest.raises(ValueError, match="retired") as exc:
    PipelineRunner().find_template(skill, name)
  assert str(exc.value) in {
      ht.retirement_message(name),
      ht.retirement_message(name.replace("_2stage.yl2", "")),
  }


def test_find_template_resolves_radar_360_sector_queries():
  path = PipelineRunner().find_template(RM, "user_1_auth_risk.yl2")
  assert path == get_skills_root() / RM / "templates" / "radar_360" / "user_1_auth_risk.yl2"


def test_find_template_still_raises_file_not_found_for_unknown_templates():
  with pytest.raises(FileNotFoundError):
    PipelineRunner().find_template(SH, "no_such_template_2stage.yl2")


# ---------------------------------------------------------------------------
# validate_ast delegates to the skills' validators
# ---------------------------------------------------------------------------


def test_clean_query_passes_every_validator():
  runner = PipelineRunner()
  assert runner.validate_ast(_CLEAN_QUERY) == []
  assert runner.validate_ast(_CLEAN_QUERY, skill=SH) == []
  assert runner.validate_ast(_CLEAN_QUERY, skill=RM) == []


@pytest.mark.parametrize(
    "mutation,expected",
    [
        # Platform rule: bare sqrt( is invalid (math.sqrt only).
        (("$total = sum($host_counts.event_count)", "$total = sqrt(sum($host_counts.event_count))"), "sqrt"),
        # Platform rule: no compound arithmetic inside if() branches.
        (("$observation_count = max($host_counts.event_count)",
          "$observation_count = if($total > 0, $total * 2, 0)"), "INVALID_IF_CONDITIONAL"),
        # submission_tests.check_stage_references
        (("$observation_count = max($host_counts.event_count)",
          "$observation_count = max($missing_stage.event_count)"), "UNDEFINED_STAGE_REFERENCE"),
        # submission_tests.check_root_match_stage_prefix
        (("match:\n  $host\n", "match:\n  $host_counts.host\n"), "ILLEGAL_MATCH_STAGE_PREFIX"),
        # submission_tests.check_outcome_conditionals_and_divisions
        (("$observation_count = max($host_counts.event_count)",
          "$observation_count = max($host_counts.event_count) / 0"), "DIVISION_BY_ZERO_LITERAL"),
    ],
)
def test_validate_ast_enforces_platform_rules_for_every_query(mutation, expected):
  old, new = mutation
  assert old in _CLEAN_QUERY
  query = _CLEAN_QUERY.replace(old, new, 1)
  errors = PipelineRunner().validate_ast(query)
  assert isinstance(errors, list)
  assert any(expected in e for e in errors), errors


def test_validate_ast_enforces_ecg_prevalence_invariants():
  query = _CLEAN_QUERY.replace(
      '    $host != ""\n',
      '    $host != ""\n    $g.graph.metadata.source_type = "DERIVED_CONTEXT"\n'
      '    $g.graph.entity.domain.prevalence.day_count = 3\n',
      1,
  )
  errors = PipelineRunner().validate_ast(query)
  assert any("ECG_PREVALENCE_INVARIANT" in e for e in errors), errors


def test_validate_ast_rejects_compound_arithmetic_in_either_if_branch():
  """Platform rule: no compound arithmetic inside if() branches, else branch included.

  Compile-checked live in Chronicle SIEM (2026-10-30): `$x = if($obs > 1, $obs, $obs * 2)` is rejected with
  "invalid argument", while precomputing the branch (`$double = $obs * 2`, `if($obs > 1, $obs, $double)`)
  compiles. The skill primitives submission_tests.iter_if_calls / if_branch_has_compound_arithmetic decide.
  """
  anchor = "  $observation_count = max($host_counts.event_count)"
  else_branch = _CLEAN_QUERY.replace(anchor, anchor + "\n  $x = if($total > 1, $total, $total * 2)", 1)
  for skill in (None, SH, RM):
    errors = PipelineRunner().validate_ast(else_branch, skill=skill)
    assert any("compound arithmetic in 'else' clause" in e for e in errors), (skill, errors)
  precomputed = _CLEAN_QUERY.replace(
      anchor, anchor + "\n  $double_total = $total * 2\n  $x = if($total > 1, $total, $double_total)", 1)
  assert PipelineRunner().validate_ast(precomputed) == []
  assert PipelineRunner().validate_ast(precomputed, skill=SH) == []


def test_validate_ast_stats_hunter_queries_get_the_stats_hunter_validator():
  outcome_lines = "\n".join(f"  $v{i} = max($host_counts.event_count)" for i in range(21))
  query = _CLEAN_QUERY.replace(
      "  $observation_count = max($host_counts.event_count)", outcome_lines, 1)
  # 22 root outcome variables: the stats-hunter validator enforces <= 20 per outcome block, root included.
  errors = PipelineRunner().validate_ast(query, skill=SH)
  assert any("OUTCOME LIMIT EXCEEDED" in e for e in errors), errors


def test_validate_ast_stats_hunter_scope_exclusions():
  query = _CLEAN_QUERY.replace(
      "  $observation_count = max($host_counts.event_count)",
      "  $observation_count = max(metrics.auth_attempts_total(period: 1d, window: 30d, metric: event_count_sum, "
      "agg: avg, principal.hostname: principal.hostname))",
      1,
  )
  errors = PipelineRunner().validate_ast(query, skill=SH)
  assert any("metrics." in e and "VIOLATION" in e for e in errors), errors


def test_validate_ast_returns_the_skill_validators_own_findings():
  """Delegation, not re-implementation: every finding of the skills' validators is reported verbatim."""
  st = _submission_tests()
  mqb = _sh_query_builder()
  query = (
      _CLEAN_QUERY.replace("$total = sum($host_counts.event_count)", "$total = sqrt(sum($nostage.event_count)) / 0")
      .replace("match:\n  $host\n", "match:\n  $host_counts.host\n")
  )
  generic = PipelineRunner().validate_ast(query)
  for check in (st.check_stage_references, st.check_root_match_stage_prefix,
                st.check_outcome_conditionals_and_divisions, st.check_ecg_invariants):
    for finding in check(query):
      assert finding in generic
  stats = PipelineRunner().validate_ast(query, skill=SH)
  for finding in mqb.validate_multistage_syntax(query) + mqb.check_scope_exclusions(query):
    assert finding in stats
  assert set(generic) <= set(stats)


def test_validate_ast_rejects_unknown_skill():
  with pytest.raises(ValueError):
    PipelineRunner().validate_ast(_CLEAN_QUERY, skill="secops-unknown-skill")


def test_validate_ast_fails_closed_when_a_validator_cannot_load(monkeypatch):
  runner = PipelineRunner()

  def _boom(*_args, **_kwargs):
    raise ImportError("validator unavailable")

  monkeypatch.setattr(runner, "get_stats_hunter_builder", _boom)
  errors = runner.validate_ast(_CLEAN_QUERY, skill=SH)
  assert errors and any("AST_VALIDATOR_UNAVAILABLE" in e for e in errors)


def test_stats_hunter_scripts_load_by_path_without_scripts_package_collision():
  runner = PipelineRunner()
  builder = runner.get_stats_hunter_builder()
  helpers = runner.get_micro_python_helpers()
  sh_scripts = (get_skills_root() / SH / "scripts").resolve()
  assert Path(builder.__file__).resolve() == sh_scripts / "multistage_query_builder.py"
  assert Path(helpers.__file__).resolve() == sh_scripts / "micro_python_helpers.py"
  # Loaded under private names: the risk-metrics `scripts` package is never shadowed.
  assert not builder.__name__.startswith("scripts")
  assert not helpers.__name__.startswith("scripts")
  runner.validate_ast(_CLEAN_QUERY, skill=SH)
  pv = importlib.import_module("scripts.preflight_validator")
  rm_scripts = (get_skills_root() / RM / "scripts").resolve()
  assert Path(pv.__file__).resolve().parent == rm_scripts
  assert Path(sys.modules["scripts"].__file__).resolve().parent == rm_scripts
  # The same builder object harness_truth uses (one load per process).
  assert runner.get_stats_hunter_builder() is builder

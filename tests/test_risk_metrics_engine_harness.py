# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""RiskMetricsEngine applies the remediated UEBA harness (secops-risk-metrics-multistage v2.3.0).

Every query the engine renders or builds must satisfy the platform rules and the skills' validators;
retired models are refused with the skill's own message; windows, gates, CRI, verdicts and score
semantics come from src.harness_truth at runtime.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import importlib.util
import math
import re
import sys

import pytest

from src import harness_truth
from src.config import get_skills_root
from src.query_integrity_gate import QueryIntegrityGate
from src.risk_metrics_engine import RiskMetricsEngine

NOW = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone.utc)
D = harness_truth.mode_a_day(NOW)
INLINE_MARKER = "Query source: agentic_ueba RiskMetricsEngine"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Capture:
  """Replaces execute_query_via_mcp; records (query, startTime, endTime) and returns fixed rows."""

  def __init__(self, eng, rows=None):
    self.calls = []
    self.rows = rows

    async def _fake(session, query, start_iso, end_iso, *args, **kwargs):
      self.calls.append((query, start_iso, end_iso))
      return {"stats": list(self.rows) if self.rows is not None else []}

    eng.runner.execute_query_via_mcp = _fake


def _run(coro):
  return asyncio.run(coro)


def _code(query):
  no_block = re.sub(r"/\*.*?\*/", "", query, flags=re.S)
  return "\n".join(re.sub(r"//[^\n]*", "", ln) for ln in no_block.splitlines())


def _outcome_counts(query):
  """Outcome variable count for every outcome: block (named stages and root)."""
  counts = []
  lines = _code(query).splitlines()
  i = 0
  while i < len(lines):
    if re.match(r"^\s*outcome:\s*$", lines[i]):
      n = 0
      i += 1
      while i < len(lines) and not re.match(r"^\s*(condition|order|limit|match|outcome):", lines[i]) \
          and not lines[i].strip().startswith("}") and not re.match(r"^\s*stage\s+\w+", lines[i]):
        if re.match(r"^\s*\$\w+\s*=", lines[i]):
          n += 1
        i += 1
      counts.append(n)
    else:
      i += 1
  return counts


def _root_condition(query):
  m = re.search(r"^condition:[ \t]*\n(.*?)\n[ \t]*\n[ \t]*order:", query, re.M | re.S)
  return " ".join(m.group(1).split()) if m else None


def _rm_submission_tests():
  RiskMetricsEngine().runner._ensure_skill_path()
  from scripts import submission_tests
  return submission_tests


def _sh_validator():
  name = "_pkg_b_sh_multistage_query_builder"
  if name in sys.modules:
    return sys.modules[name]
  path = get_skills_root() / "secops-statistical-hunter" / "scripts" / "multistage_query_builder.py"
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  sys.modules[name] = module
  spec.loader.exec_module(module)
  return module


def _all_engine_queries():
  """Every query the engine dispatches, across all entry points, with representative arguments."""
  eng = RiskMetricsEngine()
  cap = _Capture(eng)
  out = []

  def take(label):
    for q, _, _ in cap.calls:
      out.append((label, q))
    cap.calls.clear()

  _run(eng.resolve_user_identifier(None, "alice.smith@example.com"))
  take("identity_probe")
  for et, ent in (("USER", "user.a"), ("ASSET", "host-a")):
    _run(eng.run_360_behavioral_radar(None, ent, entity_type=et, lookback_days=1, now_utc=NOW))
    take(f"radar_{et}")
    for name, q in eng.build_fleet_360_sector_queries(entity_type=et).items():
      out.append((f"fleet_{et}_{name}", q))
  _run(eng.run_cloud_crud_surge(None, "user.a", now_utc=NOW))
  take("cloud_crud")
  _run(eng.run_workspace_triad(None, "user.a", now_utc=NOW))
  take("triad")
  _run(eng.run_alert_surge(None, "host-a", entity_type="ASSET", now_utc=NOW))
  _run(eng.run_alert_surge(None, "user.a", entity_type="USER", now_utc=NOW))
  take("alert_surge")
  for fm in ("auth_attempts_fail", "http_queries_fail", "dns_queries_fail"):
    _run(eng.run_failure_ratio_surge(None, "user.a", fail_metric=fm, now_utc=NOW))
  take("failure_ratio")
  for mode in ("fail", "success", "total"):
    _run(eng.run_cloud_repository_scope(None, "sa@proj.iam.gserviceaccount.com", outcome_mode=mode, now_utc=NOW))
  take("cloud_repository_scope")
  KillChainArchetype, _ = eng.runner.get_killchain_archetypes()
  for arch in KillChainArchetype:
    _run(eng.run_killchain_archetype(None, "user.a", archetype=arch.value, now_utc=NOW))
    take(f"killchain_{arch.value}")
  for pair, four in ((["workspace_total_download_actions", "network_bytes_outbound"], False),
                     (["resource_creation_total", "auth_attempts_fail"], False),
                     (["auth_attempts_fail", "network_bytes_outbound"], True)):
    _run(eng.run_sector_fusion(None, "user.a", fusion_metrics=pair, four_stage=four, now_utc=NOW))
    take(f"fusion_{'_'.join(pair)}")
  _run(eng.run_hybrid_enrichment(None, "user.a", now_utc=NOW))
  take("hybrid_enrichment")
  _run(eng.run_data_table_bridge(None, now_utc=NOW))
  _run(eng.run_data_table_bridge(None, data_table_name="my_cohort", column_name="hostname", now_utc=NOW))
  take("data_table_bridge")
  _run(eng.run_macd_momentum_velocity(None, "user.a", now_utc=NOW))
  _run(eng.run_macd_momentum_velocity(None, "host-a", metric_name="auth_attempts_total",
                                      dimension_key="principal.asset.hostname", now_utc=NOW))
  take("above_historical_max_z")
  _run(eng.run_quantile_iqr_skew(None, "host-a", now_utc=NOW))
  take("quantile_iqr_skew")
  models = (
      ("STANDARD_Z_SCORE", "network_bytes_outbound", "ASSET"),
      ("MAD", "network_bytes_outbound", "ASSET"),
      ("MAD", "auth_attempts_total", "USER"),
      ("QUANTILE_IQR_SKEW", "auth_attempts_total", "USER"),
      ("RELATIVE_DEVIATION", "http_queries_total", "ASSET"),
      ("VARIANCE", "auth_attempts_total", "USER"),
      ("POISSON", "auth_attempts_total", "USER"),
      ("COEFFICIENT_OF_VARIATION", "auth_attempts_total", "USER"),
      ("BAYESIAN_GAMMA", "auth_attempts_total", "USER"),
      ("BAYESIAN_BETA_BINOMIAL", "auth_attempts_fail", "USER"),
      ("LONGITUDINAL_CUSUM_DRIFT", "dns_queries_fail", "USER"),
      ("TWO_PART_HURDLE", "workspace_total_download_actions", "USER"),
      ("ADAPTIVE_CONTEXT_THRESHOLD", "auth_attempts_total", "USER"),
      ("ABOVE_HISTORICAL_MAX_Z", "network_bytes_outbound", "ASSET"),
      ("MACD_MOMENTUM_VELOCITY", "network_bytes_outbound", "ASSET"),
      ("ASYMMETRIC_DIRECTIONAL_Z", "auth_attempts_total", "USER"),
      ("FIRST_SEEN_NOVELTY", "auth_attempts_total", "USER"),
      ("DIVERSITY_DEFICIT", "network_bytes_outbound", "ASSET"),
      ("PART_OF_THE_WHOLE_MULTILEVEL", "http_queries_total", "ASSET"),
      ("DUAL_BASELINE_3STAGE", "auth_attempts_total", "USER"),
      ("EMPIRICAL_BAYES_3STAGE", "auth_attempts_total", "USER"),
      ("CLOUD_REPOSITORY_SCOPE", "resource_read_total", "USER"),
      ("HTTP_ERROR_RATIO_SURGE_2STAGE", "http_queries_fail", "ASSET"),
      ("HTTP_TARGET_SURGE_2STAGE", "http_queries_total", "ASSET"),
      ("HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE", "http_queries_total", "ASSET"),
      ("HYBRID_METRIC_RAW_ENRICHMENT_2STAGE", "network_bytes_outbound", "ASSET"),
      ("HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE", "network_bytes_outbound", "ASSET"),
      ("HYBRID_METRIC_FLEET_PREVALENCE_2STAGE", "file_executions_total", "ASSET"),
      ("HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE", "file_executions_total", "ASSET"),
      ("HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE", "http_queries_total", "ASSET"),
      ("HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE", "http_queries_total", "ASSET"),
      ("HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE", "auth_attempts_total", "ASSET"),
      ("RARE_DESTINATION_ECG_3STAGE", "dns_queries_total", "ASSET"),
      ("RARE_DESTINATION_ECG_3STAGE", "http_queries_total", "ASSET"),
      ("RARE_DESTINATION_ECG_3STAGE", "network_bytes_outbound", "ASSET"),
      ("FUSION_RARE_DESTINATION_3STAGE", "dns_queries_total", "ASSET"),
      ("HYBRID_DATA_TABLE_BRIDGE_2STAGE", "network_bytes_outbound", "ASSET"),
  )
  for model, metric, et in models:
    _run(eng.run_dynamic_metric_pipeline(None, "ent-a", entity_type=et, target_metric=metric,
                                         model_name=model, lookback_days=1, now_utc=NOW))
    take(f"dynamic_{model}_{metric}")
  return eng, out


# ---------------------------------------------------------------------------
# Query rules and validators
# ---------------------------------------------------------------------------


def test_every_engine_query_satisfies_platform_rules_and_skill_validators():
  st = _rm_submission_tests()
  sh = _sh_validator()
  eng, queries = _all_engine_queries()
  assert len(queries) >= 90
  problems = []
  for label, q in queries:
    code = _code(q)
    if re.search(r"\{\{\w+\}\}", code):
      problems.append((label, "unrendered placeholder"))
    for idx, n in enumerate(_outcome_counts(q)):
      if n > 20:
        problems.append((label, f"outcome block {idx} has {n} variables"))
    if re.search(r"(?<!math\.)\bsqrt\s*\(", code):
      problems.append((label, "bare sqrt("))
    for call, args in st.iter_if_calls(q):
      if len(args) < 3 or any(st.if_branch_has_compound_arithmetic(b) for b in args[1:3]):
        problems.append((label, f"compound arithmetic in if() branch: {call}"))
    # In-query CRI: a CRI outcome column or the logistic 100 / (1 + e^...) ladder (PIECEWISE_CRI is retired).
    # math.pow(2.718..., ...) alone is legitimate: the skew-adjusted Tukey fence uses e^(1.35 * B).
    if re.search(r"^\s*\$(?:cri|cri_score|calibrated_risk_index)\s*=", code, re.M) or re.search(
        r"\b100(?:\.0)?\s*/\s*\(\s*1(?:\.0)?\s*\+\s*math\.pow\(", code):
      problems.append((label, "in-query CRI"))
    for fn in (st.check_stage_references, st.check_root_match_stage_prefix,
               st.check_outcome_conditionals_and_divisions, st.check_ecg_invariants):
      problems.extend((label, f"{fn.__name__}: {e}") for e in fn(q))
    gate = QueryIntegrityGate.verify_pre_dispatch(q, ast_validator_fn=eng.runner.validate_ast, raise_on_error=False)
    problems.extend((label, f"integrity gate: {e}") for e in gate["errors"])
    if INLINE_MARKER in q:
      problems.extend(
          (label, f"validate_multistage_syntax: {e}")
          for e in sh.validate_multistage_syntax(q)
          if not e.startswith("MISSING METHODOLOGY HEADER")
      )
  assert problems == []


def test_inline_queries_are_only_the_ones_without_a_skill_template():
  """User radar, cloud CRUD, triad, fusion, ... come from the skill; only catalog-driven sectors are built here."""
  _, queries = _all_engine_queries()
  inline = sorted({label for label, q in queries if INLINE_MARKER in q})
  assert inline == sorted({
      "identity_probe", "radar_ASSET",
      "fleet_USER_Auth", "fleet_USER_Cloud", "fleet_USER_Workspace", "fleet_USER_Egress", "fleet_USER_DNS",
      "fleet_ASSET_Auth", "fleet_ASSET_Egress", "fleet_ASSET_DNS", "fleet_ASSET_Flows", "fleet_ASSET_Web",
  })


def test_user_radar_runs_the_canonical_radar_360_templates_verbatim():
  eng = RiskMetricsEngine()
  cap = _Capture(eng)
  _run(eng.run_360_behavioral_radar(None, "user.a", entity_type="USER", lookback_days=1, now_utc=NOW))
  tpl_dir = get_skills_root() / RiskMetricsEngine.SKILL_NAME / "templates" / "radar_360"
  expected = sorted(p.read_text(encoding="utf-8").replace("{{entity_id}}", "user.a") for p in tpl_dir.glob("user_*.yl2"))
  assert len(expected) == 6
  assert sorted(q for q, _, _ in cap.calls) == expected


def test_asset_radar_alert_spoke_is_the_canonical_alert_template_scoped_to_the_host():
  eng = RiskMetricsEngine()
  cap = _Capture(eng)
  _run(eng.run_360_behavioral_radar(None, "host-a", entity_type="ASSET", lookback_days=1, now_utc=NOW))
  alert_q = [q for q, _, _ in cap.calls if "metrics.alert_event_name_count" in q]
  assert len(alert_q) == 1
  assert "stage alerts_risk" in alert_q[0] and '$host = "host-a"' in alert_q[0]
  assert len(cap.calls) == 6


def test_asset_radar_inline_sectors_are_maturity_gated_with_skill_dispersion_floors():
  eng = RiskMetricsEngine()
  cap = _Capture(eng)
  _run(eng.run_360_behavioral_radar(None, "host-a", entity_type="ASSET", lookback_days=1, now_utc=NOW))
  min_days = harness_truth.min_baseline_days()
  eng.runner._ensure_skill_path()
  from scripts.template_router import resolve_byte_dispersion_floor
  byte_floor = resolve_byte_dispersion_floor("network_bytes_outbound")
  inline = [q for q, _, _ in cap.calls if INLINE_MARKER in q]
  assert len(inline) == 5
  for q in inline:
    assert f"$z = if($active_days >= {min_days}, $raw_z, 0.0)" in q
    assert "agg: num_metric_periods" in q
    assert 'principal.asset.hostname = "host-a"' in q
    if "metrics.network_bytes_outbound" in q:
      assert f"$safe_std = if($dispersion > {byte_floor}, $dispersion, {byte_floor})" in q
    else:
      assert "$floor = math.sqrt(if($baseline > 1.0, $baseline, 1.0))" in q


def test_fleet_cloud_sector_uses_count_floors_and_maturity_gates():
  """v2.3.0 (D8 / WS1-04) replaced zero-SD fallbacks on count metrics with max(sd, sqrt(max(avg, 1)))."""
  q = RiskMetricsEngine().build_fleet_360_sector_queries(entity_type="USER")["Cloud"]
  min_days = harness_truth.min_baseline_days()
  assert "1000000.0" not in q
  for fam, z in (("r", "zr_u"), ("w", "zw_u"), ("c", "zc_u"), ("d", "zd_u")):
    assert f"${fam}_flr = math.sqrt(if(${fam}_avg > 1.0, ${fam}_avg, 1.0))" in q
    assert f"${fam}_sd = if(${fam}_std > ${fam}_flr, ${fam}_std, ${fam}_flr)" in q
    assert f"if(${fam}_days >= {min_days}, ${z}, 0.0)" in q
  assert 'not re.regex(principal.user.userid, "\\\\$$")' in q
  for fam in ("resource_read_total", "resource_written_total", "resource_deletion_total", "resource_creation_total"):
    assert f"metrics.{fam}(" in q


def test_identity_probe_uses_namespaced_coalesce_and_case_insensitive_spot_check():
  eng = RiskMetricsEngine()
  cap = _Capture(eng, rows=[{"uid": "alice", "cnt": 3}])
  assert _run(eng.resolve_user_identifier(None, "alice@example.com", lookback_days=14)) == "alice"
  q = cap.calls[0][0]
  assert "strings.coalesce(principal.user.userid, target.user.userid)" in q
  assert 'principal.user.email_addresses = "alice@example.com" nocase' in q


# ---------------------------------------------------------------------------
# Retired models and templates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "CIRCADIAN_VON_MISES", "CIRCADIAN_VON_MISES_2STAGE", "HOURLY_TEMPORAL_ZSCORE", "PIECEWISE_CRI",
    "FLEET_PREVALENCE_SHIELD", "HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE",
])
def test_dynamic_pipeline_refuses_retired_models_with_the_skill_message(name):
  eng = RiskMetricsEngine()
  cap = _Capture(eng)
  with pytest.raises(ValueError) as exc:
    _run(eng.run_dynamic_metric_pipeline(None, "alice", target_metric="auth_attempts_total", model_name=name))
  assert str(exc.value) == harness_truth.retirement_message(name)
  assert cap.calls == []


def test_circadian_entry_point_refuses_and_points_to_hour_of_day_profile():
  eng = RiskMetricsEngine()
  cap = _Capture(eng)
  with pytest.raises(ValueError) as exc:
    _run(eng.run_circadian_von_mises(None, "alice"))
  assert str(exc.value) == harness_truth.retirement_message("circadian_von_mises_2stage.yl2")
  assert "HOUR_OF_DAY_PROFILE" in str(exc.value)
  assert cap.calls == []


def test_unknown_model_is_refused_instead_of_silently_running_cusum():
  eng = RiskMetricsEngine()
  cap = _Capture(eng)
  with pytest.raises(ValueError, match="Unknown statistical model"):
    _run(eng.run_dynamic_metric_pipeline(None, "alice", model_name="NOT_A_REAL_MODEL"))
  assert cap.calls == []


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------


def _window(eng, coro):
  cap = _Capture(eng)
  res = _run(coro)
  return cap.calls, res


def test_mode_a_scores_the_last_complete_utc_day():
  eng = RiskMetricsEngine()
  calls, res = _window(eng, eng.run_dynamic_metric_pipeline(
      None, "alice", target_metric="auth_attempts_total", model_name="STANDARD_Z_SCORE", lookback_days=1, now_utc=NOW))
  assert (calls[0][1], calls[0][2]) == harness_truth.mode_a_window(D)
  assert res["evaluation_window"]["mode"] == "A"
  assert res["evaluation_window"]["scored_day"] == D.isoformat()

  for et, ent in (("USER", "user.a"), ("ASSET", "host-a")):
    calls, res = _window(eng, eng.run_360_behavioral_radar(None, ent, entity_type=et, lookback_days=1, now_utc=NOW))
    assert {(s, e) for _, s, e in calls} == {harness_truth.mode_a_window(D)}
    assert res["evaluated_day"] == D.isoformat()

  calls, res = _window(eng, eng.run_fleet_360_sweep(None, entity_type="USER", inter_query_delay_sec=0.0,
                                                    ingest_events=False, now_utc=NOW))
  assert {(s, e) for _, s, e in calls} == {harness_truth.mode_a_window(D)}
  assert res["window"]["bucket_date"] == D.isoformat()


def test_today_so_far_is_an_explicit_labelled_partial_day_option():
  eng = RiskMetricsEngine()
  calls, res = _window(eng, eng.run_360_behavioral_radar(
      None, "user.a", entity_type="USER", lookback_days=1, today_so_far=True, now_utc=NOW))
  start, end, _ = RiskMetricsEngine._mode_a_today_window(NOW)
  assert {(s, e) for _, s, e in calls} == {(start, end)}
  assert res["evaluation_window"]["is_partial_day"] is True


def test_entity_graph_windows_start_at_d_minus_2_and_pin_event_stages_to_d():
  eng = RiskMetricsEngine()
  pin = harness_truth.event_day_pin(D)
  for model, metric in (("HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE", "http_queries_total"),
                        ("RARE_DESTINATION_ECG_3STAGE", "dns_queries_total"),
                        ("FUSION_RARE_DESTINATION_3STAGE", "network_bytes_outbound")):
    calls, res = _window(eng, eng.run_dynamic_metric_pipeline(
        None, "host-a", entity_type="ASSET", target_metric=metric, model_name=model, lookback_days=14, now_utc=NOW))
    q, start, end = calls[0]
    assert (start, end) == harness_truth.ecg_window(D), model
    assert pin in q, model
    assert set(re.findall(r'timestamp\.get_date\(metadata\.event_timestamp\.seconds\)\s*=\s*"([\d-]+)"', q)) == {D.isoformat()}
  KillChainArchetype, catalog = eng.runner.get_killchain_archetypes()
  rare = [a for a in KillChainArchetype if catalog.get(a, {}).get("rare_destination")]
  assert rare
  calls, _ = _window(eng, eng.run_killchain_archetype(None, "host-a", archetype=rare[0].value,
                                                      entity_type="ASSET", now_utc=NOW))
  assert (calls[0][1], calls[0][2]) == harness_truth.ecg_window(D)
  assert pin in calls[0][0]


def test_mode_b_windows_are_capped_by_the_skill():
  eng = RiskMetricsEngine()
  caps = harness_truth.mode_caps()
  today = D + timedelta(days=1)
  calls, res = _window(eng, eng.run_dynamic_metric_pipeline(
      None, "alice", target_metric="auth_attempts_total", model_name="STANDARD_Z_SCORE", lookback_days=14, now_utc=NOW))
  n = caps["mode_b_macro_days"]
  assert calls[0][1] == f"{(today - timedelta(days=n - 1)).isoformat()}T00:00:00Z"
  assert calls[0][2] == NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
  assert res["evaluation_window"]["mode"] == "B"
  assert res["evaluation_window"]["scored_days"] == n
  assert res["evaluation_window"]["capped_from_days"] == 14

  calls, res = _window(eng, eng.run_dynamic_metric_pipeline(
      None, "alice", target_metric="dns_queries_fail", model_name="LONGITUDINAL_CUSUM_DRIFT", lookback_days=30,
      now_utc=NOW))
  n = caps["mode_b_cusum_macro_days"]
  assert calls[0][1] == f"{(today - timedelta(days=n - 1)).isoformat()}T00:00:00Z"
  assert res["evaluation_window"]["scored_days"] == n


def test_robust_models_read_30_raw_days_and_score_only_the_mode_a_day():
  eng = RiskMetricsEngine()
  for model in ("MAD", "QUANTILE_IQR_SKEW"):
    calls, _ = _window(eng, eng.run_dynamic_metric_pipeline(
        None, "host-a", entity_type="ASSET", target_metric="network_bytes_outbound", model_name=model,
        lookback_days=1, now_utc=NOW))
    q, start, end = calls[0]
    assert start == f"{(D - timedelta(days=29)).isoformat()}T00:00:00Z", model
    assert end == harness_truth.mode_a_window(D)[1], model
    assert f'>= "{D.isoformat()}"' in q, model


# ---------------------------------------------------------------------------
# Gates, CRI, verdicts, severity
# ---------------------------------------------------------------------------


def test_engine_gates_come_from_the_harness_sensitivity_thresholds():
  eng = RiskMetricsEngine()
  c = harness_truth.constants()
  _, expected = c.resolve_sensitivity_thresholds(None)
  gates = eng.gate_thresholds()
  for key, value in expected.items():
    assert gates[key] == value
  assert gates["tukey_excess_threshold"] == c.DEFAULT_TUKEY_EXCESS_THRESHOLD

  calls, _ = _window(eng, eng.run_sector_fusion(None, "user.a", fusion_metrics=["auth_attempts_fail", "network_bytes_outbound"],
                                                now_utc=NOW))
  assert _root_condition(calls[0][0]) == f"$composite_threat_norm_sq >= {gates['fusion_threshold_sq']}"
  calls, _ = _window(eng, eng.run_dynamic_metric_pipeline(
      None, "host-a", entity_type="ASSET", target_metric="network_bytes_outbound", model_name="STANDARD_Z_SCORE",
      now_utc=NOW))
  assert _root_condition(calls[0][0]) == (
      f"$active_days >= {harness_truth.min_baseline_days()} and $personal_z >= {gates['anomaly_threshold']}")


@pytest.mark.parametrize("cri", [None, "N/A", 0, 12, 25, 26, 45, 46, 69, 70, 89, 90, 100])
def test_derive_cri_severity_uses_the_harness_cri_bands(cri):
  code = harness_truth.cri_band(cri)[0]
  assert RiskMetricsEngine.derive_cri_severity(cri) == ("UNKNOWN_SEVERITY" if code == "N/A" else code)


def test_cri_is_never_computed_with_the_legacy_runner_sigmoid():
  eng = RiskMetricsEngine()

  def _legacy(*args, **kwargs):
    raise AssertionError("PipelineRunner.calculate_cri (legacy sigmoid) must not be used")

  eng.runner.calculate_cri = _legacy
  _Capture(eng, rows=[{"z": 2.5, "observed": 9, "baseline": 2.0, "dispersion": 1.0, "active_days": 20,
                       "personal_z": 4.0, "composite_threat_norm_sq": 16.0, "alert_z": 3.2, "fail_z": 3.3,
                       "composite_risk": 3.4, "d_vs_fleet_sq": 13.0, "macro_z_score": 3.1, "macd_z": 3.6}])
  results = [
      _run(eng.run_360_behavioral_radar(None, "user.a", lookback_days=1, now_utc=NOW)),
      _run(eng.run_sector_fusion(None, "user.a", now_utc=NOW)),
      _run(eng.run_dynamic_metric_pipeline(None, "user.a", target_metric="auth_attempts_total",
                                           model_name="STANDARD_Z_SCORE", now_utc=NOW)),
      _run(eng.run_alert_surge(None, "host-a", now_utc=NOW)),
      _run(eng.run_failure_ratio_surge(None, "user.a", now_utc=NOW)),
      _run(eng.run_cloud_repository_scope(None, "sa@proj.iam.gserviceaccount.com", now_utc=NOW)),
      _run(eng.run_workspace_triad(None, "user.a", now_utc=NOW)),
      _run(eng.run_hybrid_enrichment(None, "user.a", now_utc=NOW)),
      _run(eng.run_macd_momentum_velocity(None, "user.a", now_utc=NOW)),
      _run(eng.run_cloud_crud_surge(None, "user.a", now_utc=NOW)),
      _run(eng.run_killchain_archetype(None, "user.a", now_utc=NOW)),
      _run(eng.run_data_table_bridge(None, now_utc=NOW)),
  ]
  for res in results:
    cri = res["calibrated_risk_index"]
    assert isinstance(cri, int)
    assert res["verdict"] == harness_truth.verdict_for(cri)
    assert res["is_outlier"] == (harness_truth.recommended_action(cri) != "MONITOR")


def test_zero_telemetry_is_a_nominal_clean_hunt():
  eng = RiskMetricsEngine()
  _Capture(eng, rows=[])
  for res in (
      _run(eng.run_dynamic_metric_pipeline(None, "alice", target_metric="auth_attempts_total",
                                           model_name="STANDARD_Z_SCORE", now_utc=NOW)),
      _run(eng.run_360_behavioral_radar(None, "alice", lookback_days=1, now_utc=NOW)),
      _run(eng.run_sector_fusion(None, "alice", now_utc=NOW)),
  ):
    assert res["calibrated_risk_index"] == 0
    assert res["verdict"] == harness_truth.verdict_for(0) == "NOMINAL_BASELINE"
    assert res["is_outlier"] is False


def test_radar_cri_and_verdict_use_the_rectified_composite_distance():
  eng = RiskMetricsEngine()

  async def fake(session, query, start_iso, end_iso, *a, **k):
    if "metrics.auth_attempts_total" in query:
      return {"stats": [{"z": 3.0, "observed": 20, "baseline": 4.0, "dispersion": 2.0, "active_days": 30}]}
    if "metrics.network_bytes_outbound" in query:
      return {"stats": [{"z": 4.0, "observed": 9e6, "baseline": 1e6, "dispersion": 2e6, "active_days": 30}]}
    if "metrics.dns_queries_total" in query:
      return {"stats": [{"z": -6.0, "observed": 1, "baseline": 400.0, "dispersion": 60.0, "active_days": 30}]}
    return {"stats": []}

  eng.runner.execute_query_via_mcp = fake
  res = _run(eng.run_360_behavioral_radar(None, "user.a", entity_type="USER", lookback_days=1, now_utc=NOW))
  assert res["composite_d"] == 5.0
  assert res["calibrated_risk_index"] == harness_truth.calculate_cri(5.0)
  assert res["verdict"] == harness_truth.verdict_for(res["calibrated_risk_index"])
  assert res["sector_cri_scores"]["DNS"] == 0
  assert "DNS" not in res["outlier_sectors"]
  assert set(res["outlier_sectors"]) == {"Auth", "Egress"}
  assert res["sector_metrics"]["Auth"] == "auth_attempts_total"
  assert res["sector_metrics"]["DNS"] == "dns_queries_total"


# ---------------------------------------------------------------------------
# Python-side scoring: Z-equivalent semantics, maturity gate, dispersion floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("model, metric, entity_type, row, key", [
    ("STANDARD_Z_SCORE", "auth_attempts_total", "USER", {"personal_z": 4.5, "active_days": 20}, "personal_z"),
    ("RELATIVE_DEVIATION", "http_queries_total", "ASSET", {"fold_change": 2.0, "personal_z": 9.0}, "fold_change"),
    ("MAD", "network_bytes_outbound", "ASSET", {"modified_z": 3.5, "personal_z": 1.0, "raw_active_days": 20}, "modified_z"),
    ("QUANTILE_IQR_SKEW", "network_bytes_outbound", "ASSET",
     {"tukey_excess_z": 1.0, "personal_z": 9.0, "raw_active_days": 20}, "tukey_excess_z"),
    ("COEFFICIENT_OF_VARIATION", "auth_attempts_total", "USER", {"surge_ratio": 2.5, "cv": 0.3, "active_days": 20},
     "surge_ratio"),
    ("LONGITUDINAL_CUSUM_DRIFT", "dns_queries_fail", "USER",
     {"cusum_drift_score": 3.7, "max_daily_z": 2.2, "drift_days": 3, "active_days": 20}, "cusum_drift_score"),
    ("HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE", "file_executions_total", "ASSET",
     {"z_score": 3.3, "threat_score": 9.9, "active_baseline_days": 20}, "z_score"),
])
def test_model_scores_map_through_harness_z_equivalent_semantics(model, metric, entity_type, row, key):
  eng = RiskMetricsEngine()
  _Capture(eng, rows=[row])
  res = _run(eng.run_dynamic_metric_pipeline(None, "ent-a", entity_type=entity_type, target_metric=metric,
                                             model_name=model, now_utc=NOW))
  c = harness_truth.constants()
  z_eq = c.score_to_z_equivalent(key, row[key])
  assert res["score_key"] == key
  assert res["top_z_score"] == round(row[key], 2)
  assert res["z_equivalent"] == pytest.approx(z_eq, abs=1e-4)
  assert res["calibrated_risk_index"] == harness_truth.calculate_cri(z_eq)
  assert res["is_true_sigma"] is c.is_true_sigma_key(key)


def test_squared_fusion_norms_are_reported_as_distance_and_scored_on_the_squared_scale():
  eng = RiskMetricsEngine()
  fusion_sq = harness_truth.constants().DEFAULT_FUSION_THRESHOLD_SQ
  _Capture(eng, rows=[{"composite_threat_norm_sq": fusion_sq, "z_a": 3.0, "z_b": 1.8}])
  res = _run(eng.run_sector_fusion(None, "user.a", now_utc=NOW))
  assert res["composite_d"] == round(math.sqrt(fusion_sq), 2)
  assert res["z_equivalent"] == pytest.approx(3.0)
  assert res["calibrated_risk_index"] == harness_truth.calculate_cri(3.0)


def test_fusion_fallback_norm_is_rectified():
  eng = RiskMetricsEngine()
  _Capture(eng, rows=[{"z_a": -4.0, "z_b": 2.0}])
  res = _run(eng.run_sector_fusion(None, "user.a", now_utc=NOW))
  assert res["composite_d"] == 2.0


def test_python_maturity_gate_mirrors_the_query_gate():
  eng = RiskMetricsEngine()
  min_days = harness_truth.min_baseline_days()
  _Capture(eng, rows=[{"personal_z": 6.0, "active_days": min_days - 1}])
  res = _run(eng.run_dynamic_metric_pipeline(None, "alice", target_metric="auth_attempts_total",
                                             model_name="STANDARD_Z_SCORE", now_utc=NOW))
  assert res["baseline_mature"] is False
  assert res["calibrated_risk_index"] == 0
  assert res["is_outlier"] is False
  _Capture(eng, rows=[{"personal_z": 6.0, "active_days": min_days}])
  res = _run(eng.run_dynamic_metric_pipeline(None, "alice", target_metric="auth_attempts_total",
                                             model_name="STANDARD_Z_SCORE", now_utc=NOW))
  assert res["baseline_mature"] is True
  assert res["calibrated_risk_index"] == harness_truth.calculate_cri(6.0)

  # Poisson is the route for sparse entities: no maturity gate in the query, none in Python.
  _Capture(eng, rows=[{"poisson_z": 4.0, "active_days": 2}])
  res = _run(eng.run_dynamic_metric_pipeline(None, "alice", target_metric="auth_attempts_total",
                                             model_name="POISSON", now_utc=NOW))
  assert res["calibrated_risk_index"] == harness_truth.calculate_cri(4.0)


def test_radar_immature_sector_is_zeroed_and_missing_z_uses_skill_dispersion_floors():
  eng = RiskMetricsEngine()
  min_days = harness_truth.min_baseline_days()
  eng.runner._ensure_skill_path()
  from scripts.template_router import resolve_byte_dispersion_floor
  byte_floor = resolve_byte_dispersion_floor("network_bytes_outbound")

  async def fake(session, query, start_iso, end_iso, *a, **k):
    if "metrics.auth_attempts_fail" in query:  # immature baseline
      return {"stats": [{"z": 9.0, "observed": 40, "baseline": 1.0, "dispersion": 1.0, "active_days": min_days - 2}]}
    if "metrics.dns_queries_fail" in query:  # no z column: count floor sqrt(max(avg, 1))
      return {"stats": [{"observed": 30, "baseline": 4.0, "dispersion": 0.0, "active_days": 20}]}
    if "metrics.network_bytes_outbound" in query:  # no z column: byte floor
      return {"stats": [{"observed": 500000.0, "baseline": 100000.0, "dispersion": 10.0, "active_days": 20}]}
    return {"stats": []}

  eng.runner.execute_query_via_mcp = fake
  res = _run(eng.run_360_behavioral_radar(None, "host-a", entity_type="ASSET", lookback_days=1, now_utc=NOW))
  assert res["sector_z_scores"]["Auth"] == 0.0
  assert res["sector_z_scores"]["DNS"] == round((30 - 4.0) / math.sqrt(4.0), 2)
  assert res["sector_z_scores"]["Egress"] == round((500000.0 - 100000.0) / byte_floor, 2)


# ---------------------------------------------------------------------------
# Renamed / relabelled models and the data-table bridge
# ---------------------------------------------------------------------------


def test_macd_is_relabelled_above_historical_max_z():
  eng = RiskMetricsEngine()
  cap = _Capture(eng, rows=[{"macd_z": 4.2, "macd_momentum_score": 4.2, "personal_z": 3.1, "above_max_z": 1.1,
                             "active_days": 20, "observed": 9000000.0, "hist_avg": 1000000.0}])
  res = _run(eng.run_macd_momentum_velocity(None, "user.a", now_utc=NOW))
  q = cap.calls[0][0]
  assert "ABOVE-HISTORICAL-MAX Z" in q and "$above_max_z" in q
  assert _root_condition(q) == (
      f"$active_days >= {harness_truth.min_baseline_days()} and $macd_z >= {eng.gate_thresholds()['anomaly_threshold']}")
  assert res["model"] == "ABOVE_HISTORICAL_MAX_Z"
  assert res["statistical_model"] == "MACD_MOMENTUM_VELOCITY"
  assert res["score_key"] == "macd_z"
  assert (res["macd_z"], res["personal_z"], res["above_max_z"]) == (4.2, 3.1, 1.1)
  assert res["calibrated_risk_index"] == harness_truth.calculate_cri(4.2)


def test_data_table_bridge_uses_the_canonical_entity_column():
  eng = RiskMetricsEngine()
  cap = _Capture(eng, rows=[{"personal_z": 4.5, "observed_24h": 100.0, "baseline_mean": 10.0, "active_days": 20}])
  res = _run(eng.run_data_table_bridge(None, now_utc=NOW))
  assert "principal.asset.hostname in %ueba_hunt_bridge.entity" in cap.calls[-1][0]
  assert res["data_table"] == "%ueba_hunt_bridge.entity"
  assert res["personal_z"] == 4.5 and res["active_days"] == 20

  res = _run(eng.run_data_table_bridge(None, data_table_name="%my_cohort", column_name="hostname", now_utc=NOW))
  assert "principal.asset.hostname in %my_cohort.hostname" in cap.calls[-1][0]
  assert res["data_table"] == "%my_cohort.hostname"

  with pytest.raises(ValueError):
    _run(eng.run_data_table_bridge(None, data_table_name="bad table", now_utc=NOW))

  _run(eng.run_dynamic_metric_pipeline(None, "*", entity_type="ASSET", model_name="HYBRID_DATA_TABLE_BRIDGE_2STAGE",
                                       now_utc=NOW))
  assert "in %ueba_hunt_bridge.entity" in cap.calls[-1][0]


def test_workspace_triad_z_scores_follow_the_requested_metric_order():
  eng = RiskMetricsEngine()
  _Capture(eng, rows=[{"d_vs_fleet_sq": 16.0, "z1_vs_enterprise": 2.0, "z2_vs_enterprise": 3.0,
                       "z3_vs_enterprise": 1.73, "m1_observed": 12, "m2_observed": 85, "m3_observed": 19}])
  # A non-default order of a valid (single event family) triad; the skill rejects mixed families.
  metrics = ["workspace_total_download_actions", "workspace_total_change_actions", "workspace_auth_attempts_total"]
  res = _run(eng.run_workspace_triad(None, "insider", target_metrics=metrics, now_utc=NOW))
  assert res["metric_z_scores"] == dict(zip(metrics, (2.0, 3.0, 1.73)))
  assert (res["download_z"], res["change_z"], res["auth_z"]) == (2.0, 3.0, 1.73)
  assert res["email_z"] == 0.0
  assert res["fusion_metrics"] == metrics
  assert res["composite_z_score"] == 4.0

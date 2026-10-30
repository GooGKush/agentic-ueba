# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
"""Integration of the engines, the MCP server and the hunter with the remediated UEBA harness.

* Retired models never execute. RiskMetricsEngine, StatsHunterEngine and the MCP server refuse them with the
  skill's own retirement message (src.harness_truth) and name the skill's replacement. Unknown model names raise
  instead of silently running another model.
* hunt_hour_of_day_profile runs secops-statistical-hunter HOUR_OF_DAY_PROFILE end to end: server tool, hunter fast
  path, StatsHunterEngine plan and score.
* AutonomousHunterEngine renders N/A when an engine result carries None for the CRI or a model metric
  (coefficient_of_variation, shannon_entropy_score, ewma_velocity_score, ...). A None never crashes a
  deterministic fast path, a Tier 2 card or the radar SVG.
"""

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src import harness_truth as ht
from src.autonomous_hunter import AutonomousHunterEngine
from src.config import TenantConfig
from src.models import JITHuntRequest, StrategyDirective
from src.query_integrity_gate import QueryIntegrityGate
from src.risk_metrics_engine import RiskMetricsEngine
import src.server as srv
from src.stats_hunter_engine import StatsHunterEngine

ENTITY = "subject-01"
NOW = datetime(2026, 10, 30, 14, 0, 0, tzinfo=timezone.utc)
HOD = "HOUR_OF_DAY_PROFILE"
NA = ht.format_cri(None)  # the harness rendering of a missing value: "N/A"


@pytest.fixture
def anyio_backend():
  return "asyncio"


def _run(coro):
  return asyncio.run(coro)


class _NoDispatch:
  """execute_query_via_mcp double that fails the test if anything is dispatched."""

  def __init__(self):
    self.calls = []

  async def __call__(self, session, query, start_iso, end_iso, *args, **kwargs):
    self.calls.append(query)
    raise AssertionError("a refused model must not dispatch a query")


class _StreamCtx:

  async def __aenter__(self):
    return (AsyncMock(), AsyncMock())

  async def __aexit__(self, *args):
    return False


@pytest.fixture
def mcp_session(monkeypatch):
  """MCP session double for execute_jit_hunt; a fast path that falls through to the ReAct loop fails loudly."""
  session = AsyncMock()
  session.__aenter__.return_value = session
  session.initialize = AsyncMock()
  session.call_tool = AsyncMock(return_value=SimpleNamespace(content=[]))
  session.list_tools = AsyncMock(
      side_effect=AssertionError("deterministic fast path fell through to the ReAct loop"))
  monkeypatch.setattr("src.autonomous_hunter.streamable_http_client", lambda *a, **k: _StreamCtx())
  monkeypatch.setattr("src.autonomous_hunter.ClientSession", lambda *a, **k: session)
  monkeypatch.setattr("src.config.TenantConfig.get_auth_headers", lambda self: {"Authorization": "Bearer test"})
  monkeypatch.setattr(
      "src.autonomous_hunter.StrategyDecider.decide_tier2_deep_dive", AsyncMock(return_value=None))
  monkeypatch.setattr("src.autonomous_hunter.DynamicProtocolAdapter.build_jit_persona", lambda self, **kw: "persona")
  monkeypatch.setattr(
      "src.autonomous_hunter.DynamicProtocolAdapter.build_bilateral_jit_persona", lambda self, **kw: "persona")
  return session


# ---------------------------------------------------------------------------
# 1. RiskMetricsEngine: no silent model fallback, current names via the skill, no retired entries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["BOGUS_FUSION", "NOT_A_FUSION_MODEL", "MULTI_SECTOR_THREAT_FUSION"])
def test_unknown_model_names_containing_fusion_are_refused_not_run_as_sector_fusion(name):
  # MULTI_SECTOR_THREAT_FUSION is a secops-statistical-hunter archetype, not a risk-metrics model.
  eng = RiskMetricsEngine()
  eng.runner.execute_query_via_mcp = _NoDispatch()
  with pytest.raises(ValueError, match="Unknown statistical model"):
    _run(eng.run_dynamic_metric_pipeline(None, "alice", target_metric="auth_attempts_total", model_name=name,
                                         now_utc=NOW))
  assert eng.runner.execute_query_via_mcp.calls == []


@pytest.mark.parametrize("name,four_stage", [
    ("DUAL_SECTOR_FUSION_3STAGE", False),
    ("MULTI_SECTOR_FUSION_4STAGE", True),
    ("SECTOR_FUSION", False),
    ("DUAL_SECTOR_FUSION", False),
    ("MULTI_SECTOR_FUSION", True),
    # run_sector_fusion's own roll-up labels: the 4-stage roll-up is the 3-stage fusion plus the roll-up stage.
    ("ROLLUP_SECTOR_FUSION_4STAGE", False),
    ("ROLLUP_SECTOR_FUSION_5STAGE", True),
])
def test_sector_fusion_model_names_run_sector_fusion_with_their_shape(monkeypatch, name, four_stage):
  eng = RiskMetricsEngine()
  fusion = AsyncMock(return_value={"model": name})
  monkeypatch.setattr(eng, "run_sector_fusion", fusion)
  _run(eng.run_dynamic_metric_pipeline(None, "alice", target_metric="auth_attempts_total", model_name=name,
                                       now_utc=NOW))
  assert fusion.await_args.kwargs["four_stage"] is four_stage


@pytest.mark.parametrize("name,metric,entity_type,gate_fragment", [
    ("ABOVE_HISTORICAL_MAX_Z", "network_bytes_outbound", "ASSET", "$macd_z >="),
    ("WINDOWED_SLACK_SUM", "dns_queries_fail", "USER", "$cusum_drift_score >="),
    ("FIRST_SEEN_NOVELTY", "auth_attempts_total", "USER", "$novelty_flag = 1"),
])
def test_current_model_names_map_through_the_skill_resolver(name, metric, entity_type, gate_fragment):
  """The renamed / new v2.3.0 names resolve with the skill's own resolver (no engine-side copy of the map)."""
  eng = RiskMetricsEngine()
  calls = []

  async def _capture(session, query, start_iso, end_iso, *args, **kwargs):
    calls.append(query)
    return {"stats": []}

  eng.runner.execute_query_via_mcp = _capture
  res = _run(eng.run_dynamic_metric_pipeline(None, "ent-a", entity_type=entity_type, target_metric=metric,
                                             model_name=name, lookback_days=7, now_utc=NOW))
  expected = eng.runner.get_hybrid_engine().resolve_statistical_model(name)
  router = eng.runner.get_template_router()
  assert res["model"] == name
  assert res["statistical_model"] == expected.value
  assert res["model_label"] == router.MODEL_DESCRIPTIONS[expected]
  assert f"// Statistical Model: {expected.value}" in calls[0]
  assert gate_fragment in (router.root_condition(calls[0]) or "")
  assert not ht.is_retired(name) and not ht.is_retired(expected.value)


def test_windowed_slack_sum_runs_in_the_cusum_window():
  caps = ht.mode_caps()
  eng = RiskMetricsEngine()

  async def _empty(session, query, start_iso, end_iso, *args, **kwargs):
    return {"stats": []}

  eng.runner.execute_query_via_mcp = _empty
  res = _run(eng.run_dynamic_metric_pipeline(None, "ent-a", target_metric="dns_queries_fail",
                                             model_name="WINDOWED_SLACK_SUM", lookback_days=30, now_utc=NOW))
  assert res["evaluation_window"]["mode"] == "B"
  assert res["evaluation_window"]["scored_days"] == caps["mode_b_cusum_macro_days"]


def test_engine_model_maps_hold_no_retired_entries():
  for mapping in (RiskMetricsEngine._MODEL_LABEL_ALIASES, RiskMetricsEngine._STAT_MODEL_ALIASES,
                  RiskMetricsEngine._PIPELINE_ALIASES):
    retired = [name for pair in mapping.items() for name in pair if ht.is_retired(name)]
    assert retired == []


def test_unknown_killchain_archetype_is_refused_instead_of_defaulting():
  eng = RiskMetricsEngine()
  eng.runner.execute_query_via_mcp = _NoDispatch()
  with pytest.raises(ValueError, match="Unknown kill-chain archetype"):
    _run(eng.run_killchain_archetype(None, "alice", archetype="NOT_A_KILL_CHAIN", now_utc=NOW))
  assert eng.runner.execute_query_via_mcp.calls == []


# ---------------------------------------------------------------------------
# 2. Retired entry points refuse before any execution path
# ---------------------------------------------------------------------------


def _unreachable(*args, **kwargs):
  raise AssertionError("a retired model must not reach an execution path")


def test_circadian_von_mises_refuses_without_rendering_or_dispatching(monkeypatch):
  eng = RiskMetricsEngine()
  monkeypatch.setattr(eng.runner, "get_template_router", _unreachable)
  eng.runner.execute_query_via_mcp = _NoDispatch()
  with pytest.raises(ValueError) as exc:
    _run(eng.run_circadian_von_mises(None, "alice"))
  assert str(exc.value) == ht.retirement_message("circadian_von_mises_2stage.yl2")
  assert HOD in str(exc.value)


def test_impossible_travel_refuses_without_planning_or_dispatching(monkeypatch):
  eng = StatsHunterEngine()
  monkeypatch.setattr(eng, "plan_hunt", _unreachable)
  monkeypatch.setattr(eng, "run_dynamic_archetype_pipeline", _unreachable)
  eng.runner.execute_query_via_mcp = _NoDispatch()
  with pytest.raises(ValueError) as exc:
    _run(eng.run_impossible_travel_velocity(None, "traveler"))
  assert str(exc.value) == ht.retirement_message("IMPOSSIBLE_TRAVEL_GEO_VELOCITY")
  assert HOD in str(exc.value)


# ---------------------------------------------------------------------------
# 3. hunt_hour_of_day_profile: server tool -> hunter fast path -> StatsHunterEngine HOUR_OF_DAY_PROFILE
# ---------------------------------------------------------------------------


def _udm_stats(columns):
  """A udm_search response in the real columnar `stats` shape."""
  def cell(value):
    if isinstance(value, int):
      return {"value": {"int64Val": str(value)}}
    if isinstance(value, float):
      return {"value": {"doubleVal": value}}
    return {"value": {"stringVal": str(value)}}

  return {"stats": {"results": [
      {"column": name, "values": [cell(v) for v in values]} for name, values in columns.items()]}}


@pytest.mark.anyio
async def test_hunt_hour_of_day_profile_runs_the_stats_hunter_model_end_to_end(monkeypatch, mcp_session):
  dispatched = []

  async def _udm_search(self, session, query, start_iso, end_iso, *args, **kwargs):
    QueryIntegrityGate.verify_pre_dispatch(query, raise_on_error=True)
    dispatched.append((query, start_iso, end_iso))
    return _udm_stats({"entity": ["night.owl"], "hod": [3], "ws": [1793156400], "observed": [41.0],
                       "in_scoring_window": [1], "entity_active_hours": [96], "hod_z_score": [4.5]})

  monkeypatch.setattr("src.pipeline_runner.PipelineRunner.execute_query_via_mcp", _udm_search)

  out = await srv.hunt_hour_of_day_profile(username="night.owl", lookback_days=7, post_to_case_wall=False)

  assert len(dispatched) == 1
  query = dispatched[0][0]
  assert "stage hod_baseline" in query and "$hod_z_score" in query  # hour_of_day_profile_3stage.yl2
  assert out["status"] == "SUCCESS"
  triage = out["triage"]
  assert triage["primary_vector"] == "hour_of_day_login_anomaly"
  z_eq = ht.constants().score_to_z_equivalent("hod_z_score", 4.5)
  assert triage["top_z_score"] == round(z_eq, 2)
  assert triage["calibrated_risk_index"] == float(ht.calculate_cri(z_eq))
  assert triage["verdict"] == ht.verdict_for(ht.calculate_cri(z_eq))
  assert triage["recommended_action"] == ht.recommended_action(ht.calculate_cri(z_eq),
                                                               containment_action="FORCE_MFA_CHALLENGE")
  mcp_session.list_tools.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize("tool,model", [
    ("hunt_circadian_von_mises", "CIRCADIAN_VON_MISES"),
    ("hunt_impossible_travel", "IMPOSSIBLE_TRAVEL_GEO_VELOCITY"),
])
async def test_retired_model_tools_point_to_the_hour_of_day_profile_tool(monkeypatch, tool, model):
  execute = AsyncMock(side_effect=AssertionError("a retired model's tool must not run a hunt"))
  monkeypatch.setattr(srv.engine, "execute_jit_hunt", execute)

  out = await getattr(srv, tool)(username="alice")

  assert out["status"] == srv.RETIRED_MODEL_STATUS
  assert out["error_message"] == ht.retirement_message(model)
  assert (out["replacement_model"], out["replacement_tool"]) == (HOD, "hunt_hour_of_day_profile")
  tools = {t.name for t in await srv.mcp.list_tools()}
  assert out["replacement_tool"] in tools  # the named replacement is a registered MCP tool
  execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# 4. AutonomousHunterEngine: engine results that carry None render N/A
# ---------------------------------------------------------------------------


def _not_evaluated(model, **metrics):
  base = {"model": model, "top_z_score": None, "calibrated_risk_index": None, "is_outlier": False,
          "stats_rows": 0, "executed_query": f"// {model}"}
  base.update(metrics)
  return base


# (query, engine class, method, None-laden result, label of the line that must render N/A, primary vector)
NONE_FAST_PATHS = [
    pytest.param("c2_jitter", "StatsHunterEngine", "run_c2_beaconing_jitter",
                 _not_evaluated("C2_BEACONING_JITTER", coefficient_of_variation=None, target_destination=None,
                                not_evaluated_reason="C2_INSUFFICIENT_INTERVALS"),
                 "Coefficient of Variation", "c2_timing_regularity", id="c2_jitter"),
    pytest.param("poisson_burst", "StatsHunterEngine", "run_poisson_burst_spray",
                 _not_evaluated("POISSON_BURST_CLUSTERING", top_fano=None, fano_factor=None),
                 "Fano Factor", "poisson_burst_clustering", id="poisson_burst"),
    pytest.param("cloud_crud", "RiskMetricsEngine", "run_cloud_crud_surge",
                 _not_evaluated("CLOUD_CRUD_SURGE", observed_events=None),
                 "Cloud Mutation Z-Score", "cloud_crud_surge", id="cloud_crud"),
    pytest.param("hour_of_day_profile", "StatsHunterEngine", "run_dynamic_archetype_pipeline",
                 _not_evaluated(HOD, score_metric=None, primary_score=None),
                 "Hour-of-Day Profile Score", "hour_of_day_login_anomaly", id="hour_of_day_profile"),
    pytest.param("macd", "RiskMetricsEngine", "run_macd_momentum_velocity",
                 _not_evaluated("ABOVE_HISTORICAL_MAX_Z", macd_momentum_score=None, fast_z=None, slow_z=None),
                 "MACD Momentum Score", "macd_momentum_acceleration", id="macd"),
    pytest.param("shannon_entropy", "StatsHunterEngine", "run_shannon_character_entropy",
                 _not_evaluated("SHANNON_ENTROPY_CHARACTER", shannon_entropy_score=None, sample_token=None,
                                not_evaluated_reason="INSUFFICIENT_BENIGN_LENGTH_COHORT"),
                 "Shannon Entropy", "command_line_obfuscation_entropy", id="shannon"),
    pytest.param("markov_transition", "StatsHunterEngine", "run_markov_transition_rarity",
                 _not_evaluated("MARKOV_2GRAM_TRANSITION_RARITY", surprisal_score=None, parent_process=None,
                                child_process=None),
                 "Information Surprisal", "markov_process_transition_rarity", id="markov"),
    pytest.param("zipf", "StatsHunterEngine", "run_zipfian_process_rarity",
                 _not_evaluated("ZIPFIAN_PROCESS_RARITY", zipf_rarity_score=None, rare_binary=None),
                 "Zipf Rarity Score", "zipfian_rare_tool_execution", id="zipf"),
    pytest.param("ewma", "StatsHunterEngine", "run_ewma_burst_velocity",
                 _not_evaluated("EWMA_BURST_VELOCITY", ewma_velocity_score=None, velocity_score=None),
                 "EWMA Velocity Score", "ewma_kinetic_burst_velocity", id="ewma"),
    pytest.param("producer_consumer", "StatsHunterEngine", "run_producer_consumer_inversion",
                 _not_evaluated("PRODUCER_CONSUMER_RATIO_INVERSION", producer_ratio=None, pcr_z_score=None),
                 "Producer Ratio", "producer_consumer_ratio_inversion", id="producer_consumer"),
    pytest.param("sector_fusion", "RiskMetricsEngine", "run_sector_fusion",
                 _not_evaluated("DUAL_SECTOR_FUSION_3STAGE", composite_threat_score=None, sector_a_z=None,
                                sector_b_z=None),
                 "Composite Fusion Score", "multi_sector_fusion_convergence", id="sector_fusion"),
    pytest.param("dynamic_metric", "RiskMetricsEngine", "run_dynamic_metric_pipeline",
                 _not_evaluated("STANDARD_Z_SCORE", observed_value=None),
                 "Metric Deviation", "dynamic_metric_workspace_total_download_actions", id="dynamic_metric"),
]


def _line(report, label):
  lines = [ln for ln in report.splitlines() if label in ln]
  assert lines, f"no line labelled {label!r} in the report"
  return lines[0]


def _assert_no_raw_none(text):
  for raw in ("`None`", "Noneσ", "None σ", "= None", ": None", "(None", "None bits"):
    assert raw not in text, raw


@pytest.mark.anyio
@pytest.mark.parametrize("query,engine_cls,method,result,label,vector", NONE_FAST_PATHS)
async def test_fast_paths_render_na_when_the_engine_result_carries_none(
    monkeypatch, mcp_session, query, engine_cls, method, result, label, vector):
  monkeypatch.setattr(f"src.autonomous_hunter.{engine_cls}.{method}", AsyncMock(return_value=dict(result)))
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", query=query, lookback_days=7)

  resp = await AutonomousHunterEngine().execute_jit_hunt(req)

  assert resp.status == "SUCCESS"
  assert resp.triage.primary_vector == vector  # the deterministic fast path answered
  assert resp.triage.verdict == ht.verdict_for(None)
  assert resp.triage.recommended_action == ht.recommended_action(None)
  assert resp.triage.top_z_score is None  # not evaluated: no invented 0.0 score
  report = resp.forensics.markdown_report
  assert NA in _line(report, label)
  _assert_no_raw_none(report)
  mcp_session.list_tools.assert_not_awaited()


@pytest.mark.anyio
async def test_radar_fast_path_renders_na_for_a_missing_sector_score_and_cri(monkeypatch, mcp_session):
  radar = {
      "entity": ENTITY, "evaluated_day": "2026-10-29", "composite_d": None, "calibrated_risk_index": None,
      "top_sector": "Auth", "is_outlier": False,
      "sector_z_scores": {"Auth": None, "Cloud": 0.4, "Workspace": 0.0, "Egress": 0.0, "DNS": 0.0, "Web": 0.0},
      "sector_observed_counts": {"Auth": 0, "Cloud": 2, "Workspace": 0, "Egress": 0, "DNS": 0, "Web": 0},
  }
  monkeypatch.setattr("src.autonomous_hunter.RiskMetricsEngine.run_360_behavioral_radar",
                      AsyncMock(return_value=radar))
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", query="profile_360_risk", lookback_days=7)

  resp = await AutonomousHunterEngine().execute_jit_hunt(req)

  assert resp.status == "SUCCESS"
  assert resp.triage.primary_vector == "Auth_behavioral_drift"
  assert resp.triage.verdict == ht.verdict_for(None)
  assert resp.triage.top_z_score is None
  assert resp.triage.radar_dimensions == {"Cloud": 0.4, "Workspace": 0.0, "Egress": 0.0, "DNS": 0.0, "Web": 0.0}
  assert NA in _line(resp.forensics.markdown_report, "**Auth Sector**")
  assert resp.forensics.radar_svg and resp.forensics.radar_svg.startswith("<svg")
  mcp_session.list_tools.assert_not_awaited()


def test_behavioral_radar_svg_renders_na_for_a_missing_sector_score():
  svg = AutonomousHunterEngine().generate_behavioral_radar(
      ENTITY, {"Auth": None, "Cloud": 1.5, "Workspace": float("nan"), "Egress": 0.0, "DNS": 0.0, "Web": 0.0})
  assert svg.startswith("<svg")
  assert f"(Z = {NA})" in svg
  assert "(Z = +1.50σ)" in svg


# (directive query, model, engine class, method, None-laden result, label of the row that must render N/A)
NONE_SECONDARY = [
    pytest.param("killchain_archetype", "CREDENTIAL_ACCESS_TO_EXECUTION", "RiskMetricsEngine",
                 "run_killchain_archetype",
                 _not_evaluated("KILLCHAIN_CREDENTIAL_ACCESS_TO_EXECUTION", archetype="CREDENTIAL_ACCESS_TO_EXECUTION",
                                composite_threat_score=None, stats_rows=None),
                 "MITRE Kill-Chain Archetype", id="killchain"),
    pytest.param("workspace_triad", "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL", "RiskMetricsEngine", "run_workspace_triad",
                 _not_evaluated("PART_OF_THE_WHOLE_TRIAD_MULTILEVEL", composite_z_score=None, observed_value=None),
                 "Workspace Triad Composite", id="workspace_triad"),
    pytest.param("cloud_repo_scope", "CLOUD_REPOSITORY_SCOPE", "RiskMetricsEngine", "run_cloud_repository_scope",
                 _not_evaluated("CLOUD_REPOSITORY_SCOPE", fold_change=None, observed_events=None),
                 "Cloud Repository Scope", id="cloud_repo_scope"),
    pytest.param("failure_ratio_surge", "FAILURE_RATIO_SURGE", "RiskMetricsEngine", "run_failure_ratio_surge",
                 _not_evaluated("FAILURE_RATIO_SURGE", failure_ratio=None), "Failure Ratio Surge",
                 id="failure_ratio_surge"),
    pytest.param("alert_surge", "STANDARD_Z_SCORE", "RiskMetricsEngine", "run_alert_surge",
                 _not_evaluated("ALERT_SURGE", observed_alerts=None), "Security Alert Surge", id="alert_surge"),
    pytest.param("sector_fusion", "DUAL_SECTOR_FUSION_3STAGE", "RiskMetricsEngine", "run_sector_fusion",
                 _not_evaluated("DUAL_SECTOR_FUSION_3STAGE", composite_threat_score=None, sector_a_z=None,
                                sector_b_z=None),
                 "Composite Fusion Score", id="sector_fusion"),
    pytest.param("macd_momentum", "ABOVE_HISTORICAL_MAX_Z", "RiskMetricsEngine", "run_macd_momentum_velocity",
                 _not_evaluated("ABOVE_HISTORICAL_MAX_Z", macd_momentum_score=None, fast_z=None, slow_z=None),
                 "MACD Momentum Score", id="macd"),
    pytest.param("hour_of_day_profile", HOD, "StatsHunterEngine", "run_dynamic_archetype_pipeline",
                 _not_evaluated(HOD, primary_score=None), "Hour-of-Day Profile Score", id="hour_of_day_profile"),
    pytest.param("cloud_crud", "CLOUD_CRUD_SURGE", "RiskMetricsEngine", "run_cloud_crud_surge",
                 _not_evaluated("CLOUD_CRUD_SURGE", observed_events=None), "Cloud CRUD Z-Score", id="cloud_crud"),
    pytest.param("dynamic_metric", "STANDARD_Z_SCORE", "RiskMetricsEngine", "run_dynamic_metric_pipeline",
                 _not_evaluated("STANDARD_Z_SCORE", observed_value=None), "Metric Deviation", id="dynamic_metric"),
    pytest.param("c2_jitter", "C2_BEACONING_JITTER", "StatsHunterEngine", "run_c2_beaconing_jitter",
                 _not_evaluated("C2_BEACONING_JITTER", coefficient_of_variation=None, target_destination=None),
                 "Coefficient of Variation", id="c2_jitter"),
    pytest.param("poisson_burst", "POISSON_BURST_CLUSTERING", "StatsHunterEngine", "run_poisson_burst_spray",
                 _not_evaluated("POISSON_BURST_CLUSTERING", top_fano=None), "Fano Factor", id="poisson_burst"),
    pytest.param("shannon_entropy", "SHANNON_ENTROPY_CHARACTER", "StatsHunterEngine", "run_shannon_character_entropy",
                 _not_evaluated("SHANNON_ENTROPY_CHARACTER", shannon_entropy_score=None, sample_token=None),
                 "Shannon Entropy", id="shannon"),
    pytest.param("markov_transition", "MARKOV_2GRAM_TRANSITION_RARITY", "StatsHunterEngine",
                 "run_markov_transition_rarity",
                 _not_evaluated("MARKOV_2GRAM_TRANSITION_RARITY", surprisal_score=None, parent_process=None,
                                child_process=None),
                 "Information Surprisal", id="markov"),
    pytest.param("zipfian_rarity", "ZIPFIAN_PROCESS_RARITY", "StatsHunterEngine", "run_zipfian_process_rarity",
                 _not_evaluated("ZIPFIAN_PROCESS_RARITY", zipf_rarity_score=None, rare_binary=None),
                 "Zipf Rarity Score", id="zipf"),
    pytest.param("ewma_burst", "EWMA_BURST_VELOCITY", "StatsHunterEngine", "run_ewma_burst_velocity",
                 _not_evaluated("EWMA_BURST_VELOCITY", ewma_velocity_score=None), "EWMA Velocity Score", id="ewma"),
    pytest.param("producer_consumer_inversion", "PRODUCER_CONSUMER_RATIO_INVERSION", "StatsHunterEngine",
                 "run_producer_consumer_inversion",
                 _not_evaluated("PRODUCER_CONSUMER_RATIO_INVERSION", pcr_z_score=None, producer_ratio=None),
                 "Producer-Consumer Ratio Z", id="producer_consumer"),
    pytest.param("poisson_rare_surge", "POISSON_RARE_SURGE", "StatsHunterEngine", "run_poisson_rare_surge",
                 _not_evaluated("POISSON_RARE_SURGE", poisson_z=None, stats_rows=None), "Poisson Arrival Rarity",
                 id="poisson_rare_surge"),
]


@pytest.mark.anyio
@pytest.mark.parametrize("query,model,engine_cls,method,result,label", NONE_SECONDARY)
async def test_secondary_cards_render_na_when_the_engine_result_carries_none(
    monkeypatch, query, model, engine_cls, method, result, label):
  monkeypatch.setattr(f"src.autonomous_hunter.{engine_cls}.{method}", AsyncMock(return_value=dict(result)))
  directive = StrategyDirective(model_name=model, directive_query=query, target_entity=ENTITY, entity_type="USER",
                                investigation_tier="TIER_2_DEEP_DIVE", outlier_vector="Auth")
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", case_id="77")

  res, card = await AutonomousHunterEngine()._execute_secondary_directive(
      AsyncMock(), TenantConfig(project_id="p", customer_id="c"), req, directive)

  assert res is not None and card is not None
  assert f"`{ht.verdict_for(None)}`" in card
  assert NA in _line(card, label)
  _assert_no_raw_none(card)
  assert directive.post_data_outcome_class == "CLEAN_OR_SUBTHRESHOLD"

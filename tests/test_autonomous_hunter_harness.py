# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
"""Harness truth in the autonomous hunter loop and the federated bridge.

Verdicts, recommended actions and CRI produced by src/autonomous_hunter.py and
src/federated_bridge.py must come from src/harness_truth.py (the remediated UEBA
harness): the skills' 26/46/70/90 CRI bands, the caller's domain containment
action only at Critical, INVESTIGATE at High/Medium, MONITOR below Medium and for
missing CRI. Actions are recommendations only; nothing executes containment.
Retired models route to the replacement named by the skill's own retirement
message (harness_truth.retirement_message) or are not executed at all.
"""

import json
import math
from pathlib import Path
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src import harness_truth as ht
from src.autonomous_hunter import AutonomousHunterEngine
from src.config import TenantConfig
from src.models import JITHuntRequest, StrategyDirective

ENTITY = "subject-01"
HOD = "HOUR_OF_DAY_PROFILE"

# (cri, verdict, response kind) at every boundary of the skills' 26/46/70/90 CRI bands
# (secops-risk-metrics-multistage/references/calibrated-risk-index-guide.md, Tiers 1-5).
BOUNDARIES = [
    (25, "NOMINAL_BASELINE", "MONITOR"),
    (26, "LOW_OUTLIER", "MONITOR"),
    (45, "LOW_OUTLIER", "MONITOR"),
    (46, "MEDIUM_OUTLIER", "INVESTIGATE"),
    (69, "MEDIUM_OUTLIER", "INVESTIGATE"),
    (70, "HIGH_OUTLIER", "INVESTIGATE"),
    (89, "HIGH_OUTLIER", "INVESTIGATE"),
    (90, "CRITICAL_OUTLIER", "CONTAIN"),
    (None, "NOT_EVALUATED", "MONITOR"),
]


def _expected_action(kind, containment):
  return containment if kind == "CONTAIN" else kind


def _expects_quarantine(kind, containment):
  """Entities are listed for containment only when the harness recommends a containment action."""
  return kind == "CONTAIN" and containment not in ("INVESTIGATE", "MONITOR")


def _flag(cri):
  return cri is not None and cri >= 46


@pytest.fixture
def anyio_backend():
  return "asyncio"


class _StreamCtx:

  async def __aenter__(self):
    return (AsyncMock(), AsyncMock())

  async def __aexit__(self, *args):
    return False


@pytest.fixture
def mcp_session(monkeypatch):
  """MCP session double: records tool calls and fails loudly if a fast path falls through to ReAct."""
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
  # The JIT persona is not under test here, and building it re-reads the skills on every hunt.
  monkeypatch.setattr("src.autonomous_hunter.DynamicProtocolAdapter.build_jit_persona", lambda self, **kw: "persona")
  monkeypatch.setattr(
      "src.autonomous_hunter.DynamicProtocolAdapter.build_bilateral_jit_persona", lambda self, **kw: "persona")
  return session


# ---------------------------------------------------------------------------
# Engine result doubles for every deterministic fast path
# ---------------------------------------------------------------------------


def _radar(cri, **extra):
  res = {
      "entity": ENTITY,
      "evaluated_day": "2026-10-29",
      "composite_d": 1.1,
      "calibrated_risk_index": cri,
      "top_sector": "Auth",
      "is_outlier": _flag(cri),
      "sector_z_scores": {"Auth": 1.1, "Cloud": 0.0, "Workspace": 0.0, "Egress": 0.0, "DNS": 0.0, "Web": 0.0},
      "sector_observed_counts": {"Auth": 3, "Cloud": 0, "Workspace": 0, "Egress": 0, "DNS": 0, "Web": 0},
      # The engine's own verdict string must never decide the hunter's verdict.
      "verdict": "ENGINE_VERDICT_IS_NOT_THE_HARNESS_VERDICT",
  }
  res.update(extra)
  return res


def _c2(cri):
  return {"model": "C2_BEACONING_JITTER", "coefficient_of_variation": 0.15, "target_destination": "203.0.113.9",
          "top_z_score": 3.3, "calibrated_risk_index": cri, "is_outlier": _flag(cri), "stats_rows": 30,
          "executed_query": "// c2 jitter"}


def _burst(cri):
  return {"model": "POISSON_BURST_CLUSTERING", "top_fano": 5.0, "fano_factor": 5.0, "top_z_score": 5.0,
          "calibrated_risk_index": cri, "is_outlier": _flag(cri), "stats_rows": 12, "executed_query": "// burst"}


def _cloud(cri):
  return {"model": "CLOUD_CRUD_SURGE", "top_z_score": 3.4, "observed_events": 40, "calibrated_risk_index": cri,
          "is_outlier": _flag(cri), "executed_query": "// cloud crud"}


def _hod(cri):
  return {"entity": ENTITY, "entity_type": "USER", "model": HOD, "score_metric": "hod_z_score",
          "primary_score": 3.4, "top_z_score": 3.4, "calibrated_risk_index": cri, "is_outlier": _flag(cri),
          "stats_rows": 4, "executed_query": "// hour of day profile"}


def _macd(cri):
  return {"model": "MACD_MOMENTUM_VELOCITY", "macd_momentum_score": 3.2, "fast_z": 3.5, "slow_z": 0.3,
          "top_z_score": 3.2, "calibrated_risk_index": cri, "is_outlier": _flag(cri), "stats_rows": 2,
          "executed_query": "// macd"}


def _shannon(cri):
  return {"model": "SHANNON_CHARACTER_ENTROPY", "shannon_entropy_score": 5.9, "sample_token": "SQBFAFgA",
          "top_z_score": 3.2, "calibrated_risk_index": cri, "is_outlier": _flag(cri), "stats_rows": 3,
          "executed_query": "// shannon"}


def _markov(cri):
  return {"model": "MARKOV_TRANSITION_RARITY", "surprisal_score": 4.1, "parent_process": "word.exe",
          "child_process": "powershell.exe", "top_z_score": 4.0, "calibrated_risk_index": cri,
          "is_outlier": _flag(cri), "stats_rows": 1, "executed_query": "// markov"}


def _zipf(cri):
  return {"model": "ZIPFIAN_PROCESS_RARITY", "zipf_rarity_score": 3.1, "rare_binary": "rclone.exe",
          "top_z_score": 3.7, "calibrated_risk_index": cri, "is_outlier": _flag(cri), "stats_rows": 2,
          "executed_query": "// zipf"}


def _ewma(cri):
  return {"model": "EWMA_BURST_VELOCITY", "ewma_velocity_score": 2.4, "top_z_score": 3.6,
          "calibrated_risk_index": cri, "is_outlier": _flag(cri), "stats_rows": 5, "executed_query": "// ewma"}


def _pc(cri):
  return {"model": "PRODUCER_CONSUMER_RATIO_INVERSION", "producer_ratio": 0.82, "top_z_score": 3.5,
          "calibrated_risk_index": cri, "is_outlier": _flag(cri), "stats_rows": 2, "executed_query": "// pcr"}


def _fusion(cri):
  return {"model": "DUAL_SECTOR_FUSION_3STAGE", "template_name": "dual_sector_fusion_3stage.yl2",
          "composite_threat_score": 4.1, "sector_a_z": 3.1, "sector_b_z": 2.7, "top_z_score": 4.1,
          "calibrated_risk_index": cri, "is_outlier": _flag(cri), "stats_rows": 2, "executed_query": "// fusion"}


def _dyn(cri):
  return {"model": "STANDARD_Z_SCORE", "top_z_score": 3.3, "observed_value": 120.0, "calibrated_risk_index": cri,
          "is_outlier": _flag(cri), "stats_rows": 1, "executed_query": "// dynamic metric"}


# (query, engine class, method, result builder, domain containment action, primary vector)
FAST_PATHS = [
    pytest.param("profile_360_risk", "RiskMetricsEngine", "run_360_behavioral_radar", _radar, "QUARANTINE",
                 "Auth_behavioral_drift", id="radar_360"),
    pytest.param("c2_jitter", "StatsHunterEngine", "run_c2_beaconing_jitter", _c2, "ISOLATE_HOST",
                 "c2_timing_regularity", id="c2_jitter"),
    pytest.param("poisson_burst", "StatsHunterEngine", "run_poisson_burst_spray", _burst, "LOCK_ACCOUNT",
                 "poisson_burst_clustering", id="poisson_burst"),
    pytest.param("cloud_crud", "RiskMetricsEngine", "run_cloud_crud_surge", _cloud, "REVOKE_IAM_ROLES",
                 "cloud_crud_surge", id="cloud_crud"),
    pytest.param("hour_of_day_profile", "StatsHunterEngine", "run_dynamic_archetype_pipeline", _hod,
                 "FORCE_MFA_CHALLENGE", "hour_of_day_login_anomaly", id="hour_of_day_profile"),
    pytest.param("macd", "RiskMetricsEngine", "run_macd_momentum_velocity", _macd, "THROTTLE_EGRESS",
                 "macd_momentum_acceleration", id="macd"),
    pytest.param("shannon_entropy", "StatsHunterEngine", "run_shannon_character_entropy", _shannon,
                 "TERMINATE_PROCESS", "command_line_obfuscation_entropy", id="shannon"),
    pytest.param("markov_transition", "StatsHunterEngine", "run_markov_transition_rarity", _markov,
                 "ISOLATE_HOST", "markov_process_transition_rarity", id="markov"),
    pytest.param("zipf", "StatsHunterEngine", "run_zipfian_process_rarity", _zipf, "ISOLATE_HOST",
                 "zipfian_rare_tool_execution", id="zipf"),
    pytest.param("ewma", "StatsHunterEngine", "run_ewma_burst_velocity", _ewma, "RATE_LIMIT_ENTITY",
                 "ewma_kinetic_burst_velocity", id="ewma"),
    pytest.param("producer_consumer", "StatsHunterEngine", "run_producer_consumer_inversion", _pc,
                 "ISOLATE_HOST", "producer_consumer_ratio_inversion", id="producer_consumer"),
    pytest.param("sector_fusion", "RiskMetricsEngine", "run_sector_fusion", _fusion, "QUARANTINE",
                 "multi_sector_fusion_convergence", id="sector_fusion"),
    pytest.param("dynamic_metric", "RiskMetricsEngine", "run_dynamic_metric_pipeline", _dyn, "INVESTIGATE",
                 "dynamic_metric_workspace_total_download_actions", id="dynamic_metric"),
]


def _patch_engine(monkeypatch, engine_cls, method, result):
  mock = AsyncMock(return_value=result)
  monkeypatch.setattr(f"src.autonomous_hunter.{engine_cls}.{method}", mock)
  return mock


# ---------------------------------------------------------------------------
# 1. Every fast path: verdict, action and quarantine list at each band boundary
# ---------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("cri,verdict,kind", BOUNDARIES)
@pytest.mark.parametrize("query,engine_cls,method,builder,containment,vector", FAST_PATHS)
async def test_fast_path_verdict_and_action_follow_harness_bands(
    monkeypatch, mcp_session, query, engine_cls, method, builder, containment, vector, cri, verdict, kind):
  _patch_engine(monkeypatch, engine_cls, method, builder(cri))
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", query=query, lookback_days=7)

  resp = await AutonomousHunterEngine().execute_jit_hunt(req)

  action = _expected_action(kind, containment)
  assert resp.status == "SUCCESS"
  assert resp.triage.primary_vector == vector  # the deterministic fast path answered, not ReAct
  assert resp.triage.verdict == verdict
  assert resp.triage.recommended_action == action
  assert resp.clean_hand_off.escalation_action == action
  assert resp.triage.calibrated_risk_index == float(cri if cri is not None else 0)
  # Containment targets are listed only when the harness recommends containment (Critical band).
  assert resp.triage.entities_to_quarantine == ([ENTITY] if _expects_quarantine(kind, containment) else [])
  # Actions are recommendations only, and the report says so.
  assert ht.RECOMMENDATION_NOTE in resp.forensics.markdown_report
  mcp_session.list_tools.assert_not_awaited()


@pytest.mark.anyio
async def test_critical_fast_path_posts_only_a_case_comment_and_never_executes_containment(
    monkeypatch, mcp_session):
  _patch_engine(monkeypatch, "StatsHunterEngine", "run_markov_transition_rarity", _markov(97))
  req = JITHuntRequest(target_entity=ENTITY, entity_type="ASSET", query="markov_transition", case_id="9001",
                       post_to_case_wall=True, lookback_days=7)

  resp = await AutonomousHunterEngine().execute_jit_hunt(req)

  assert resp.triage.verdict == "CRITICAL_OUTLIER"
  assert resp.triage.recommended_action == "ISOLATE_HOST"
  tools_called = [c.args[0] for c in mcp_session.call_tool.await_args_list]
  assert tools_called == ["create_case_comment"]
  posted = mcp_session.call_tool.await_args_list[0].args[1]["comment"]
  assert "Recommendation only" in posted


# ---------------------------------------------------------------------------
# 2. Retired models route to the skill's named replacement or do not run
# ---------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    "query,retired_name,legacy_engine,legacy_method",
    [
        ("circadian_von_mises", "CIRCADIAN_VON_MISES", "RiskMetricsEngine", "run_circadian_von_mises"),
        ("impossible_travel", "IMPOSSIBLE_TRAVEL_GEO_VELOCITY", "StatsHunterEngine",
         "run_impossible_travel_velocity"),
    ],
)
async def test_retired_fast_path_query_routes_to_the_skill_replacement(
    monkeypatch, mcp_session, query, retired_name, legacy_engine, legacy_method):
  msg = ht.retirement_message(retired_name)
  assert msg and HOD in msg and not ht.is_retired(HOD)  # the skill itself names the replacement
  legacy = _patch_engine(monkeypatch, legacy_engine, legacy_method, {"calibrated_risk_index": 99})
  hod = _patch_engine(monkeypatch, "StatsHunterEngine", "run_dynamic_archetype_pipeline", _hod(92))
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", query=query, lookback_days=7)

  resp = await AutonomousHunterEngine().execute_jit_hunt(req)

  legacy.assert_not_awaited()
  hod.assert_awaited_once()
  assert hod.await_args.kwargs["archetype"] == HOD
  assert resp.triage.primary_vector == "hour_of_day_login_anomaly"
  assert resp.triage.common_vector == "AUTH"
  assert resp.triage.verdict == "CRITICAL_OUTLIER"
  assert resp.triage.recommended_action == "FORCE_MFA_CHALLENGE"
  assert resp.clean_hand_off.primary_model == "secops-statistical-hunter"
  assert msg in resp.forensics.markdown_report
  assert retired_name not in resp.clean_hand_off.outlier_topology


@pytest.mark.anyio
@pytest.mark.parametrize(
    "model_name,directive_query,legacy_engine,legacy_method",
    [
        ("CIRCADIAN_VON_MISES", "circadian_von_mises", "RiskMetricsEngine", "run_circadian_von_mises"),
        ("IMPOSSIBLE_TRAVEL_GEO_VELOCITY", "impossible_travel", "StatsHunterEngine",
         "run_impossible_travel_velocity"),
    ],
)
async def test_retired_secondary_directive_routes_to_the_skill_replacement(
    monkeypatch, model_name, directive_query, legacy_engine, legacy_method):
  legacy = _patch_engine(monkeypatch, legacy_engine, legacy_method, {"calibrated_risk_index": 99})
  hod = _patch_engine(monkeypatch, "StatsHunterEngine", "run_dynamic_archetype_pipeline", _hod(72))
  directive = StrategyDirective(model_name=model_name, directive_query=directive_query, target_entity=ENTITY,
                                entity_type="USER", investigation_tier="TIER_2_DEEP_DIVE", outlier_vector="Auth")
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", case_id="77")

  res, card = await AutonomousHunterEngine()._execute_secondary_directive(
      AsyncMock(), TenantConfig(project_id="p", customer_id="c"), req, directive)

  legacy.assert_not_awaited()
  assert hod.await_args.kwargs["archetype"] == HOD
  assert res["model"] == HOD
  assert directive.model_name == HOD
  assert ht.retirement_message(model_name) in card
  assert ht.RECOMMENDATION_NOTE in card


@pytest.mark.anyio
async def test_retired_secondary_model_without_a_runnable_replacement_is_not_executed(monkeypatch):
  dyn = _patch_engine(monkeypatch, "RiskMetricsEngine", "run_dynamic_metric_pipeline", _dyn(95))
  directive = StrategyDirective(model_name="FLEET_PREVALENCE_SHIELD", directive_query="dynamic_metric",
                                target_entity=ENTITY, entity_type="USER", target_metric="file_executions_total")
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", case_id="77")

  res, card = await AutonomousHunterEngine()._execute_secondary_directive(
      AsyncMock(), TenantConfig(project_id="p", customer_id="c"), req, directive)

  assert (res, card) == (None, None)
  dyn.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize("retired", ["PIECEWISE_CRI", "ASYMMETRIC_Z"])
async def test_retired_z_variants_run_as_the_skill_named_standard_z_score(monkeypatch, retired):
  dyn = _patch_engine(monkeypatch, "RiskMetricsEngine", "run_dynamic_metric_pipeline", _dyn(50))
  directive = StrategyDirective(model_name=retired, directive_query="dynamic_metric", target_entity=ENTITY,
                                entity_type="USER", target_metric="auth_attempts_total")
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", case_id="77")

  res, card = await AutonomousHunterEngine()._execute_secondary_directive(
      AsyncMock(), TenantConfig(project_id="p", customer_id="c"), req, directive)

  assert res is not None and card is not None
  assert dyn.await_args.kwargs["model_name"] == "STANDARD_Z_SCORE"
  assert ht.retirement_message(retired) in card


# ---------------------------------------------------------------------------
# 3. Secondary (Tier 2) cards and the Tier 2 escalation of the radar verdict
# ---------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("cri,verdict,kind", BOUNDARIES)
async def test_secondary_card_guidance_follows_harness_bands(monkeypatch, cri, verdict, kind):
  _patch_engine(monkeypatch, "StatsHunterEngine", "run_c2_beaconing_jitter", _c2(cri))
  directive = StrategyDirective(model_name="C2_BEACONING_JITTER", directive_query="c2_jitter", target_entity=ENTITY,
                                entity_type="ASSET", investigation_tier="TIER_2_DEEP_DIVE", outlier_vector="Egress")
  req = JITHuntRequest(target_entity=ENTITY, entity_type="ASSET", case_id="77")

  res, card = await AutonomousHunterEngine()._execute_secondary_directive(
      AsyncMock(), TenantConfig(project_id="p", customer_id="c"), req, directive)

  assert res is not None and card is not None  # missing CRI renders instead of crashing
  assert f"`{verdict}`" in card
  assert f"`{_expected_action(kind, 'ISOLATE_HOST')}`" in card
  assert ht.action_guidance(cri) in card


def _tier2_directive():
  return StrategyDirective(model_name="C2_BEACONING_JITTER", directive_query="c2_jitter", target_entity=ENTITY,
                           entity_type="USER", investigation_tier="TIER_2_DEEP_DIVE", outlier_vector="Auth",
                           confidence_score=0.95)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "sec_cri,post,verdict,action,quarantine",
    [
        (88, True, "HIGH_OUTLIER", "INVESTIGATE", []),
        (92, True, "CRITICAL_OUTLIER", "QUARANTINE", [ENTITY]),
        (92, False, "CRITICAL_OUTLIER", "QUARANTINE", [ENTITY]),
    ],
)
async def test_tier2_outlier_escalates_radar_verdict_and_action_through_the_harness(
    monkeypatch, mcp_session, sec_cri, post, verdict, action, quarantine):
  _patch_engine(monkeypatch, "RiskMetricsEngine", "run_360_behavioral_radar", _radar(60))
  _patch_engine(monkeypatch, "StatsHunterEngine", "run_c2_beaconing_jitter", _c2(sec_cri))
  monkeypatch.setattr("src.autonomous_hunter.StrategyDecider.decide_tier2_deep_dive",
                      AsyncMock(return_value=_tier2_directive()))
  monkeypatch.setattr("src.autonomous_hunter.StrategyDecider.decide_tier2_pivot", MagicMock(return_value=None))
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", query="profile_360_risk", case_id="4242",
                       post_to_case_wall=post, lookback_days=7)

  resp = await AutonomousHunterEngine().execute_jit_hunt(req)

  assert resp.triage.calibrated_risk_index == float(sec_cri)
  assert resp.triage.verdict == verdict
  assert resp.triage.recommended_action == action
  assert resp.clean_hand_off.escalation_action == action
  assert resp.triage.entities_to_quarantine == quarantine
  assert resp.triage.second_order_ran is True


@pytest.mark.anyio
@pytest.mark.parametrize("cri,expect_secondary", [(45, False), (46, True)])
async def test_secondary_sweep_cri_gate_is_the_harness_alertable_band(
    monkeypatch, mcp_session, cri, expect_secondary):
  radar = _radar(cri, is_outlier=False)
  radar["sector_z_scores"]["Auth"] = 1.0
  _patch_engine(monkeypatch, "RiskMetricsEngine", "run_360_behavioral_radar", radar)
  monkeypatch.setattr("src.autonomous_hunter.StrategyDecider.analyze_360_insights", MagicMock(return_value={}))
  planner = AsyncMock(return_value=None)
  monkeypatch.setattr("src.autonomous_hunter.StrategyDecider.decide_tier2_deep_dive", planner)
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", query="profile_360_risk", lookback_days=7)

  await AutonomousHunterEngine().execute_jit_hunt(req)

  assert planner.await_count == (1 if expect_secondary else 0)


# ---------------------------------------------------------------------------
# 4. Write-back and Mode A windows
# ---------------------------------------------------------------------------


def _fleet_tenant():
  return TenantConfig(project_id="test-proj", customer_id="test-cust", fleet_360_enabled=True,
                      fleet_360_ingest_events=True, fleet_360_spike_threshold_z=3.0)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "cri,expect_ingest",
    [(ht.writeback_cri_threshold() - 1, False), (ht.writeback_cri_threshold(), True), (None, False)],
)
async def test_case_360_udm_write_back_is_gated_by_the_harness_writeback_cri(
    monkeypatch, mcp_session, cri, expect_ingest):
  _patch_engine(monkeypatch, "RiskMetricsEngine", "run_360_behavioral_radar", _radar(cri, composite_d=3.6))
  build = MagicMock(return_value={"metadata": {}})
  ingest = MagicMock(return_value={"status": "SUCCESS"})
  monkeypatch.setattr("src.autonomous_hunter.RiskMetricsEngine.build_360_outlier_udm_event", build)
  monkeypatch.setattr("src.autonomous_hunter.RiskMetricsEngine.ingest_udm_events", ingest)
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", query="profile_360_risk", case_id="21558",
                       post_to_case_wall=True, lookback_days=7)

  resp = await AutonomousHunterEngine(_fleet_tenant()).execute_jit_hunt(req)

  assert resp.triage.primary_vector == "Auth_behavioral_drift"
  assert ingest.call_count == (1 if expect_ingest else 0)
  if expect_ingest:
    assert build.call_args.kwargs["composite_cri"] == cri


@pytest.mark.anyio
async def test_radar_without_evaluated_day_uses_the_mode_a_scored_day(monkeypatch, mcp_session):
  radar = _radar(75, composite_d=4.6)
  radar.pop("evaluated_day")
  _patch_engine(monkeypatch, "RiskMetricsEngine", "run_360_behavioral_radar", radar)
  build = MagicMock(return_value={"metadata": {}})
  monkeypatch.setattr("src.autonomous_hunter.RiskMetricsEngine.build_360_outlier_udm_event", build)
  monkeypatch.setattr("src.autonomous_hunter.RiskMetricsEngine.ingest_udm_events", MagicMock())
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", query="profile_360_risk", case_id="21558",
                       post_to_case_wall=True, lookback_days=7)

  resp = await AutonomousHunterEngine(_fleet_tenant()).execute_jit_hunt(req)

  day = ht.mode_a_day().isoformat()
  assert build.call_args.kwargs["evaluated_day"] == day
  assert resp.clean_hand_off.evaluated_window == day


@pytest.mark.anyio
async def test_radar_hand_off_reports_the_engine_evaluated_day(monkeypatch, mcp_session):
  _patch_engine(monkeypatch, "RiskMetricsEngine", "run_360_behavioral_radar", _radar(30))
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", query="profile_360_risk", lookback_days=7)

  resp = await AutonomousHunterEngine().execute_jit_hunt(req)

  assert resp.clean_hand_off.evaluated_window == "2026-10-29"


MACRO_FAST_PATHS = [
    pytest.param("cloud_crud", "run_cloud_crud_surge", _cloud, id="cloud_crud"),
    pytest.param("macd", "run_macd_momentum_velocity", _macd, id="macd"),
    pytest.param("sector_fusion", "run_sector_fusion", _fusion, id="sector_fusion"),
    pytest.param("dynamic_metric", "run_dynamic_metric_pipeline", _dyn, id="dynamic_metric"),
]


@pytest.mark.anyio
@pytest.mark.parametrize("engine_day", ["2026-10-28", None])
@pytest.mark.parametrize("query,method,builder", MACRO_FAST_PATHS)
async def test_macro_fast_path_hand_off_reports_the_mode_a_scored_day(
    monkeypatch, mcp_session, query, method, builder, engine_day):
  result = builder(72)
  if engine_day:
    result["evaluated_day"] = engine_day
  _patch_engine(monkeypatch, "RiskMetricsEngine", method, result)
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", query=query, lookback_days=7)

  resp = await AutonomousHunterEngine().execute_jit_hunt(req)

  assert resp.clean_hand_off.primary_model == "secops-risk-metrics-multistage"
  assert resp.clean_hand_off.evaluated_window == (engine_day or ht.mode_a_day().isoformat())


# ---------------------------------------------------------------------------
# 5. ReAct loop: Mode A / Entity Graph windows in the prompt, harness triage
# ---------------------------------------------------------------------------


class _FakeChat:

  def __init__(self, text):
    self.text = text
    self.prompts = []

  async def send_message(self, message):
    self.prompts.append(message)
    return SimpleNamespace(function_calls=None, text=self.text)


def _triage_text(payload):
  return f"#### 1. Statistical Outlier Report\nNarrative.\n\n```json_triage\n{json.dumps(payload)}\n```"


@pytest.mark.anyio
async def test_react_prompt_carries_mode_a_and_entity_graph_windows_and_triage_is_harness_derived(
    monkeypatch, mcp_session):
  mcp_session.list_tools = AsyncMock(return_value=SimpleNamespace(tools=[]))
  chat = _FakeChat(_triage_text(
      {"calibrated_risk_index": 72, "verdict": "CRITICAL_OUTLIER", "recommended_action": "LOCK_ACCOUNT",
       "entities_to_quarantine": [ENTITY], "primary_vector": "auth_spray"}))
  client = SimpleNamespace(aio=SimpleNamespace(chats=SimpleNamespace(create=lambda **kw: chat)))
  monkeypatch.setattr(AutonomousHunterEngine, "_get_genai_client", lambda self, tenant, model_name=None: client)
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER", query="assess identity behaviour",
                       case_id="31337", post_to_case_wall=True, lookback_days=7)

  resp = await AutonomousHunterEngine().execute_jit_hunt(req)

  prompt = chat.prompts[0]
  a_start, a_end = ht.mode_a_window()
  g_start, g_end = ht.ecg_window()
  for fragment in (a_start, a_end, g_start, g_end, ht.event_day_pin(), ht.RECOMMENDATION_NOTE):
    assert fragment in prompt
  assert resp.triage.verdict == "HIGH_OUTLIER"  # harness band for CRI 72, not the LLM's verdict string
  assert resp.triage.recommended_action == "INVESTIGATE"
  assert resp.triage.entities_to_quarantine == []
  assert ht.RECOMMENDATION_NOTE in resp.forensics.markdown_report
  posted = [c.args[1]["comment"] for c in mcp_session.call_tool.await_args_list if c.args[0] == "create_case_comment"]
  assert posted and "Recommendation only" in posted[-1]


@pytest.mark.parametrize("cri,verdict,kind", BOUNDARIES + [("N/A", "NOT_EVALUATED", "MONITOR")])
def test_react_json_triage_verdict_and_action_follow_harness_bands(cri, verdict, kind):
  payload = {"verdict": "CRITICAL_OUTLIER", "recommended_action": "LOCK_ACCOUNT", "top_z_score": 9.0}
  if cri is not None:
    payload["calibrated_risk_index"] = cri
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER")

  resp = AutonomousHunterEngine()._build_hunt_response(
      final_text=_triage_text(payload), executed_query="", radar_svg=None, case_wall_updated=False, req=req,
      skill_name="secops-risk-metrics-multistage")

  action = _expected_action(kind, "LOCK_ACCOUNT")
  assert resp.triage.verdict == verdict
  assert resp.triage.recommended_action == action
  assert resp.clean_hand_off.escalation_action == action
  assert resp.triage.is_outlier is (kind != "MONITOR")
  assert resp.triage.entities_to_quarantine == ([ENTITY] if kind == "CONTAIN" else [])
  assert ht.RECOMMENDATION_NOTE in resp.forensics.markdown_report


def test_react_critical_without_llm_containment_uses_generic_quarantine():
  req = JITHuntRequest(target_entity=ENTITY, entity_type="USER")
  resp = AutonomousHunterEngine()._build_hunt_response(
      final_text=_triage_text({"calibrated_risk_index": 95, "recommended_action": "MONITOR"}), executed_query="",
      radar_svg=None, case_wall_updated=False, req=req, skill_name="secops-statistical-hunter")
  assert resp.triage.verdict == "CRITICAL_OUTLIER"
  assert resp.triage.recommended_action == "QUARANTINE"


# ---------------------------------------------------------------------------
# 6. Federated bridge
# ---------------------------------------------------------------------------


def _bridge(monkeypatch, macro, micro=None):
  from src.federated_bridge import FederatedBridge

  bridge = FederatedBridge(TenantConfig(project_id="test-proj", customer_id="test-cust"))
  monkeypatch.setattr(bridge.risk_engine, "run_360_behavioral_radar", AsyncMock(return_value=macro))
  micro_mock = AsyncMock(return_value=micro)
  for name in ("run_markov_transition_rarity", "run_c2_beaconing_jitter", "run_poisson_rare_surge",
               "run_poisson_burst_clustering"):
    monkeypatch.setattr(bridge.stats_engine, name, micro_mock)
  return bridge, micro_mock


@pytest.mark.anyio
@pytest.mark.parametrize(
    "macro_cri,status,verdict",
    [(None, "NOT_EVALUATED", "NOT_EVALUATED"), ("N/A", "NOT_EVALUATED", "NOT_EVALUATED"),
     (25, "NOMINAL_BASELINE", "NOMINAL_BASELINE"), (45, "NOMINAL_BASELINE", "LOW_OUTLIER")],
)
async def test_bridge_stops_below_the_alertable_band_without_crashing_or_escalating(
    monkeypatch, macro_cri, status, verdict):
  bridge, micro = _bridge(monkeypatch, {"calibrated_risk_index": macro_cri, "top_z_score": 2.0, "top_sector": "Auth"})

  res = await bridge.run_two_phase_chained_hunt(session=AsyncMock(), username=ENTITY, macro_vector="360")

  micro.assert_not_awaited()
  assert res["status"] == status
  assert res["verdict"] == verdict
  assert res["recommended_action"] == "MONITOR"
  assert res["is_chained_threat"] is False
  assert res["recommendation_note"] == ht.RECOMMENDATION_NOTE


@pytest.mark.anyio
async def test_bridge_runs_micro_phase_from_the_medium_band(monkeypatch):
  bridge, micro = _bridge(monkeypatch, {"calibrated_risk_index": 46, "top_z_score": 3.0, "top_sector": "Auth"},
                          {"calibrated_risk_index": 20, "top_z_score": 0.5})

  res = await bridge.run_two_phase_chained_hunt(session=AsyncMock(), username=ENTITY, macro_vector="360")

  micro.assert_awaited_once()
  assert res["status"] == "MACRO_OUTLIER_UNVERIFIED_MICRO"
  assert res["is_chained_threat"] is False
  assert res["loopback_eligible"] is False


@pytest.mark.anyio
async def test_bridge_fused_cri_is_the_harness_cri_of_the_euclidean_norm(monkeypatch):
  bridge, _ = _bridge(monkeypatch, {"calibrated_risk_index": 78, "top_z_score": 4.5, "top_sector": "Web"},
                      {"calibrated_risk_index": 84, "top_z_score": 5.2})

  res = await bridge.run_two_phase_chained_hunt(session=AsyncMock(), username=ENTITY, macro_vector="http2shell")

  fused = ht.calculate_cri(math.sqrt(4.5 ** 2 + 5.2 ** 2))
  assert res["calibrated_risk_index"] == fused
  assert res["verdict"] == ht.verdict_for(fused) == "CRITICAL_OUTLIER"
  assert res["recommended_action"] == ht.recommended_action(fused, containment_action="ISOLATE_HOST_AND_REVOKE_TOKENS")
  assert res["status"] == "CHAINED_THREAT_CONFIRMED"
  assert res["recommendation_note"] == ht.RECOMMENDATION_NOTE


@pytest.mark.anyio
async def test_bridge_high_band_confirmed_threat_recommends_investigation_not_containment(monkeypatch):
  bridge, _ = _bridge(monkeypatch, {"calibrated_risk_index": 65, "top_z_score": 4.0, "top_sector": "Auth"},
                      {"calibrated_risk_index": 46, "top_z_score": 2.0})

  res = await bridge.run_two_phase_chained_hunt(session=AsyncMock(), username=ENTITY, macro_vector="360")

  fused = ht.calculate_cri(math.sqrt(4.0 ** 2 + 2.0 ** 2))
  assert res["status"] == "CHAINED_THREAT_CONFIRMED"
  assert res["calibrated_risk_index"] == fused
  assert res["verdict"] == "HIGH_OUTLIER"
  assert res["recommended_action"] == "INVESTIGATE"
  assert res["loopback_eligible"] is False  # 20.0 < the harness sum-Z^2 threshold


@pytest.mark.anyio
async def test_bridge_maps_non_z_micro_scores_through_the_score_semantics_registry(monkeypatch):
  bridge, _ = _bridge(monkeypatch, {"calibrated_risk_index": 50, "top_z_score": 3.0, "top_sector": "Egress"},
                      {"calibrated_risk_index": 70, "coefficient_of_variation": 0.1, "is_outlier": True})

  res = await bridge.run_two_phase_chained_hunt(session=AsyncMock(), username=ENTITY, macro_vector="shadow_ai")

  micro_z = ht.constants().score_to_z_equivalent("cv", 0.1)
  assert res["combined_norm_sq"] == round(3.0 ** 2 + micro_z ** 2, 2)
  assert res["calibrated_risk_index"] == ht.calculate_cri(math.sqrt(3.0 ** 2 + micro_z ** 2))


@pytest.mark.anyio
@pytest.mark.parametrize(
    "macro_z,micro_z,micro_cri,eligible",
    [(3.0, 4.0, 65, True), (3.5, 3.5, 57, False), (3.0, 4.6, 20, False)],
)
async def test_bridge_loopback_uses_harness_hits_and_sum_z_sq(monkeypatch, macro_z, micro_z, micro_cri, eligible):
  min_hits, sum_z_sq = ht.loopback_thresholds()
  bridge, _ = _bridge(monkeypatch, {"calibrated_risk_index": 50, "top_z_score": macro_z, "top_sector": "Auth"},
                      {"calibrated_risk_index": micro_cri, "top_z_score": micro_z})

  res = await bridge.run_two_phase_chained_hunt(session=AsyncMock(), username=ENTITY, macro_vector="360")

  hits = 1 + (1 if micro_cri >= 46 else 0)
  assert res["loopback_eligible"] is (hits >= min_hits and res["combined_norm_sq"] >= sum_z_sq) is eligible


# ---------------------------------------------------------------------------
# 7. Static guard: no raw CRI ladders or sigmoid copies left in the two files
# ---------------------------------------------------------------------------

_SRC = Path(__file__).resolve().parents[1] / "src"
_BRIEF_GATE = re.compile(r"(cri|score|risk)[a-z_]*\s*>=?\s*(80|60|90|70)\b")
_ANY_RAW_GATE = re.compile(r"\w*(?:cri|score|risk)\w*\)?\s*(?:>=|<=|>|<)\s*\d")


@pytest.mark.parametrize("filename", ["autonomous_hunter.py", "federated_bridge.py"])
def test_no_raw_cri_gates_or_local_sigmoid_remain(filename):
  source = (_SRC / filename).read_text()
  offending = [
      f"{i}: {line.strip()}" for i, line in enumerate(source.splitlines(), 1)
      if _BRIEF_GATE.search(line) or _ANY_RAW_GATE.search(line)
  ]
  assert not offending, "raw CRI/score gates must come from harness_truth:\n" + "\n".join(offending)
  assert "math.exp" not in source
  assert "harness_truth" in source

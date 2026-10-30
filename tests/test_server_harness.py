# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Server and tenant config read thresholds, verdicts, actions and retired models from harness_truth."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

from src import harness_truth as ht
from src.config import TenantConfig
from src.models import ForensicsSummary, JITHuntResponse, TriageSummary
import src.server as srv
from src.watchdog import WatchdogState


@pytest.fixture
def anyio_backend():
  return "asyncio"


@pytest.fixture
def hunt(tmp_path, monkeypatch):
  """Stubs the hunt engine and isolates watchdog state so no test reaches a tenant or data/."""
  monkeypatch.setattr(srv.watchdog, "state", WatchdogState(tmp_path / "server_state.json"))
  execute = AsyncMock(return_value=JITHuntResponse(
      status="SUCCESS",
      triage=TriageSummary(
          calibrated_risk_index=72.0, verdict="HIGH_OUTLIER", is_outlier=True,
          primary_vector="auth", top_z_score=4.6, recommended_action="INVESTIGATE"),
      forensics=ForensicsSummary(executed_query="stage s1 { ... }", markdown_report="# Report"),
  ))
  monkeypatch.setattr(srv.engine, "execute_jit_hunt", execute)
  return execute


def _request(path, body):
  raw = json.dumps(body).encode("utf-8")

  async def receive():
    return {"type": "http.request", "body": raw, "more_body": False}

  scope = {
      "type": "http", "method": "POST", "path": path, "query_string": b"",
      "headers": [(b"content-type", b"application/json")], "path_params": {},
  }
  return Request(scope, receive)


def _assert_not_evaluated(payload, message):
  assert payload["error_message"] == message
  assert payload["triage"]["calibrated_risk_index"] is None
  assert payload["triage"]["verdict"] == ht.verdict_for(None)
  assert payload["triage"]["recommended_action"] == ht.recommended_action(None)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "tool,kwargs,model",
    [
        ("hunt_circadian_von_mises", {"username": "alice"}, "CIRCADIAN_VON_MISES"),
        ("hunt_impossible_travel", {"username": "alice"}, "IMPOSSIBLE_TRAVEL_GEO_VELOCITY"),
    ],
)
async def test_retired_model_tools_return_the_skill_retirement_message(hunt, tool, kwargs, model):
  out = await getattr(srv, tool)(**kwargs)
  assert out["status"] == "RETIRED_MODEL"
  _assert_not_evaluated(out, ht.retirement_message(model))
  # Both skill messages name HOUR_OF_DAY_PROFILE; the response points to the tool that runs it here.
  assert out["replacement_model"] == "HOUR_OF_DAY_PROFILE"
  assert out["replacement_tool"] == "hunt_hour_of_day_profile"
  hunt.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize("tool", ["hunt_circadian_von_mises", "hunt_impossible_travel"])
async def test_retired_model_tools_never_run_a_hunt_even_without_a_registry_entry(hunt, monkeypatch, tool):
  """agentic_ueba has no execution path for these models: a stale skill mirror cannot revive the tools."""
  monkeypatch.setattr(ht, "retirement_message", lambda name: None)
  out = await getattr(srv, tool)(username="alice")
  assert out["status"] == "RETIRED_MODEL"
  assert out["triage"]["calibrated_risk_index"] is None
  hunt.assert_not_awaited()


@pytest.mark.anyio
async def test_hunt_hour_of_day_profile_tool_requests_the_stats_hunter_fast_path(hunt):
  from src.strategy_decider import StrategyDecider

  out = await srv.hunt_hour_of_day_profile(
      username="night.owl", case_id="12", lookback_days=10, post_to_case_wall=False)
  assert out["status"] == "SUCCESS"
  hunt.assert_awaited_once()
  req = hunt.await_args.args[0]
  assert req.query == StrategyDecider.MODEL_DIRECTIVE_QUERIES["HOUR_OF_DAY_PROFILE"] == "hour_of_day_profile"
  assert (req.target_entity, req.entity_type, req.skill) == ("night.owl", "USER", "stats-hunter")
  assert (req.case_id, req.lookback_days, req.post_to_case_wall) == ("12", 10, False)


@pytest.mark.anyio
async def test_hunt_hour_of_day_profile_tool_consults_the_harness_retirement_registry(hunt, monkeypatch):
  real = ht.retirement_message
  monkeypatch.setattr(
      ht, "retirement_message",
      lambda name: "retired for this test" if str(name).upper() == "HOUR_OF_DAY_PROFILE" else real(name))
  out = await srv.hunt_hour_of_day_profile(username="night.owl")
  assert out["status"] == "RETIRED_MODEL"
  _assert_not_evaluated(out, "retired for this test")
  hunt.assert_not_awaited()


@pytest.mark.anyio
async def test_model_tools_consult_the_harness_retirement_registry(hunt, monkeypatch):
  real = ht.retirement_message
  monkeypatch.setattr(
      ht, "retirement_message",
      lambda name: "retired for this test" if str(name).upper() == "SHANNON_ENTROPY_CHARACTER" else real(name))

  out = await srv.hunt_shannon_entropy(entity="host-1")
  assert out["status"] == "RETIRED_MODEL"
  _assert_not_evaluated(out, "retired for this test")
  hunt.assert_not_awaited()

  out = await srv.hunt_markov_transition(host="host-1")
  assert out["status"] == "SUCCESS"
  hunt.assert_awaited_once()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "kwargs,name",
    [
        ({"statistical_model": "PIECEWISE_CRI"}, "PIECEWISE_CRI"),
        ({"architecture": "hybrid_metric_orthogonal_space_2stage"}, "hybrid_metric_orthogonal_space_2stage"),
    ],
)
async def test_compile_hunt_pipeline_rejects_retired_models_before_compiling(monkeypatch, kwargs, name):
  import src.pipeline_runner as pipeline_runner

  def _unreachable(*args, **kwargs):
    raise AssertionError("the hybrid engine must not be reached for a retired model")

  monkeypatch.setattr(pipeline_runner.PipelineRunner, "get_hybrid_engine", _unreachable)
  out = await srv.compile_hunt_pipeline(**kwargs)
  assert out["status"] == "RETIRED_MODEL"
  assert out["error_message"] == ht.retirement_message(name)


@pytest.mark.anyio
async def test_jit_endpoint_error_triage_is_the_harness_not_evaluated_band(hunt):
  hunt.side_effect = RuntimeError("backend unavailable")
  resp = await srv.jit_playbook_endpoint(_request("/api/v1/hunt/jit", {"target_entity": "alice"}))
  assert resp.status_code == 500
  body = json.loads(resp.body.decode("utf-8"))
  assert body["status"] == "ERROR"
  _assert_not_evaluated(body, "backend unavailable")


@pytest.mark.anyio
async def test_jit_endpoint_rejects_retired_models(hunt):
  resp = await srv.jit_playbook_endpoint(
      _request("/api/v1/hunt/jit", {"target_entity": "alice", "query": "circadian_von_mises"}))
  assert resp.status_code == 400
  body = json.loads(resp.body.decode("utf-8"))
  assert body["status"] == "RETIRED_MODEL"
  _assert_not_evaluated(body, ht.retirement_message("CIRCADIAN_VON_MISES"))
  assert (body["replacement_model"], body["replacement_tool"]) == ("HOUR_OF_DAY_PROFILE", "hunt_hour_of_day_profile")
  hunt.assert_not_awaited()


@pytest.mark.anyio
async def test_micro_tool_directives_use_harness_score_thresholds(hunt, monkeypatch):
  registry = ht.constants().get_score_semantics
  overrides = {"cv": 0.15, "fano_factor": 5.5}
  stub = SimpleNamespace(get_score_semantics=lambda key: (
      SimpleNamespace(threshold=overrides[key]) if key in overrides else registry(key)))
  monkeypatch.setattr(ht, "constants", lambda: stub)

  await srv.hunt_c2_jitter(src_ip="10.0.0.9")
  directive = hunt.await_args.args[0].query
  assert "CV <= 0.15" in directive
  assert "min connections" not in directive  # left to the skill's sensitivity tier

  await srv.hunt_c2_jitter(src_ip="10.0.0.9", cv_threshold=0.1, min_conns=40)
  assert "CV <= 0.1 and min connections >= 40" in hunt.await_args.args[0].query

  await srv.hunt_poisson_burst(entity="bob")
  assert "Fano factor >= 5.5" in hunt.await_args.args[0].query


@pytest.mark.anyio
async def test_tool_descriptions_quote_harness_thresholds_and_retirements():
  tools = {t.name: t.description for t in await srv.mcp.list_tools()}
  semantics = ht.constants().get_score_semantics
  assert f"CV <= {semantics('cv').threshold}" in tools["hunt_c2_jitter"]
  assert f"F >= {semantics('fano_factor').threshold}" in tools["hunt_poisson_burst"]
  assert f">= {semantics('producer_ratio').threshold}" in tools["hunt_producer_consumer_inversion"]
  assert "0.80" not in tools["hunt_producer_consumer_inversion"]
  assert ht.retirement_message("CIRCADIAN_VON_MISES") in tools["hunt_circadian_von_mises"]
  assert ht.retirement_message("IMPOSSIBLE_TRAVEL_GEO_VELOCITY") in tools["hunt_impossible_travel"]
  assert "Above-Historical-Max Z" in tools["hunt_macd_momentum"]
  # Retired tools advertise only the refusal and the replacement tool, never the retired capability.
  for retired_tool in ("hunt_circadian_von_mises", "hunt_impossible_travel"):
    assert "hunt_hour_of_day_profile" in tools[retired_tool]
    for capability in ("von Mises clock", "geodesic", "km/h", "Evaluates", "Detects"):
      assert capability not in tools[retired_tool]
  assert "HOUR_OF_DAY_PROFILE" in tools["hunt_hour_of_day_profile"]
  assert f"hod_z_score >= {semantics('hod_z_score').threshold}" in tools["hunt_hour_of_day_profile"]


@pytest.mark.anyio
async def test_fleet_360_mcp_tool_defers_score_gates_to_tenant_config(monkeypatch):
  sweep = AsyncMock(return_value={"status": "SUCCESS"})
  monkeypatch.setattr(srv.watchdog, "run_fleet_360_sweep_once", sweep)
  await srv.run_fleet_360_sweep()
  kwargs = sweep.await_args.kwargs
  assert kwargs["spike_threshold_z"] is None
  assert kwargs["spoke_inclusion_z"] is None
  await srv.run_fleet_360_sweep(spike_threshold_z=4.0, spoke_inclusion_z=2.5)
  assert (sweep.await_args.kwargs["spike_threshold_z"], sweep.await_args.kwargs["spoke_inclusion_z"]) == (4.0, 2.5)


def test_fleet_360_score_gates_default_to_harness_sensitivity_tiers(monkeypatch):
  monkeypatch.delenv("FLEET_360_SPIKE_THRESHOLD_Z", raising=False)
  monkeypatch.delenv("FLEET_360_SPOKE_INCLUSION_Z", raising=False)
  c = ht.constants()
  tenant = TenantConfig()
  assert tenant.fleet_360_spike_threshold_z == c.resolve_sensitivity_thresholds()[1]["anomaly_threshold"]
  assert tenant.fleet_360_spoke_inclusion_z == (
      c.resolve_sensitivity_thresholds("HIGH_RECALL")[1]["anomaly_threshold"])

  # Sourced, not copied: a different harness yields different defaults.
  tiers = {"BALANCED": {"anomaly_threshold": 3.3}, "HIGH_RECALL": {"anomaly_threshold": 2.2}}
  stub = SimpleNamespace(resolve_sensitivity_thresholds=lambda tier=None, strict=False: (
      tier or "BALANCED", dict(tiers[tier or "BALANCED"])))
  monkeypatch.setattr(ht, "constants", lambda: stub)
  tenant = TenantConfig()
  assert (tenant.fleet_360_spike_threshold_z, tenant.fleet_360_spoke_inclusion_z) == (3.3, 2.2)

  # Explicit environment overrides still win.
  monkeypatch.setenv("FLEET_360_SPIKE_THRESHOLD_Z", "4.5")
  monkeypatch.setenv("FLEET_360_SPOKE_INCLUSION_Z", "2.75")
  tenant = TenantConfig()
  assert (tenant.fleet_360_spike_threshold_z, tenant.fleet_360_spoke_inclusion_z) == (4.5, 2.75)

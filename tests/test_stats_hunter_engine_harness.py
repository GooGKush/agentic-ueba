# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
"""StatsHunterEngine applies the remediated secops-statistical-hunter harness.

Every template the engine renders is the skill's current template (rendered by the skill's own
MultiStageTemplateRouter) and passes PipelineRunner.validate_ast; CRI, verdicts, retirements,
windows and caps come from src/harness_truth.py; EWMA, Shannon and C2 jitter are scored by the
skill's vetted Python helpers (D6) over the raw udm_search payload.
"""

from datetime import datetime, timedelta, timezone
import math
import re

import pytest

from src import harness_truth as ht
from src.config import get_skills_root
from src.stats_hunter_engine import StatsHunterEngine

SH = ht.STATS_HUNTER_SKILL


@pytest.fixture
def anyio_backend():
  return "asyncio"


class _FakeSecOps:
  """Stands in for PipelineRunner.execute_query_via_mcp (4 positional args) and records every dispatch."""

  def __init__(self, payload=None):
    self.payload = payload if payload is not None else {}
    self.calls = []

  async def __call__(self, session, query, start_iso, end_iso):
    self.calls.append({"query": query, "start": start_iso, "end": end_iso})
    if callable(self.payload):
      return self.payload(query, start_iso, end_iso)
    return self.payload


def _engine(monkeypatch, payload=None):
  engine = StatsHunterEngine()
  fake = _FakeSecOps(payload)
  monkeypatch.setattr(engine.runner, "execute_query_via_mcp", fake)
  return engine, fake


def _epoch(iso: str) -> int:
  return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


def _cell(value):
  if isinstance(value, bool):
    return {"value": {"boolVal": value}}
  if isinstance(value, int):
    return {"value": {"int64Val": str(value)}}
  if isinstance(value, float):
    return {"value": {"doubleVal": value}}
  if isinstance(value, list):
    return {"list": {"values": [
        {"int64Val": str(v)} if isinstance(v, int) else {"stringVal": str(v)} for v in value
    ]}}
  return {"value": {"stringVal": str(value)}}


def _columnar(rows):
  """Chronicle udm_search columnar `stats` payload (the raw wire format the helpers require)."""
  columns = list(rows[0].keys())
  return {"stats": {"results": [
      {"column": col, "values": [_cell(r[col]) for r in rows]} for col in columns
  ]}}


def _stage_blocks(query: str):
  return re.findall(r"stage\s+([a-zA-Z0-9_]+)\s*\{([^}]*)\}", query, flags=re.DOTALL)


def _root_section(query: str) -> str:
  blocks = list(re.finditer(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", query, flags=re.DOTALL))
  return query[blocks[-1].end():] if blocks else query


def _template_stage_names(template_file: str):
  text = (get_skills_root() / SH / "templates" / "pipelines" / template_file).read_text(encoding="utf-8")
  return re.findall(r"stage\s+([a-zA-Z0-9_]+)\s*\{", text)


def _assert_current_template_and_valid(engine, query: str, template_file: str):
  assert "{{" not in query and "}}" not in query
  assert engine.runner.validate_ast(query, skill=SH) == []
  for name in _template_stage_names(template_file):
    assert f"stage {name} {{" in query, f"{template_file}: stage {name} missing"


# ---------------------------------------------------------------------------
# Every template the engine uses is the current skill template and passes validate_ast
# ---------------------------------------------------------------------------

ENGINE_TEMPLATES = [
    ("run_c2_beaconing_jitter", {"src_ip": "10.10.20.55"}, "c2_beaconing_jitter_2stage.yl2"),
    ("run_poisson_burst_clustering", {"entity": "spray.victim"}, "poisson_burst_clustering_2stage.yl2"),
    ("run_poisson_rare_surge", {"entity": "admin.rare"}, "poisson_rare_surge_2stage.yl2"),
    ("run_markov_transition_rarity", {"host": "wkstn-markov-01"}, "markov_2gram_transition_rarity_2stage.yl2"),
    ("run_shannon_character_entropy", {"entity": "wkstn-entropy-01"}, "shannon_entropy_character_2stage.yl2"),
    ("run_zipfian_process_rarity", {"host": "wkstn-zipf-01"}, "zipfian_process_rarity_2stage.yl2"),
    ("run_ewma_burst_velocity", {"entity": "10.20.30.99"}, "ewma_burst_velocity_2stage.yl2"),
    ("run_producer_consumer_inversion", {"hostname": "wkstn-pivot-09"},
     "producer_consumer_ratio_inversion_2stage.yl2"),
    ("run_iqr_tukey_skew_fences", {"entity": "wks-dev-01"}, "iqr_tukey_skew_fences_3stage.yl2"),
    ("run_hour_of_day_profile", {"entity": "night.owl"}, "hour_of_day_profile_3stage.yl2"),
]


@pytest.mark.anyio
@pytest.mark.parametrize("method,kwargs,template_file", ENGINE_TEMPLATES)
async def test_engine_methods_render_current_templates_that_pass_validate_ast(
    monkeypatch, method, kwargs, template_file):
  engine, fake = _engine(monkeypatch)
  result = await getattr(engine, method)(None, **kwargs)
  assert len(fake.calls) == 1
  query = fake.calls[0]["query"]
  assert result["executed_query"] == query
  assert result["template"] == template_file
  _assert_current_template_and_valid(engine, query, template_file)
  # Zero rows is a nominal baseline: CRI 0, never an invented score.
  assert result["calibrated_risk_index"] == 0
  assert result["verdict"] == "NOMINAL_BASELINE"
  assert result["is_outlier"] is False


@pytest.mark.anyio
async def test_dynamic_pipeline_renders_every_active_stats_hunter_template(monkeypatch):
  engine, fake = _engine(monkeypatch)
  router = engine._get_stats_hunter_builder().MultiStageTemplateRouter()
  failures = []
  for template_file, archetype in sorted(router.TEMPLATE_TO_SENSITIVITY_KEY.items()):
    fake.calls.clear()
    result = await engine.run_dynamic_archetype_pipeline(
        None, entity="wks-eng-01", archetype=archetype, entity_type="ASSET", lookback_days=7)
    query = fake.calls[0]["query"]
    try:
      assert result["template"] == template_file
      _assert_current_template_and_valid(engine, query, template_file)
    except AssertionError as exc:
      failures.append(f"{archetype}: {exc}")
  assert not failures, "\n".join(failures)


@pytest.mark.anyio
async def test_engine_queries_are_rendered_by_the_skill_router(monkeypatch):
  """No hand-filled placeholder dictionaries: the skill's own router renders the template."""
  engine, fake = _engine(monkeypatch)
  await engine.run_markov_transition_rarity(None, host="wkstn-markov-01", lookback_days=7)
  call = fake.calls[0]
  expected = engine._get_stats_hunter_builder().MultiStageTemplateRouter().build_query(
      archetype="MARKOV_2GRAM_TRANSITION_RARITY",
      tier="BALANCED",
      entity_type="host",
      window_hours=7 * 24.0,
      start_time=call["start"],
      end_time=call["end"],
      target_entity_value="wkstn-markov-01",
  )
  assert call["query"] == expected


# ---------------------------------------------------------------------------
# Retired models
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_retired_impossible_travel_refuses_with_the_skill_message(monkeypatch):
  engine, fake = _engine(monkeypatch)
  with pytest.raises(ValueError) as exc:
    await engine.run_impossible_travel_velocity(None, user_id="traveler.user")
  assert str(exc.value) == ht.retirement_message("IMPOSSIBLE_TRAVEL_GEO_VELOCITY")
  for alias in ("IMPOSSIBLE_TRAVEL_GEO_VELOCITY", "impossible_travel", "GEO_VELOCITY", "SUPERSONIC_TRAVEL"):
    with pytest.raises(ValueError) as exc:
      await engine.run_dynamic_archetype_pipeline(None, archetype=alias)
    assert str(exc.value) == ht.retirement_message(alias)
  assert fake.calls == []


# ---------------------------------------------------------------------------
# CRI, verdict and outlier classification come from harness_truth
# ---------------------------------------------------------------------------

TEMPLATE_SCORE_CASES = [
    ("run_markov_transition_rarity", {"host": "wkstn-markov-01"},
     {"host": "wkstn-markov-01", "parent": "C:\\Office\\winword.exe", "child": "C:\\Windows\\powershell.exe",
      "markov_threat_score": 4.8, "transition_launches": 1, "window_parent_launches": 120},
     "markov_threat_score", 4.8),
    ("run_zipfian_process_rarity", {"host": "wkstn-zipf-01"},
     {"host": "wkstn-zipf-01", "binary": "C:\\Temp\\adfind.exe", "zipf_rarity_score": 4.5, "adopter_hosts": 1},
     "zipf_rarity_score", 4.5),
    ("run_poisson_burst_clustering", {"entity": "spray.victim"},
     {"entity": "spray.victim", "fano_factor": 6.5, "observation_count": 40},
     "fano_factor", 6.5),
    ("run_poisson_rare_surge", {"entity": "admin.rare"},
     {"entity": "admin.rare", "tool": "vssadmin.exe", "poisson_z_sq": 16.0, "observation_count": 9},
     "poisson_z_sq", 16.0),
    ("run_producer_consumer_inversion", {"hostname": "wkstn-pivot-09"},
     {"entity": "wkstn-pivot-09", "z_score": 4.3, "producer_ratio": 0.92},
     "z_score", 4.3),
]


@pytest.mark.anyio
@pytest.mark.parametrize("method,kwargs,row,score_key,score", TEMPLATE_SCORE_CASES)
async def test_cri_verdict_and_outlier_come_from_harness_truth(monkeypatch, method, kwargs, row, score_key, score):
  c = ht.constants()
  engine, _ = _engine(monkeypatch, {"stats": [row]})
  result = await getattr(engine, method)(None, **kwargs)
  cri = c.cri_from_model_score(score_key, score)
  assert result["score_metric"] == score_key
  assert result["primary_score"] == score
  assert result["calibrated_risk_index"] == cri
  assert result["top_z_score"] == round(c.score_to_z_equivalent(score_key, score), 2)
  assert result["verdict"] == ht.verdict_for(cri)
  assert result["cri_band"] == ht.cri_band(cri)[0]
  assert result["is_outlier"] is (ht.cri_band(cri)[0] in ("MEDIUM", "HIGH", "CRITICAL"))
  assert result["stats_rows"] == 1


@pytest.mark.anyio
async def test_model_specific_result_fields(monkeypatch):
  engine, _ = _engine(monkeypatch, {"stats": [TEMPLATE_SCORE_CASES[3][2]]})
  rare = await engine.run_poisson_rare_surge(None, entity="admin.rare")
  assert rare["poisson_z"] == 4.0  # sqrt(poisson_z_sq)
  assert rare["model"] == "POISSON_RARE_SURGE"

  engine, _ = _engine(monkeypatch, {"stats": [TEMPLATE_SCORE_CASES[0][2]]})
  markov = await engine.run_markov_transition_rarity(None, host="wkstn-markov-01")
  assert markov["model"] == "MARKOV_2GRAM_TRANSITION_RARITY"
  assert markov["markov_threat_score"] == 4.8
  assert markov["surprisal_score"] == 4.8  # the template's Laplace-smoothed surprisal is the threat score
  assert markov["parent_process"].endswith("winword.exe")
  assert markov["child_process"].endswith("powershell.exe")

  engine, _ = _engine(monkeypatch, {"stats": [TEMPLATE_SCORE_CASES[4][2]]})
  pcr = await engine.run_producer_consumer_inversion(None, hostname="wkstn-pivot-09")
  assert pcr["pcr_z_score"] == 4.3
  assert pcr["producer_ratio"] == 0.92


@pytest.mark.anyio
async def test_rows_without_the_model_score_are_not_evaluated(monkeypatch):
  engine, _ = _engine(monkeypatch, {"stats": [{"host": "wkstn-markov-01", "parent": "a", "child": "b"}]})
  result = await engine.run_markov_transition_rarity(None, host="wkstn-markov-01")
  assert result["calibrated_risk_index"] is None
  assert result["verdict"] == "NOT_EVALUATED"
  assert result["is_outlier"] is False


@pytest.mark.anyio
async def test_iqr_tukey_skew_fences_scores_the_scale_invariant_fence_z(monkeypatch):
  c = ht.constants()
  engine, fake = _engine(monkeypatch, {"stats": [
      {"entity": "wks-dev-01", "fence_z": 4.2, "surge_ratio": 3.85, "bowley_skew": 0.52, "tail_heaviness": 2.95}]})
  result = await engine.run_iqr_tukey_skew_fences(None, entity="wks-dev-01", lookback_days=30)
  assert "$fence_z" in fake.calls[0]["query"]
  assert result["model"] == "IQR_TUKEY_SKEW_FENCES"
  assert result["score_metric"] == "fence_z"
  assert result["calibrated_risk_index"] == c.cri_from_model_score("fence_z", 4.2)
  assert result["top_z_score"] == round(c.score_to_z_equivalent("fence_z", 4.2), 2)
  assert result["is_outlier"] is True


# ---------------------------------------------------------------------------
# Windows: Mode A day boundary, micro-plane cap, Entity Graph D-2 anchoring
# ---------------------------------------------------------------------------


def test_raw_windows_end_at_the_mode_a_boundary_and_respect_the_micro_cap():
  cap = ht.mode_caps()["mode_b_micro_days"]
  assert StatsHunterEngine.enforce_telemetry_physics_window(cap + 16) == cap
  assert StatsHunterEngine.enforce_telemetry_physics_window(3) == 3
  engine = StatsHunterEngine()
  assert engine._iso_window(1) == ht.mode_a_window()
  start, end = engine._iso_window(30)
  assert end == ht.mode_a_window()[1]
  assert _epoch(end) - _epoch(start) == cap * 86400


@pytest.mark.anyio
async def test_entity_graph_hunts_start_at_d_minus_2_with_scoring_pinned_to_the_window(monkeypatch):
  engine, fake = _engine(monkeypatch)
  await engine.run_dynamic_archetype_pipeline(
      None, entity="*", archetype="DERIVED_CONTEXT_DOMAIN_PREVALENCE", entity_type="ASSET", lookback_days=1)
  call = fake.calls[0]
  day = ht.mode_a_day()
  assert (call["start"], call["end"]) == ht.ecg_window(day)
  day_start, day_end = ht.mode_a_window(day)
  assert "$in_scoring_window" in call["query"]
  assert f">= {_epoch(day_start)}" in call["query"]
  assert f"< {_epoch(day_end)}" in call["query"]


# ---------------------------------------------------------------------------
# Entity binding: the skill's target-entity binding (fleet templates at root, self-baselines in stage 1)
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_fleet_templates_bind_the_target_at_root_and_self_baselines_in_raw_stages(monkeypatch):
  engine, fake = _engine(monkeypatch)
  await engine.run_zipfian_process_rarity(None, host="wkstn-zipf-01")
  zipf_q = fake.calls[-1]["query"]
  assert '$host = "wkstn-zipf-01"' in _root_section(zipf_q)
  assert all("wkstn-zipf-01" not in body for _, body in _stage_blocks(zipf_q))  # fleet prevalence intact

  await engine.run_producer_consumer_inversion(None, hostname="wkstn-pivot-09")
  pcr_q = fake.calls[-1]["query"]
  assert any('principal.asset.hostname = "wkstn-pivot-09"' in body for _, body in _stage_blocks(pcr_q))

  await engine.run_c2_beaconing_jitter(None, src_ip="10.10.20.55")
  assert '$src_ip = "10.10.20.55"' in _root_section(fake.calls[-1]["query"])


# ---------------------------------------------------------------------------
# D6 vetted Python helpers (EWMA, Shannon, C2 jitter) over the raw udm_search payload
# ---------------------------------------------------------------------------


def _ewma_payload(entity: str):
  baseline = [5, 6, 5, 4, 6, 5, 5, 6, 4, 5, 6, 5]
  burst = [5, 6, 20, 30, 40, 45, 50, 55, 60, 60, 60, 60]

  def build(query, start_iso, end_iso):
    t0 = _epoch(start_iso)
    rows = [
        {"entity": entity, "ws": t0 + i * 3600, "window_events": n, "fleet_prevalence": 4, "distinct_binaries": 2}
        for i, n in enumerate(baseline + burst)
    ]
    return _columnar(rows)
  return build


@pytest.mark.anyio
async def test_ewma_burst_velocity_is_scored_by_the_vetted_ewma_helper(monkeypatch):
  engine, fake = _engine(monkeypatch, _ewma_payload("10.20.30.99"))
  result = await engine.run_ewma_burst_velocity(None, entity="10.20.30.99", lookback_days=1)
  call = fake.calls[0]
  builder = engine._get_stats_hunter_builder()
  control_l = builder.SENSITIVITY_MAP["EWMA_BURST_VELOCITY"]["BALANCED"]["velocity_threshold"]
  expected = engine.runner.get_micro_python_helpers().run_ewma_helper(
      _ewma_payload("10.20.30.99")(call["query"], call["start"], call["end"]),
      query_text=call["query"], start_time=call["start"], end_time=call["end"],
      control_l=control_l, bucket_seconds=3600)
  top = expected["entity_results"][0]
  assert result["model"] == "EWMA_BURST_VELOCITY"
  assert result["helper"]["provenance"] == expected["provenance"]
  assert result["ewma_velocity_score"] == round(top["ewma_z"], 2)
  assert result["calibrated_risk_index"] == top["cri"]
  assert result["is_outlier"] is True
  assert result["verdict"] == ht.verdict_for(top["cri"])


def _shannon_payload():
  benign = [
      "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule",
      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe --type=renderer",
      "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
      "C:\\Windows\\System32\\taskhostw.exe Install $(Arg0)",
      "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE /recycle",
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -File update.ps1",
  ]
  candidate = "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
  rows = [{"token": t, "sample_entities": ["h1", "h2", "h3", "h4", "h5"], "host_prevalence": 5,
           "token_events": 50, "raw_length": len(t), "distinct_binaries": 1} for t in benign]
  rows.append({"token": candidate, "sample_entities": ["wkstn-entropy-01"], "host_prevalence": 1,
               "token_events": 1, "raw_length": len(candidate), "distinct_binaries": 1})
  return _columnar(rows), candidate


@pytest.mark.anyio
async def test_shannon_entropy_is_scored_by_the_vetted_shannon_helper(monkeypatch):
  payload, candidate = _shannon_payload()
  engine, fake = _engine(monkeypatch, payload)
  result = await engine.run_shannon_character_entropy(None, entity="wkstn-entropy-01")
  query = fake.calls[0]["query"]
  builder = engine._get_stats_hunter_builder()
  min_length = builder.SENSITIVITY_MAP["SHANNON_ENTROPY_CHARACTER"]["BALANCED"]["min_length"]
  expected = engine.runner.get_micro_python_helpers().run_shannon_helper(
      payload, query_text=query, min_length=min_length,
      z_threshold=ht.constants().DEFAULT_ANOMALY_THRESHOLD)
  top = expected["candidate_results"][0]
  assert top["token"] == candidate
  assert result["model"] == "SHANNON_ENTROPY_CHARACTER"
  assert result["sample_token"] == candidate
  assert result["shannon_entropy_score"] == round(top["entropy_bits"], 2)
  assert result["shannon_z"] == round(top["shannon_z"], 2)
  assert result["calibrated_risk_index"] == top["cri"]
  assert result["helper"]["provenance"] == expected["provenance"]
  assert result["is_outlier"] is (ht.cri_band(top["cri"])[0] in ("MEDIUM", "HIGH", "CRITICAL"))
  assert "principal.process.command_line" in query  # token_field slot default


def _c2_payload():
  rows = []
  base = 1_761_696_000
  for hour in range(3):
    ts = [base + hour * 3600 + k * 300 + (7 if k % 2 else -7) for k in range(12)]
    rows.append({"src_ip": "10.10.20.55", "dst_ip": "198.51.100.42", "ws": base + hour * 3600,
                 "event_timestamps": ts, "bucket_conns": 12, "total_conns": 36, "active_hours": 3,
                 "fleet_prevalence": 1, "distinct_binaries": 1})
  for hour in range(2):
    ts = [base + hour * 3600 + k * 600 for k in range(6)]
    rows.append({"src_ip": "10.10.20.55", "dst_ip": "10.1.2.3", "ws": base + hour * 3600,
                 "event_timestamps": ts, "bucket_conns": 6, "total_conns": 12, "active_hours": 2,
                 "fleet_prevalence": 1, "distinct_binaries": 1})
  return _columnar(rows)


@pytest.mark.anyio
async def test_c2_beaconing_jitter_is_scored_by_the_vetted_c2_jitter_helper(monkeypatch):
  engine, fake = _engine(monkeypatch, _c2_payload())
  result = await engine.run_c2_beaconing_jitter(None, src_ip="10.10.20.55")
  query = fake.calls[0]["query"]
  builder = engine._get_stats_hunter_builder()
  max_cv = builder.SENSITIVITY_MAP["C2_BEACONING_JITTER"]["BALANCED"]["cv"]
  expected = engine.runner.get_micro_python_helpers().run_c2_jitter_helper(
      _c2_payload(), query_text=query, max_cv=max_cv)
  top = expected["pair_results"][0]
  assert top["dst_ip"] == "198.51.100.42"
  assert result["model"] == "C2_BEACONING_JITTER"
  assert result["target_destination"] == "198.51.100.42"
  assert result["coefficient_of_variation"] == round(top["cv"], 3)
  assert result["is_beaconing"] is True
  assert result["calibrated_risk_index"] == top["cri"]
  assert result["is_outlier"] is True
  # RFC1918 / loopback / multicast / link-local destinations are excluded by the template and the helper.
  assert {"src_ip": "10.10.20.55", "dst_ip": "10.1.2.3"} in result["helper"]["skipped_non_external_destinations"]
  for cidr in ("10.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "169.254.0.0/16", "fe80::/10"):
    assert cidr in query


@pytest.mark.anyio
async def test_helper_models_fail_closed_on_malformed_payloads(monkeypatch):
  # D6 G2: a non-Chronicle payload is rejected, never silently scored.
  engine, _ = _engine(monkeypatch, {"stats": [{"entity": "10.20.30.99", "ewma_velocity_score": 9.9}]})
  with pytest.raises(ValueError, match="G2_"):
    await engine.run_ewma_burst_velocity(None, entity="10.20.30.99", lookback_days=1)


@pytest.mark.anyio
async def test_insufficient_helper_evidence_is_not_evaluated_rather_than_nominal(monkeypatch):
  # C2: rows exist but no external pair has enough consecutive intervals -> N/A, not a clean CRI 0.
  sparse = _columnar([{"src_ip": "10.10.20.55", "dst_ip": "198.51.100.42", "ws": 1_761_696_000,
                       "event_timestamps": [1_761_696_000, 1_761_696_300], "bucket_conns": 2}])
  engine, _ = _engine(monkeypatch, sparse)
  c2 = await engine.run_c2_beaconing_jitter(None, src_ip="10.10.20.55")
  assert c2["calibrated_risk_index"] is None
  assert c2["verdict"] == "NOT_EVALUATED"
  assert c2["is_outlier"] is False
  assert c2["helper"]["skipped_insufficient_intervals"]

  # Shannon: a rare candidate without >= 3 benign reference strings cannot be standardized.
  payload, _ = _shannon_payload()
  rows = payload["stats"]["results"]
  thin = {"stats": {"results": [{"column": col["column"], "values": col["values"][-3:]} for col in rows]}}
  engine, _ = _engine(monkeypatch, thin)
  shannon = await engine.run_shannon_character_entropy(None, entity="wkstn-entropy-01")
  assert shannon["calibrated_risk_index"] is None
  assert shannon["verdict"] == "NOT_EVALUATED"
  assert "INSUFFICIENT_BENIGN_LENGTH_COHORT" in shannon["not_evaluated_reason"]


@pytest.mark.anyio
async def test_dynamic_pipeline_routes_helper_models_to_their_helpers(monkeypatch):
  engine, _ = _engine(monkeypatch, _c2_payload())
  result = await engine.run_dynamic_archetype_pipeline(
      None, entity="10.10.20.55", archetype="C2_BEACONING_JITTER", entity_type="IP")
  assert result["model"] == "C2_BEACONING_JITTER"
  assert result["helper"]["provenance"]["helper_name"] == "c2-jitter"
  assert result["is_outlier"] is True
  assert not math.isnan(result["top_z_score"])

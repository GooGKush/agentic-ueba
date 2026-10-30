# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit tests for deterministic Risk Metrics, Stats Hunter, and Hybrid pipeline engines."""

import math
from pathlib import Path
import pytest

from src.config import get_skills_root
from src.pipeline_runner import PipelineRunner
from src.risk_metrics_engine import RiskMetricsEngine
from src.stats_hunter_engine import StatsHunterEngine


def test_cri_sigmoid_math():
  runner = PipelineRunner()
  # At Z = 3.0 sigma, CRI must equal 50
  assert runner.calculate_cri(3.0) == 50
  # At Z <= 0.0 sigma, CRI is 0 (harness zero floor, ueba_constants.calculate_cri / D5)
  assert runner.calculate_cri(0.0) == 0
  # At Z = 4.5 sigma, CRI must be high outlier (>= 71)
  assert runner.calculate_cri(4.5) >= 71
  # At extreme Z, must reach high saturation
  assert runner.calculate_cri(10.0) >= 98
  assert runner.calculate_cri(15.0) == 100


def test_composite_euclidean_distance():
  runner = PipelineRunner()
  # 3-4-5 Pythagorean triangle across 2 sectors: D = sqrt(3^2 + 4^2) = 5.0
  z_scores = {"Auth": 3.0, "Cloud": 4.0, "Egress": 0.0}
  d = runner.compute_euclidean_distance(z_scores)
  assert pytest.approx(d, 0.01) == 5.0


def test_risk_metrics_radar_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-risk-metrics-multistage", "radar_360_decoupled_sector.yl2")
  rendered = runner.render_template(tpl, {})
  
  assert "metrics.auth_attempts_total" in rendered
  assert "order:" in rendered
  assert "by 1d" in rendered
  assert "$user = $auth_risk.user" in rendered


def test_stats_hunter_c2_jitter_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-statistical-hunter", "c2_beaconing_jitter_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_type": "NETWORK_CONNECTION",
      "entity_field": "principal.ip",
      "event_filter": "",
      "min_conns": "30",
      "max_conns": "500",
      "min_active_hours": "3",
      "prevalence": "5",
      "tier": "STANDARD",
      "bucket_size": "1h",
      "cv": "0.20",
  })
  
  assert 'metadata.event_type = "NETWORK_CONNECTION"' in rendered
  assert "not net.ip_in_range_cidr" in rendered
  # WS5/WS6-04: loopback, multicast, broadcast and link-local destinations are excluded too.
  for cidr in ("127.0.0.0/8", "224.0.0.0/4", "169.254.0.0/16", "fe80::/10"):
    assert cidr in rendered
  assert "{{min_conns}}" not in rendered
  assert "{{max_conns}}" not in rendered
  assert "cv <= 0.20" in rendered.lower() or "cv" in rendered.lower()
  assert runner.validate_ast(rendered, skill="secops-statistical-hunter") == []


def test_hybrid_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-risk-metrics-multistage", "hybrid_metric_raw_enrichment_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "macro_event_type": "USER_LOGIN",
      "macro_entity_field": "target.user.userid",
      "macro_event_filter": 'target.user.userid = "frank.kolzig"',
      "macro_observed_agg": "count(metadata.id)",
      "target_metric_func_avg": "metrics.auth_attempts_total(agg: avg, period: 1d, window: 30d)",
      "target_metric_func_stddev": "metrics.auth_attempts_total(agg: stddev, period: 1d, window: 30d)",
      "target_metric_func_active_days": "30",
      "raw_event_type": "USER_LOGIN",
      "raw_entity_field": "target.user.userid",
      "raw_event_filter": 'target.user.userid = "frank.kolzig"',
      "raw_signature_field": "principal.ip",
      "anomaly_threshold": "3.0",
      "min_baseline_days": "14",
      "min_raw_events": "5",
      "max_signature_diversity": "3",
  })
  
  assert "stage1_macro_baseline" in rendered
  assert "stage2_raw_telemetry" in rendered
  assert "count_distinct(principal.ip)" in rendered
  assert "DUAL-PLANE HYBRID METRIC" in rendered
  assert "{{macro_event_type}}" not in rendered


def test_circadian_von_mises_template_rendering():
  """CIRCADIAN_VON_MISES is retired (skill v2.3.0 D1 / PF-10): the template is gone and the engine refuses.

  The refusal carries the skill's own retirement message, which hands off to secops-statistical-hunter
  HOUR_OF_DAY_PROFILE (daily metrics.* baselines carry no per-hour circadian state).
  """
  import asyncio
  from src import harness_truth

  runner = PipelineRunner()
  message = harness_truth.retirement_message("circadian_von_mises_2stage.yl2")
  assert message and "HOUR_OF_DAY_PROFILE" in message
  # PipelineRunner.find_template refuses a retired template with the skill's own message (pointing to
  # HOUR_OF_DAY_PROFILE) before looking for the file, so the refusal is a ValueError, not FileNotFoundError.
  with pytest.raises(ValueError, match="retired") as find_exc:
    runner.find_template("secops-risk-metrics-multistage", "circadian_von_mises_2stage.yl2")
  assert str(find_exc.value) == message

  engine = RiskMetricsEngine()
  with pytest.raises(ValueError) as exc:
    asyncio.run(engine.run_circadian_von_mises(None, "frank.kolzig"))
  assert str(exc.value) == message
  with pytest.raises(ValueError, match="HOUR_OF_DAY_PROFILE"):
    asyncio.run(engine.run_dynamic_metric_pipeline(None, "frank.kolzig", model_name="CIRCADIAN_VON_MISES"))


def test_macd_momentum_velocity_template_rendering():
  """MACD_MOMENTUM_VELOCITY is relabelled Above-Historical-Max Z (skill v2.3.0 D1 / WS1-02).

  macd_momentum_velocity_2stage.yl2 keeps its file name; the dual-spine fast/slow Z became a personal Z
  plus a linear exceedance above the 30-day maximum, gated on the 7-active-day maturity floor.
  """
  from src import harness_truth

  runner = PipelineRunner()
  tpl = runner.find_template("secops-risk-metrics-multistage", "macd_momentum_velocity_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_filter": "network.sent_bytes > 0",
      "entity_field": "principal.user.userid",
      "observed_aggregation": "sum(network.sent_bytes)",
      "target_metric_name": "network_bytes_outbound",
      "metric_type_val": "value_sum",
      "dimension_key": "principal.user.userid",
      "extra_dimensions": "",
      "min_baseline_days": harness_truth.min_baseline_days(),
      "anomaly_threshold": 3.0,
  })
  assert "ABOVE-HISTORICAL-MAX Z" in rendered
  assert "MACD DUAL-SPINE" not in rendered
  assert "metrics.network_bytes_outbound" in rendered
  assert "$macd_momentum_score" in rendered and "$above_max_z" in rendered
  assert "$fast_z" not in rendered and "$slow_z" not in rendered
  assert _unfilled(rendered) == []
  assert _root_gate(rendered) == f"$active_days >= {harness_truth.min_baseline_days()} and $macd_z >= 3.0"


def test_markov_2gram_transition_rarity_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-statistical-hunter", "markov_2gram_transition_rarity_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_type": "PROCESS_LAUNCH",
      "entity_field": "principal.hostname",
      "bucket_size": "1d",
      "min_parent_count": "5",
      "surprisal_threshold": "3.5",
      "vocab_smooth": "100.0",
      "tier": "STANDARD",
  })
  # WS5: whole-window Laplace-smoothed surprisal with the {{vocab_smooth}} slot.
  assert "Laplace-Smoothed Markov 2-Gram" in rendered
  assert "principal.process.file.full_path" in rendered
  assert "$markov_threat_score" in rendered
  assert "{{min_parent_count}}" not in rendered
  assert "{{vocab_smooth}}" not in rendered
  assert runner.validate_ast(rendered, skill="secops-statistical-hunter") == []


def test_shannon_entropy_character_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-statistical-hunter", "shannon_entropy_character_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_type": "PROCESS_LAUNCH",
      "entity_field": "principal.hostname",
      "token_field": "principal.process.command_line",
      "event_filter": "",
      "min_length": "20",
      "tier": "STANDARD",
  })
  # WS5/WS6-03: ungated token extractor on the {{token_field}} slot; exact per-character entropy is
  # computed by scripts/micro_python_helpers.py shannon, not in-query.
  assert "Length-Normalized Per-Character Shannon Entropy" in rendered
  assert "strings.length" in rendered
  assert "$host_prevalence" in rendered
  assert "micro_python_helpers.py shannon" in rendered
  assert "{{token_field}}" not in rendered
  assert runner.validate_ast(rendered, skill="secops-statistical-hunter") == []


def test_zipfian_process_rarity_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-statistical-hunter", "zipfian_process_rarity_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_type": "PROCESS_LAUNCH",
      "entity_field": "principal.hostname",
      "bucket_size": "1d",
      "max_adopters": "2",
      "min_count": "1",
      "min_fleet_hosts": "10",
      "zipf_threshold": "3.5",
      "tier": "STANDARD",
  })
  # WS5: host-prevalence inverse document frequency ln(N_fleet / H) with the {{min_fleet_hosts}} floor.
  assert "Zipfian long tail" in rendered
  assert "fleet_process_popularity" in rendered
  assert "$zipf_rarity_score" in rendered
  assert "{{max_adopters}}" not in rendered
  assert "{{min_fleet_hosts}}" not in rendered
  assert runner.validate_ast(rendered, skill="secops-statistical-hunter") == []


def test_ewma_burst_velocity_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-statistical-hunter", "ewma_burst_velocity_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_type": "NETWORK_CONNECTION",
      "entity_field": "principal.ip",
      "event_filter": "",
      "bucket_size": "1h",
      "min_active_samples": "3",
      "min_count": "5",
      "tier": "STANDARD",
  })
  # WS6-02: ungated bucketed series extractor; the recursive EWMA is computed by
  # scripts/micro_python_helpers.py ewma (in-query approximation lives in BURST_Z_SCREEN).
  assert "Exponentially Weighted Moving Average Control Chart" in rendered
  assert "stage entity_hourly" in rendered
  assert "stage entity_prefilter" in rendered
  assert "$window_events" in rendered
  assert "micro_python_helpers.py ewma" in rendered
  assert "{{min_active_samples}}" not in rendered
  assert runner.validate_ast(rendered, skill="secops-statistical-hunter") == []


def test_strategy_decider_routing_all_new_models():
  from src.strategy_decider import StrategyDecider

  # 1. C2 Beaconing
  skill, query, model = StrategyDecider.decide("", "Beaconing to Suspicious IP", "Periodic jitter detected", "IP")
  assert skill == "secops-statistical-hunter"
  assert model == "C2_BEACONING_JITTER"

  # 2. Poisson Spray
  skill, query, model = StrategyDecider.decide("", "Password Spray Attack", "Poisson burst of failed logins", "USER")
  assert skill == "secops-statistical-hunter"
  assert model == "POISSON_BURST_CLUSTERING"

  # 3. Shannon Entropy (current stats-hunter archetype name)
  skill, query, model = StrategyDecider.decide("", "Obfuscated Command Line", "High Shannon entropy base64 payload", "HOST")
  assert skill == "secops-statistical-hunter"
  assert model == "SHANNON_ENTROPY_CHARACTER"

  # 4. Markov 2-gram Transition (current stats-hunter archetype name)
  skill, query, model = StrategyDecider.decide("", "Unusual Process Parent Child", "Rare LotL Markov transition", "HOST")
  assert skill == "secops-statistical-hunter"
  assert model == "MARKOV_2GRAM_TRANSITION_RARITY"

  # 5. Zipfian Rare Binary
  skill, query, model = StrategyDecider.decide("", "Rare Binary Execution", "Long tail rare admin tool in fleet", "HOST")
  assert skill == "secops-statistical-hunter"
  assert model == "ZIPFIAN_PROCESS_RARITY"

  # 6. EWMA Kinetic Burst
  skill, query, model = StrategyDecider.decide("", "Kinetic Rate Acceleration", "EWMA burst velocity divergence", "IP")
  assert skill == "secops-statistical-hunter"
  assert model == "EWMA_BURST_VELOCITY"

  # 7. Off-hours / circadian -> learned 24-bin HOUR_OF_DAY_PROFILE (CIRCADIAN_VON_MISES retired, D1 / PF-10)
  skill, query, model = StrategyDecider.decide("", "Off-Hours Login Surge", "Circadian temporal anomaly after hours", "USER")
  assert skill == "secops-statistical-hunter"
  assert model == "HOUR_OF_DAY_PROFILE"

  # 8. MACD label -> Above-Historical-Max Z (risk-metrics v2.3.0 honest rename)
  skill, query, model = StrategyDecider.decide("", "MACD Momentum Velocity Divergence", "Acceleration surge outbound bytes", "USER")
  assert skill == "secops-risk-metrics-multistage"
  assert model == "ABOVE_HISTORICAL_MAX_Z"

  # 9. Cloud CRUD Surge
  skill, query, model = StrategyDecider.decide("", "Cloud IAM Surge", "Cloud permission and resource_creation changes", "USER")
  assert skill == "secops-risk-metrics-multistage"
  assert model == "CLOUD_CRUD_SURGE"

  # 10. User 360 Radar
  skill, query, model = StrategyDecider.decide("", "Insider Data Hoarding", "Unusual access across sectors", "USER")
  assert skill == "secops-risk-metrics-multistage"
  assert model == "360_DECOUPLED_RADAR"

  # 11. File IoC / Dropper on Endpoint IP -> Zipfian Process Rarity
  skill, query, model = StrategyDecider.decide(
      case_title="ATI High Priority Rule Match for File IoCs (target.file.sha256)",
      alert_name="ATI HIGH PRIORITY RULE MATCH FOR FILE IOCS (TARGET.FILE.SHA256)",
      alert_desc="AgentTesla malware dropper binary delivered via HTTP",
      entity_type="IP",
  )
  assert skill == "secops-statistical-hunter"
  assert model == "ZIPFIAN_PROCESS_RARITY"

  # 12. Credential Stealer on User Identity -> Poisson Burst Clustering
  skill, query, model = StrategyDecider.decide(
      case_title="",
      alert_name="AgentTesla Credential Stealer Activity",
      alert_desc="Harvested credentials attempted against single sign-on portal",
      entity_type="USER",
  )
  assert skill == "secops-statistical-hunter"
  assert model == "POISSON_BURST_CLUSTERING"


def test_parse_stats_response():
  runner = PipelineRunner()
  # 1. Protobuf StatsData structure
  proto_resp = {
      "stats": {
          "results": [
              {
                  "column": "$z",
                  "values": [{"value": {"doubleVal": 4.2}}, {"value": {"doubleVal": 1.1}}]
              },
              {
                  "column": "$user",
                  "values": [{"value": {"stringVal": "alice"}}, {"value": {"stringVal": "bob"}}]
              }
          ]
      }
  }
  rows = runner.parse_stats_response(proto_resp)
  assert len(rows) == 2
  assert rows[0]["z"] == 4.2
  assert rows[0]["user"] == "alice"
  assert rows[1]["z"] == 1.1
  assert rows[1]["user"] == "bob"

  # 2. List format
  list_resp = {"stats": [{"z": 3.0, "user": "carol"}]}
  rows2 = runner.parse_stats_response(list_resp)
  assert len(rows2) == 1
  assert rows2[0]["z"] == 3.0

  # 3. Empty or missing stats
  assert runner.parse_stats_response({}) == []
  assert runner.parse_stats_response({"stats": None}) == []
  assert runner.parse_stats_response({"stats": {}}) == []


@pytest.fixture
def anyio_backend():
  return "asyncio"


@pytest.mark.anyio
async def test_deterministic_jit_hunt_radar_fast_path(monkeypatch):
  from unittest.mock import AsyncMock, MagicMock
  from src.autonomous_hunter import AutonomousHunterEngine
  from src.models import JITHuntRequest

  engine = AutonomousHunterEngine()
  req = JITHuntRequest(
      target_entity="test_user",
      entity_type="USER",
      query="profile_360_risk",
      lookback_days=7,
  )

  # Mock RiskMetricsEngine
  mock_radar_res = {
      "entity": "test_user",
      "composite_d": 4.5,
      "calibrated_risk_index": 71,
      "top_sector": "Auth",
      "is_outlier": True,
      "sector_z_scores": {"Auth": 4.5, "Cloud": 0.0, "Workspace": 0.0, "Egress": 0.0, "DNS": 0.0},
      "sector_observed_counts": {"Auth": 100, "Cloud": 0, "Workspace": 0, "Egress": 0, "DNS": 0},
      "verdict": "HIGH_OUTLIER",
  }

  async def mock_run_radar(*args, **kwargs):
    return mock_radar_res

  monkeypatch.setattr(
      "src.autonomous_hunter.RiskMetricsEngine.run_360_behavioral_radar",
      mock_run_radar,
  )

  # Mock mcp_context
  mock_session = AsyncMock()
  mock_session.initialize = AsyncMock()
  
  class MockContext:
    async def __aenter__(self):
      return (AsyncMock(), AsyncMock())
    async def __aexit__(self, *args):
      pass

  monkeypatch.setattr("src.autonomous_hunter.streamable_http_client", lambda *args, **kwargs: MockContext())
  monkeypatch.setattr("src.autonomous_hunter.ClientSession", lambda *args, **kwargs: mock_session)
  monkeypatch.setattr("src.config.TenantConfig.get_auth_headers", lambda self: {"Authorization": "Bearer test"})

  resp = await engine.execute_jit_hunt(req)
  assert resp.status == "SUCCESS"
  assert resp.triage.calibrated_risk_index == 71
  assert resp.triage.verdict == "HIGH_OUTLIER"
  assert resp.triage.primary_vector == "Auth_behavioral_drift"
  assert resp.forensics.radar_svg is not None
  assert "<svg" in resp.forensics.radar_svg


def test_sanitize_case_comment():
  from src.autonomous_hunter import AutonomousHunterEngine

  raw = (
      '```json_triage\\n{\\n  \\"version\\": \\"1.0\\",\\n  \\"verdict\\": \\"NOMINAL_BASELINE\\"\\n}\\n```\\n\\n'
      '#### 1. Statistical Outlier Report: Rare Process Execution Prevalence\\n'
      '- **Target Entity**: `timaddler-pc`\\n'
      '- **CRI**: 0 / 100'
  )
  clean = AutonomousHunterEngine.sanitize_case_comment(raw)
  assert "json_triage" not in clean
  assert "\\n" not in clean
  assert '{\n  "version"' not in clean
  assert "<h4>1. Statistical Outlier Report: Rare Process Execution Prevalence</h4>" in clean
  assert "<li><strong>Target Entity</strong>: <code>timaddler-pc</code></li>" in clean
  assert "<li><strong>CRI</strong>: 0 / 100</li>" in clean
  assert "style=" not in clean
  assert "class=" not in clean


def test_case_wall_card_to_soar_html():
  from src.formatters.case_wall_card import CaseWallCardFormatter
  from src.strategy_decider import StrategyDecider

  directive = StrategyDecider.decide_tier1_360(
      target_entity="tim.smith",
      entity_type="USER",
      case_id="20794",
      case_title="Workspace File Download Surge",
  )
  sector_rows = [
      {
          "metric": "**Auth Sector** (`auth_attempts_total`)",
          "observed": "Z = +0.00 (0 events)",
          "threshold": "|Z| <= 2.0σ",
          "assessment": "✅ Nominal Baseline",
      },
      {
          "metric": "**Workspace Sector** (`workspace_total_download_actions`)",
          "observed": "Z = +3.45 (42 events)",
          "threshold": "|Z| <= 2.0σ",
          "assessment": "⚠️ Significant Behavioral Drift",
      },
  ]
  md_card = CaseWallCardFormatter.format_card(
      target_entity="tim.smith",
      entity_type="USER",
      model_name="360_DECOUPLED_RADAR",
      calibrated_risk_index=65.0,
      is_outlier=True,
      case_id="20794",
      rows_count=42,
      directive=directive,
      metrics_table_rows=sector_rows,
  )
  soar_html = CaseWallCardFormatter.to_soar_html(md_card)

  # Verify semantic HTML tags and table structure
  assert "<h3>🛡️ Tier 1 360° Behavioral Radar: <code>tim.smith</code></h3>" in soar_html
  assert '<table border="1" cellpadding="6" cellspacing="0" width="100%">' in soar_html
  assert '<th align="left">Metric / Dimension</th>' in soar_html
  assert "<td><strong>Auth Sector</strong> (<code>auth_attempts_total</code>)</td>" in soar_html
  # Verify |Z| in table cell was preserved without splitting into extra columns
  assert "<td>∣Z∣ &lt;= 2.0σ</td>" in soar_html
  # Verify LaTeX ($H_0$, $H_1$) converted to HTML subscripts
  assert "H<sub>0</sub>" in soar_html
  assert "H<sub>1</sub>" in soar_html
  assert "$H_0$" not in soar_html
  assert "| :--- |" not in soar_html
  # Verify safevalues DEFAULT_SANITIZER_TABLE compliance (no style/class attributes, no stray newlines)
  assert "style=" not in soar_html
  assert "class=" not in soar_html
  assert "\n" not in soar_html
  # Verify idempotency
  assert CaseWallCardFormatter.to_soar_html(soar_html) == soar_html


@pytest.mark.anyio
async def test_deterministic_jit_hunt_circadian_fast_path(monkeypatch):
  # CIRCADIAN_VON_MISES is retired in the remediated harness (metrics.* has only daily baselines);
  # the skill's retirement message hands off-hours hunts to secops-statistical-hunter's
  # HOUR_OF_DAY_PROFILE, so the circadian alert now runs that model instead of the retired one.
  from unittest.mock import AsyncMock
  from src.autonomous_hunter import AutonomousHunterEngine
  from src.models import JITHuntRequest

  engine = AutonomousHunterEngine()
  req = JITHuntRequest(
      target_entity="night_owl_user",
      entity_type="USER",
      alert_name="Circadian Off-Hours Activity",
      lookback_days=14,
  )

  mock_hod = {
      "entity": "night_owl_user",
      "entity_type": "USER",
      "model": "HOUR_OF_DAY_PROFILE",
      "score_metric": "hod_z_score",
      "primary_score": 4.8,
      "top_z_score": 4.8,
      "calibrated_risk_index": 75,
      "is_outlier": True,
      "stats_rows": 1,
      "executed_query": "// Hour-of-Day Profile Query",
  }

  retired_circadian = AsyncMock(return_value={"calibrated_risk_index": 99})
  run_hod = AsyncMock(return_value=mock_hod)
  monkeypatch.setattr("src.autonomous_hunter.RiskMetricsEngine.run_circadian_von_mises", retired_circadian)
  monkeypatch.setattr("src.autonomous_hunter.StatsHunterEngine.run_dynamic_archetype_pipeline", run_hod)

  mock_session = AsyncMock()
  mock_session.initialize = AsyncMock()
  mock_session.__aenter__.return_value = mock_session
  # Fail fast instead of reaching the live Gemini ReAct loop if the deterministic path is skipped.
  mock_session.list_tools = AsyncMock(side_effect=AssertionError("circadian alert fell through to the ReAct loop"))
  class MockContext:
    async def __aenter__(self):
      return (AsyncMock(), AsyncMock())
    async def __aexit__(self, *args):
      pass

  monkeypatch.setattr("src.autonomous_hunter.streamable_http_client", lambda *args, **kwargs: MockContext())
  monkeypatch.setattr("src.autonomous_hunter.ClientSession", lambda *args, **kwargs: mock_session)
  monkeypatch.setattr("src.config.TenantConfig.get_auth_headers", lambda self: {"Authorization": "Bearer test"})

  # Keep this unit test hermetic: if no deterministic fast path matches the
  # decided directive, execute_jit_hunt falls through to the live Gemini ReAct
  # loop. Fail fast instead of calling Vertex AI (or hanging the suite).
  def _no_live_gemini(*args, **kwargs):
    raise RuntimeError("unit test must not reach the live Gemini ReAct fallback")

  monkeypatch.setattr(AutonomousHunterEngine, "_get_genai_client", _no_live_gemini)

  resp = await engine.execute_jit_hunt(req)
  assert resp.status == "SUCCESS"
  retired_circadian.assert_not_awaited()
  assert run_hod.await_args.kwargs["archetype"] == "HOUR_OF_DAY_PROFILE"
  assert resp.triage.calibrated_risk_index == 75
  assert resp.triage.verdict == "HIGH_OUTLIER"
  assert resp.triage.primary_vector == "hour_of_day_login_anomaly"
  assert resp.clean_hand_off.outlier_topology == "HOUR_OF_DAY_PROFILE_DEPARTURE"


@pytest.mark.anyio
async def test_deterministic_jit_hunt_markov_fast_path(monkeypatch):
  from unittest.mock import AsyncMock
  from src.autonomous_hunter import AutonomousHunterEngine
  from src.models import JITHuntRequest

  engine = AutonomousHunterEngine()
  req = JITHuntRequest(
      target_entity="workstation-99",
      entity_type="HOST",
      alert_name="Living off the Land Markov Chain",
      lookback_days=7,
  )

  mock_markov = {
      "entity": "workstation-99",
      "model": "MARKOV_TRANSITION_RARITY",
      "markov_threat_score": 5.2,
      "surprisal_score": 4.1,
      "parent_process": "word.exe",
      "child_process": "powershell.exe",
      "top_z_score": 5.2,
      "calibrated_risk_index": 82,
      "is_outlier": True,
      "stats_rows": 1,
      "executed_query": "// Markov Query",
  }

  async def mock_run_markov(*args, **kwargs):
    return mock_markov

  monkeypatch.setattr("src.autonomous_hunter.StatsHunterEngine.run_markov_transition_rarity", mock_run_markov)

  mock_session = AsyncMock()
  mock_session.initialize = AsyncMock()
  class MockContext:
    async def __aenter__(self):
      return (AsyncMock(), AsyncMock())
    async def __aexit__(self, *args):
      pass

  monkeypatch.setattr("src.autonomous_hunter.streamable_http_client", lambda *args, **kwargs: MockContext())
  monkeypatch.setattr("src.autonomous_hunter.ClientSession", lambda *args, **kwargs: mock_session)
  monkeypatch.setattr("src.config.TenantConfig.get_auth_headers", lambda self: {"Authorization": "Bearer test"})

  resp = await engine.execute_jit_hunt(req)
  assert resp.status == "SUCCESS"
  assert resp.triage.calibrated_risk_index == 82
  # Remediated harness bands (26/46/70/90): CRI 82 is High Threat -> analyst investigation;
  # the domain containment recommendation (ISOLATE_HOST) is reserved for Critical (>= 90).
  assert resp.triage.verdict == "HIGH_OUTLIER"
  assert resp.triage.primary_vector == "markov_process_transition_rarity"
  assert resp.triage.recommended_action == "INVESTIGATE"


@pytest.mark.anyio
async def test_two_tier_strategy_decider():
  from src.strategy_decider import StrategyDecider

  # Tier 1 Baseline Directive
  t1 = StrategyDecider.decide_tier1_360(
      target_entity="target.analyst",
      entity_type="USER",
      case_id="case-999",
      case_title="Phishing Investigation",
  )
  assert t1.selected_skill == "secops-risk-metrics-multistage"
  assert t1.model_name == "360_DECOUPLED_RADAR"
  assert t1.investigation_tier == "TIER_1_BASELINE"
  assert len(t1.recommended_avenues) >= 2
  assert "Tier 1 360° Behavioral Radar" in t1.flight_card_title

  # Tier 2 Deep Dive: Egress Outlier
  t2_egress = await StrategyDecider.decide_tier2_deep_dive(
      target_entity="target.analyst",
      entity_type="USER",
      outlier_vector="Egress",
      case_info={"id": "case-999", "title": "C2 Beaconing Investigation"},
      alerts=[{"name": "Suspected Beaconing", "description": "Regular interval outbound connection"}],
      connector_events=[],
  )
  assert t2_egress.selected_skill == "secops-statistical-hunter"
  assert t2_egress.model_name == "C2_BEACONING_JITTER"
  assert t2_egress.investigation_tier == "TIER_2_DEEP_DIVE"
  assert t2_egress.outlier_vector == "Egress"
  assert len(t2_egress.recommended_avenues) >= 2

  # Tier 2 Deep Dive: Auth Outlier
  t2_auth = await StrategyDecider.decide_tier2_deep_dive(
      target_entity="target.analyst",
      entity_type="USER",
      outlier_vector="Auth",
      case_info={"id": "case-999", "title": "Auth Spray Investigation"},
      alerts=[{"name": "Failed Login Waves", "description": "Poisson burst spray"}],
      connector_events=[],
  )
  assert t2_auth.selected_skill == "secops-statistical-hunter"
  assert t2_auth.model_name == "POISSON_BURST_CLUSTERING"
  assert t2_auth.investigation_tier == "TIER_2_DEEP_DIVE"

  # Tier 2 Deep Dive: Cloud Outlier
  t2_cloud = await StrategyDecider.decide_tier2_deep_dive(
      target_entity="sa-deployer@proj.iam.gserviceaccount.com",
      entity_type="USER",
      outlier_vector="Cloud",
      case_info={"id": "case-999", "title": "IAM Privilege Escalation"},
      alerts=[{"name": "Resource Written Surge", "description": "Key minting"}],
      connector_events=[],
  )
  assert t2_cloud.selected_skill == "secops-risk-metrics-multistage"
  assert t2_cloud.model_name == "CLOUD_CRUD_SURGE"
  assert t2_cloud.investigation_tier == "TIER_2_DEEP_DIVE"


def test_case_wall_card_two_tier_and_avenues():
  from src.formatters.case_wall_card import CaseWallCardFormatter
  from src.models import StrategyDirective

  directive = StrategyDirective(
      selected_skill="secops-statistical-hunter",
      model_name="C2_BEACONING_JITTER",
      directive_query="c2_jitter",
      target_entity="igw-ecs-bridge",
      entity_type="ASSET",
      investigation_tier="TIER_2_DEEP_DIVE",
      outlier_vector="Egress",
      threat_summary="Robotic polling detected.",
      hypothesis_h0="Benign background traffic.",
      hypothesis_h1="Automated C2 polling.",
      selection_rationale="Evaluated CV regularity.",
      flight_card_title="C2 Beaconing Jitter Analysis: `igw-ecs-bridge`",
      recommended_avenues=[
          "Inspect outbound firewall logs for destination IP.",
          "Check process execution tree spawning network socket.",
          "Isolate endpoint if beaconing persists.",
      ],
  )

  card = CaseWallCardFormatter.format_card(
      target_entity="igw-ecs-bridge",
      entity_type="ASSET",
      model_name="C2_BEACONING_JITTER",
      calibrated_risk_index=75.0,
      is_outlier=True,
      case_id="case-20730",
      rows_count=42,
      directive=directive,
  )

  assert "Tier 2: Targeted Deep Dive (Egress)" in card
  assert "### 🧭 Recommended Avenues to Pursue" in card
  assert "1. Inspect outbound firewall logs for destination IP." in card
  assert "2. Check process execution tree spawning network socket." in card
  assert "3. Isolate endpoint if beaconing persists." in card
  assert "### 🔬 Investigation Hypotheses & Model Selection" in card


@pytest.mark.anyio
async def test_host_360_radar_query_generation(monkeypatch):
  from unittest.mock import AsyncMock, MagicMock
  from src.risk_metrics_engine import RiskMetricsEngine
  from src.config import TenantConfig

  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  engine = RiskMetricsEngine(tenant)

  captured_queries = []

  async def mock_execute(session, query, start_iso, end_iso):
    captured_queries.append(query)
    mock_res = MagicMock()
    mock_res.content = [MagicMock(text='{"stats": [{"z": 2.5, "obs": 15}]}')]
    return mock_res

  monkeypatch.setattr(engine.runner, "execute_query_via_mcp", mock_execute)

  mock_session = AsyncMock()
  res = await engine.run_360_behavioral_radar(
      session=mock_session,
      username="workstation-corp-01",
      lookback_days=7,
      entity_type="ASSET",
  )

  assert res["entity"] == "workstation-corp-01"
  assert len(captured_queries) == 6  # Auth, Egress, DNS, Flows, Alerts, Web
  # Verify host-specific UDM predicates and v1.8.0 baseline-aligned metrics are used
  assert any("principal.asset.hostname" in q for q in captured_queries)
  assert any("metrics.auth_attempts_fail" in q for q in captured_queries)
  assert any("metrics.network_bytes_outbound" in q for q in captured_queries)
  assert any("metrics.dns_queries_fail" in q for q in captured_queries)
  assert any("metrics.http_queries_total" in q for q in captured_queries)


@pytest.mark.anyio
async def test_situational_non_auth_non_network_metric_selection():
  from src.strategy_decider import StrategyDecider

  # 1. Workspace Outlier -> selects workspace_total_download_actions + MACD & Cross-Vector Fusion candidate
  t2_ws = await StrategyDecider.decide_tier2_deep_dive(
      target_entity="insider.user",
      entity_type="USER",
      outlier_vector="Workspace",
      case_info={"id": "case-ws-1", "title": "Google Drive Mass Download"},
      alerts=[{"name": "Workspace Exfiltration", "description": "Spike in Google Drive file downloads"}],
      connector_events=[],
  )
  assert t2_ws.selected_skill == "secops-risk-metrics-multistage"
  assert t2_ws.target_metric == "workspace_total_download_actions"
  assert t2_ws.confidence_score >= StrategyDecider.TIER_2A_AUTO_EXECUTE_THRESHOLD
  assert t2_ws.confidence_band == "AUTO_EXECUTE"
  assert any("workspace_total_download_actions" in c.fusion_metrics for c in t2_ws.candidate_hypotheses)

  # 2. Web / HTTP Proxy Outlier -> selects http_queries_total or http_queries_fail
  t2_web = await StrategyDecider.decide_tier2_deep_dive(
      target_entity="scraper.user",
      entity_type="USER",
      outlier_vector="Web",
      case_info={"id": "case-web-1", "title": "Anomalous Web Proxy Activity"},
      alerts=[{"name": "HTTP Proxy Surge", "description": "Unusual HTTP user_agent and URI scraping"}],
      connector_events=[],
  )
  assert t2_web.selected_skill == "secops-risk-metrics-multistage"
  assert t2_web.target_metric in ("http_queries_total", "http_queries_fail")
  assert t2_web.confidence_score >= StrategyDecider.TIER_2A_AUTO_EXECUTE_THRESHOLD

  # 3. DNS Outlier -> selects dns_queries_fail with LONGITUDINAL_CUSUM (current risk-metrics model name)
  t2_dns = await StrategyDecider.decide_tier2_deep_dive(
      target_entity="10.20.30.40",
      entity_type="IP",
      outlier_vector="DNS",
      case_info={"id": "case-dns-1", "title": "NXDOMAIN Resolution Surge"},
      alerts=[{"name": "DNS Failure Spike", "description": "Elevated dns_queries_fail count"}],
      connector_events=[],
  )
  assert t2_dns.selected_skill == "secops-risk-metrics-multistage"
  assert t2_dns.model_name == "LONGITUDINAL_CUSUM"
  assert t2_dns.target_metric == "dns_queries_fail"


@pytest.mark.anyio
async def test_sector_fusion_and_rollup_fusion_generation(monkeypatch):
  from unittest.mock import AsyncMock, MagicMock
  from src.risk_metrics_engine import RiskMetricsEngine
  from src.config import TenantConfig

  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  engine = RiskMetricsEngine(tenant)
  captured_queries = []

  async def mock_execute(session, query, start_iso, end_iso):
    captured_queries.append(query)
    return {"stats": [{"composite_threat_score": 4.6, "sector_a_z": 3.4, "sector_b_z": 3.1}]}

  monkeypatch.setattr(engine.runner, "execute_query_via_mcp", mock_execute)
  mock_session = AsyncMock()

  # 1. Entity-keyed Dual-Sector Fusion: workspace_total_download_actions + network_bytes_outbound
  res_dual = await engine.run_sector_fusion(
      session=mock_session,
      entity="alice.smith",
      fusion_metrics=["workspace_total_download_actions", "network_bytes_outbound"],
      lookback_days=7,
  )
  assert res_dual["template_name"] == "dual_sector_fusion_3stage.yl2"
  assert res_dual["is_outlier"] is True
  assert "metrics.workspace_total_download_actions" in res_dual["executed_query"]
  assert "metrics.network_bytes_outbound" in res_dual["executed_query"]
  assert 'alice.smith' in res_dual["executed_query"]

  # 2. Composite Roll-Up Sector Fusion: resource_creation_total (composite) + auth_attempts_fail (entity-keyed)
  res_rollup = await engine.run_sector_fusion(
      session=mock_session,
      entity="bob.devops",
      fusion_metrics=["resource_creation_total", "auth_attempts_fail"],
      lookback_days=7,
  )
  assert res_rollup["template_name"] == "rollup_sector_fusion_4stage.yl2"
  assert "metrics.resource_creation_total" in res_rollup["executed_query"]
  assert "metrics.auth_attempts_fail" in res_rollup["executed_query"]
  assert 'bob.devops' in res_rollup["executed_query"]


def test_confidence_scale_and_anti_runaway_guardrails():
  from src.strategy_decider import StrategyDecider

  radar_res = {
      "sector_z_scores": {"Workspace": 3.8, "Egress": 3.2, "Auth": 0.1, "DNS": 0.0},
      "sector_observed_counts": {"Workspace": 45, "Egress": 12000, "Auth": 2, "DNS": 0},
      "outlier_sectors": ["Workspace", "Egress"],
  }
  ctx = {
      "case_title": "Workspace Exfiltration",
      "case_description": "User downloaded sensitive files from Google Drive",
      "alerts": ["Drive Download Surge"],
      "udm_event_types": ["USER_RESOURCE_ACCESS"],
      "rule_generators": [],
      "threat_associations": [],
  }

  # 1. High-Confidence Tier 2A Hypothesis -> AUTO_EXECUTE (>= 0.75)
  score, band, breakdown = StrategyDecider.score_hypothesis_confidence(
      model_name="MACD_MOMENTUM_VELOCITY",
      target_metric="workspace_total_download_actions",
      outlier_vector="Workspace",
      ctx=ctx,
      radar_result=radar_res,
  )
  assert score >= 0.75
  assert band == "AUTO_EXECUTE"
  assert "Tier1_Workspace_Z=+3.80σ" in breakdown

  # 2. Duplicate Signature Veto -> 0.00 SUPPRESSED
  sig = StrategyDecider.build_signature("MACD_MOMENTUM_VELOCITY", "workspace_total_download_actions", [])
  score_dup, band_dup, _ = StrategyDecider.score_hypothesis_confidence(
      model_name="MACD_MOMENTUM_VELOCITY",
      target_metric="workspace_total_download_actions",
      outlier_vector="Workspace",
      ctx=ctx,
      radar_result=radar_res,
      executed_signatures={sig},
  )
  assert score_dup == 0.0
  assert band_dup == "SUPPRESSED"

  # 3. Zero-Telemetry Family Lockout -> 0.10 SUPPRESSED
  score_empty, band_empty, _ = StrategyDecider.score_hypothesis_confidence(
      model_name="LONGITUDINAL_CUSUM_DRIFT",
      target_metric="dns_queries_fail",
      outlier_vector="DNS",
      ctx=ctx,
      radar_result=radar_res,
      empty_families={"DNS"},
  )
  assert score_empty == 0.10
  assert band_empty == "SUPPRESSED"


@pytest.mark.anyio
async def test_bounded_tier2a_to_tier2b_epistemic_pivot_auto_execution(monkeypatch):
  from unittest.mock import AsyncMock
  from src.autonomous_hunter import AutonomousHunterEngine
  from src.models import JITHuntRequest

  engine = AutonomousHunterEngine()
  req = JITHuntRequest(
      target_entity="compromised_user",
      entity_type="USER",
      case_id="case-pivot-777",
      alert_name="Suspicious Outbound Data Transfer",
      alert_description="Elevated network egress and Workspace download activity",
      query="profile_360_risk",
      lookback_days=7,
      post_to_case_wall=True,
  )

  # Tier 1 360° Radar returns Egress (Z=3.9) and Workspace (Z=3.4) outliers
  mock_radar_res = {
      "entity": "compromised_user",
      "composite_d": 5.17,
      "calibrated_risk_index": 82,
      "top_sector": "Egress",
      "is_outlier": True,
      "outlier_sectors": ["Egress", "Workspace"],
      "sector_z_scores": {"Auth": 0.2, "Cloud": 0.0, "Workspace": 3.4, "Egress": 3.9, "DNS": 0.1, "Web": 0.0},
      "sector_observed_counts": {"Auth": 5, "Cloud": 0, "Workspace": 42, "Egress": 500, "DNS": 10, "Web": 0},
      "sector_metrics": {
          "Auth": "auth_attempts_fail",
          "Cloud": "resource_creation_total",
          "Workspace": "workspace_total_download_actions",
          "Egress": "network_bytes_outbound",
          "DNS": "dns_queries_fail",
          "Web": "http_queries_total",
      },
      "verdict": "CRITICAL_OUTLIER",
  }

  # Tier 2A (C2_BEACONING_JITTER) runs first and REFUTES periodic beaconing (is_outlier=False, CV=0.85)
  mock_c2_refuted = {
      "entity": "compromised_user",
      "model": "C2_BEACONING_JITTER",
      "coefficient_of_variation": 0.85,
      "target_destination": "203.0.113.50",
      "top_z_score": 0.5,
      "calibrated_risk_index": 20,
      "is_outlier": False,
      "stats_rows": 25,
      "executed_query": "// C2 Jitter Query",
  }

  # Tier 2B Pivot (DUAL_SECTOR_FUSION_3STAGE) auto-executes and CONFIRMS multi-sector exfiltration (CRI=88)
  mock_fusion_confirmed = {
      "entity": "compromised_user",
      "model": "DUAL_SECTOR_FUSION_3STAGE",
      "template_name": "dual_sector_fusion_3stage.yl2",
      "fusion_metrics": ["network_bytes_outbound", "workspace_total_download_actions"],
      "composite_threat_score": 5.1,
      "sector_a_z": 3.9,
      "sector_b_z": 3.4,
      "top_z_score": 5.1,
      "calibrated_risk_index": 88,
      "is_outlier": True,
      "stats_rows": 2,
      "executed_query": "// Dual Sector Fusion Query",
  }

  monkeypatch.setattr("src.autonomous_hunter.RiskMetricsEngine.run_360_behavioral_radar", AsyncMock(return_value=mock_radar_res))
  monkeypatch.setattr("src.autonomous_hunter.StatsHunterEngine.run_c2_beaconing_jitter", AsyncMock(return_value=mock_c2_refuted))
  monkeypatch.setattr("src.autonomous_hunter.RiskMetricsEngine.run_sector_fusion", AsyncMock(return_value=mock_fusion_confirmed))

  posted_comments = []
  mock_session = AsyncMock()
  mock_session.initialize = AsyncMock()
  mock_session.__aenter__.return_value = mock_session

  async def mock_call_tool(tool_name, args):
    if tool_name == "create_case_comment":
      posted_comments.append(args["comment"])

  mock_session.call_tool = mock_call_tool

  class MockContext:
    async def __aenter__(self):
      return (AsyncMock(), AsyncMock())
    async def __aexit__(self, *args):
      pass

  monkeypatch.setattr("src.autonomous_hunter.streamable_http_client", lambda *args, **kwargs: MockContext())
  monkeypatch.setattr("src.autonomous_hunter.ClientSession", lambda *args, **kwargs: mock_session)
  monkeypatch.setattr("src.config.TenantConfig.get_auth_headers", lambda self: {"Authorization": "Bearer test"})

  resp = await engine.execute_jit_hunt(req)
  assert resp.status == "SUCCESS"
  # Verify exactly 3 Case Wall cards were posted: Tier 1 360° Radar, Tier 2A Refuted C2 Jitter, Tier 2B Confirmed Fusion Pivot
  assert len(posted_comments) == 3
  assert "Tier 1: 360° Behavioral Radar Baseline" in posted_comments[0]
  assert "Tier 2: Targeted Deep Dive (Egress)" in posted_comments[1]
  assert "Tier 2B: Autonomous Hypothesis Pivot" in posted_comments[2]
  assert "Autonomous Pivot Lineage" in posted_comments[2]
  assert "Hypothesis Confidence Scale" in posted_comments[1]
  assert "Defense of Hypothesis" in posted_comments[1]
  assert resp.triage.calibrated_risk_index == 88.0
  assert resp.triage.primary_vector == "tier2b_dual_sector_fusion_3stage"
  assert resp.triage.common_vector == "MULTI_SECTOR"
  assert resp.triage.second_order_ran is True
  # Harness CRI bands (26/46/70/90): CRI 88 is the High band, so the risk tag is RISK:HIGH and the
  # Tier 2B card shows High Threat; RISK:CRITICAL is reserved for the Critical band (CRI >= 90).
  assert "RISK:HIGH" in resp.triage.tags
  assert "RISK:CRITICAL" not in resp.triage.tags
  assert "HIGH THREAT" in posted_comments[2]
  assert "VECTOR:MULTI_SECTOR" in resp.triage.tags
  assert "SECOND_ORDER_HUNT" in resp.triage.tags


@pytest.mark.anyio
async def test_v181_risk_metrics_date_filter_and_rare_destination_scoping(monkeypatch):
  from unittest.mock import AsyncMock
  from src.risk_metrics_engine import RiskMetricsEngine
  from src.config import TenantConfig

  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  engine = RiskMetricsEngine(tenant)

  async def mock_execute(session, query, start_iso, end_iso):
    return {"stats": [{"z": 3.5, "z_sector": 3.2, "d_sq": 12.4}]}

  monkeypatch.setattr(engine.runner, "execute_query_via_mcp", mock_execute)
  mock_session = AsyncMock()

  # 1. v1.8.1: HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE with http_queries_total uses {{today_date}}
  res_http = await engine.run_dynamic_metric_pipeline(
      session=mock_session,
      entity="web.user",
      metric_name="http_queries_total",
      model_name="HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE",
      lookback_days=7,
  )
  assert res_http["model"] == "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE"
  assert "timestamp.get_date(metadata.event_timestamp.seconds) =" in res_http["executed_query"]
  assert "{{today_date}}" not in res_http["executed_query"]
  assert "{{today_start_epoch}}" not in res_http["executed_query"]
  assert "metrics.http_queries_total" in res_http["executed_query"]

  # 2. v1.8.1: Non-HTTP metric (dns_queries_fail) passed to HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE
  # automatically reroutes to RARE_DESTINATION_ECG_3STAGE (rare_destination_ecg_3stage.yl2)
  res_dns_reroute = await engine.run_dynamic_metric_pipeline(
      session=mock_session,
      entity="10.20.30.40",
      metric_name="dns_queries_fail",
      model_name="HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE",
      lookback_days=7,
  )
  assert res_dns_reroute["model"] == "RARE_DESTINATION_ECG_3STAGE"
  assert "stage rare_dest" in res_dns_reroute["executed_query"]
  assert "network.dns.questions.name" in res_dns_reroute["executed_query"]
  assert "timestamp.get_date(metadata.event_timestamp.seconds) =" in res_dns_reroute["executed_query"]

  # 3. v1.8.1: FUSION_RARE_DESTINATION_3STAGE renders multi-sector fusion with rare destination ECG
  res_fusion_rare = await engine.run_dynamic_metric_pipeline(
      session=mock_session,
      entity="alice.smith",
      metric_name="network_bytes_outbound",
      model_name="FUSION_RARE_DESTINATION_3STAGE",
      lookback_days=7,
  )
  assert res_fusion_rare["model"] == "FUSION_RARE_DESTINATION_3STAGE"
  assert "stage rare_dest" in res_fusion_rare["executed_query"]
  assert "metrics.http_queries_total" in res_fusion_rare["executed_query"]
  assert "metrics.network_bytes_outbound" in res_fusion_rare["executed_query"]


def test_case_triage_tagging_taxonomy_and_watchdog_filtering(tmp_path):
  from src.formatters.case_wall_card import CaseWallCardFormatter
  from src.models import TriageSummary, StrategyDirective
  from src.watchdog import WatchdogState

  # 1. Critical finding (harness Critical band: CRI 90-100) + Common Vector + Second-Order Hunt
  triage_crit = TriageSummary(
      is_outlier=True,
      calibrated_risk_index=92.0,
      verdict="CRITICAL_OUTLIER",
      top_z_score=7.1,
      primary_vector="Workspace_behavioral_drift",
      second_order_ran=True,
      recommended_action="REVOKE_SESSION",
  )
  assert triage_crit.common_vector == "WORKSPACE"
  assert triage_crit.tags == ["RISK:CRITICAL", "VECTOR:WORKSPACE", "SECOND_ORDER_HUNT"]

  # 2. High finding (harness High band: CRI 70-89) + Common Vector without Second-Order Hunt
  triage_high = TriageSummary(
      is_outlier=True,
      calibrated_risk_index=75.0,
      verdict="HIGH_OUTLIER",
      top_z_score=4.8,
      primary_vector="Auth_behavioral_drift",
      second_order_ran=False,
      recommended_action="INVESTIGATE",
  )
  assert triage_high.common_vector == "AUTH"
  assert triage_high.tags == ["RISK:HIGH", "VECTOR:AUTH"]

  # 2b. Medium outlier (harness Medium band: CRI 46-69) -> VECTOR tag only, no RISK:* tag
  triage_med = TriageSummary(
      is_outlier=True,
      calibrated_risk_index=68.0,
      verdict="MEDIUM_OUTLIER",
      top_z_score=3.4,
      primary_vector="Auth_behavioral_drift",
      second_order_ran=False,
      recommended_action="INVESTIGATE",
  )
  assert triage_med.tags == ["VECTOR:AUTH"]

  # 3. Nominal / Low finding (CRI <= 45) with no Second-Order Hunt -> No tags
  triage_low = TriageSummary(
      is_outlier=False,
      calibrated_risk_index=25.0,
      verdict="NOMINAL_BASELINE",
      top_z_score=0.8,
      primary_vector="Auth",
      second_order_ran=False,
      recommended_action="MONITOR",
  )
  assert triage_low.tags == []

  # 4. Nominal finding (CRI <= 25) where a Second-Order Hunt ran and refuted the anomaly
  triage_refuted = TriageSummary(
      is_outlier=False,
      calibrated_risk_index=20.0,
      verdict="NOMINAL_BASELINE",
      top_z_score=0.5,
      primary_vector="Egress",
      second_order_ran=True,
      recommended_action="MONITOR",
  )
  assert triage_refuted.tags == ["VECTOR:EGRESS", "SECOND_ORDER_HUNT"]

  # 5. Verify Case Wall card renders Case Triage Tags in Markdown and SOAR HTML
  directive = StrategyDirective(
      selected_skill="secops-risk-metrics-multistage",
      model_name="MACD_MOMENTUM_VELOCITY",
      target_metric="workspace_total_download_actions",
      directive_query="macd",
      target_entity="insider.user",
      entity_type="USER",
      investigation_tier="TIER_2_DEEP_DIVE",
      outlier_vector="Workspace",
  )
  md_card = CaseWallCardFormatter.format_card(
      target_entity="insider.user",
      entity_type="USER",
      model_name="MACD_MOMENTUM_VELOCITY",
      calibrated_risk_index=92.0,
      is_outlier=True,
      case_id="20999",
      rows_count=12,
      directive=directive,
  )
  assert "**Case Triage Tags**: `RISK:CRITICAL` `VECTOR:WORKSPACE` `SECOND_ORDER_HUNT`" in md_card
  html_card = CaseWallCardFormatter.to_soar_html(md_card)
  assert "<strong>Case Triage Tags</strong>: <code>RISK:CRITICAL</code>" in html_card
  assert "<code>VECTOR:WORKSPACE</code>" in html_card
  assert "<code>SECOND_ORDER_HUNT</code>" in html_card

  # 6. WatchdogState activity filtering by tag
  state_file = tmp_path / "watchdog_state.json"
  wd = WatchdogState(state_file=state_file)
  wd.record_case("1001", {
      "case_id": "1001",
      "target_entity": "alice",
      "entity_type": "USER",
      "calibrated_risk_index": 92.0,
      "verdict": "CRITICAL_OUTLIER",
      "primary_vector": "Workspace",
      "common_vector": "WORKSPACE",
      "second_order_ran": True,
      "tags": ["RISK:CRITICAL", "VECTOR:WORKSPACE", "SECOND_ORDER_HUNT"],
  })
  wd.record_case("1002", {
      "case_id": "1002",
      "target_entity": "bob",
      "entity_type": "USER",
      "calibrated_risk_index": 75.0,
      "verdict": "HIGH_OUTLIER",
      "primary_vector": "Auth",
      "common_vector": "AUTH",
      "second_order_ran": False,
      "tags": ["RISK:HIGH", "VECTOR:AUTH"],
  })
  wd.record_case("1003", {
      "case_id": "1003",
      "target_entity": "carol",
      "entity_type": "USER",
      "calibrated_risk_index": 12.0,
      "verdict": "NOMINAL_BASELINE",
      "primary_vector": "none",
      "common_vector": "NONE",
      "second_order_ran": False,
      "tags": [],
  })

  all_report = wd.get_activity_report()
  assert all_report["total_cases_triaged"] == 3
  assert all_report["summary_by_tag"]["RISK:CRITICAL"] == 1
  assert all_report["summary_by_tag"]["RISK:HIGH"] == 1
  assert all_report["summary_by_tag"]["SECOND_ORDER_HUNT"] == 1

  crit_report = wd.get_activity_report(tag="RISK:CRITICAL")
  assert crit_report["total_cases_triaged"] == 1
  assert crit_report["cases"][0]["case_id"] == "1001"

  second_order_report = wd.get_activity_report(tag="SECOND_ORDER_HUNT")
  assert second_order_report["total_cases_triaged"] == 1
  assert second_order_report["cases"][0]["case_id"] == "1001"


def test_fleet_360_sector_queries_structure_and_gating():
  eng = RiskMetricsEngine()
  user_queries = eng.build_fleet_360_sector_queries(
      entity_type="USER", min_z=2.0, min_obs=5
  )
  assert set(user_queries.keys()) == {"Auth", "Cloud", "Workspace", "Egress", "DNS", "Web"}
  for sector, q in user_queries.items():
    assert "condition:" in q, f"Missing root condition in {sector}"
    assert "$z >= 2.00 and $observed >=" in q
    assert "$user =" in q
    assert "$baseline =" in q
    assert "$dispersion =" in q

  asset_queries = eng.build_fleet_360_sector_queries(
      entity_type="ASSET", min_z=2.0, min_obs=5
  )
  assert set(asset_queries.keys()) == {"Auth", "Egress", "DNS", "Flows", "Alerts", "Web"}
  for sector, q in asset_queries.items():
    assert "$z >= 2.00 and $observed >=" in q
    assert "principal.asset.hostname" in q or "target.asset.hostname" in q
    assert "$host =" in q


def test_mode_a_today_window_and_midnight_rollover_guard():
  from datetime import datetime, timezone

  # 1. Normal daytime UTC run (14:30Z) -> evaluates today's partial UTC bucket
  start_iso, end_iso, bucket_date = RiskMetricsEngine._mode_a_today_window(
      datetime(2026, 10, 8, 14, 30, 0, tzinfo=timezone.utc)
  )
  assert start_iso == "2026-10-08T00:00:00Z"
  assert end_iso == "2026-10-08T14:30:00Z"
  assert bucket_date == "2026-10-08"

  # 2. Midnight rollover guard (00:12Z) -> evaluates yesterday's full 24h UTC bucket
  start_roll, end_roll, bucket_roll = RiskMetricsEngine._mode_a_today_window(
      datetime(2026, 10, 8, 0, 12, 0, tzinfo=timezone.utc)
  )
  assert start_roll == "2026-10-07T00:00:00Z"
  assert end_roll == "2026-10-07T23:59:59Z"
  assert bucket_roll == "2026-10-07"


def test_build_360_outlier_udm_event_minimal_consistent_schema():
  eng = RiskMetricsEngine()
  eng.runner._ensure_skill_path()
  from scripts import chronicle_ingest

  sector_stats = {
      "Auth": {"z": 2.2, "obs": 12.0, "avg": 3.0, "std": 2.0},
      "Workspace": {"z": 4.8, "obs": 95.0, "avg": 8.0, "std": 6.0},
      "Egress": {"z": 3.5, "obs": 50000000.0, "avg": 2000000.0, "std": 1500000.0},
  }
  composite_d = eng.runner.compute_euclidean_distance(
      {k: v["z"] for k, v in sector_stats.items()}
  )
  composite_cri = eng.runner.calculate_cri(composite_d)

  ev = eng.build_360_outlier_udm_event(
      entity_id="alex.mercer",
      entity_type="USER",
      sectors=sector_stats,
      composite_d=composite_d,
      composite_cri=composite_cri,
      campaign_id="sweep-360-user-2026-10-08-160000",
      run_timestamp_iso="2026-10-08T16:00:00Z",
      evaluated_day="2026-10-08",
  )

  md = ev["metadata"]
  for k, v in RiskMetricsEngine.RADAR_360_EVENT_METADATA.items():
    assert md[k] == v
  # Event time is the sweep run time; ingestion time is left to Chronicle.
  assert md["event_timestamp"] == "2026-10-08T16:00:00Z"
  assert "ingested_timestamp" not in md
  assert ev["principal"] == {"user": {"userid": "alex.mercer"}}

  sr = ev["security_result"]
  # 1 COMPOSITE_360 entry + 3 non-zero SECTOR_VECTOR entries (WORKSPACE, EGRESS, AUTH; zero sectors omitted)
  assert len(sr) == 4
  assert sr[0]["rule_type"] == "COMPOSITE_360"
  assert sr[0]["risk_score"] == composite_cri and isinstance(sr[0]["risk_score"], int)
  assert "threat_name" not in sr[0]
  assert "confidence_score" not in sr[0]
  assert "detection_fields" not in sr[0]
  assert "network" not in ev

  # Non-zero vectors sorted descending by Z-score: WORKSPACE (4.8), EGRESS (3.5), AUTH (2.2)
  assert [s["threat_name"] for s in sr[1:]] == ["WORKSPACE", "EGRESS", "AUTH"]
  assert all(s["rule_type"] == "SECTOR_VECTOR" for s in sr[1:])
  assert sr[1]["risk_score"] == eng.runner.calculate_cri(4.8)
  assert sr[1]["confidence_score"] == 4.8
  assert sr[1]["threat_status"] == "ACTIVE"
  assert sr[2]["risk_score"] == eng.runner.calculate_cri(3.5)
  assert sr[2]["confidence_score"] == 3.5
  assert sr[2]["threat_status"] == "ACTIVE"
  assert sr[3]["risk_score"] == eng.runner.calculate_cri(2.2)
  assert sr[3]["confidence_score"] == 2.2
  assert sr[3]["threat_status"] == "CLEARED"

  labels = {l["key"]: l["value"] for l in ev["target"]["resource"]["attribute"]["labels"]}
  assert list(labels) == [
      "Hunt Campaign ID", "Evaluated Day", "Composite CRI", "Composite D",
      "Peak Vector", "Peak CRI", "Peak Z", "Breached Vectors",
  ]
  assert labels["Composite CRI"] == str(composite_cri)
  assert labels["Composite D"] == f"{composite_d:.2f}"
  assert labels["Peak Vector"] == "WORKSPACE"
  assert labels["Peak CRI"] == str(eng.runner.calculate_cri(4.8))
  assert labels["Peak Z"] == "4.80"
  assert labels["Breached Vectors"] == "WORKSPACE, EGRESS"

  assert chronicle_ingest.validate_events([ev]) == []


def test_build_360_outlier_udm_event_asset_identity_matches_user():
  eng = RiskMetricsEngine()
  common = dict(
      sectors={"Flows": {"z": 3.9}, "Alerts": {"z": 2.4}, "Web": {"z": 4.1}},
      composite_d=5.66, composite_cri=82,
      campaign_id="c", run_timestamp_iso="2026-10-08T16:00:00Z", evaluated_day="2026-10-08",
  )
  user_ev = eng.build_360_outlier_udm_event(entity_id="u", entity_type="USER", **common)
  asset_ev = eng.build_360_outlier_udm_event(entity_id="h", entity_type="ASSET", **common)
  ident = ("product_name", "vendor_name", "event_type", "product_event_type")
  assert {k: user_ev["metadata"][k] for k in ident} == {k: asset_ev["metadata"][k] for k in ident}
  assert user_ev["observer"] == asset_ev["observer"]
  assert asset_ev["principal"] == {"hostname": "h", "asset": {"hostname": "h"}}
  # Asset event includes ASSET-specific sectors (FLOWS, ALERTS, WEB) in security_result[1:]
  assert [s["threat_name"] for s in asset_ev["security_result"][1:]] == ["WEB", "FLOWS", "ALERTS"]
  assert [s["threat_name"] for s in user_ev["security_result"][1:]] == ["WEB"]


@pytest.mark.anyio
async def test_run_fleet_360_sweep_euclidean_aggregation_and_circuit_breaker(monkeypatch):
  from datetime import datetime, timezone
  from unittest.mock import AsyncMock
  from src.config import TenantConfig

  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  eng = RiskMetricsEngine(tenant)

  # Simulate sector responses:
  # - Workspace has 1 entity (alice) at Z=4.0
  # - Auth has alice at Z=2.5 (secondary spoke) and bob at Z=2.6 (only < 3.0, should NOT trigger outlier emission)
  # - DNS has 5 entities (exceeding max_outliers_per_sector=3 -> circuit breaker trips on DNS!)
  async def fake_execute(session, query, start_iso, end_iso):
    if "workspace_total_download_actions" in query:
      return {
          "stats": [
              {"user": "alice", "z": 4.0, "observed": 60, "baseline": 5.0, "dispersion": 3.0}
          ]
      }
    if "auth_attempts_fail" in query:
      return {
          "stats": [
              {"user": "alice", "z": 2.5, "observed": 15, "baseline": 2.0, "dispersion": 2.0},
              {"user": "bob", "z": 2.6, "observed": 12, "baseline": 2.0, "dispersion": 1.5},
          ]
      }
    if "dns_queries_fail" in query:
      return {
          "stats": [
              {"user": f"user_{i}", "z": 3.8, "observed": 50, "baseline": 2.0, "dispersion": 1.0}
              for i in range(5)
          ]
      }
    return {"stats": []}

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_execute)

  ingested_batches = []
  def fake_ingest(events):
    ingested_batches.append(events)
    return {"status": "SUCCESS", "events_ingested": len(events), "batches": 1}

  monkeypatch.setattr(eng, "ingest_udm_events", fake_ingest)

  res = await eng.run_fleet_360_sweep(
      session=AsyncMock(),
      entity_type="USER",
      spike_threshold_z=3.0,
      spoke_inclusion_z=2.0,
      min_observed=5,
      max_outliers_per_sector=3,
      inter_query_delay_sec=0.0,
      ingest_events=True,
      now_utc=datetime(2026, 10, 8, 15, 0, 0, tzinfo=timezone.utc),
  )

  # DNS should be tripped by circuit breaker (5 rows >= 3.0, limit is 3 -> 5 > 3)
  assert "DNS" in res["suppressed_sectors"]
  # Bob only had Z=2.6 (< 3.0 spike_threshold_z), so only Alice qualifies as a true outlier
  assert res["outliers_detected"] == 1
  assert res["outliers_emitted"] == 1
  alice_rec = res["outliers"][0]
  assert alice_rec["entity"] == "alice"
  # Alice's Euclidean D combines Workspace (4.0) + Auth (2.5): sqrt(16 + 6.25) = sqrt(22.25) = 4.72
  assert pytest.approx(alice_rec["composite_d"], 0.01) == math.sqrt(4.0**2 + 2.5**2)
  assert alice_rec["breached_sectors"] == ["WORKSPACE"]
  # Exactly one UDM event per outlier entity, stamped with the sweep run time
  assert res["udm_events_generated"] == 1
  assert len(ingested_batches) == 1
  assert len(ingested_batches[0]) == 1
  assert ingested_batches[0][0]["metadata"]["event_timestamp"] == "2026-10-08T15:00:00Z"


@pytest.mark.anyio
async def test_run_fleet_360_sweep_multiday_backfill_time_buckets(monkeypatch):
  from datetime import datetime, timezone
  from unittest.mock import AsyncMock
  from src.config import TenantConfig

  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  eng = RiskMetricsEngine(tenant)

  # Simulate Chronicle columnar stats response with timestampVal in TIME_BUCKET across 2 days
  async def fake_execute(session, query, start_iso, end_iso):
    if "http_queries_total" in query:
      return {
          "stats": {
              "results": [
                  {
                      "column": "user",
                      "values": [
                          {"value": {"stringVal": "admin@gus.joonix.net"}},
                          {"value": {"stringVal": "admin@gus.joonix.net"}},
                      ],
                  },
                  {
                      "column": "TIME_BUCKET",
                      "values": [
                          {"value": {"timestampVal": "2026-10-03T00:00:00Z"}},
                          {"value": {"timestampVal": "2026-10-05T00:00:00Z"}},
                      ],
                  },
                  {
                      "column": "z",
                      "values": [
                          {"value": {"doubleVal": 4.2}},
                          {"value": {"doubleVal": 7.0}},
                      ],
                  },
                  {
                      "column": "observed",
                      "values": [
                          {"value": {"int64Val": "42"}},
                          {"value": {"int64Val": "70"}},
                      ],
                  },
                  {
                      "column": "baseline",
                      "values": [
                          {"value": {"doubleVal": 10.0}},
                          {"value": {"doubleVal": 10.0}},
                      ],
                  },
                  {
                      "column": "dispersion",
                      "values": [
                          {"value": {"doubleVal": 5.0}},
                          {"value": {"doubleVal": 5.0}},
                      ],
                  },
              ]
          }
      }
    return {"stats": []}

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_execute)
  monkeypatch.setattr(
      eng,
      "ingest_udm_events",
      lambda events: {"status": "SUCCESS", "events_ingested": len(events), "batches": 1},
  )

  res = await eng.run_fleet_360_sweep(
      session=AsyncMock(),
      entity_type="USER",
      spike_threshold_z=3.0,
      spoke_inclusion_z=2.0,
      min_observed=5,
      inter_query_delay_sec=0.0,
      ingest_events=True,
      now_utc=datetime(2026, 10, 7, 23, 59, 0, tzinfo=timezone.utc),
      lookback_days=7,
  )

  assert res["window"]["start"] == "2026-10-01T00:00:00Z"
  assert res["window"]["end"] == "2026-10-07T23:59:00Z"
  assert res["window"]["lookback_days"] == 7
  assert res["outliers_detected"] == 2
  assert res["outliers_emitted"] == 2
  dates = [o["bucket_date"] for o in res["outliers"]]
  assert dates == ["2026-10-05", "2026-10-03"]
  # One event per outlier day; all stamped with the sweep run time, scored day in a label
  assert len(res["udm_events"]) == 2
  assert {ev["metadata"]["event_timestamp"] for ev in res["udm_events"]} == {"2026-10-07T23:59:00Z"}
  evaluated = sorted(
      l["value"]
      for ev in res["udm_events"]
      for l in ev["target"]["resource"]["attribute"]["labels"]
      if l["key"] == "Evaluated Day"
  )
  assert evaluated == ["2026-10-03", "2026-10-05"]



@pytest.mark.anyio
async def test_run_fleet_360_sweep_preserves_source_entity_casing(monkeypatch):
  from datetime import datetime, timezone
  from unittest.mock import AsyncMock
  from src.config import TenantConfig

  eng = RiskMetricsEngine(TenantConfig(project_id="p", customer_id="c"))

  async def fake_execute(session, query, start_iso, end_iso):
    if "network_flows_outbound" in query:
      return {"stats": [{"host": "CYM-PROD-GCP-WIN01", "z": 4.0, "observed": 60, "baseline": 5.0, "dispersion": 3.0}]}
    if "dns_queries_fail" in query:
      return {"stats": [{"host": "cym-prod-gcp-win01", "z": 2.5, "observed": 9, "baseline": 2.0, "dispersion": 1.0}]}
    return {"stats": []}

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_execute)
  res = await eng.run_fleet_360_sweep(
      session=AsyncMock(), entity_type="ASSET", inter_query_delay_sec=0.0,
      ingest_events=False, now_utc=datetime(2026, 10, 8, 16, 0, 0, tzinfo=timezone.utc),
  )

  # Case variants merge into one entity (both sectors in D) ...
  assert res["outliers_detected"] == 1
  assert pytest.approx(res["outliers"][0]["composite_d"], 0.01) == math.sqrt(4.0**2 + 2.5**2)
  # ... and the event carries the ID exactly as the source telemetry spelled it.
  assert res["outliers"][0]["entity"] == "CYM-PROD-GCP-WIN01"
  assert res["udm_events"][0]["principal"]["asset"]["hostname"] == "CYM-PROD-GCP-WIN01"


def test_build_360_outlier_udm_event_matches_skill_handoff_schema():
  """Drift guard: the sweep event must have the same shape as skill §10."""
  import json as _json
  import re as _re

  eng = RiskMetricsEngine()
  schema = eng.runner._ensure_skill_path() / "references" / "clean-handoff-udm-schema.md"
  if not schema.is_file():
    pytest.skip("secops-risk-metrics-multistage skill not available")
  text = schema.read_text(encoding="utf-8")
  sec = text[text.index("### 10. `BEHAVIORAL_RISK_RADAR_360`"):]
  doc = _json.loads(_re.search(r"```json\n(.*?)\n```", sec, _re.S).group(1))["udm"]

  labels = {l["key"]: l["value"] for l in doc["target"]["resource"]["attribute"]["labels"]}
  sectors = {
      sr["threat_name"].title(): {"z": float(sr["confidence_score"])}
      for sr in doc["security_result"][1:]
  }
  sectors = {("DNS" if k == "Dns" else k): v for k, v in sectors.items()}
  ev = eng.build_360_outlier_udm_event(
      entity_id=doc["principal"]["user"]["userid"],
      entity_type="USER",
      sectors=sectors,
      composite_d=float(labels["Composite D"]),
      composite_cri=int(labels["Composite CRI"]),
      campaign_id=labels["Hunt Campaign ID"],
      run_timestamp_iso=doc["metadata"]["event_timestamp"],
      evaluated_day=labels["Evaluated Day"],
  )

  # Same identity, observer, principal, label keys/values, and full security_result[] array as §10.
  for k in ("product_name", "vendor_name", "event_type", "product_event_type", "event_timestamp"):
    assert ev["metadata"][k] == doc["metadata"][k], k
  assert sorted(ev["metadata"]) == sorted(doc["metadata"])
  assert ev["observer"] == doc["observer"]
  assert ev["principal"] == doc["principal"]
  assert ev["target"]["resource"]["attribute"]["labels"] == doc["target"]["resource"]["attribute"]["labels"]
  assert ev["security_result"] == doc["security_result"]


# --- Skill v1.8.6 root significance gate compatibility -------------------------------------------

def _root_gate(query: str):
  import re
  m = re.search(r"^condition:[ \t]*\n(.*?)\n[ \t]*\n[ \t]*order:", query, re.M | re.S)
  return " ".join(m.group(1).split()) if m else None


def _unfilled(query: str):
  import re
  code = "\n".join(ln for ln in query.splitlines() if not ln.lstrip().startswith("//"))
  return sorted(set(re.findall(r"\{\{(\w+)\}\}", code)))


def test_template_paths_fill_skill_gate_placeholders():
  """Every template the engine fills by hand must resolve all of its placeholders, gates included.

  Unfilled `{{anomaly_threshold}}` / `{{fusion_threshold_sq}}` / `{{min_baseline_days}}` would reach
  Chronicle verbatim and fail compilation (render_template only logs a warning). Gate values come from
  the harness sensitivity thresholds and the harness 7-active-day maturity floor.
  """
  import asyncio
  from src import harness_truth

  engine = RiskMetricsEngine()
  gates = engine.gate_thresholds()
  min_days = harness_truth.min_baseline_days()
  captured = []

  async def fake_exec(session, query, *args, **kwargs):
    captured.append(query)
    return {}

  engine.runner.execute_query_via_mcp = fake_exec
  asyncio.run(engine.run_macd_momentum_velocity(None, "alice"))
  asyncio.run(engine.run_hybrid_enrichment(None, "alice"))
  cases = {
      "rare_destination_ecg": (engine._render_rare_destination_ecg_query("dns_queries_total"),
                               f"$z_sector >= {gates['anomaly_threshold']}"),
      "rare_destination_ecg_bytes": (engine._render_rare_destination_ecg_query("network_bytes_outbound"),
                                     f"$z_sector >= {gates['anomaly_threshold']}"),
      "fusion_rare_destination": (engine._render_fusion_rare_destination_query(),
                                  f"$d_sq >= {gates['fusion_threshold_sq']}"),
      "macd_momentum_velocity_2stage.yl2": (
          captured[0], f"$active_days >= {min_days} and $macd_z >= {gates['anomaly_threshold']}"),
  }
  for name, (query, expected_gate) in cases.items():
    assert _unfilled(query) == [], name
    assert _root_gate(query) == expected_gate, name
  hybrid = captured[1]
  assert _unfilled(hybrid) == []
  assert f"$macro_z_score >= {gates['anomaly_threshold']}" in hybrid
  assert f"$active_baseline_days >= {min_days}" in hybrid


def test_router_paths_use_engine_outlier_gates():
  """Router-built queries carry the engine's harness gates plus the 7-active-day maturity floor (v2.3.0 PF-2)."""
  from src import harness_truth

  engine = RiskMetricsEngine()
  gates = engine.gate_thresholds()
  router = engine.runner.get_template_router()
  EntityType, _, StatisticalModel, _ = engine.runner.get_validator_enums()
  spec_a, spec_b = engine.resolve_compatible_fusion_specs(["auth_attempts_fail", "network_bytes_outbound"], "USER")
  fusion = router.build_sector_fusion_query(spec_a, spec_b, fusion_threshold_sq=gates["fusion_threshold_sq"])
  # run_sector_fusion scores D on the harness Z-equivalent scale, so the query keeps every row at the gate.
  assert _root_gate(fusion) == f"$composite_threat_norm_sq >= {gates['fusion_threshold_sq']}"
  zq = router.build_query(target_metric="network_bytes_outbound", entity_type=EntityType.ASSET,
                          statistical_model=StatisticalModel.STANDARD_Z_SCORE,
                          anomaly_threshold=gates["anomaly_threshold"])
  assert _root_gate(zq) == (
      f"$active_days >= {harness_truth.min_baseline_days()} and $personal_z >= {gates['anomaly_threshold']}")
  assert _unfilled(fusion) == [] and _unfilled(zq) == []


@pytest.mark.anyio
async def test_v191_360_radar_baseline_enrichment_and_insights_synthesis(monkeypatch):
  from unittest.mock import AsyncMock
  from src.config import TenantConfig
  from src.risk_metrics_engine import RiskMetricsEngine
  from src.strategy_decider import StrategyDecider

  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  eng = RiskMetricsEngine(tenant)

  # Simulate:
  # - Egress has sub-threshold Z=1.70 with inflated std=80.0 vs avg=15.0 (variance-masked!)
  # - Cloud has dormant baseline awakening: obs=6, avg=0.10, std=3.5, z=1.68
  # - Workspace has sub-threshold Z=1.55 (pairs with Cloud -> CLOUD_DISCOVERY_TO_COLLECTION)
  async def fake_exec(session, query, start_iso, end_iso):
    if "network_bytes_outbound" in query:
      return {"stats": [{"z": 1.70, "obs": 151.0, "avg": 15.0, "std": 80.0}]}
    if "resource_creation_total" in query:
      return {"stats": [{"z": 1.68, "obs": 6.0, "avg": 0.10, "std": 3.5}]}
    if "workspace_total_download_actions" in query:
      return {"stats": [{"z": 1.55, "obs": 18.0, "avg": 4.0, "std": 9.0}]}
    return {"stats": [{"z": 0.2, "obs": 2.0, "avg": 2.0, "std": 1.0}]}

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_exec)
  radar_res = await eng.run_360_behavioral_radar(AsyncMock(), "dev.user", entity_type="USER")

  assert "Egress" in radar_res["variance_masked_sectors"]
  assert "Cloud" in radar_res["dormant_awakening_sectors"]
  assert set(radar_res["subthreshold_sectors"]) >= {"Egress", "Cloud", "Workspace"}
  assert radar_res["sector_baseline_std"]["Egress"] == 80.0
  assert radar_res["sector_baseline_avg"]["Cloud"] == 0.10

  insights = StrategyDecider.analyze_360_insights(
      radar_result=radar_res,
      ctx={
          "primary_entity": "dev.user",
          "extracted_hosts": ["wkstn-dev-01"],
          "case_title": "Suspicious Cloud and Workspace Activity",
      },
      entity_type="USER",
  )
  assert insights["secondary_warranted"] is True
  assert "Egress" in insights["variance_masked_sectors"]
  assert "Cloud" in insights["dormant_awakening_sectors"]
  archetype_names = [m["archetype"] for m in insights["matched_killchain_archetypes"]]
  assert "CLOUD_DISCOVERY_TO_COLLECTION" in archetype_names
  assert any(c["entity"] == "wkstn-dev-01" and c["entity_type"] == "ASSET" for c in insights["companion_entities"])


@pytest.mark.anyio
async def test_v191_variance_masked_and_dormant_awakening_secondary_routing(monkeypatch):
  from src.strategy_decider import StrategyDecider

  monkeypatch.delenv("GEMINI_API_KEY", raising=False)

  # 1. Variance-masked sub-threshold sector -> routes to 4-Stage Non-Parametric MAD
  radar_vm = {
      "top_sector": "Egress",
      "outlier_sectors": [],
      "subthreshold_sectors": ["Egress"],
      "variance_masked_sectors": ["Egress"],
      "dormant_awakening_sectors": [],
      "sector_z_scores": {"Auth": 0.1, "Cloud": 0.2, "Workspace": 0.1, "Egress": 1.72, "DNS": 0.1, "Web": 0.1},
      "sector_observed_counts": {"Auth": 1, "Cloud": 1, "Workspace": 1, "Egress": 25, "DNS": 1, "Web": 1},
      "sector_baseline_avg": {"Egress": 10.0},
      "sector_baseline_std": {"Egress": 65.0},
  }
  dir_vm = await StrategyDecider.decide_tier2_deep_dive(
      target_entity="masked.user",
      entity_type="USER",
      outlier_vector="Egress",
      case_info={"id": "301", "title": "Outbound Traffic Variance Check"},
      alerts=[{"name": "Anomalous Outbound Data"}],
      connector_events=[],
      radar_result=radar_vm,
  )
  assert dir_vm.model_name == "MAD"
  assert dir_vm.directive_query == "dynamic_metric"
  assert dir_vm.target_metric == "network_bytes_outbound"
  assert dir_vm.confidence_score >= StrategyDecider.TIER_2A_AUTO_EXECUTE_THRESHOLD

  # 2. Dormant baseline awakening -> routes to TWO_PART_HURDLE
  radar_da = {
      "top_sector": "Workspace",
      "outlier_sectors": [],
      "subthreshold_sectors": ["Workspace"],
      "variance_masked_sectors": [],
      "dormant_awakening_sectors": ["Workspace"],
      "sector_z_scores": {"Auth": 0.1, "Cloud": 0.1, "Workspace": 1.65, "Egress": 0.1, "DNS": 0.1, "Web": 0.1},
      "sector_observed_counts": {"Auth": 1, "Cloud": 0, "Workspace": 9, "Egress": 1, "DNS": 1, "Web": 1},
      "sector_baseline_avg": {"Workspace": 0.05},
      "sector_baseline_std": {"Workspace": 4.0},
  }
  dir_da = await StrategyDecider.decide_tier2_deep_dive(
      target_entity="dormant.user",
      entity_type="USER",
      outlier_vector="Workspace",
      case_info={"id": "302", "title": "Dormant Workspace Account Activity"},
      alerts=[{"name": "Sudden Drive Activity"}],
      connector_events=[],
      radar_result=radar_da,
  )
  assert dir_da.model_name == "TWO_PART_HURDLE"
  assert dir_da.directive_query == "dynamic_metric"
  assert dir_da.target_metric == "workspace_total_download_actions"
  assert dir_da.confidence_score >= StrategyDecider.TIER_2A_AUTO_EXECUTE_THRESHOLD


def test_v191_bidirectional_tier2b_pivot_confirmed_and_refuted():
  from src.models import StrategyDirective
  from src.strategy_decider import StrategyDecider

  # 1. CONFIRMED Tier 2A Outlier on Workspace + elevated Cloud -> pivots to Workspace Triad or Kill-Chain
  radar_ws_cloud = {
      "top_sector": "Workspace",
      "outlier_sectors": ["Workspace", "Cloud"],
      "sector_z_scores": {"Auth": 0.2, "Cloud": 2.6, "Workspace": 3.8, "Egress": 0.3, "DNS": 0.1, "Web": 0.2},
      "sector_observed_counts": {"Auth": 2, "Cloud": 14, "Workspace": 45, "Egress": 5, "DNS": 2, "Web": 3},
      "sector_baseline_avg": {"Cloud": 2.0, "Workspace": 4.0},
      "sector_baseline_std": {"Cloud": 3.0, "Workspace": 5.0},
  }
  t2a_ws = StrategyDirective(
      selected_skill="secops-risk-metrics-multistage",
      model_name="MACD_MOMENTUM_VELOCITY",
      directive_query="macd_momentum",
      target_entity="insider.user",
      entity_type="USER",
      target_metric="workspace_total_download_actions",
      investigation_tier="TIER_2_DEEP_DIVE",
      outlier_vector="Workspace",
  )
  piv_confirmed = StrategyDecider.decide_tier2_pivot(
      target_entity="insider.user",
      entity_type="USER",
      radar_result=radar_ws_cloud,
      tier2a_directive=t2a_ws,
      tier2a_result={"is_outlier": True, "calibrated_risk_index": 82, "stats_rows": 4},
      alerts=[{"name": "Workspace Mass Download"}],
      connector_events=[],
      executed_signatures={StrategyDecider.build_signature("MACD_MOMENTUM_VELOCITY", "workspace_total_download_actions", None, "insider.user")},
      empty_families=set(),
      secondary_hunts_run=1,
  )
  assert piv_confirmed is not None
  assert piv_confirmed.investigation_tier == "TIER_2B_PIVOT"
  assert piv_confirmed.post_data_outcome_class == "ACUTE_OUTLIER"
  assert piv_confirmed.directive_query in ("workspace_triad", "killchain_archetype", "sector_fusion")
  assert piv_confirmed.confidence_score >= StrategyDecider.TIER_2B_PIVOT_AUTO_EXECUTE_THRESHOLD

  # 2. REFUTED Tier 2A on Cloud CRUD -> pivots to CLOUD_REPOSITORY_SCOPE (fail mode) or 4-Stage MAD
  radar_cloud = {
      "top_sector": "Cloud",
      "outlier_sectors": ["Cloud"],
      "sector_z_scores": {"Auth": 0.2, "Cloud": 2.9, "Workspace": 0.1, "Egress": 0.2, "DNS": 0.1, "Web": 0.1},
      "sector_observed_counts": {"Auth": 2, "Cloud": 22, "Workspace": 1, "Egress": 2, "DNS": 1, "Web": 1},
  }
  t2a_cloud = StrategyDirective(
      selected_skill="secops-risk-metrics-multistage",
      model_name="CLOUD_CRUD_SURGE",
      directive_query="cloud_crud",
      target_entity="sa-prod@proj.iam",
      entity_type="USER",
      target_metric="resource_creation_total",
      investigation_tier="TIER_2_DEEP_DIVE",
      outlier_vector="Cloud",
  )
  piv_refuted = StrategyDecider.decide_tier2_pivot(
      target_entity="sa-prod@proj.iam",
      entity_type="USER",
      radar_result=radar_cloud,
      tier2a_directive=t2a_cloud,
      tier2a_result={"is_outlier": False, "calibrated_risk_index": 20, "stats_rows": 3},
      alerts=[{"name": "IAM Permission Denied Recon"}],
      connector_events=[],
      executed_signatures={StrategyDecider.build_signature("CLOUD_CRUD_SURGE", "resource_creation_total", None, "sa-prod@proj.iam")},
      empty_families=set(),
      secondary_hunts_run=1,
  )
  assert piv_refuted is not None
  assert piv_refuted.model_name == "CLOUD_REPOSITORY_SCOPE"
  assert piv_refuted.directive_query == "cloud_repo_scope"
  assert piv_refuted.outcome_mode == "fail"


@pytest.mark.anyio
async def test_v191_new_risk_metrics_methods_and_6spoke_hex_radar(monkeypatch):
  from unittest.mock import AsyncMock
  from src.autonomous_hunter import AutonomousHunterEngine
  from src.config import TenantConfig
  from src.models import JITHuntRequest, StrategyDirective
  from src.risk_metrics_engine import RiskMetricsEngine

  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  eng = RiskMetricsEngine(tenant)
  captured_windows = []

  async def fake_exec(session, query, start_iso, end_iso):
    captured_windows.append((start_iso, end_iso, query))
    return {
        "stats": [
            {
                "composite_threat_norm_sq": 16.0,
                "z_a_gated": 3.2,
                "z_b_gated": 2.4,
                "alert_z": 4.1,
                "total_alerts": 18,
                "fail_z": 3.9,
                "fail_ratio": 0.72,
                "composite_risk": 4.3,
                "fold_change": 5.5,
                "composite_z_score": 4.4,
                "modified_z": 4.2,
            }
        ]
    }

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_exec)
  mock_session = AsyncMock()

  # 1. 4-Stage MAD enforces >= 30d window
  res_mad = await eng.run_dynamic_metric_pipeline(
      mock_session, entity="alice", target_metric="network_bytes_outbound", model_name="MAD", lookback_days=7
  )
  assert res_mad["is_outlier"] is True
  assert res_mad["modified_z"] == 4.2

  # 2. All 5 new v1.9.1 engine methods execute and parse scores
  res_kc = await eng.run_killchain_archetype(
      mock_session, entity="alice", archetype="CLOUD_DISCOVERY_TO_COLLECTION", entity_type="USER"
  )
  assert res_kc["is_outlier"] is True
  assert res_kc["archetype"] == "CLOUD_DISCOVERY_TO_COLLECTION"

  res_alert = await eng.run_alert_surge(mock_session, entity="wkstn-01", entity_type="ASSET")
  assert res_alert["is_outlier"] is True
  assert res_alert["total_alerts"] == 18

  res_fail = await eng.run_failure_ratio_surge(
      mock_session, entity="alice", fail_metric="http_queries_fail", entity_type="USER"
  )
  assert res_fail["is_outlier"] is True
  assert res_fail["failure_ratio"] == 0.72

  res_repo = await eng.run_cloud_repository_scope(mock_session, entity="sa@proj", outcome_mode="fail")
  assert res_repo["is_outlier"] is True
  assert res_repo["outcome_mode"] == "fail"
  assert res_repo["target_metric"] == "resource_read_fail"

  res_triad = await eng.run_workspace_triad(mock_session, entity="alice")
  assert res_triad["is_outlier"] is True
  assert res_triad["composite_z_score"] == 4.4

  # 3. 6-spoke hexagonal radar SVG for USER and ASSET
  hunter = AutonomousHunterEngine(tenant)
  svg_user = hunter.generate_behavioral_radar(
      "alice",
      {"Auth": 1.0, "Cloud": 2.0, "Workspace": 3.5, "Egress": 1.2, "DNS": 0.5, "Web": 2.1},
      entity_type="USER",
  )
  assert "USER: ALICE" in svg_user
  assert "Web & Proxy" in svg_user
  assert "6-Spoke Hex" in svg_user

  svg_asset = hunter.generate_behavioral_radar(
      "wkstn-01",
      {"Auth": 0.5, "Egress": 3.2, "DNS": 1.1, "Flows": 2.8, "Alerts": 4.0, "Web": 1.5},
      entity_type="ASSET",
  )
  assert "ASSET: WKSTN-01" in svg_asset
  assert "Outbound Flows" in svg_asset
  assert "Security Alerts" in svg_asset

  # 4. _execute_secondary_directive dispatches all 5 new v1.9.1 directive_query types
  monkeypatch.setattr("src.autonomous_hunter.RiskMetricsEngine", lambda t: eng)
  req = JITHuntRequest(target_entity="alice", entity_type="USER", case_id="999")
  for dq, mname in (
      ("killchain_archetype", "KILLCHAIN_CLOUD_DISCOVERY_TO_COLLECTION"),
      ("workspace_triad", "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL"),
      ("cloud_repo_scope", "CLOUD_REPOSITORY_SCOPE"),
      ("failure_ratio_surge", "FAILURE_RATIO_SURGE"),
      ("alert_surge", "ALERT_SURGE"),
  ):
    d = StrategyDirective(
        selected_skill="secops-risk-metrics-multistage",
        model_name=mname,
        directive_query=dq,
        target_entity="alice",
        entity_type="USER",
        target_metric="workspace_total_download_actions",
    )
    s_res, s_card = await hunter._execute_secondary_directive(mock_session, tenant, req, d)
    assert s_res is not None and s_res["is_outlier"] is True
    assert s_card is not None and "Post-Data Outcome Class" in s_card
    assert d.post_data_outcome_class == "ACUTE_OUTLIER"


def test_vertex_location_and_model_resolution(monkeypatch):
  from src.config import TenantConfig
  monkeypatch.delenv("VERTEX_LOCATION", raising=False)
  monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
  monkeypatch.delenv("GEMINI_MODEL", raising=False)

  cfg = TenantConfig()
  assert cfg.model == "gemini-3.1-pro-preview"
  assert cfg.resolve_vertex_location("gemini-3.1-pro-preview") == "global"
  assert cfg.resolve_vertex_location("gemini-3-flash-preview") == "global"
  assert cfg.resolve_vertex_location("publishers/google/models/gemini-4-argon") == "global"
  assert cfg.resolve_vertex_location("gemini-4-argon") == "global"
  assert cfg.resolve_vertex_location("gemini-2.5-pro") == "us-central1"
  assert cfg.resolve_vertex_location("gemini-2.5-flash") == "us-central1"

  # Explicit env override wins over automatic model-based routing
  monkeypatch.setenv("VERTEX_LOCATION", "europe-west4")
  cfg_override = TenantConfig()
  assert cfg_override.resolve_vertex_location("gemini-3.1-pro-preview") == "europe-west4"
  assert cfg_override.resolve_vertex_location("gemini-2.5-pro") == "europe-west4"


@pytest.mark.anyio
async def test_v201_email_to_userid_identity_resolution(monkeypatch):
  from unittest.mock import AsyncMock
  eng = RiskMetricsEngine()

  assert eng.extract_email_local_part("admin@demo.wsexample.org") == "admin"
  assert eng.extract_email_local_part("frank.kolzig@stackedpads.local") == "frank.kolzig"
  assert eng.extract_email_local_part("frank.kolzig") is None
  assert eng.extract_email_local_part("sa-prod@proj.iam.gserviceaccount.com") is None
  assert eng.extract_email_local_part("sa-prod@proj.iam") is None

  captured_queries = []

  async def fake_exec(session, query, start_iso, end_iso):
    captured_queries.append(query)
    return {"stats": [{"uid": "admin", "cnt": 42}]}

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_exec)
  resolved = await eng.resolve_user_identifier(AsyncMock(), "admin@demo.wsexample.org", lookback_days=7)
  assert resolved == "admin"
  assert len(captured_queries) == 1
  assert 'principal.user.email_addresses = "admin@demo.wsexample.org"' in captured_queries[0]
  assert "coalesce(principal.user.userid, target.user.userid)" in captured_queries[0]

  # Service accounts bypass the email probe
  sa_resolved = await eng.resolve_user_identifier(AsyncMock(), "sa-prod@proj.iam.gserviceaccount.com")
  assert sa_resolved == "sa-prod@proj.iam.gserviceaccount.com"
  assert len(captured_queries) == 1


@pytest.mark.anyio
async def test_query_integrity_gate_and_data_table_bridge(monkeypatch):
  from unittest.mock import AsyncMock, MagicMock
  from src.config import TenantConfig
  from src.pipeline_runner import PipelineRunner
  from src.query_integrity_gate import (
      ChronicleBackendQueryError,
      QueryIntegrityGate,
      QueryValidationError,
  )

  runner = PipelineRunner(TenantConfig(project_id="test-proj", customer_id="test-cust"))

  # 1. Pre-dispatch gate catches unresolved placeholder
  with pytest.raises(QueryValidationError, match="UNRESOLVED_TEMPLATE_PLACEHOLDERS"):
    QueryIntegrityGate.verify_pre_dispatch(
        'stage s1 {\n  metadata.event_type = "{{event_type}}"\n  match: $user\n}'
    )

  # 2. Pre-dispatch gate catches preflight query mutation
  with pytest.raises(QueryValidationError, match="PREFLIGHT_QUERY_MUTATION"):
    QueryIntegrityGate.verify_pre_dispatch(
        'stage s1 {\n  metadata.event_type = "USER_LOGIN"\n  match: $user\n}',
        expected_preflight_query='stage s1 {\n  metadata.event_type = "NETWORK_CONNECTION"\n  match: $user\n}',
    )

  # 3. Pre-dispatch gate catches missing entity filter when expected_entity is provided
  with pytest.raises(QueryValidationError, match="MISSING_ENTITY_FILTER"):
    QueryIntegrityGate.verify_pre_dispatch(
        'stage s1 {\n  metadata.event_type = "USER_LOGIN"\n  match: $user\n}',
        expected_entity="alice.smith",
    )

  # 4. Pre-dispatch gate catches bare %table without .<column>
  with pytest.raises(QueryValidationError, match="INVALID_DATA_TABLE_COLUMN_SYNTAX"):
    QueryIntegrityGate.verify_pre_dispatch(
        'stage s1 {\n  metadata.event_type = "USER_LOGIN"\n  $user in %ueba_hunt_bridge\n  match: $user\n}'
    )

  # Valid %table.column syntax passes pre-dispatch gate
  res_ok = QueryIntegrityGate.verify_pre_dispatch(
      'stage s1 {\n  metadata.event_type = "USER_LOGIN"\n  $user in %ueba_hunt_bridge.entity\n  $user = "alice.smith"\n  match: $user\n}',
      expected_entity="alice.smith",
  )
  assert res_ok["passed"] is True

  # 5. Post-execution gate catches Chronicle compiler error and retries in execute_query_via_mcp
  call_count = 0

  async def mock_call_tool(tool_name, args):
    nonlocal call_count
    call_count += 1
    m = MagicMock()
    if tool_name == "udm_search" and call_count == 1:
      m.isError = False
      m.content = [MagicMock(text='{"error": {"message": "invalid argument: syntax error at line 3"}}')]
      return m
    if tool_name == "udm_search":
      m.isError = False
      m.content = [MagicMock(text='{"stats": [{"user": "alice.smith", "z": 3.8}]}')]
      return m
    if tool_name == "list_data_table_rows":
      m.isError = False
      m.content = [MagicMock(text='{"rows": [{"values": ["alice.smith", "CRITICAL", "88"]}]}')]
      return m
    m.isError = False
    m.content = [MagicMock(text='{"status": "OK"}')]
    return m

  mock_session = AsyncMock()
  mock_session.call_tool = mock_call_tool

  # The match placeholder is bound to a UDM field: the remediated risk-metrics validator rejects match
  # variables bound only to constant literals (CONSTANT_LITERAL_MATCH_VARIABLE, INVALID_ARGUMENT on Malachite).
  valid_q = 'stage s1 {\n  metadata.event_type = "USER_LOGIN"\n  principal.user.userid = $user\n  $user = "alice.smith"\n  match: $user\n  outcome: $c = count(metadata.id)\n}\n$user = $s1.user\nmatch: $user\noutcome: $z = max($s1.c)'
  resp = await runner.execute_query_via_mcp(
      mock_session,
      valid_q,
      "2026-10-01T00:00:00Z",
      "2026-10-08T00:00:00Z",
      expected_entity="alice.smith",
  )
  assert call_count == 2
  assert resp["stats"][0]["user"] == "alice.smith"

  # 5b. Pre-dispatch gate enforces the harness platform rules itself (compound arithmetic in an if()
  # else-branch) before any udm_search call is made.
  compound_q = valid_q.replace("$z = max($s1.c)", "$z = if(max($s1.c) > 0, 1.0, max($s1.c) - 1.0)")
  with pytest.raises(QueryValidationError, match="COMPOUND_ARITHMETIC_IN_IF_BRANCH"):
    await runner.execute_query_via_mcp(
        mock_session,
        compound_q,
        "2026-10-01T00:00:00Z",
        "2026-10-08T00:00:00Z",
    )
  assert call_count == 2

  # 6. Persistent backend compiler error raises ChronicleBackendQueryError after 2 attempts
  async def mock_always_error(tool_name, args):
    m = MagicMock()
    m.isError = True
    m.content = [MagicMock(text="compilation error: semantic error in stage s1")]
    return m

  mock_session_err = AsyncMock()
  mock_session_err.call_tool = mock_always_error
  with pytest.raises(ChronicleBackendQueryError, match="CHRONICLE_BACKEND_QUERY_ERROR"):
    await runner.execute_query_via_mcp(
        mock_session_err,
        valid_q,
        "2026-10-01T00:00:00Z",
        "2026-10-08T00:00:00Z",
    )

  # 7. Data Table materialization and row retrieval
  mat = await runner.materialize_bridge_data_table(
      mock_session,
      "%ueba_hunt_bridge",
      [{"entity": "alice.smith", "risk_tier": "CRITICAL", "cri_score": "88"}],
  )
  assert mat["table_name"] == "ueba_hunt_bridge"
  assert mat["rows_added"] == 1
  rows = await runner.fetch_data_table_rows(mock_session, "%ueba_hunt_bridge")
  assert len(rows) == 1


@pytest.mark.anyio
async def test_stats_hunter_entity_scoping_and_new_archetypes(monkeypatch):
  from unittest.mock import AsyncMock
  from datetime import datetime
  from src.config import TenantConfig
  from src.pipeline_runner import PipelineRunner
  from src.stats_hunter_engine import StatsHunterEngine

  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  engine = StatsHunterEngine(tenant)
  captured_queries = []

  def _cell(v):
    if isinstance(v, int):
      return {"value": {"int64Val": str(v)}}
    if isinstance(v, float):
      return {"value": {"doubleVal": v}}
    if isinstance(v, list):
      return {"list": {"values": [{"int64Val": str(x)} if isinstance(x, int) else {"stringVal": x} for x in v]}}
    return {"value": {"stringVal": str(v)}}

  def _columnar(rows):
    return {"stats": {"results": [
        {"column": col, "values": [_cell(r[col]) for r in rows]} for col in rows[0]
    ]}}

  def _payload_for(query, start_iso):
    # D6: EWMA, Shannon and C2 jitter are scored by scripts/micro_python_helpers.py over the raw
    # Chronicle columnar payload; the other templates emit their own score columns.
    t0 = int(datetime.fromisoformat(start_iso.replace("Z", "+00:00")).timestamp())
    if "stage pair_persistence" in query:  # c2_beaconing_jitter_2stage.yl2
      return _columnar([
          {"src_ip": "10.10.20.55", "dst_ip": "198.51.100.42", "ws": t0 + h * 3600,
           "event_timestamps": [t0 + h * 3600 + k * 300 + (5 if k % 2 else -5) for k in range(12)],
           "bucket_conns": 12, "total_conns": 36, "active_hours": 3}
          for h in range(3)
      ])
    if "stage entity_prefilter" in query:  # ewma_burst_velocity_2stage.yl2
      series = [5, 6, 5, 4, 6, 5, 5, 6, 4, 5, 6, 5] + [5, 6, 20, 30, 40, 45, 50, 55, 60, 60, 60, 60]
      return _columnar([
          {"entity": "10.20.30.99", "ws": t0 + i * 3600, "window_events": n} for i, n in enumerate(series)
      ])
    if "stage token_stats" in query:  # shannon_entropy_character_2stage.yl2
      benign = [
          "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule",
          "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted",
          "C:\\Windows\\System32\\svchost.exe -k UnistackSvcGroup -s CDPUserSvc",
          "C:\\Windows\\System32\\svchost.exe -k NetworkService -p -s Dnscache",
          "C:\\Windows\\System32\\svchost.exe -k LocalSystemNetworkRestricted",
      ]
      candidate = "cmd /c q8Zr2LxP9vKt4WmB7nYc3HdF6jGs1QaE5uRo0TiXyZpVb"
      rows = [{"token": t, "sample_entities": ["h1", "h2", "h3"], "host_prevalence": 3, "token_events": 9}
              for t in benign]
      rows.append({"token": candidate, "sample_entities": ["wkstn-entropy-01"], "host_prevalence": 1,
                   "token_events": 1})
      return _columnar(rows)
    return {"stats": [{
        "dst_ip": "198.51.100.42",
        "fano_factor": 6.5,
        "poisson_z_sq": 17.64,
        "markov_threat_score": 4.8,
        "zipf_rarity_score": 4.5,
        "z_score": 4.3,
        "producer_ratio": 0.92,
        "entity": "wkstn-pivot-09",
    }]}

  async def fake_exec(session, query, start_iso, end_iso):
    captured_queries.append(query)
    return _payload_for(query, start_iso)

  monkeypatch.setattr(engine.runner, "execute_query_via_mcp", fake_exec)
  mock_session = AsyncMock()

  # Verify $e.-prefixed raw UDM stage scoping works
  e_prefixed = (
      'stage raw_stage {\n'
      '  $e.metadata.event_type = "PROCESS_LAUNCH"\n'
      '  $e.principal.asset.hostname = $host\n'
      '  match: $host\n'
      '  outcome: $c = count($e.metadata.id)\n'
      '}'
  )
  scoped_e = PipelineRunner.scope_query_to_entity(e_prefixed, "wkstn-e-01", entity_type="ASSET")
  assert '$host = "wkstn-e-01"' in scoped_e

  # 1. C2 Beaconing Jitter scopes $src_ip (fleet template: bound at root, dst prevalence intact)
  r1 = await engine.run_c2_beaconing_jitter(mock_session, src_ip="10.10.20.55")
  assert '$src_ip = "10.10.20.55"' in r1["executed_query"]
  assert r1["target_destination"] == "198.51.100.42"
  assert r1["is_outlier"] is True

  # 2. Poisson Burst Clustering scopes $entity
  r2 = await engine.run_poisson_burst_clustering(mock_session, entity="spray.victim")
  assert '"spray.victim"' in r2["executed_query"]
  assert r2["is_outlier"] is True

  # 3. Poisson Rare Surge resolves all placeholders and scopes $entity
  r3 = await engine.run_poisson_rare_surge(mock_session, entity="admin.rare")
  assert '"admin.rare"' in r3["executed_query"]
  assert "{{" not in r3["executed_query"]
  assert r3["poisson_z"] == 4.2
  assert r3["is_outlier"] is True

  # 4. Markov Transition Rarity scopes $entity
  r4 = await engine.run_markov_transition_rarity(mock_session, host="wkstn-markov-01")
  assert '"wkstn-markov-01"' in r4["executed_query"]
  assert r4["is_outlier"] is True

  # 5. Shannon Character Entropy scopes $entity
  r5 = await engine.run_shannon_character_entropy(mock_session, entity="wkstn-entropy-01")
  assert '"wkstn-entropy-01"' in r5["executed_query"]
  assert r5["sample_token"].startswith("cmd /c q8Zr2LxP9vKt4")
  assert r5["is_outlier"] is True

  # 6. Zipfian Process Rarity scopes $entity
  r6 = await engine.run_zipfian_process_rarity(mock_session, host="wkstn-zipf-01")
  assert '"wkstn-zipf-01"' in r6["executed_query"]
  assert r6["is_outlier"] is True

  # 7. EWMA Burst Velocity scopes $entity
  r7 = await engine.run_ewma_burst_velocity(mock_session, entity="10.20.30.99", lookback_days=1)
  assert '"10.20.30.99"' in r7["executed_query"]
  assert r7["is_outlier"] is True

  # 8. Impossible Travel Geo Velocity is retired (D1): refused with the skill's message, nothing executed
  n_queries = len(captured_queries)
  with pytest.raises(ValueError, match="IMPOSSIBLE_TRAVEL_GEO_VELOCITY is retired"):
    await engine.run_impossible_travel_velocity(mock_session, user_id="traveler.user")
  assert len(captured_queries) == n_queries

  # 9. Producer-Consumer Ratio Inversion (template score column: $z_score)
  r9 = await engine.run_producer_consumer_inversion(mock_session, hostname="wkstn-pivot-09")
  assert r9["model"] == "PRODUCER_CONSUMER_RATIO_INVERSION"
  assert '"wkstn-pivot-09"' in r9["executed_query"]
  assert r9["pcr_z_score"] == 4.3
  assert r9["is_outlier"] is True

  # Every executed stats-hunter query passes the skills' validators
  for q in captured_queries:
    assert engine.runner.validate_ast(q, skill="secops-statistical-hunter") == []


@pytest.mark.anyio
async def test_fleet_360_composite_multisector_outlier_emission(monkeypatch):
  """Entities with multiple sub-3σ spokes whose Euclidean D >= 3.0σ (CRI >= 50) must be emitted."""
  from datetime import datetime, timezone
  from unittest.mock import AsyncMock
  from src.config import TenantConfig

  eng = RiskMetricsEngine(TenantConfig(project_id="test-proj", customer_id="test-cust"))

  # admin has Cloud Z=2.51 and Web Z=2.51 on the same day -> D = sqrt(2.51^2 + 2.51^2) = 3.55 >= 3.0 (CRI=58)
  # single_sub has only Web Z=2.51 -> D = 2.51 < 3.0 (should NOT be emitted)
  async def fake_execute(session, query, start_iso, end_iso):
    if "resource_creation_total" in query:
      return {
          "stats": [
              {"user": "admin", "z": 2.51, "observed": 12, "baseline": 2.0, "dispersion": 4.0}
          ]
      }
    if "http_queries_total" in query:
      return {
          "stats": [
              {"user": "admin", "z": 2.51, "observed": 500, "baseline": 100.0, "dispersion": 160.0},
              {"user": "single_sub", "z": 2.51, "observed": 300, "baseline": 100.0, "dispersion": 80.0},
          ]
      }
    return {"stats": []}

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_execute)
  ingested = []
  monkeypatch.setattr(
      eng,
      "ingest_udm_events",
      lambda events: (ingested.extend(events) or {"status": "SUCCESS", "events_ingested": len(events), "batches": 1}),
  )

  res = await eng.run_fleet_360_sweep(
      session=AsyncMock(),
      entity_type="USER",
      spike_threshold_z=3.0,
      spoke_inclusion_z=2.0,
      min_observed=5,
      inter_query_delay_sec=0.0,
      ingest_events=True,
      now_utc=datetime(2026, 10, 20, 16, 0, 0, tzinfo=timezone.utc),
  )

  assert res["outliers_detected"] == 1
  assert res["outliers_emitted"] == 1
  out = res["outliers"][0]
  assert out["entity"] == "admin"
  assert out["composite_d"] == 3.55
  assert out["composite_cri"] == 58
  assert set(out["breached_sectors"]) == {"CLOUD", "WEB"}
  assert len(ingested) == 1
  labels = {l["key"]: l["value"] for l in ingested[0]["target"]["resource"]["attribute"]["labels"]}
  assert labels["Composite CRI"] == "58"
  assert labels["Breached Vectors"] == "CLOUD, WEB"
  assert all(sr["threat_status"] == "ACTIVE" for sr in ingested[0]["security_result"][1:])


@pytest.mark.anyio
async def test_360_behavioral_radar_synchronous_day_bucket_alignment(monkeypatch):
  """run_360_behavioral_radar must align sectors by TIME_BUCKET rather than mixing peak days across a 14d window."""
  from unittest.mock import AsyncMock
  from src.config import TenantConfig

  eng = RiskMetricsEngine(TenantConfig(project_id="test-proj", customer_id="test-cust"))

  # Disjoint single-spoke days: Cloud peaks on 2026-10-18 (Z=2.51), Web peaks on 2026-10-12 (Z=2.51)
  async def fake_disjoint(session, query, start_iso, end_iso):
    if "resource_creation_total" in query:
      return {
          "stats": [
              {"TIME_BUCKET": "2026-10-18T00:00:00Z", "z": 2.51, "observed": 10, "avg": 2.0, "std": 3.2},
              {"TIME_BUCKET": "2026-10-20T00:00:00Z", "z": 0.40, "observed": 3, "avg": 2.0, "std": 2.5},
          ]
      }
    if "http_queries_total" in query:
      return {
          "stats": [
              {"TIME_BUCKET": "2026-10-12T00:00:00Z", "z": 2.51, "observed": 800, "avg": 200.0, "std": 240.0},
          ]
      }
    return {"stats": []}

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_disjoint)
  res_sync = await eng.run_360_behavioral_radar(AsyncMock(), "admin", lookback_days=14, entity_type="USER")
  # Must evaluate a single day (2026-10-18, D=2.51, CRI=43), NOT combine 2026-10-18 + 2026-10-12 into D=3.55 (CRI=58)
  assert res_sync["evaluated_day"] == "2026-10-18"
  assert res_sync["composite_d"] == 2.51
  assert res_sync["calibrated_risk_index"] == 43
  assert res_sync["sector_z_scores"]["Cloud"] == 2.51
  assert res_sync["sector_z_scores"]["Web"] == 0.0

  # When prefer_latest_day=True, selects 2026-10-20
  res_latest = await eng.run_360_behavioral_radar(
      AsyncMock(), "admin", lookback_days=14, entity_type="USER", prefer_latest_day=True
  )
  assert res_latest["evaluated_day"] == "2026-10-20"
  assert res_latest["sector_z_scores"]["Cloud"] == 0.40


def test_cloud_sector_zero_dispersion_and_machine_account_filter():
  """Cloud CRUD queries must guard against zero-stddev saturation and filter AD machine accounts ($).

  The v2.1.1 `if($std_X > 0, $std_X, 1000000.0)` divisor is gone: v2.3.0 (D8 / WS1-04) uses the count floor
  max(sd, sqrt(max(avg, 1))) plus the active-day maturity gate, as templates/radar_360/user_2_cloud_risk.yl2 does.
  """
  from src import harness_truth

  eng = RiskMetricsEngine()
  q_cloud = eng.build_fleet_360_sector_queries(entity_type="USER")["Cloud"]
  assert 'not re.regex(principal.user.userid, "\\\\$$")' in q_cloud
  min_days = harness_truth.min_baseline_days()
  for p, fam in (("r", "read"), ("w", "write"), ("c", "create"), ("d", "delete")):
    assert f"${p}_flr = math.sqrt(if(${p}_avg > 1.0, ${p}_avg, 1.0))" in q_cloud
    assert f"${p}_sd = if(${p}_std > ${p}_flr, ${p}_std, ${p}_flr)" in q_cloud
    assert f"$z_{fam} = if(${p}_days >= {min_days}, $z{p}_u, 0.0)" in q_cloud
  assert "1000000.0" not in q_cloud


@pytest.mark.anyio
async def test_jit_hunt_360_case_wall_ingests_udm_event_when_fleet_360_enabled(monkeypatch):
  """Posting a 360° Case Wall report with D >= 3.0σ must also ingest a BEHAVIORAL_RISK_RADAR_360 UDM event."""
  from unittest.mock import AsyncMock
  from src.autonomous_hunter import AutonomousHunterEngine
  from src.config import TenantConfig
  from src.models import JITHuntRequest

  tenant = TenantConfig(
      project_id="test-proj",
      customer_id="test-cust",
      fleet_360_enabled=True,
      fleet_360_ingest_events=True,
      fleet_360_spike_threshold_z=3.0,
  )
  engine = AutonomousHunterEngine(tenant)
  req = JITHuntRequest(
      target_entity="admin",
      entity_type="USER",
      case_id="21558",
      query="profile_360_risk",
      lookback_days=14,
      post_to_case_wall=True,
  )

  mock_radar_res = {
      "entity": "admin",
      "evaluated_day": "2026-10-20",
      "composite_d": 3.54,
      "calibrated_risk_index": 58,
      "top_sector": "Cloud",
      "is_outlier": True,
      "outlier_sectors": ["Cloud", "Web"],
      "sector_z_scores": {"Auth": 0.0, "Cloud": 2.51, "Workspace": 0.0, "Egress": 0.0, "DNS": 0.0, "Web": 2.51},
      "sector_observed_counts": {"Auth": 0, "Cloud": 10, "Workspace": 0, "Egress": 0, "DNS": 0, "Web": 850},
      "sector_baseline_avg": {"Cloud": 2.0, "Web": 200.0},
      "sector_baseline_std": {"Cloud": 3.2, "Web": 259.0},
      "verdict": "NOMINAL_BASELINE",
  }

  monkeypatch.setattr(
      "src.autonomous_hunter.RiskMetricsEngine.run_360_behavioral_radar",
      AsyncMock(return_value=mock_radar_res),
  )
  ingested_events = []
  monkeypatch.setattr(
      "src.autonomous_hunter.RiskMetricsEngine.ingest_udm_events",
      lambda self, events: (ingested_events.extend(events) or {"status": "SUCCESS", "events_ingested": len(events), "batches": 1}),
  )

  mock_session = AsyncMock()
  mock_session.initialize = AsyncMock()
  mock_session.__aenter__.return_value = mock_session

  class MockContext:
    async def __aenter__(self):
      return (AsyncMock(), AsyncMock())
    async def __aexit__(self, *args):
      pass

  monkeypatch.setattr("src.autonomous_hunter.streamable_http_client", lambda *args, **kwargs: MockContext())
  monkeypatch.setattr("src.autonomous_hunter.ClientSession", lambda *args, **kwargs: mock_session)
  monkeypatch.setattr("src.config.TenantConfig.get_auth_headers", lambda self: {"Authorization": "Bearer test"})

  resp = await engine.execute_jit_hunt(req)
  assert resp.status == "SUCCESS"
  assert len(ingested_events) == 1
  ev = ingested_events[0]
  assert ev["metadata"]["product_event_type"] == "BEHAVIORAL_RISK_RADAR_360"
  assert ev["principal"]["user"]["userid"] == "admin"
  assert ev["security_result"][0]["risk_score"] == 58


@pytest.mark.anyio
async def test_workspace_triad_and_outcome_variable_alignment(monkeypatch):
  """Verify run_workspace_triad, run_hybrid_enrichment, run_cloud_repository_scope, and run_dynamic_metric_pipeline align with v2.1.0 skill templates."""
  from unittest.mock import AsyncMock
  from src.config import TenantConfig
  from src.risk_metrics_engine import RiskMetricsEngine
  from src.stats_hunter_engine import StatsHunterEngine
  from src.strategy_decider import StrategyDecider

  # 1. StrategyDecider Workspace catalog must use valid v2.1.0 metric names
  assert "workspace_network_bytes_inbound" not in StrategyDecider.FAMILY_SIGNALS["Workspace"]["metrics"]
  assert "workspace_network_bytes_total" in StrategyDecider.FAMILY_SIGNALS["Workspace"]["metrics"]
  assert "workspace_emails_sent_total" in StrategyDecider.FAMILY_SIGNALS["Workspace"]["metrics"]

  eng = RiskMetricsEngine(TenantConfig(project_id="test-proj", customer_id="test-cust"))

  # 2. run_workspace_triad renders workspace_activity_triad_3stage.yl2 and parses d_vs_fleet_sq
  async def fake_ws_execute(session, query, start_iso, end_iso):
    assert "metrics.workspace_auth_attempts_total" in query
    assert "metrics.workspace_total_download_actions" in query
    assert "metrics.workspace_total_change_actions" in query
    return {
        "stats": [{
            "entity": "insider.user",
            "d_vs_fleet_sq": 16.0,
            "z1_vs_enterprise": 2.0,
            "z2_vs_enterprise": 3.0,
            "z3_vs_enterprise": 1.73,
            "m1_observed": 12,
            "m2_observed": 85,
            "m3_observed": 19,
        }]
    }

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_ws_execute)
  ws_res = await eng.run_workspace_triad(AsyncMock(), "insider.user", lookback_days=7)
  assert ws_res["composite_z_score"] == 4.0  # sqrt(16.0)
  assert ws_res["top_z_score"] == 4.0
  assert ws_res["is_outlier"] is True
  # z1..z3 follow the requested triad order (auth attempts, downloads, changes); z1 is not an email score.
  assert ws_res["auth_z"] == 2.0
  assert ws_res["download_z"] == 3.0
  assert ws_res["change_z"] == 1.73
  assert ws_res["observed_value"] == 116.0
  assert ws_res["fusion_metrics"] == [
      "workspace_auth_attempts_total",
      "workspace_total_download_actions",
      "workspace_total_change_actions",
  ]

  # 3. run_hybrid_enrichment parses macro_z_score & signature_diversity
  async def fake_hybrid_execute(session, query, start_iso, end_iso):
    return {"stats": [{"entity": "insider.user", "macro_z_score": 4.2, "signature_diversity": 2, "raw_event_count": 30}]}

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_hybrid_execute)
  hyb_res = await eng.run_hybrid_enrichment(AsyncMock(), "insider.user", lookback_days=7)
  assert hyb_res["macro_z_score"] == 4.2
  assert hyb_res["distinct_micro_signatures"] == 2
  assert hyb_res["is_outlier"] is True

  # 4. run_cloud_repository_scope parses obs & dest_z (the dual-branch template has no fold-change column)
  async def fake_repo_execute(session, query, start_iso, end_iso):
    return {"stats": [{"entity": "sa@proj.iam.gserviceaccount.com", "obs": 44, "dest_z": 3.8, "origin_z": 2.9}]}

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_repo_execute)
  repo_res = await eng.run_cloud_repository_scope(AsyncMock(), "sa@proj.iam.gserviceaccount.com", lookback_days=7)
  assert repo_res["observed_events"] == 44.0
  assert repo_res["composite_risk"] == 3.8
  assert repo_res["dest_z"] == 3.8
  assert repo_res["origin_z"] == 2.9
  assert "fold_change" not in repo_res
  assert repo_res["top_z_score"] == 3.8
  assert repo_res["is_outlier"] is True

  # 5. run_dynamic_metric_pipeline extracts specialized score_key (cusum_drift_score) ahead of personal_z
  async def fake_cusum_execute(session, query, start_iso, end_iso):
    return {"stats": [{"entity": "user1", "cusum_drift_score": 3.7, "daily_excess_z": 1.2, "obs": 25, "avg_base": 5.0}]}

  monkeypatch.setattr(eng.runner, "execute_query_via_mcp", fake_cusum_execute)
  cusum_res = await eng.run_dynamic_metric_pipeline(
      AsyncMock(),
      entity="user1",
      model_name="LONGITUDINAL_CUSUM_DRIFT",
      target_metric="dns_queries_fail",
      lookback_days=7,
  )
  assert cusum_res["top_z_score"] == 3.7
  assert cusum_res["observed_value"] == 25.0
  assert cusum_res["is_outlier"] is True

  # 6. StatsHunterEngine outcome alignment (poisson_z_sq, z_score & producer_ratio); IMPOSSIBLE_TRAVEL_GEO_VELOCITY
  #    is retired (secops-statistical-hunter D1), so its entry point refuses with the skill's own message before
  #    any query is dispatched instead of scoring distance_km.
  from src import harness_truth

  stats_eng = StatsHunterEngine(TenantConfig(project_id="test-proj", customer_id="test-cust"))

  async def fake_poisson_rare(session, query, start_iso, end_iso):
    return {"stats": [{"entity": "admin1", "poisson_z_sq": 16.0, "obs_count": 9}]}

  monkeypatch.setattr(stats_eng.runner, "execute_query_via_mcp", fake_poisson_rare)
  pr_res = await stats_eng.run_poisson_rare_surge(AsyncMock(), "admin1", lookback_days=7)
  assert pr_res["poisson_z"] == 4.0  # sqrt(16.0)
  assert pr_res["is_outlier"] is True

  async def no_travel_dispatch(session, query, start_iso, end_iso):
    raise AssertionError("retired IMPOSSIBLE_TRAVEL_GEO_VELOCITY must not dispatch a query")

  monkeypatch.setattr(stats_eng.runner, "execute_query_via_mcp", no_travel_dispatch)
  with pytest.raises(ValueError, match="retired") as travel_exc:
    await stats_eng.run_impossible_travel_velocity(AsyncMock(), "traveler", lookback_days=7)
  assert str(travel_exc.value) == harness_truth.retirement_message("IMPOSSIBLE_TRAVEL_GEO_VELOCITY")
  assert "HOUR_OF_DAY_PROFILE" in str(travel_exc.value)

  async def fake_pc(session, query, start_iso, end_iso):
    return {"stats": [{"entity": "10.0.0.5", "z_score": 4.5, "producer_ratio": 0.92, "sent_bytes": 9200000}]}

  monkeypatch.setattr(stats_eng.runner, "execute_query_via_mcp", fake_pc)
  pc_res = await stats_eng.run_producer_consumer_inversion(AsyncMock(), "10.0.0.5", lookback_days=7)
  assert pc_res["pcr_z_score"] == 4.5
  assert pc_res["producer_ratio"] == 0.92
  assert pc_res["is_outlier"] is True


def test_v212_v282_skill_alignment_and_score_extraction(monkeypatch):
  import asyncio
  asyncio.run(_async_v212_v282_skill_alignment_and_score_extraction(monkeypatch))


async def _async_v212_v282_skill_alignment_and_score_extraction(monkeypatch):
  """Verifies agentic_ueba alignment with secops-risk-metrics-multistage v2.1.2 and secops-statistical-hunter v2.8.2."""
  from src.query_integrity_gate import QueryIntegrityGate, QueryValidationError

  rm_engine = RiskMetricsEngine()
  sh_engine = StatsHunterEngine()

  # 1. QueryIntegrityGate ignores commented-out %table references (e.g. privileged_lateral_expansion_2stage.yl2)
  builder = sh_engine._get_stats_hunter_builder()
  priv_q = builder.MultiStageTemplateRouter().build_query(
      archetype="PRIVILEGED_LATERAL_EXPANSION",
      tier="BALANCED",
      entity_type="user",
  )
  gate_res = QueryIntegrityGate.validate_preflight_query(priv_q, raise_on_error=True)
  assert gate_res["valid"] is True

  # Bare %table in active code is still caught
  with pytest.raises(QueryValidationError):
    QueryIntegrityGate.verify_pre_dispatch("stage s1 { principal.hostname in %bad_table match: $h outcome: $c = count(metadata.id) }")

  # 2. Verify Stage 2 math model score extraction for the remediated (v2.3.0) outcome names: the score is
  #    the variable each template's root significance gate tests (falling back to its order: variable),
  #    and retired models are refused with the skill's own message instead of being rendered.
  from src import harness_truth

  for retired in ("HOURLY_TEMPORAL_ZSCORE", "FLEET_PREVALENCE_SHIELD", "PIECEWISE_CRI"):
    with pytest.raises(ValueError) as exc:
      await rm_engine.run_dynamic_metric_pipeline(
          session=None, entity="alex.lund", entity_type="USER", target_metric="auth_attempts_total",
          model_name=retired)
    assert str(exc.value) == harness_truth.retirement_message(retired)

  model_mock_rows = [
      ("ADAPTIVE_CONTEXT_THRESHOLD", {"adaptive_z": 3.75, "sensitivity_excess": 0.75, "personal_z": 7.20, "observed": 40, "hist_avg": 4.0, "active_days": 20}, 3.75),
      ("TWO_PART_HURDLE", {"hurdle_threat_score": 12.40, "dormant_score": 12.40, "intensity_z": 2.1, "observed": 10}, 12.40),
      ("ASYMMETRIC_DIRECTIONAL_Z", {"personal_z": 5.15, "observed": 80, "hist_avg": 10.0, "active_days": 20}, 5.15),
      ("VARIANCE", {"fano_factor": 8.50, "observed": 60, "lambda": 7.0}, 8.50),
      ("POISSON", {"poisson_z": 4.85, "k": 25, "hist_avg": 2.0}, 4.85),
      ("LONGITUDINAL_CUSUM", {"cusum_drift_score": 7.40, "drift_days": 4, "max_daily_z": 3.80, "hist_avg": 12.0, "active_days": 20}, 7.40),
      ("DIVERSITY_DEFICIT_ENTROPY", {"macro_z": 4.20, "diversity_ratio": 0.02, "concentration_ratio": 0.9, "active_baseline_days": 20}, 4.20),
      ("MAD", {"modified_z": 4.90, "personal_z": 2.0, "median_val": 3.0, "raw_active_days": 25}, 4.90),
      ("MACD_MOMENTUM_VELOCITY", {"macd_z": 4.40, "macd_momentum_score": 4.40, "above_max_z": 1.2, "active_days": 20}, 4.40),
  ]

  for model_name, fake_row, expected_score in model_mock_rows:
    async def _fake_exec(session, query, start_iso, end_iso, _row=fake_row):
      # Validate query through QueryIntegrityGate before returning mock row
      QueryIntegrityGate.verify_pre_dispatch(
          query,
          ast_validator_fn=rm_engine.runner.validate_ast,
          raise_on_error=True,
      )
      return _row

    monkeypatch.setattr(rm_engine.runner, "execute_query_via_mcp", _fake_exec)
    monkeypatch.setattr(rm_engine.runner, "parse_stats_response", lambda resp: [resp])
    res = await rm_engine.run_dynamic_metric_pipeline(
        session=None,
        entity="alex.lund",
        entity_type="USER",
        target_metric="auth_attempts_total",
        model_name=model_name,
    )
    assert res["top_z_score"] == pytest.approx(expected_score, 0.01)
    assert res["calibrated_risk_index"] == harness_truth.calculate_cri(res["z_equivalent"])
    if model_name == "LONGITUDINAL_CUSUM":
      assert res["drift_days"] == 4
      assert res["max_daily_z"] == pytest.approx(3.80, 0.01)

  # 3. Verify HTTP_ERROR_RATIO_SURGE_2STAGE metric guard & HYBRID_DATA_TABLE_BRIDGE_2STAGE
  for pipe_model in ("HTTP_ERROR_RATIO_SURGE_2STAGE", "HYBRID_DATA_TABLE_BRIDGE_2STAGE"):
    async def _fake_pipe_exec(session, query, start_iso, end_iso):
      QueryIntegrityGate.verify_pre_dispatch(
          query,
          ast_validator_fn=rm_engine.runner.validate_ast,
          raise_on_error=True,
      )
      return {"personal_z": 4.5, "z_score": 4.5, "observed_24h": 100.0, "baseline_mean": 10.0}

    monkeypatch.setattr(rm_engine.runner, "execute_query_via_mcp", _fake_pipe_exec)
    monkeypatch.setattr(rm_engine.runner, "parse_stats_response", lambda resp: [resp])
    p_res = await rm_engine.run_dynamic_metric_pipeline(
        session=None,
        entity="srv-web-01",
        entity_type="ASSET",
        target_metric="http_queries_total",
        model_name=pipe_model,
    )
    assert p_res["top_z_score"] == 4.5

  # 4. Verify run_hybrid_enrichment passes un-mocked QueryIntegrityGate with num_metric_periods
  async def _fake_hybrid_exec(session, query, start_iso, end_iso):
    assert "num_metric_periods" in query
    QueryIntegrityGate.verify_pre_dispatch(
        query,
        ast_validator_fn=rm_engine.runner.validate_ast,
        raise_on_error=True,
    )
    return {"macro_z_score": 5.2, "signature_diversity": 2}

  monkeypatch.setattr(rm_engine.runner, "execute_query_via_mcp", _fake_hybrid_exec)
  monkeypatch.setattr(rm_engine.runner, "parse_stats_response", lambda resp: [resp])
  h_res = await rm_engine.run_hybrid_enrichment(session=None, username="frank.kolzig")
  assert h_res["macro_z_score"] == 5.2

  # 5. Verify StatsHunterEngine.run_dynamic_archetype_pipeline across the current templates. The mocks return the
  #    real udm_search `stats` shape (columnar stats.results[].values[].value.<type>Val) and the real
  #    PipelineRunner.parse_stats_response decodes it: template archetypes are scored on their root `order:`
  #    column, and EWMA_BURST_VELOCITY is scored by the skill's micro_python_helpers.run_ewma_helper over the raw
  #    payload, whose D6 G2 guardrail rejects anything that is not a udm_search `stats` block.
  from datetime import datetime, timezone

  c = harness_truth.constants()

  def _udm_cell(value):
    if isinstance(value, bool):
      return {"value": {"boolVal": value}}
    if isinstance(value, int):
      return {"value": {"int64Val": str(value)}}
    if isinstance(value, float):
      return {"value": {"doubleVal": value}}
    return {"value": {"stringVal": str(value)}}

  def _udm_stats(columns):
    return {"stats": {"results": [
        {"column": name, "values": [_udm_cell(v) for v in values]} for name, values in columns.items()]}}

  def _epoch(iso):
    return int(datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())

  template_payloads = {
      "ZSCORE_PROCESS_SURGE": ("z_score", _udm_stats({
          "entity": ["wks-eng-01"], "window_start": [1793059200], "observation_count": [42],
          "baseline_mean": [6.0], "baseline_dispersion": [8.6], "z_score": [4.2]})),
      "PRIVILEGED_LATERAL_EXPANSION": ("z_score", _udm_stats({
          "entity": ["wks-eng-01"], "ws": [1793059200], "observation_count": [9], "new_targets": [2],
          "z_score": [4.2]})),
      "DERIVED_CONTEXT_PREVALENCE": ("threat_score", _udm_stats({
          "user": ["alice"], "host": ["wks-eng-01"], "ws": [1793059200], "z_score": [2.1],
          "threat_score": [4.2], "in_scoring_window": [1]})),
  }
  for arch, (score_col, payload) in template_payloads.items():
    async def _fake_sh_exec(session, query, start_iso, end_iso, _payload=payload):
      QueryIntegrityGate.verify_pre_dispatch(query, raise_on_error=True)
      return _payload

    monkeypatch.setattr(sh_engine.runner, "execute_query_via_mcp", _fake_sh_exec)
    sh_res = await sh_engine.run_dynamic_archetype_pipeline(
        session=None,
        entity="wks-eng-01",
        archetype=arch,
        entity_type="ASSET",
    )
    assert sh_res["score_metric"] == score_col, arch
    assert sh_res["top_z_score"] == 4.2, arch
    assert sh_res["calibrated_risk_index"] == c.cri_from_model_score(score_col, 4.2), arch
    assert sh_res["stats_rows"] == 1, arch

  # EWMA: the ungated hourly (entity, ws, window_events) series of ewma_burst_velocity_2stage.yl2 over the
  # dispatched window. Baseline half: 4 events / hour (zero sample SD, so sigma_0 is the Poisson floor
  # sqrt(4) = 2); scored half: 7 events / hour, a sustained shift EWMA accumulates (lambda = 0.25).
  ewma_calls = []

  async def _fake_ewma_exec(session, query, start_iso, end_iso):
    QueryIntegrityGate.verify_pre_dispatch(query, raise_on_error=True)
    start, end = _epoch(start_iso), _epoch(end_iso)
    hours = (end - start) // 3600
    series = [4 if h < hours // 2 else 7 for h in range(hours)]
    payload = _udm_stats({
        "entity": ["wks-eng-01"] * hours,
        "ws": [start + h * 3600 for h in range(hours)],
        "window_events": series,
        "total_events": [sum(series)] * hours,
    })
    ewma_calls.append((query, start_iso, end_iso, payload))
    return payload

  monkeypatch.setattr(sh_engine.runner, "execute_query_via_mcp", _fake_ewma_exec)
  ewma_res = await sh_engine.run_dynamic_archetype_pipeline(
      session=None,
      entity="wks-eng-01",
      archetype="EWMA_BURST_VELOCITY",
      entity_type="ASSET",
  )
  query, start_iso, end_iso, payload = ewma_calls[0]
  control_l = ewma_res["control_limit_l"]
  # Closed form at the last of the k scored buckets: (S_k - mu_0) / sigma_EWMA with S_k - mu_0 = 3 * (1 - 0.75^k)
  # and sigma_EWMA = sigma_0 * sqrt(lambda / (2 - lambda)).
  hours = (_epoch(end_iso) - _epoch(start_iso)) // 3600
  k = hours - hours // 2
  expected_ewma_z = 3.0 * (1.0 - 0.75 ** k) / (2.0 * math.sqrt(0.25 / 1.75))
  expected_z_eq = c.score_to_z_equivalent("ewma_z", expected_ewma_z, threshold_override=control_l)
  assert ewma_res["score_metric"] == "ewma_z"
  assert ewma_res["ewma_velocity_score"] == round(expected_ewma_z, 2)
  assert ewma_res["top_z_score"] == round(expected_z_eq, 2)
  assert ewma_res["calibrated_risk_index"] == c.cri_from_model_score(
      "ewma_z", expected_ewma_z, threshold_override=control_l)
  assert ewma_res["is_outlier"] is True
  # Same numbers as the skill's own helper over the same raw payload, query and window.
  oracle = sh_engine.runner.get_micro_python_helpers().run_ewma_helper(
      payload, query_text=query, start_time=start_iso, end_time=end_iso, control_l=control_l, bucket_seconds=3600)
  top = max(oracle["entity_results"], key=lambda r: r["ewma_z"])
  assert ewma_res["top_z_score"] == round(top["z_equiv"], 2)
  assert ewma_res["calibrated_risk_index"] == top["cri"]

  # The D6 G2 guardrail still fails closed on a payload without a udm_search `stats` block.
  async def _fake_flat_exec(session, query, start_iso, end_iso):
    return {"z_score": 4.2, "ewma_velocity_score": 4.2, "velocity_score": 4.2}

  monkeypatch.setattr(sh_engine.runner, "execute_query_via_mcp", _fake_flat_exec)
  with pytest.raises(ValueError, match="G2_MISSING_STATS_BLOCK"):
    await sh_engine.run_dynamic_archetype_pipeline(
        session=None, entity="wks-eng-01", archetype="EWMA_BURST_VELOCITY", entity_type="ASSET")


def test_bilateral_ueba_harness_and_telemetry_physics_guardrail():
  """Verify Telemetry Physics 14d raw ceiling and Bilateral UEBA Harness routing."""
  from datetime import datetime
  from src.autonomous_hunter import AutonomousHunterEngine
  from src.models import JITHuntRequest
  from src.strategy_decider import StrategyDecider

  # 1. Telemetry Physics Guardrail: raw UDM lookback is clamped to <= 14 days (never 30d)
  assert StatsHunterEngine.enforce_telemetry_physics_window(30) == 14
  assert StatsHunterEngine.enforce_telemetry_physics_window(7) == 7
  sh_engine = StatsHunterEngine()
  start_iso, end_iso = sh_engine._iso_window(30)
  dt_start = datetime.strptime(start_iso, "%Y-%m-%dT%H:%M:%SZ")
  dt_end = datetime.strptime(end_iso, "%Y-%m-%dT%H:%M:%SZ")
  assert (dt_end - dt_start).days == 14

  # 2. Bilateral UEBA Harness routing for http2shell / web-to-shell exploit inquiries
  ctx_http2shell = {
      "case_title": "HTTP2Shell Exploit Investigation",
      "alerts": ["Web-to-Shell RCE Suspected"],
      "case_description": "Use UEBA to detect http2shell exploit chain on web server",
      "entity_type": "ASSET",
      "primary_entity": "web-prod-01",
      "investigation_tier": "TIER_2_DEEP_DIVE",
  }
  directive = StrategyDecider._deterministic_reasoner(ctx_http2shell)
  assert directive.selected_skill == "secops-risk-metrics-multistage"
  assert directive.model_name == "DUAL_SECTOR_FUSION_3STAGE"
  assert directive.fusion_metrics == ["http_queries_fail", "file_executions_total"]
  cand_models = {c.model_name for c in directive.candidate_hypotheses}
  assert "MARKOV_2GRAM_TRANSITION_RARITY" in cand_models
  assert "SHANNON_ENTROPY_CHARACTER" in cand_models
  assert "C2_BEACONING_JITTER" in cand_models

  # 3. Producer-Consumer Byte Ratio Inversion routing
  skill, query, model = StrategyDecider.decide(
      case_title="Workstation Producer-Consumer Role Inversion",
      alert_name="Net Producer Asymmetry",
      alert_desc="Endpoint pcr_z_score breach",
      entity_type="ASSET",
  )
  assert skill == "secops-statistical-hunter"
  assert query == "producer_consumer_inversion"
  assert model == "PRODUCER_CONSUMER_RATIO_INVERSION"

  # 4. AutonomousHunterEngine bilateral skill resolution
  hunter = AutonomousHunterEngine()
  req_bilateral = JITHuntRequest(
      target_entity="web-prod-01",
      entity_type="ASSET",
      alert_name="HTTP2Shell Web-to-Shell Exploit Chain",
  )
  assert hunter.resolve_skill_selection(req_bilateral) == "bilateral"


@pytest.mark.anyio
async def test_quantile_iqr_skew_and_tukey_skew_fences_pipelines(monkeypatch):
  """Verify v2.2.0 QUANTILE_IQR_SKEW (risk-metrics) and v2.9.0 IQR_TUKEY_SKEW_FENCES (stats-hunter) pipelines."""
  from src import harness_truth
  from src.query_integrity_gate import QueryIntegrityGate

  rm_engine = RiskMetricsEngine()
  sh_engine = StatsHunterEngine()

  async def _fake_rm_quantile(session, query, start_iso, end_iso):
    QueryIntegrityGate.verify_pre_dispatch(query, raise_on_error=True)
    assert "window.percentile(" in query
    assert "stage quantile_envelope" in query
    assert "$bowley_skew" in query
    # v2.3.0 (WS1-03): scored as robust-scale excess above the Bowley-adjusted Tukey fence.
    assert "$tukey_excess_z" in query
    return {
        "observed": 50000000.0,
        "q25_val": 1000000.0,
        "q50_val": 2500000.0,
        "q75_val": 6000000.0,
        "bowley_skew": 0.40,
        "tail_heaviness": 3.1,
        "adj_upper_fence": 12000000.0,
        "robust_scale": 3700000.0,
        "tukey_excess_z": 2.5,
        "personal_z": 2.4,
        "raw_active_days": 21,
    }

  monkeypatch.setattr(rm_engine.runner, "execute_query_via_mcp", _fake_rm_quantile)
  monkeypatch.setattr(rm_engine.runner, "parse_stats_response", lambda resp: [resp])

  q_res = await rm_engine.run_quantile_iqr_skew(
      session=None,
      entity="wks-dev-01",
      entity_type="ASSET",
      target_metric="network_bytes_outbound",
      lookback_days=14,
  )
  assert q_res["model"] == "QUANTILE_IQR_SKEW"
  assert q_res["score_key"] == "tukey_excess_z"
  assert q_res["top_z_score"] == 2.5
  assert q_res["tukey_excess_z"] == 2.5
  assert q_res["z_equivalent"] == pytest.approx(
      harness_truth.constants().score_to_z_equivalent("tukey_excess_z", 2.5))
  assert q_res["is_true_sigma"] is False
  assert q_res["bowley_skew"] == 0.4
  assert q_res["tail_heaviness"] == 3.1
  assert q_res["is_outlier"] is True

  async def _fake_sh_tukey(session, query, start_iso, end_iso):
    QueryIntegrityGate.verify_pre_dispatch(query, raise_on_error=True)
    assert "window.percentile(" in query
    assert "stage quantile_fences" in query
    assert "$bowley_skew" in query
    assert "$surge_ratio" in query
    # v3.0.0 (WS5): recalibrated 1.35 Bowley exponent, ranked by the scale-invariant $fence_z.
    assert "1.35 * $pos_skew" in query
    assert "$fence_z" in query
    return {
        "fence_z": 4.2,
        "surge_ratio": 3.85,
        "bowley_skew": 0.52,
        "tail_heaviness": 2.95,
    }

  monkeypatch.setattr(sh_engine.runner, "execute_query_via_mcp", _fake_sh_tukey)
  monkeypatch.setattr(sh_engine.runner, "parse_stats_response", lambda resp: [resp])

  sh_res = await sh_engine.run_iqr_tukey_skew_fences(
      session=None,
      entity="wks-dev-01",
      entity_type="ASSET",
      event_type="NETWORK_CONNECTION",
      lookback_days=30,
  )
  from src import harness_truth as ht
  assert sh_res["model"] == "IQR_TUKEY_SKEW_FENCES"
  assert sh_res["score_metric"] == "fence_z"
  assert sh_res["primary_score"] == 4.2
  assert sh_res["top_z_score"] == round(ht.constants().score_to_z_equivalent("fence_z", 4.2), 2)
  assert sh_res["calibrated_risk_index"] == ht.constants().cri_from_model_score("fence_z", 4.2)
  assert sh_res["is_outlier"] is True



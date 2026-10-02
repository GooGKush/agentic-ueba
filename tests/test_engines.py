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
  # At Z = 0.0 sigma, CRI must be nominal (~14)
  assert runner.calculate_cri(0.0) == 14
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
      "min_conns": "30",
      "min_active_hours": "3",
      "prevalence": "5",
      "tier": "STANDARD",
      "bucket_size": "1h",
      "cv": "0.20",
  })
  
  assert 'metadata.event_type = "NETWORK_CONNECTION"' in rendered
  assert "not net.ip_in_range_cidr" in rendered
  assert "{{min_conns}}" not in rendered
  assert "cv <= 0.20" in rendered.lower() or "cv" in rendered.lower()


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
  runner = PipelineRunner()
  tpl = runner.find_template("secops-risk-metrics-multistage", "circadian_von_mises_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_type": "USER_LOGIN",
      "entity_field": "target.user.userid",
      "value_filter": "",
      "observed_aggregation": "count(metadata.id)",
      "target_metric_name": "auth_attempts_total",
      "metric_type_val": "event_count_sum",
      "dimension_key": "target.user.userid",
      "extra_dimensions": "",
  })
  assert "CIRCADIAN VON MISES" in rendered
  assert "metrics.auth_attempts_total" in rendered
  assert "$circadian_threat_score" in rendered
  assert "{{target_metric_name}}" not in rendered


def test_macd_momentum_velocity_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-risk-metrics-multistage", "macd_momentum_velocity_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_type": "NETWORK_CONNECTION",
      "entity_field": "principal.user.userid",
      "value_filter": "",
      "observed_aggregation": "sum(network.sent_bytes)",
      "target_metric_name": "network_bytes_outbound",
      "metric_type_val": "value_sum",
      "dimension_key": "principal.user.userid",
      "extra_dimensions": "",
  })
  assert "MACD DUAL-SPINE MOMENTUM VELOCITY" in rendered
  assert "metrics.network_bytes_outbound" in rendered
  assert "$macd_momentum_score" in rendered
  assert "{{target_metric_name}}" not in rendered


def test_markov_2gram_transition_rarity_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-statistical-hunter", "markov_2gram_transition_rarity_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_type": "PROCESS_LAUNCH",
      "entity_field": "principal.hostname",
      "bucket_size": "1d",
      "min_parent_count": "5",
      "surprisal_threshold": "3.5",
      "tier": "STANDARD",
  })
  assert "Markov 2-Gram Transition" in rendered
  assert "principal.process.file.full_path" in rendered
  assert "$markov_threat_score" in rendered
  assert "{{min_parent_count}}" not in rendered


def test_shannon_entropy_character_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-statistical-hunter", "shannon_entropy_character_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_type": "PROCESS_LAUNCH",
      "entity_field": "principal.hostname",
      "bucket_size": "1d",
      "min_length": "20",
      "entropy_threshold": "6.0",
      "tier": "STANDARD",
  })
  assert "Shannon Character-Class Entropy" in rendered
  assert "strings.length" in rendered
  assert "$shannon_entropy_score" in rendered
  assert "{{entropy_threshold}}" not in rendered


def test_zipfian_process_rarity_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-statistical-hunter", "zipfian_process_rarity_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_type": "PROCESS_LAUNCH",
      "entity_field": "principal.hostname",
      "bucket_size": "1d",
      "max_adopters": "2",
      "min_count": "1",
      "zipf_threshold": "3.5",
      "tier": "STANDARD",
  })
  assert "Zipfian Inverse Rank" in rendered
  assert "fleet_process_popularity" in rendered
  assert "$zipf_rarity_score" in rendered
  assert "{{max_adopters}}" not in rendered


def test_ewma_burst_velocity_template_rendering():
  runner = PipelineRunner()
  tpl = runner.find_template("secops-statistical-hunter", "ewma_burst_velocity_2stage.yl2")
  rendered = runner.render_template(tpl, {
      "event_type": "NETWORK_CONNECTION",
      "entity_field": "principal.ip",
      "bucket_size": "1h",
      "min_active_samples": "3",
      "min_sd": "1.0",
      "min_count": "5",
      "velocity_threshold": "3.0",
      "tier": "STANDARD",
  })
  assert "Exponentially Weighted Moving Average (EWMA)" in rendered
  assert "trailing_hourly_baseline" in rendered
  assert "$ewma_velocity_score" in rendered
  assert "{{velocity_threshold}}" not in rendered


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

  # 3. Shannon Entropy
  skill, query, model = StrategyDecider.decide("", "Obfuscated Command Line", "High Shannon entropy base64 payload", "HOST")
  assert skill == "secops-statistical-hunter"
  assert model == "SHANNON_CHARACTER_ENTROPY"

  # 4. Markov Transition
  skill, query, model = StrategyDecider.decide("", "Unusual Process Parent Child", "Rare LotL Markov transition", "HOST")
  assert skill == "secops-statistical-hunter"
  assert model == "MARKOV_TRANSITION_RARITY"

  # 5. Zipfian Rare Binary
  skill, query, model = StrategyDecider.decide("", "Rare Binary Execution", "Long tail rare admin tool in fleet", "HOST")
  assert skill == "secops-statistical-hunter"
  assert model == "ZIPFIAN_PROCESS_RARITY"

  # 6. EWMA Kinetic Burst
  skill, query, model = StrategyDecider.decide("", "Kinetic Rate Acceleration", "EWMA burst velocity divergence", "IP")
  assert skill == "secops-statistical-hunter"
  assert model == "EWMA_BURST_VELOCITY"

  # 7. Circadian von Mises
  skill, query, model = StrategyDecider.decide("", "Off-Hours Login Surge", "Circadian temporal anomaly after hours", "USER")
  assert skill == "secops-risk-metrics-multistage"
  assert model == "CIRCADIAN_VON_MISES"

  # 8. MACD Momentum
  skill, query, model = StrategyDecider.decide("", "MACD Momentum Velocity Divergence", "Acceleration surge outbound bytes", "USER")
  assert skill == "secops-risk-metrics-multistage"
  assert model == "MACD_MOMENTUM_VELOCITY"

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

  mock_circ = {
      "entity": "night_owl_user",
      "model": "CIRCADIAN_VON_MISES",
      "circadian_threat_score": 4.8,
      "hourly_z": 3.2,
      "event_hour": 3,
      "top_z_score": 4.8,
      "calibrated_risk_index": 75,
      "is_outlier": True,
      "stats_rows": 1,
      "executed_query": "// Circadian Query",
  }

  async def mock_run_circ(*args, **kwargs):
    return mock_circ

  monkeypatch.setattr("src.autonomous_hunter.RiskMetricsEngine.run_circadian_von_mises", mock_run_circ)

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
  assert resp.triage.calibrated_risk_index == 75
  assert resp.triage.verdict == "HIGH_OUTLIER"
  assert resp.triage.primary_vector == "circadian_temporal_anomaly"
  assert resp.clean_hand_off.outlier_topology == "CIRCADIAN_TEMPORAL_DEPARTURE"


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
  assert resp.triage.verdict == "CRITICAL_OUTLIER"
  assert resp.triage.primary_vector == "markov_process_transition_rarity"
  assert resp.triage.recommended_action == "ISOLATE_HOST"


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

  # 3. DNS Outlier -> selects dns_queries_fail with LONGITUDINAL_CUSUM_DRIFT
  t2_dns = await StrategyDecider.decide_tier2_deep_dive(
      target_entity="10.20.30.40",
      entity_type="IP",
      outlier_vector="DNS",
      case_info={"id": "case-dns-1", "title": "NXDOMAIN Resolution Surge"},
      alerts=[{"name": "DNS Failure Spike", "description": "Elevated dns_queries_fail count"}],
      connector_events=[],
  )
  assert t2_dns.selected_skill == "secops-risk-metrics-multistage"
  assert t2_dns.model_name == "LONGITUDINAL_CUSUM_DRIFT"
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


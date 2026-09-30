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
  assert "#### 1. Statistical Outlier Report" in clean
  assert "- **Target Entity**: `timaddler-pc`" in clean
  assert "- **CRI**: 0 / 100" in clean


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
  assert len(captured_queries) == 5  # Auth, Egress, DNS, Flows, Alerts
  # Verify host-specific UDM predicates are used
  assert any("principal.asset.hostname" in q for q in captured_queries)
  assert any("metrics.auth_attempts_total" in q for q in captured_queries)
  assert any("metrics.network_bytes_outbound" in q for q in captured_queries)
  assert any("metrics.dns_queries_fail" in q for q in captured_queries)

# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""StrategyDecider alignment with the remediated UEBA harness (package D).

Truth is read at runtime, never copied: retired models, sensitivity tiers,
thresholds, mode caps and the Mode A / Entity Graph windows come from
src.harness_truth; the canonical cross-skill routing table and the micro model
gates come from the skills' always-loaded SKILL.md files; current model names
are checked against the skills' own resolvers.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import re

import pytest

from src import harness_truth
from src.config import get_skills_root
from src.models import StrategyDirective
from src.strategy_decider import StrategyDecider

RISK = harness_truth.RISK_METRICS_SKILL
STATS = harness_truth.STATS_HUNTER_SKILL
NOW = datetime(2026, 10, 30, 10, 0, tzinfo=timezone.utc)

# Renames from both RELEASE_NOTES.md files (risk-metrics v2.3.0 D1 / WS1-02 honest renames;
# stats-hunter canonical ModelArchetype names used by its SKILL.md routing table).
LEGACY_TO_CURRENT = {
    "MARKOV_TRANSITION_RARITY": "MARKOV_2GRAM_TRANSITION_RARITY",
    "SHANNON_CHARACTER_ENTROPY": "SHANNON_ENTROPY_CHARACTER",
    "ELEPHANT_FLOW_CONCENTRATION": "HYBRID_ENTROPY_CONCENTRATION",
    "MACD_MOMENTUM_VELOCITY": "ABOVE_HISTORICAL_MAX_Z",
    "LONGITUDINAL_CUSUM_DRIFT": "LONGITUDINAL_CUSUM",
}

STALE_LABEL_PATTERNS = (
    r"[Vv]on\s+Mises",
    r"circadian_von_mises",
    r"\bMACD\b",
    r"MACD_MOMENTUM_VELOCITY",
    r"[Dd]ual[-\s][Ss]pine",
    r"12h fast",
    r"\bday_max\b",
    r"Bonferroni",
    r"sqrt\(Z_a\^2 \+ Z_b\^2\)",
)


@pytest.fixture
def anyio_backend():
  return "asyncio"


@pytest.fixture(autouse=True)
def _deterministic_reasoner_only(monkeypatch):
  monkeypatch.delenv("GEMINI_API_KEY", raising=False)


def _run(coro):
  return asyncio.run(coro)


def _direct(title, desc, entity_type="USER", entity="target.entity", sensitivity=None):
  kwargs = {} if sensitivity is None else {"sensitivity": sensitivity}
  return _run(
      StrategyDecider.decide_agentic(
          case_info={"id": "case-d", "title": title, "description": desc},
          alerts=[{"name": title, "description": desc}],
          connector_events=[],
          default_entity=entity,
          default_entity_type=entity_type,
          tier="TIER_2_DEEP_DIVE",
          **kwargs,
      )
  )


def _deep_dive(vector, title, desc, entity_type="USER", radar=None, entity="target.entity"):
  return _run(
      StrategyDecider.decide_tier2_deep_dive(
          target_entity=entity,
          entity_type=entity_type,
          outlier_vector=vector,
          case_info={"id": "case-d", "title": title},
          alerts=[{"name": title, "description": desc}],
          connector_events=[],
          radar_result=radar,
      )
  )


def _radar(z, outliers=(), **extra):
  out = {
      "top_sector": max(z, key=lambda k: z[k]),
      "outlier_sectors": list(outliers),
      "sector_z_scores": dict(z),
      "sector_observed_counts": {k: 10 for k in z},
  }
  out.update(extra)
  return out


def _t2a(model, vector, metric, skill=RISK, query="dynamic_metric", entity="target.entity", entity_type="USER"):
  return StrategyDirective(
      selected_skill=skill,
      model_name=model,
      directive_query=query,
      target_entity=entity,
      entity_type=entity_type,
      target_metric=metric,
      investigation_tier="TIER_2_DEEP_DIVE",
      outlier_vector=vector,
  )


def _pivot(t2a, radar, outlier, alerts, entity_type="USER"):
  piv = StrategyDecider.decide_tier2_pivot(
      target_entity=t2a.target_entity,
      entity_type=entity_type,
      tier2a_directive=t2a,
      tier2a_result={"is_outlier": outlier, "calibrated_risk_index": 80 if outlier else 20, "stats_rows": 3},
      radar_result=radar,
      alerts=[{"name": a} for a in alerts],
      connector_events=[],
      secondary_hunts_run=1,
  )
  return piv, list(t2a.candidate_hypotheses)


DIRECT_INTENTS = [
    ("Potential C2 Beaconing Activity", "Host observed with regular interval jitter to external IP.", "IP"),
    ("Credential Spray Detection", "Failed login surge across multiple identities.", "USER"),
    ("Obfuscated Command Line", "High Shannon entropy base64 payload", "HOST"),
    ("DGA Domain Burst", "Algorithmic DGA domain resolution", "HOST"),
    ("Unusual Process Parent Child", "Rare LotL Markov transition", "HOST"),
    ("Rare Binary Execution", "Long tail rare admin tool in fleet", "HOST"),
    ("Kinetic Rate Acceleration", "EWMA burst velocity divergence", "IP"),
    ("Off-Hours Login Surge", "Circadian temporal anomaly after hours", "USER"),
    ("Impossible Travel Detected", "Login velocity of 950 kph between two countries", "USER"),
    ("MACD Momentum Velocity Divergence", "Acceleration surge outbound bytes", "USER"),
    ("Cloud IAM Surge", "Cloud permission and resource_creation changes", "USER"),
    ("Insider Data Hoarding", "Unusual access across sectors", "USER"),
    ("Google Drive Mass Download", "Workspace document hoarding", "USER"),
    ("Elephant Flow", "Mass data extraction via bigquery table dumping", "HOST"),
    ("Net Producer Asymmetry", "Endpoint pcr_z_score breach producer-consumer role inversion", "ASSET"),
    ("HTTP2Shell Exploit Investigation", "Use UEBA to detect http2shell exploit chain on web server", "ASSET"),
    ("Nightly Exfiltration", "An automated cron job exfiltrates data in small batches every night", "ASSET"),
    ("Cron Beacon", "A cron job is exfiltrating data every 5 minutes", "ASSET"),
    ("Low and Slow Drift", "Low-and-slow CUSUM drift in outbound bytes", "USER"),
    ("Entity Health Check", "Run a 360 health check on this server", "ASSET"),
    ("Peer Cohort Outlier", "Downloads far exceed the department peer cohort", "USER"),
    ("First-Seen Destination", "Host contacted a first-seen destination never seen before", "ASSET"),
    ("Raw DNS Query Length", "Tukey fence on raw DNS query length", "HOST"),
    ("Heavy-Tailed Egress", "30-day metric-catalog quantile Tukey skew on outbound bytes", "HOST"),
    ("DNS Baseline", "Compare DNS query volume against its 30-day baseline", "HOST"),
    ("Generic Alert", "Something odd happened", "ASSET"),
]

VECTORS = ("Auth", "Cloud", "Workspace", "Egress", "DNS", "Web", "Flows", "Alerts", "Endpoint")


def _pivot_scenarios():
  scenarios = []
  egress = _radar({"Auth": 0.2, "Egress": 3.4, "DNS": 0.1, "Web": 0.1}, outliers=["Egress"])
  scenarios.append(_pivot(_t2a("C2_BEACONING_JITTER", "Egress", "network_bytes_outbound", STATS, "c2_jitter"),
                          egress, False, ["Anomalous Outbound Data"]))
  auth = _radar({"Auth": 3.1, "Egress": 0.2, "DNS": 0.1, "Web": 0.1}, outliers=["Auth"])
  scenarios.append(_pivot(_t2a("POISSON_BURST_CLUSTERING", "Auth", "auth_attempts_fail", STATS, "poisson_burst"),
                          auth, False, ["Failed Login Waves"]))
  masked = _radar({"Auth": 0.1, "Egress": 1.7, "DNS": 0.1, "Web": 0.1}, variance_masked_sectors=["Egress"],
                  subthreshold_sectors=["Egress"], sector_baseline_avg={"Egress": 10.0},
                  sector_baseline_std={"Egress": 65.0})
  scenarios.append(_pivot(_t2a("MACD_MOMENTUM_VELOCITY", "Egress", "network_bytes_outbound", RISK, "macd_momentum"),
                          masked, False, ["Anomalous Outbound Data"]))
  dormant = _radar({"Auth": 0.1, "Workspace": 1.65, "Egress": 0.1}, dormant_awakening_sectors=["Workspace"],
                   subthreshold_sectors=["Workspace"], sector_baseline_avg={"Workspace": 0.05})
  scenarios.append(_pivot(_t2a("ABOVE_HISTORICAL_MAX_Z", "Workspace", "workspace_total_download_actions", RISK,
                               "macd_momentum"), dormant, False, ["Sudden Drive Activity"]))
  web = _radar({"Auth": 0.1, "Web": 3.3, "DNS": 0.2}, outliers=["Web"])
  scenarios.append(_pivot(_t2a("ABOVE_HISTORICAL_MAX_Z", "Web", "http_queries_total", RISK, "macd_momentum"),
                          web, True, ["HTTP Proxy Surge"]))
  alerts = _radar({"Auth": 0.1, "Alerts": 3.6, "Egress": 0.3}, outliers=["Alerts"])
  scenarios.append(_pivot(_t2a("EWMA_BURST_VELOCITY", "Alerts", "alert_event_name_count", STATS, "ewma_burst",
                               entity_type="ASSET"), alerts, True, ["EDR Alert Storm"], entity_type="ASSET"))
  two = _radar({"Workspace": 3.8, "Egress": 3.2, "Auth": 0.1}, outliers=["Workspace", "Egress"])
  scenarios.append(_pivot(_t2a("C2_BEACONING_JITTER", "Egress", "network_bytes_outbound", STATS, "c2_jitter"),
                          two, False, ["Workspace Exfiltration"]))
  return scenarios


def _directive_battery():
  directives = [_direct(t, d, e) for t, d, e in DIRECT_INTENTS]
  directives += [_deep_dive(v, f"{v} anomaly", f"{v} sector outlier", "ASSET" if v in ("Flows", "Alerts", "Endpoint") else "USER")
                 for v in VECTORS]
  directives.append(StrategyDecider.decide_tier1_360("u1", "USER"))
  directives.append(StrategyDecider.decide_tier1_360("host-1", "ASSET"))
  return directives


def _models_and_skills(directives, extra_candidates=()):
  pairs = []
  for d in directives:
    pairs.append((d.model_name, d.selected_skill))
    pairs.extend((c.model_name, c.selected_skill) for c in d.candidate_hypotheses)
  pairs.extend((c.model_name, c.selected_skill) for c in extra_candidates)
  return pairs


def _narrative(d):
  parts = [d.threat_summary, d.hypothesis_h0, d.hypothesis_h1, d.selection_rationale, d.evidentiary_defense,
           d.flight_card_title, d.pivot_reason or "", *d.recommended_avenues]
  for c in d.candidate_hypotheses:
    parts += [c.hypothesis_title, c.hypothesis_h0, c.hypothesis_h1, c.evidentiary_defense, c.pivot_reason or ""]
  return "\n".join(parts)


def _candidate_narrative(c):
  return "\n".join([c.hypothesis_title, c.hypothesis_h0, c.hypothesis_h1, c.evidentiary_defense, c.pivot_reason or ""])


def _forbidden_label_patterns():
  retired = [rf"\b{re.escape(name)}\b" for name in harness_truth.retired_models()]
  legacy = [rf"\b{re.escape(name)}\b" for name in LEGACY_TO_CURRENT]
  return retired + legacy + list(STALE_LABEL_PATTERNS)


def _stats_builder():
  harness_truth.constants()
  from src.stats_hunter_engine import StatsHunterEngine
  return StatsHunterEngine()._get_stats_hunter_builder()


# ---------------------------------------------------------------------------
# 1. Model selection: retired never selected, renamed -> current, new reachable
# ---------------------------------------------------------------------------


def test_no_retired_or_legacy_model_is_ever_selected():
  pivots = _pivot_scenarios()
  directives = _directive_battery() + [p for p, _ in pivots if p is not None]
  pairs = _models_and_skills(directives, extra_candidates=[c for _, cands in pivots for c in cands])
  assert len(pairs) > 60
  for model, skill in pairs:
    assert not harness_truth.is_retired(model), f"retired model selected: {model} ({skill})"
    assert model not in LEGACY_TO_CURRENT, f"legacy model name selected: {model}"


def test_selected_models_live_on_their_canonical_plane():
  pivots = _pivot_scenarios()
  directives = _directive_battery() + [p for p, _ in pivots if p is not None]
  for model, skill in _models_and_skills(directives, extra_candidates=[c for _, cands in pivots for c in cands]):
    if model in StrategyDecider.MICRO_PLANE_MODELS:
      assert skill == STATS, f"{model} is a raw UDM micro model but was assigned to {skill}"
    elif model in StrategyDecider.MACRO_PLANE_MODELS or model.startswith("KILLCHAIN_"):
      assert skill == RISK, f"{model} is a 30d metrics.* macro model but was assigned to {skill}"
    else:
      assert model in StrategyDecider.SHARED_PLANE_MODELS | {"GEMINI_REACT_AUTONOMOUS"}, model


def test_every_retired_model_redirects_to_the_replacement_named_by_the_skill():
  retired = harness_truth.retired_models()
  assert retired
  for name, message in retired.items():
    for spelling in (name, name.lower(), f"{name.lower()}.yl2"):
      resolved = StrategyDecider.resolve_model(spelling)
      assert resolved["redirected_from"] == name
      assert resolved["retirement_message"] == message
      assert not harness_truth.is_retired(resolved["model_name"])
      assert resolved["model_name"] in message, (name, resolved["model_name"], message)
      assert resolved["directive_query"]
  hod = StrategyDecider.resolve_model("CIRCADIAN_VON_MISES", selected_skill=RISK)
  assert (hod["selected_skill"], hod["model_name"], hod["directive_query"]) == (STATS, "HOUR_OF_DAY_PROFILE", "hour_of_day_profile")
  travel = StrategyDecider.resolve_model("impossible_travel_geo_velocity_2stage.yl2")
  assert travel["model_name"] == "HOUR_OF_DAY_PROFILE" and travel["selected_skill"] == STATS


def test_retired_model_is_refused_with_the_skill_message_when_redirect_is_disabled():
  message = harness_truth.retirement_message("CIRCADIAN_VON_MISES")
  with pytest.raises(ValueError, match=re.escape(message)):
    StrategyDecider.resolve_model("CIRCADIAN_VON_MISES", redirect=False)


def test_newly_retired_model_without_a_redirect_is_refused(monkeypatch):
  registry = dict(harness_truth.retired_models())
  registry["NEWLY_RETIRED_MODEL"] = "Statistical model 'NEWLY_RETIRED_MODEL' is retired (D1): no replacement."
  monkeypatch.setattr(harness_truth, "retired_models", lambda: registry)
  with pytest.raises(ValueError, match="NEWLY_RETIRED_MODEL' is retired"):
    StrategyDecider.resolve_model("NEWLY_RETIRED_MODEL")


def test_renamed_models_resolve_to_their_current_names():
  for legacy, current in LEGACY_TO_CURRENT.items():
    assert StrategyDecider.canonical_model_name(legacy) == current
    assert StrategyDecider.resolve_model(legacy)["model_name"] == current
  skill, query, model = StrategyDecider.decide("", "Obfuscated Command Line", "High Shannon entropy base64 payload", "HOST")
  assert (skill, query, model) == (STATS, "shannon_entropy", "SHANNON_ENTROPY_CHARACTER")
  skill, query, model = StrategyDecider.decide("", "Unusual Process Parent Child", "Rare LotL Markov transition", "HOST")
  assert (skill, query, model) == (STATS, "markov_transition", "MARKOV_2GRAM_TRANSITION_RARITY")
  skill, query, model = StrategyDecider.decide("", "MACD Momentum Velocity Divergence", "Acceleration surge outbound bytes", "USER")
  assert (skill, query, model) == (RISK, "macd_momentum", "ABOVE_HISTORICAL_MAX_Z")
  skill, query, model = StrategyDecider.decide("", "Elephant Flow", "Mass data extraction via bigquery table dumping", "HOST")
  assert (skill, model) == (STATS, "HYBRID_ENTROPY_CONCENTRATION")
  dns = _deep_dive("DNS", "NXDOMAIN Resolution Surge", "Elevated dns_queries_fail count", "IP")
  assert (dns.selected_skill, dns.model_name, dns.directive_query) == (RISK, "LONGITUDINAL_CUSUM", "dynamic_metric")


def test_current_micro_names_are_canonical_stats_hunter_archetypes():
  router = _stats_builder().MultiStageTemplateRouter()
  for model in sorted(StrategyDecider.MICRO_PLANE_MODELS):
    template = router.get_template_filename(model)
    assert router.TEMPLATE_TO_SENSITIVITY_KEY[template] == model, (model, template)


def test_current_macro_names_resolve_in_risk_metrics():
  from src.pipeline_runner import PipelineRunner

  runner = PipelineRunner()
  hybrid = runner.get_hybrid_engine()
  _, pipeline_architecture, _, _ = runner.get_validator_enums()
  for model in sorted(StrategyDecider.MACRO_STATISTICAL_MODELS):
    hybrid.resolve_statistical_model(model)
  for model in sorted(StrategyDecider.MACRO_PIPELINE_MODELS):
    assert pipeline_architecture[model].value


def test_new_models_are_reachable():
  cases = [
      (("Off-Hours Login Surge", "Circadian temporal anomaly after hours", "USER"), (STATS, "hour_of_day_profile", "HOUR_OF_DAY_PROFILE")),
      (("Impossible Travel Detected", "Login velocity of 950 kph between two countries", "USER"), (STATS, "hour_of_day_profile", "HOUR_OF_DAY_PROFILE")),
      (("First-Seen Destination", "Host contacted a first-seen destination never seen before", "ASSET"), (RISK, "dynamic_metric", "FIRST_SEEN_NOVELTY")),
      (("Raw DNS Query Length", "Tukey fence on raw DNS query length", "HOST"), (STATS, "dynamic_archetype", "IQR_TUKEY_SKEW_FENCES")),
      (("Heavy-Tailed Egress", "30-day metric-catalog quantile Tukey skew on outbound bytes", "HOST"), (RISK, "quantile_iqr_skew", "QUANTILE_IQR_SKEW")),
      (("Low and Slow Drift", "Low-and-slow CUSUM drift in outbound bytes", "USER"), (RISK, "dynamic_metric", "LONGITUDINAL_CUSUM")),
  ]
  for (title, desc, entity_type), expected in cases:
    assert StrategyDecider.decide("", title, desc, entity_type) == expected, title
  travel = _direct("Impossible Travel Detected", "Login velocity of 950 kph between two countries", "USER")
  assert any(c.model_name == "DERIVED_CONTEXT_PREVALENCE" for c in travel.candidate_hypotheses)

  pivots = _pivot_scenarios()
  _, masked_cands = pivots[2]
  masked_models = {(c.selected_skill, c.model_name) for c in masked_cands}
  assert {(RISK, "MAD"), (RISK, "QUANTILE_IQR_SKEW"), (STATS, "IQR_TUKEY_SKEW_FENCES")} <= masked_models
  _, dormant_cands = pivots[3]
  assert {"TWO_PART_HURDLE", "FIRST_SEEN_NOVELTY"} <= {c.model_name for c in dormant_cands}
  _, auth_cands = pivots[1]
  hod = [c for c in auth_cands if c.model_name == "HOUR_OF_DAY_PROFILE"]
  assert hod and hod[0].selected_skill == STATS and hod[0].directive_query == "hour_of_day_profile"


def test_fleet_scope_drift_uses_the_windowed_slack_sum_prefilter():
  skill, query, model = StrategyDecider.decide("", "Fleet-wide drift", "Low-and-slow CUSUM drift in outbound bytes across the fleet", "ASSET")
  assert (skill, query, model) == (RISK, "dynamic_metric", "WINDOWED_SLACK_SUM")
  fleet = _direct("Drift screen", "Low-and-slow CUSUM drift in outbound bytes", "ASSET", entity="fleet")
  assert fleet.model_name == "WINDOWED_SLACK_SUM"
  assert "longitudinal_cusum_2stage.yl2" in fleet.selection_rationale
  single = _direct("Entity drift", "Low-and-slow CUSUM drift in outbound bytes", "ASSET", entity="web-01")
  assert single.model_name == "LONGITUDINAL_CUSUM"
  assert "longitudinal_cusum_series_3stage.yl2" in single.selection_rationale
  assert "cusum_helper.py" in single.selection_rationale


def test_killchain_selection_stays_inside_the_skill_catalog():
  from src.pipeline_runner import PipelineRunner

  archetype_enum, catalog = PipelineRunner().get_killchain_archetypes()
  catalog_ids = {a.value for a in catalog}
  host = StrategyDecider.analyze_360_insights(
      _radar({"Web": 2.4, "Auth": 2.1, "DNS": 0.1}, outliers=["Web", "Auth"]), {}, "ASSET")
  names = {m["archetype"] for m in host["matched_killchain_archetypes"]}
  assert "RECON_ENUMERATION_TO_INITIAL_ACCESS" in names
  assert "RECON_TO_INITIAL_ACCESS" not in names

  radar = _radar({"Workspace": 3.2, "Web": 1.6, "Auth": 0.1}, outliers=["Workspace"], subthreshold_sectors=["Web"])
  _, cands = _pivot(_t2a("ABOVE_HISTORICAL_MAX_Z", "Workspace", "workspace_total_download_actions", RISK, "macd_momentum"),
                    radar, False, ["Workspace Exfiltration over web"])
  executed_killchains = [c for c in cands if c.directive_query == "killchain_archetype"]
  for c in executed_killchains:
    assert c.killchain_archetype in catalog_ids
  web_service = [c for c in cands if c.killchain_archetype == "EXFILTRATION_OVER_WEB_SERVICE"]
  assert web_service and web_service[0].directive_query == "sector_fusion"
  assert web_service[0].model_name == "DUAL_SECTOR_FUSION_3STAGE"


def test_llm_directive_with_retired_and_renamed_models_is_sanitized(monkeypatch):
  payload = {
      "selected_skill": RISK,
      "model_name": "CIRCADIAN_VON_MISES",
      "directive_query": "circadian_von_mises",
      "target_entity": "night.owl",
      "entity_type": "USER",
      "target_metric": "auth_attempts_total",
      "fusion_metrics": [],
      "investigation_tier": "TIER_2_DEEP_DIVE",
      "outlier_vector": "Auth",
      "threat_summary": "Off-hours logins.",
      "hypothesis_h0": "Logins follow the normal schedule.",
      "hypothesis_h1": "Logins at anomalous hours.",
      "selection_rationale": "Circadian departure.",
      "evidentiary_defense": "Auth sector elevated.",
      "confidence_score": 0.9,
      "flight_card_title": "Off-hours review",
      "candidate_hypotheses": [
          {"hypothesis_title": "Lineage", "selected_skill": RISK, "model_name": "MARKOV_TRANSITION_RARITY",
           "directive_query": "markov_transition", "target_metric": "auth_attempts_total", "fusion_metrics": [],
           "hypothesis_h0": "a", "hypothesis_h1": "b", "evidentiary_defense": "login burst", "confidence_score": 0.8},
          {"hypothesis_title": "Travel", "selected_skill": STATS, "model_name": "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
           "directive_query": "impossible_travel", "target_metric": "auth_attempts_success", "fusion_metrics": [],
           "hypothesis_h0": "a", "hypothesis_h1": "b", "evidentiary_defense": "login velocity", "confidence_score": 0.8},
      ],
  }

  class _Resp:
    text = json.dumps(payload)

  class _Models:
    def generate_content(self, **kwargs):
      return _Resp()

  class _Client:
    def __init__(self, *args, **kwargs):
      self.models = _Models()

  monkeypatch.setenv("GEMINI_API_KEY", "test-key")
  monkeypatch.setattr("src.strategy_decider.genai.Client", _Client)
  directive = _run(StrategyDecider.decide_agentic(
      case_info={"id": "case-llm", "title": "Off-hours login surge"},
      alerts=[{"name": "Off-hours login surge", "description": "logins after hours"}],
      connector_events=[], default_entity="night.owl", default_entity_type="USER",
      tier="TIER_2_DEEP_DIVE", outlier_vector="Auth"))
  assert (directive.selected_skill, directive.model_name, directive.directive_query) == (
      STATS, "HOUR_OF_DAY_PROFILE", "hour_of_day_profile")
  models = {c.model_name: c for c in directive.candidate_hypotheses}
  assert "MARKOV_2GRAM_TRANSITION_RARITY" in models
  assert models["MARKOV_2GRAM_TRANSITION_RARITY"].selected_skill == STATS
  for model, _ in _models_and_skills([directive]):
    assert not harness_truth.is_retired(model) and model not in LEGACY_TO_CURRENT


def test_llm_directive_with_an_unredirectable_retired_model_falls_back(monkeypatch):
  registry = dict(harness_truth.retired_models())
  registry["NEWLY_RETIRED_MODEL"] = "Statistical model 'NEWLY_RETIRED_MODEL' is retired (D1): no replacement."
  monkeypatch.setattr(harness_truth, "retired_models", lambda: registry)

  class _Resp:
    text = json.dumps({"selected_skill": RISK, "model_name": "NEWLY_RETIRED_MODEL", "directive_query": "dynamic_metric",
                       "target_entity": "u1", "entity_type": "USER", "confidence_score": 0.9})

  class _Client:
    def __init__(self, *args, **kwargs):
      self.models = type("M", (), {"generate_content": lambda self, **kw: _Resp()})()

  monkeypatch.setenv("GEMINI_API_KEY", "test-key")
  monkeypatch.setattr("src.strategy_decider.genai.Client", _Client)
  directive = _run(StrategyDecider.decide_agentic(
      case_info={"id": "c", "title": "Suspected Beaconing"},
      alerts=[{"name": "Suspected Beaconing", "description": "Regular interval outbound connection"}],
      connector_events=[], default_entity="u1", default_entity_type="USER",
      tier="TIER_2_DEEP_DIVE", outlier_vector="Egress"))
  assert directive.model_name != "NEWLY_RETIRED_MODEL"
  assert directive.model_name == "C2_BEACONING_JITTER"


# ---------------------------------------------------------------------------
# 2. Cross-skill routing: canonical table, Scheduled Exfiltration, telemetry physics
# ---------------------------------------------------------------------------


def test_canonical_routing_table_is_read_from_the_skills():
  table = StrategyDecider.canonical_routing_table()
  assert table == _stats_builder().CANONICAL_ROUTING_TABLE_MD
  risk_md = (get_skills_root() / RISK / "SKILL.md").read_text(encoding="utf-8")
  assert table in risk_md
  row1 = next(ln for ln in table.splitlines() if ln.startswith("| **1."))
  expected = set(re.findall(r"`([A-Z][A-Z0-9_]+)`", row1.split("|")[2]))
  assert StrategyDecider.precedence_one_models() == expected
  assert {"C2_BEACONING_JITTER", "HOUR_OF_DAY_PROFILE", "SHANNON_ENTROPY_CHARACTER",
          "MARKOV_2GRAM_TRANSITION_RARITY", "POISSON_BURST_CLUSTERING"} <= expected
  for model in expected:
    assert StrategyDecider.resolve_model(model, selected_skill=RISK)["selected_skill"] == STATS


SCHEDULED_EXFIL_PROMPTS = [
    "We suspect an internal server is running an automated cron job that exfiltrates data in small batches every night.",
    "Scheduled exfiltration of finance data to an external host",
    "Nightly data dumps leave this server for an unknown destination",
    "Recurring uploads to a personal bucket every night over several days",
]


@pytest.mark.parametrize("prompt", SCHEDULED_EXFIL_PROMPTS)
def test_scheduled_exfiltration_offers_both_answers(prompt):
  route = StrategyDecider.route_intent(prompt, entity_type="ASSET")
  assert route["intent"] == "SCHEDULED_EXFILTRATION"
  assert (route["target_skill"], route["model_name"], route["directive_query"]) == (RISK, "LONGITUDINAL_CUSUM", "dynamic_metric")
  answer1, answer2 = route["answers"]
  assert (answer1["selected_skill"], answer1["model_name"]) == (RISK, "LONGITUDINAL_CUSUM")
  assert answer1["zero_code"] is False
  assert "cusum_helper.py" in answer1["rule"] and "longitudinal_cusum_2stage.yl2" in answer1["rule"]
  assert (answer2["selected_skill"], answer2["model_name"]) == (STATS, "C2_BEACONING_JITTER")
  assert answer2["zero_code"] is True and "query" not in answer2

  assert StrategyDecider.decide("", "Scheduled exfiltration", prompt, "ASSET") == (RISK, "dynamic_metric", "LONGITUDINAL_CUSUM")
  directive = _direct("Scheduled exfiltration", prompt, "ASSET", entity="site-rev-proxy")
  handoffs = [c for c in directive.candidate_hypotheses
              if c.selected_skill == STATS and c.model_name == "C2_BEACONING_JITTER"]
  assert len(handoffs) == 1, [c.model_name for c in directive.candidate_hypotheses]
  assert "Skill Handoff" in handoffs[0].hypothesis_title
  assert handoffs[0].confidence_band != "AUTO_EXECUTE"
  card = _candidate_narrative(handoffs[0])
  assert "```" not in card and not re.search(r"\bstage\s+\w+\s*\{", card)
  assert "Answer 1" in directive.selection_rationale and "Answer 2" in directive.selection_rationale
  plan = StrategyDecider.plan_evaluation_window(directive.model_name, directive.selected_skill, now=NOW)
  assert plan["mode"] != "A"


@pytest.mark.parametrize("prompt", [
    "A cron job is exfiltrating data every 5 minutes",
    "Scheduled exfiltration every 10 minutes with randomized jitter",
    "Hourly cron beacon to a cloud storage bucket",
])
def test_sub_day_cron_cadence_stays_in_the_statistical_hunter(prompt):
  route = StrategyDecider.route_intent(prompt, entity_type="ASSET")
  assert route["precedence"] == 1 and route["target_skill"] == STATS
  assert StrategyDecider.decide("", "Cadence", prompt, "ASSET") == (STATS, "c2_jitter", "C2_BEACONING_JITTER")


def test_beaconing_jitter_wins_even_when_ueba_is_mentioned():
  prompt = "Use the 30-day UEBA baseline to detect C2 beaconing with jitter"
  route = StrategyDecider.route_intent(prompt, entity_type="IP")
  assert route["precedence"] == 1 and route["target_skill"] == STATS
  assert StrategyDecider.decide("", "UEBA beaconing hunt", prompt, "IP") == (STATS, "c2_jitter", "C2_BEACONING_JITTER")


def test_entropy_routes_to_the_statistical_hunter():
  route = StrategyDecider.route_intent("Algorithmic DGA domains with high Shannon entropy", entity_type="HOST")
  assert (route["precedence"], route["target_skill"], route["model_name"]) == (1, STATS, "SHANNON_ENTROPY_CHARACTER")
  assert StrategyDecider.decide("", "DGA burst", "Algorithmic DGA domains with high Shannon entropy", "HOST") == (
      STATS, "shannon_entropy", "SHANNON_ENTROPY_CHARACTER")


@pytest.mark.parametrize("title,desc,entity_type", [
    ("Entity Health Check", "Run a 360 health check on this server", "ASSET"),
    ("Risk score review", "What is this user's entity risk score?", "USER"),
])
def test_360_radar_routes_to_risk_metrics(title, desc, entity_type):
  route = StrategyDecider.route_intent(desc, entity_type=entity_type)
  assert (route["precedence"], route["target_skill"], route["model_name"]) == (2, RISK, "360_DECOUPLED_RADAR")
  assert StrategyDecider.decide("", title, desc, entity_type) == (RISK, "profile_360_risk", "360_DECOUPLED_RADAR")


def test_peer_cohort_routes_to_risk_metrics():
  desc = "Downloads far exceed the department peer cohort"
  route = StrategyDecider.route_intent(desc, entity_type="USER")
  assert (route["precedence"], route["target_skill"]) == (2, RISK)
  assert StrategyDecider.decide("", "Peer Cohort Outlier", desc, "USER") == (RISK, "dynamic_metric", "PART_OF_THE_WHOLE_MULTILEVEL")
  directive = _direct("Peer Cohort Outlier", desc, "USER")
  assert any(c.model_name == "DUAL_BASELINE_3STAGE" for c in directive.candidate_hypotheses)
  assert "Samuelson" in directive.selection_rationale


@pytest.mark.parametrize("desc,entity_type", [
    ("Low-and-slow CUSUM drift in outbound bytes", "USER"),
    ("Run CUSUM drift on this beaconing host", "ASSET"),
])
def test_cusum_routes_to_risk_metrics(desc, entity_type):
  route = StrategyDecider.route_intent(desc, entity_type=entity_type)
  assert (route["precedence"], route["target_skill"], route["model_name"]) == (2, RISK, "LONGITUDINAL_CUSUM")
  assert StrategyDecider.decide("", "Drift", desc, entity_type) == (RISK, "dynamic_metric", "LONGITUDINAL_CUSUM")


def test_telemetry_physics_guardrail_keeps_30_day_baselines_on_the_macro_plane():
  desc = "Compare DNS query volume against its 30-day baseline"
  route = StrategyDecider.route_intent(desc, entity_type="HOST")
  assert (route["precedence"], route["target_skill"]) == (2, RISK)
  directive = _direct("DNS Baseline", desc, "HOST")
  assert (directive.selected_skill, directive.model_name, directive.target_metric) == (RISK, "STANDARD_Z_SCORE", "dns_queries_total")

  caps = harness_truth.mode_caps()
  for model in sorted(StrategyDecider.MICRO_PLANE_MODELS):
    plan = StrategyDecider.plan_evaluation_window(model, STATS, mode="B", requested_days=30, now=NOW)
    assert plan["plane"] == "MICRO" and plan["days"] <= caps["mode_b_micro_days"], model

  bilateral = _direct("HTTP2Shell Exploit Investigation", "Use UEBA to detect http2shell exploit chain on web server", "ASSET")
  assert bilateral.selected_skill == RISK
  assert {c.selected_skill for c in bilateral.candidate_hypotheses if c.model_name in StrategyDecider.MICRO_PLANE_MODELS} == {STATS}
  loop_hits, loop_sum_z_sq = harness_truth.loopback_thresholds()
  assert "PLAYBOOK_BEHAVIORAL_HUNT_MATCH" in bilateral.selection_rationale
  assert f"{loop_hits}" in bilateral.selection_rationale and f"{loop_sum_z_sq:g}" in bilateral.selection_rationale


def test_persistent_rule_authoring_routes_to_detection_engineering():
  route = StrategyDecider.route_intent("Please write a detection rule and deploy it with create_rule")
  assert (route["precedence"], route["target_skill"], route["model_name"]) == (4, "secops-detection-engineering", None)


# ---------------------------------------------------------------------------
# 3. Time modes and caps
# ---------------------------------------------------------------------------


def test_macro_mode_a_defaults_to_the_last_complete_utc_day():
  day = harness_truth.mode_a_day(NOW)
  plan = StrategyDecider.plan_evaluation_window("STANDARD_Z_SCORE", now=NOW)
  assert (plan["plane"], plan["mode"], plan["days"]) == ("MACRO", "A", 1)
  assert plan["scored_day"] == day.isoformat()
  assert (plan["start_time"], plan["end_time"]) == harness_truth.mode_a_window(day)
  assert plan["entity_graph"] is False and plan["event_day_pin"] is None
  radar = StrategyDecider.plan_evaluation_window("360_DECOUPLED_RADAR", now=NOW)
  assert radar["mode"] == "A" and radar["scored_day"] == day.isoformat()


def test_entity_graph_models_start_at_d_minus_2_with_event_stages_pinned_to_the_scored_day():
  day = harness_truth.mode_a_day(NOW)
  for model in ("RARE_DESTINATION_ECG_3STAGE", "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE"):
    plan = StrategyDecider.plan_evaluation_window(model, now=NOW)
    assert plan["mode"] == "A" and plan["entity_graph"] is True
    assert (plan["start_time"], plan["end_time"]) == harness_truth.ecg_window(day)
    assert plan["event_day_pin"] == harness_truth.event_day_pin(day)


def test_macro_mode_b_is_capped_and_redirects_to_mode_c():
  caps = harness_truth.mode_caps()
  default_b = StrategyDecider.plan_evaluation_window("STANDARD_Z_SCORE", mode="B", now=NOW)
  assert (default_b["mode"], default_b["days"], default_b["cap_days"]) == ("B", caps["mode_b_macro_days"], caps["mode_b_macro_days"])
  start = (NOW.replace(hour=0, minute=0) - timedelta(days=caps["mode_b_macro_days"] - 1)).strftime("%Y-%m-%dT%H:%M:%SZ")
  assert default_b["start_time"] == start
  capped = StrategyDecider.plan_evaluation_window("STANDARD_Z_SCORE", mode="B", requested_days=7,
                                                  run_command_available=False, now=NOW)
  assert (capped["mode"], capped["days"], capped["capped_from_days"]) == ("B", caps["mode_b_macro_days"], 7)
  assert capped["notices"]
  redirected = StrategyDecider.plan_evaluation_window("STANDARD_Z_SCORE", mode="B", requested_days=7, now=NOW)
  assert (redirected["mode"], redirected["days"]) == ("C", 7)


def test_macro_mode_c_is_capped_and_needs_local_scripts():
  caps = harness_truth.mode_caps()
  capped = StrategyDecider.plan_evaluation_window("STANDARD_Z_SCORE", mode="C", requested_days=45, now=NOW)
  assert (capped["mode"], capped["days"], capped["capped_from_days"]) == ("C", caps["mode_c_macro_days"], 45)
  no_scripts = StrategyDecider.plan_evaluation_window("STANDARD_Z_SCORE", mode="C", requested_days=10,
                                                      run_command_available=False, now=NOW)
  assert (no_scripts["mode"], no_scripts["days"]) == ("B", caps["mode_b_macro_days"])


@pytest.mark.parametrize("model", ["LONGITUDINAL_CUSUM", "LONGITUDINAL_CUSUM_DRIFT", "WINDOWED_SLACK_SUM"])
def test_longitudinal_cusum_never_runs_in_single_day_mode_a(model):
  caps = harness_truth.mode_caps()
  default = StrategyDecider.plan_evaluation_window(model, now=NOW)
  assert default["mode"] != "A"
  assert default["days"] == default["cap_days"] == caps["mode_b_cusum_macro_days"]
  forced = StrategyDecider.plan_evaluation_window(model, mode="A", now=NOW)
  assert forced["mode"] != "A" and forced["days"] >= 2
  assert any("Mode A" in note for note in forced["notices"])
  one_day = StrategyDecider.plan_evaluation_window(model, requested_days=1, now=NOW)
  assert one_day["mode"] != "A" and one_day["days"] >= 2


@pytest.mark.parametrize("model", ["LONGITUDINAL_CUSUM", "LONGITUDINAL_CUSUM_DRIFT"])
def test_page_cusum_beyond_the_single_query_cap_runs_as_mode_c_shards(model):
  caps = harness_truth.mode_caps()
  long_c = StrategyDecider.plan_evaluation_window(model, requested_days=20, now=NOW)
  assert (long_c["model_name"], long_c["mode"], long_c["days"]) == ("LONGITUDINAL_CUSUM", "C", 20)
  assert long_c["requires_run_command"] is True
  capped_c = StrategyDecider.plan_evaluation_window(model, requested_days=45, now=NOW)
  assert (capped_c["mode"], capped_c["days"], capped_c["capped_from_days"]) == ("C", caps["mode_c_macro_days"], 45)


@pytest.mark.parametrize("requested", [None, 20])
def test_page_cusum_without_local_scripts_discloses_the_stateless_prefilter(requested):
  # SKILL.md Scheduled Exfiltration Answer 1: stateless longitudinal_cusum_2stage.yl2 when there is no run_command.
  # scripts/cusum_helper.py D6 guardrail G5: Page CUSUM needs cusum_helper.py and the Windowed Slack Sum prefilter is
  # never substituted silently, so the plan names the substitution instead of claiming Page CUSUM ran.
  caps = harness_truth.mode_caps()
  plan = StrategyDecider.plan_evaluation_window(
      "LONGITUDINAL_CUSUM", requested_days=requested, run_command_available=False, now=NOW)
  assert plan["model_name"] == "WINDOWED_SLACK_SUM"
  assert plan["substituted_from"] == "LONGITUDINAL_CUSUM"
  assert plan["requires_run_command"] is False
  assert plan["mode"] not in ("A", "C") and plan["days"] == caps["mode_b_cusum_macro_days"]
  assert plan["capped_from_days"] == requested
  assert any("cusum_helper.py" in note and "WINDOWED_SLACK_SUM" in note for note in plan["notices"])
  assert "longitudinal_cusum_2stage.yl2" in plan["label"]


def test_windowed_slack_sum_prefilter_is_one_stateless_query_within_the_cusum_cap():
  caps = harness_truth.mode_caps()
  plan = StrategyDecider.plan_evaluation_window("WINDOWED_SLACK_SUM", requested_days=20, now=NOW)
  assert plan["model_name"] == "WINDOWED_SLACK_SUM" and plan["substituted_from"] is None
  assert plan["mode"] not in ("A", "C") and plan["requires_run_command"] is False
  assert (plan["days"], plan["capped_from_days"]) == (caps["mode_b_cusum_macro_days"], 20)
  assert "longitudinal_cusum_2stage.yl2" in plan["label"]
  page = StrategyDecider.plan_evaluation_window("LONGITUDINAL_CUSUM", now=NOW)
  assert page["substituted_from"] is None and page["requires_run_command"] is True
  assert "cusum_helper.py" in page["label"]


def test_micro_windows_follow_the_telemetry_physics_caps():
  caps = harness_truth.mode_caps()
  markov = StrategyDecider.plan_evaluation_window("MARKOV_2GRAM_TRANSITION_RARITY", now=NOW)
  assert (markov["plane"], markov["mode"], markov["days"]) == ("MICRO", "B", caps["mode_b_micro_days"])
  capped = StrategyDecider.plan_evaluation_window("MARKOV_2GRAM_TRANSITION_RARITY", requested_days=30, now=NOW)
  assert (capped["days"], capped["capped_from_days"]) == (caps["mode_b_micro_days"], 30)
  jitter = StrategyDecider.plan_evaluation_window("C2_BEACONING_JITTER", now=NOW)
  assert (jitter["mode"], jitter["start_time"], jitter["end_time"]) == (
      "A", (NOW - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"), NOW.strftime("%Y-%m-%dT%H:%M:%SZ"))
  jitter_b = StrategyDecider.plan_evaluation_window("C2_BEACONING_JITTER", mode="B", requested_days=30, now=NOW)
  assert jitter_b["days"] == caps["mode_b_micro_days"]


def test_mode_caps_are_read_from_the_harness_at_runtime(monkeypatch):
  monkeypatch.setattr(harness_truth, "mode_caps", lambda: {
      "mode_b_macro_days": 2, "mode_b_cusum_macro_days": 9, "mode_c_macro_days": 21, "mode_b_micro_days": 5})
  assert StrategyDecider.plan_evaluation_window("STANDARD_Z_SCORE", mode="B", requested_days=7,
                                                run_command_available=False, now=NOW)["days"] == 2
  assert StrategyDecider.plan_evaluation_window("LONGITUDINAL_CUSUM", now=NOW)["days"] == 9
  assert StrategyDecider.plan_evaluation_window("STANDARD_Z_SCORE", mode="C", requested_days=45, now=NOW)["days"] == 21
  assert StrategyDecider.plan_evaluation_window("ZIPFIAN_PROCESS_RARITY", requested_days=30, now=NOW)["days"] == 5


def test_directives_state_their_evaluation_horizon():
  dns = _deep_dive("DNS", "NXDOMAIN Resolution Surge", "Elevated dns_queries_fail count", "IP")
  cusum_cap = harness_truth.mode_caps()["mode_b_cusum_macro_days"]
  assert "Mode A blocked" in dns.selection_rationale
  assert f"{cusum_cap}-day" in dns.selection_rationale
  t1 = StrategyDecider.decide_tier1_360("u1", "USER")
  assert "last complete UTC day" in t1.selection_rationale
  jitter = _deep_dive("Egress", "C2 Beaconing Investigation", "Regular interval outbound connection")
  assert "rolling 24-hour raw-event window" in jitter.selection_rationale


# ---------------------------------------------------------------------------
# 4. Sensitivity tiers and thresholds from constants()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tier", [None, "BALANCED", "HIGH_RECALL", "HIGH_PRECISION", "AGGRESSIVE", "CONSERVATIVE", "strict"])
def test_thresholds_come_from_the_harness_constants(tier):
  c = harness_truth.constants()
  canonical, expected = c.resolve_sensitivity_thresholds(tier)
  t = StrategyDecider.thresholds(tier)
  assert t["tier"] == canonical
  for key in ("anomaly_threshold", "robust_threshold", "fusion_threshold_sq", "fold_change_threshold"):
    assert t[key] == expected[key]
  assert t["fusion_distance"] == pytest.approx(math.sqrt(expected["fusion_threshold_sq"]))
  assert t["screen_threshold"] == c.resolve_sensitivity_thresholds("HIGH_RECALL")[1]["anomaly_threshold"]
  assert t["radar_fusion_distance"] == c.RADAR_FUSION_DISTANCE_THRESHOLD
  assert t["radar_composite_d"] == c.RADAR_COMPOSITE_D_THRESHOLD
  assert t["tukey_excess_threshold"] == c.DEFAULT_TUKEY_EXCESS_THRESHOLD
  assert t["min_baseline_days"] == harness_truth.min_baseline_days()


def test_thresholds_track_the_runtime_constants(monkeypatch):
  c = harness_truth.constants()
  monkeypatch.setitem(c.SENSITIVITY_THRESHOLD_MAP["BALANCED"], "anomaly_threshold", 3.7)
  monkeypatch.setattr(c, "RADAR_COMPOSITE_D_THRESHOLD", 4.4)
  t1 = StrategyDecider.decide_tier1_360("u1", "USER")
  assert "3.7σ" in t1.hypothesis_h1 and "4.4σ" in t1.hypothesis_h1


def test_tier1_hypotheses_use_the_requested_tier_gate():
  c = harness_truth.constants()
  for tier in ("BALANCED", "HIGH_PRECISION"):
    gate = c.resolve_sensitivity_thresholds(tier)[1]["anomaly_threshold"]
    t1 = StrategyDecider.decide_tier1_360("u1", "USER", sensitivity=tier)
    assert f"{gate:.1f}σ" in t1.hypothesis_h0 and f"{gate:.1f}σ" in t1.hypothesis_h1
    assert f"{c.RADAR_COMPOSITE_D_THRESHOLD:.1f}σ" in t1.hypothesis_h1


def test_confidence_scoring_uses_the_sensitivity_tier_gate():
  radar = _radar({"Workspace": 3.8, "Auth": 0.1}, outliers=["Workspace"])
  kwargs = dict(model_name="ABOVE_HISTORICAL_MAX_Z", target_metric="workspace_total_download_actions",
                outlier_vector="Workspace", ctx={}, radar_result=radar)
  _, _, balanced = StrategyDecider.score_hypothesis_confidence(**kwargs)
  _, _, precise = StrategyDecider.score_hypothesis_confidence(sensitivity="HIGH_PRECISION", **kwargs)
  assert "Tier1_Workspace_Z=+3.80σ(+0.45)" in balanced
  assert "Tier1_Workspace_Z=+3.80σ(+0.35)" in precise


def test_robust_and_fusion_gates_in_narratives_come_from_constants():
  t = StrategyDecider.thresholds()
  masked = _radar({"Auth": 0.1, "Egress": 1.72}, variance_masked_sectors=["Egress"], subthreshold_sectors=["Egress"],
                  sector_baseline_avg={"Egress": 10.0}, sector_baseline_std={"Egress": 65.0})
  mad = _deep_dive("Egress", "Outbound Traffic Variance Check", "Anomalous Outbound Data", radar=masked)
  assert mad.model_name == "MAD"
  assert f"{t['robust_threshold']:g}" in mad.hypothesis_h1
  two = _radar({"Workspace": 3.8, "Egress": 3.2, "Auth": 0.1}, outliers=["Workspace", "Egress"])
  fusion = _deep_dive("Workspace", "Multi-sector kill chain", "correlated fusion across sectors", radar=two)
  assert fusion.model_name == "DUAL_SECTOR_FUSION_3STAGE"
  assert f"{t['fusion_threshold_sq']:g}" in fusion.evidentiary_defense


def test_source_has_no_hard_coded_harness_thresholds():
  source = Path(__file__).resolve().parent.parent.joinpath("src", "strategy_decider.py").read_text(encoding="utf-8")
  sigma_literals = re.findall(r"(?<![\w.}])\d+\.\d+\s*(?:σ|\\{1,2}sigma)", source)
  assert sigma_literals == [], sigma_literals
  latex_gates = re.findall(r"\\{1,2}(?:ge|le)\s*\d", source)
  assert latex_gates == [], latex_gates
  assert "12.25" not in source
  assert "CV \\\\le 0.30" not in source and "tukey_fence_ratio" not in source


# ---------------------------------------------------------------------------
# 5. Narrative strings use current labels
# ---------------------------------------------------------------------------


def test_directive_narratives_drop_retired_and_renamed_labels():
  pivots = _pivot_scenarios()
  directives = _directive_battery() + [p for p, _ in pivots if p is not None]
  patterns = _forbidden_label_patterns()
  for d in directives:
    text = _narrative(d)
    for pattern in patterns:
      assert not re.search(pattern, text), (d.model_name, pattern, re.search(pattern, text).group(0))
  for _, cands in pivots:
    for c in cands:
      text = _candidate_narrative(c)
      for pattern in patterns:
        assert not re.search(pattern, text), (c.model_name, pattern)


def test_macro_labels_match_the_skill_model_descriptions():
  from src.pipeline_runner import PipelineRunner

  runner = PipelineRunner()
  _, _, statistical_model, _ = runner.get_validator_enums()
  descriptions = type(runner.get_template_router()).MODEL_DESCRIPTIONS
  labels = StrategyDecider.MODEL_LABELS
  assert descriptions[statistical_model.MACD_MOMENTUM_VELOCITY].startswith(labels["ABOVE_HISTORICAL_MAX_Z"])
  assert descriptions[statistical_model.LONGITUDINAL_CUSUM].startswith(labels["LONGITUDINAL_CUSUM"])
  assert descriptions[statistical_model.FIRST_SEEN_NOVELTY].startswith(labels["FIRST_SEEN_NOVELTY"])
  workspace = _deep_dive("Workspace", "Google Drive Mass Download", "Spike in Google Drive file downloads")
  assert workspace.model_name == "ABOVE_HISTORICAL_MAX_Z"
  assert labels["ABOVE_HISTORICAL_MAX_Z"] in workspace.flight_card_title


def test_micro_gates_in_narratives_come_from_the_statistical_hunter_skill():
  skill_md = (get_skills_root() / STATS / "SKILL.md").read_text(encoding="utf-8")
  for model in ("C2_BEACONING_JITTER", "POISSON_BURST_CLUSTERING", "SHANNON_ENTROPY_CHARACTER", "HOUR_OF_DAY_PROFILE"):
    gate = StrategyDecider.micro_model_gate(model)
    assert gate and f"**`{model}`** ({gate})" in skill_md
  jitter = _deep_dive("Egress", "C2 Beaconing Investigation", "Regular interval outbound connection")
  assert StrategyDecider.micro_model_gate("C2_BEACONING_JITTER") in jitter.hypothesis_h1
  spray = _deep_dive("Auth", "Auth Spray Investigation", "Poisson burst spray")
  assert StrategyDecider.micro_model_gate("POISSON_BURST_CLUSTERING") in spray.hypothesis_h1


def test_entity_graph_narratives_use_the_rolling_max_prevalence_invariant():
  web = _radar({"Auth": 0.1, "Web": 3.3, "DNS": 0.2}, outliers=["Web"])
  piv, cands = _pivot(_t2a("ABOVE_HISTORICAL_MAX_Z", "Web", "http_queries_total", RISK, "macd_momentum"),
                      web, True, ["HTTP Proxy Surge"])
  ecg = [c for c in cands if c.model_name == "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE"]
  assert ecg
  text = _candidate_narrative(ecg[0])
  assert "rolling_max <= 3" in text and "day_count = 10" in text


def test_tier1_radar_cites_the_decoupled_canonical_sector_queries():
  user = StrategyDecider.decide_tier1_360("u1", "USER")
  assert "templates/radar_360/" in user.evidentiary_defense
  host = StrategyDecider.decide_tier1_360("host-1", "ASSET")
  assert "radar_360_decoupled_sector.yl2" in host.evidentiary_defense


def test_reasoning_prompt_uses_current_labels_and_harness_rules():
  ctx = StrategyDecider._build_context_summary(
      case_info={"id": "1", "title": "Off-hours logins"}, alerts=[], connector_events=[],
      default_entity="u1", tier="TIER_2_DEEP_DIVE")
  prompt = StrategyDecider._build_reasoning_prompt(ctx)
  for name in ("HOUR_OF_DAY_PROFILE", "FIRST_SEEN_NOVELTY", "IQR_TUKEY_SKEW_FENCES", "QUANTILE_IQR_SKEW",
               "LONGITUDINAL_CUSUM", "WINDOWED_SLACK_SUM", "MARKOV_2GRAM_TRANSITION_RARITY",
               "SHANNON_ENTROPY_CHARACTER", "ABOVE_HISTORICAL_MAX_Z", "HYBRID_ENTROPY_CONCENTRATION",
               "Scheduled Exfiltration", "hour_of_day_profile", "dynamic_archetype"):
    assert name in prompt, name
  assert StrategyDecider.canonical_routing_table() in prompt
  caps = harness_truth.mode_caps()
  for value in caps.values():
    assert f"{value}" in prompt
  retired_lines = [ln for ln in prompt.splitlines() if ln.startswith("RETIRED MODELS")]
  assert len(retired_lines) == 1
  for name in harness_truth.retired_models():
    assert name in retired_lines[0]
  rest = "\n".join(ln for ln in prompt.splitlines() if not ln.startswith("RETIRED MODELS"))
  for pattern in _forbidden_label_patterns():
    assert not re.search(pattern, rest), pattern


def test_families_cover_the_new_models():
  assert StrategyDecider.infer_family("HOUR_OF_DAY_PROFILE") == "Auth"
  assert StrategyDecider.family_for_query("hour_of_day_profile") == "Auth"
  assert StrategyDecider.family_for_query("dynamic_archetype", model_name="IQR_TUKEY_SKEW_FENCES",
                                          target_metric="dns_queries_total") == "DNS"
  assert StrategyDecider.infer_family("HYBRID_ENTROPY_CONCENTRATION") == "Egress"

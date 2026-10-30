# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Agentic Strategy Reasoner & Confidence-Gated Hypothesis Pivot Engine for SecOps Threat Hunting.

Ingests rich multi-source context (Case metadata, Alert outcomes, GCTI findings,
Tier 1 6-spoke 360° radar telemetry, and raw UDM connector events) to identify attacker
touchpoints, formulate testable hypotheses (H0 vs H1) with explicit evidentiary defenses,
score each candidate hypothesis on a calibrated [0.00 - 1.00] confidence scale, and
select optimal single-metric, cross-vector fusion, or raw micro-math models across
SecOps Risk Metrics (all 38 catalog metrics) and Statistical Outlier Hunter engines.

Harness alignment (remediated UEBA harness): retired models, sensitivity tiers,
thresholds, mode caps and the Mode A / Entity Graph windows are read at runtime through
`src.harness_truth`; the canonical cross-skill routing table and the micro model gates
are read from the skills' always-loaded SKILL.md files. No harness constant is
re-declared here.
"""

from datetime import datetime, timedelta, timezone
from functools import lru_cache
import json
import logging
import math
import os
import re
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from google import genai
from google.genai import types
from src import harness_truth
from src.config import get_skills_root
from src.models import CandidateHypothesis, StrategyDirective

logger = logging.getLogger("AgenticStrategyReasoner")


# ---------------------------------------------------------------------------
# Runtime skill truth (SKILL.md is the always-loaded rule layer of both skills)
# ---------------------------------------------------------------------------

_ROUTING_TABLE_START = "<!-- CANONICAL_SKILL_ROUTING_TABLE_START -->"
_ROUTING_TABLE_END = "<!-- CANONICAL_SKILL_ROUTING_TABLE_END -->"
_TRIGGER_ROW_RX = re.compile(r"^\|\s*\*\"[^|]*\"\*\s*\|\s*\*\*`([A-Z0-9_]+)`\*\*\s*\((.*?)\)\s*\|")


def _skill_md(skill: str) -> str:
  """A skill's always-loaded SKILL.md text, or '' when the skill is unavailable."""
  try:
    return (get_skills_root() / skill / "SKILL.md").read_text(encoding="utf-8")
  except OSError:
    return ""


@lru_cache(maxsize=None)
def _canonical_routing_table() -> str:
  """The byte-identical canonical cross-skill routing table block shared by both SKILL.md files."""
  for skill in (harness_truth.STATS_HUNTER_SKILL, harness_truth.RISK_METRICS_SKILL):
    text = _skill_md(skill)
    start = text.find(_ROUTING_TABLE_START)
    end = text.find(_ROUTING_TABLE_END, start) if start >= 0 else -1
    if start >= 0 and end > start:
      return text[start:end + len(_ROUTING_TABLE_END)]
  return ""


@lru_cache(maxsize=None)
def _precedence_one_models() -> FrozenSet[str]:
  """Model tokens of routing-table Precedence 1 (raw UDM micro plane; wins even with "UEBA")."""
  for line in _canonical_routing_table().splitlines():
    if line.startswith("| **1."):
      cells = line.split("|")
      if len(cells) > 2:
        return frozenset(re.findall(r"`([A-Z][A-Z0-9_]+)`", cells[2]))
  return frozenset()


@lru_cache(maxsize=None)
def _micro_trigger_gates() -> Dict[str, str]:
  """Model -> significance gate, from the secops-statistical-hunter SKILL.md trigger catalog."""
  gates: Dict[str, str] = {}
  for line in _skill_md(harness_truth.STATS_HUNTER_SKILL).splitlines():
    match = _TRIGGER_ROW_RX.match(line)
    if match:
      gates[match.group(1)] = match.group(2).strip()
  return gates


@lru_cache(maxsize=None)
def _killchain_catalog_ids() -> FrozenSet[str]:
  """Kill-chain archetype IDs of the risk-metrics KILLCHAIN_CATALOG (empty when the skill is unavailable)."""
  try:
    from src.pipeline_runner import PipelineRunner
    _, catalog = PipelineRunner().get_killchain_archetypes()
    return frozenset(str(getattr(arch, "value", arch)) for arch in catalog)
  except Exception as err:  # pragma: no cover - skills unavailable
    logger.debug(f"Kill-chain catalog unavailable: {err}")
    return frozenset()


def _num(value: Any) -> str:
  """Formats a harness threshold for narratives: 3.0 -> '3.0', 3.5 -> '3.5', 0.25 -> '0.25'."""
  number = float(value)
  return f"{number:.1f}" if number.is_integer() else f"{number:g}"


def _rx(pattern: str) -> "re.Pattern[str]":
  return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Intent vocabulary (signals mirror the canonical routing table rows)
# ---------------------------------------------------------------------------

_RULE_AUTHORING_RX = _rx(
    r"\b(?:create_rule|validate_rule|(?:create|write|author|deploy|build|publish)\s+(?:a\s+|an\s+|the\s+)?(?:new\s+)?"
    r"(?:persistent\s+|streaming\s+|yara[-\s]?l\s+|detection\s+)*rules?)\b"
)
_SCHEDULED_EXFIL_RX = _rx(
    r"\b(?:scheduled|automated|recurring|periodic|cron[-\s]?driven)\s+(?:\w+\s+){0,3}?"
    r"(?:exfil\w*|data\s+(?:dumps?|transfers?|uploads?|theft)|uploads?|transfers?|sync\s+jobs?|dumps?)\b"
)
_NIGHTLY_MULTIDAY_RX = _rx(
    r"\b(?:nightly|every\s+night|each\s+night|every\s+evening|each\s+evening|overnight|every\s+day|each\s+day|"
    r"once\s+a\s+day|daily\s+(?:at|batch(?:es)?|jobs?|transfers?|uploads?|dumps?|exfil\w*|schedule)|every\s+morning|"
    r"weekly|every\s+week|multi[-\s]?day|(?:over|across)\s+(?:several|multiple|many)\s+days|day\s+after\s+day)\b"
)
_EXFIL_CUE_RX = _rx(
    r"\b(?:exfil\w*|data\s+(?:dumps?|transfers?|uploads?|theft|staging|loss)|uploads?|outbound\s+transfers?|"
    r"small\s+batches|sync\s+jobs?|sends?\s+data|copies\s+data|leaves?\s+(?:the|this)\s+(?:server|host|network))\b"
)
_SUBDAY_CADENCE_RX = _rx(
    r"\b(?:every\s+\d+\s*(?:s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?)|every\s+(?:few\s+|couple\s+of\s+)?"
    r"(?:seconds?|minutes?|hours?)|hourly|sub[-\s]?(?:second|minute|hour|day)|intraday|jitter\w*|beacon\w*|"
    r"inter[-\s]?arrival|polling\s+interval|heartbeat|sleep\s+interval)\b"
)
_CUSUM_RX = _rx(
    r"\b(?:cusum|low[-\s]and[-\s]slow|creeping\s+(?:drift|exfil\w*|growth)|cumulative\s+drift|slow\s+drift|"
    r"gradual\s+drift|multi[-\s]?day\s+drift|persistent\s+drift|sustained\s+drift|windowed\s+slack\s+sum|slack\s+sum)\b"
)
_FLEET_SCOPE_RX = _rx(
    r"\b(?:across\s+the\s+(?:entire\s+|whole\s+)?fleet|fleet[-\s]?wide|entire\s+fleet|whole\s+fleet|"
    r"all\s+(?:hosts|users|assets|endpoints))\b"
)
_RADAR_360_RX = _rx(
    r"(?:\b360\b|\bhealth\s+check\b|\brisk\s+score\b|graph\.risk_score|\bbehaviou?ral\s+radar\b|\bomnibus\s+risk\b)"
)
_CRI_MENTION_RX = _rx(r"(?:calibrated\s+risk\s+index|\bcri\b)")
_C2_RX = _rx(
    r"\b(?:beacon\w*|jitter\w*|command\s+and\s+control|periodic\s+(?:connection|callback|polling)s?|"
    r"outbound\s+regularity|inter[-\s]?arrival|flow[-\s]gap|cron)\b"
)
_C2_TOKEN_RX = _rx(r"\bc2\b")
_SPRAY_RX = _rx(r"\b(?:spray\w*|brute\s+force|failed\s+login\s+surge|poisson|fano|mimikatz|pwdump|credential\s+theft)\b")
_STEALER_RX = _rx(r"\b(?:agenttesla|stealer|infostealer|keylogger)\b")
_ENTROPY_RX = _rx(r"\b(?:entropy|shannon|obfuscat\w*|base64|encoded\s+command|dga|long[-\s]string)\b")
_DGA_RX = _rx(r"\b(?:dga|domains?|dns|nxdomain)\b")
_MARKOV_RX = _rx(
    r"\b(?:markov|2[-\s]gram|process\s+transition|parent[-\s]child|parent\s+to\s+child|lotl|"
    r"living\s+off\s+the\s+land|transition\s+rarity|process\s+lineage)\b"
)
_ZIPF_RX = _rx(r"\b(?:zipf|zipfian|long\s+tail|rare\s+binary|rare\s+admin\s+tool|rare\s+process)\b")
_FILE_IOC_RX = _rx(r"\b(?:file\s+ioc|target\.file|sha256|dropper|payload|trojan|malware)\b")
_MALWARE_FAMILY_RX = _rx(r"\b(?:agenttesla|originlogger|redline|vidar|lumma|raccoon|stealer|rat)\b")
_EWMA_RX = _rx(r"\b(?:ewma|burst\s+velocity|exponentially\s+weighted|kinetic\s+burst|rate\s+acceleration|intraday\s+burst)\b")
_HOUR_OF_DAY_RX = _rx(
    r"\b(?:circadian|von\s+mises|off[-\s]hours|after[-\s]hours|out[-\s]of[-\s]hours|odd\s+hours|unusual\s+time|"
    r"temporal\s+departure|temporal\s+anomaly|night[-\s]?time|hour[-\s]of[-\s]day|time[-\s]of[-\s]day|24[-\s]bin|"
    r"unusual_interval_time)\b"
)
_TRAVEL_RX = _rx(r"\b(?:impossible\s+travel|geo[-\s]?velocity|supersonic|kph|km/h|haversine)\b")
_PCR_RX = _rx(r"\b(?:producer[-\s]+consumer|role\s+inversion|pcr_z_score|producer_ratio|net\s+producer)\b")
_ROBUST_RX = _rx(
    r"\b(?:mad|median\s+absolute\s+deviation|modified[-\s]z|tukey|iqr|interquartile|quantiles?|bowley|"
    r"skew(?:ness|ed)?|heavy[-\s]tail(?:ed)?)\b"
)
_MAD_RX = _rx(r"\b(?:mad|median\s+absolute\s+deviation|modified[-\s]z)\b")
_FENCE_RX = _rx(r"\b(?:tukey|iqr|interquartile|quantiles?|bowley|skew(?:ness|ed)?|heavy[-\s]tail(?:ed)?)\b")
_MACRO_WINDOW_RX = _rx(r"(?:\b30[-\s]?days?\b|\b30d\b|\bmetric[-\s]catalog\b|\bmetrics\.[a-z_]+|\bpre[-\s]?computed\b)")
_RAW_WINDOW_RX = _rx(
    r"\b(?:raw[-\s]field|raw\s+(?:dns\s+)?(?:logs?|events?|udm|fields?|telemetry|query)|query\s+(?:string\s+)?length|"
    r"command[-\s]line\s+length|git|ingestion\s+lag|by\s+(?:5m|1h|2h)|24[-\s]?h(?:our)?|7[-\s]?d(?:ay)?|"
    r"14[-\s]?d(?:ays?)?|ad[-\s]hoc|udm_events)\b"
)
_PEER_RX = _rx(r"\b(?:peer\s+(?:cohort|group|baseline|comparison)s?|cohorts?|department(?:al)?|colleagues|peers)\b")
_FIRST_SEEN_RX = _rx(
    r"\b(?:first[-\s_]seen|never[-\s]before[-\s]seen|never\s+seen\s+before|brand[-\s]new\s+(?:destinations?|domains?|"
    r"hosts?|assets?|pairs?|binar(?:y|ies)|process(?:es)?|countr(?:y|ies)|ips?)|first[-\s]time\s+"
    r"(?:access|seen|connection|login|contact))\b"
)
_WORKSPACE_RX = _rx(
    r"\b(?:workspace|google\s+drive|drive\s+download|document\s+hoarding|mass\s+download|workspace_total_download_actions)\b"
)
_ABOVE_MAX_RX = _rx(
    r"\b(?:macd|momentum\s+velocity|dual\s+spine|divergence\s+velocity|acceleration\s+surge|above[-\s]historical[-\s]max|"
    r"above[-\s]max|historical\s+max(?:imum)?|record\s+high|peak\s+exceedance|breakout)\b"
)
_CLOUD_RX = _rx(
    r"\b(?:resource[_\s]+written|resource[_\s]+creation|cloud\s+crud|cloud\s+permissions?|cloud\s+iam|"
    r"iam\s+modifications?|bucket\s+(?:change|modification)s?|iam\s+surge|scoutsuite)\b"
)
_ELEPHANT_RX = _rx(r"\b(?:elephant\s+flows?|mass\s+data\s+extraction|bigquery\s+exfiltration|table\s+dumping|gini\s+concentration)\b")
_ELEPHANT_VECTOR_RX = _rx(r"\b(?:elephant\s+flows?|mass\s+data\s+extraction|bigquery|table\s+dumping|gini)\b")
_BILATERAL_RX = _rx(r"\b(?:http2shell|web[-\s]+to[-\s]+shell|webshell|rce|exploit\s+chain|bilateral\s+ueba|shadow\s+ai|agentic\s+ai)\b")
_SHADOW_AI_RX = _rx(r"\b(?:shadow\s+ai|agentic\s+ai)\b")
_MACRO_BASELINE_RX = _rx(
    r"(?:\b30[-\s]?days?\b|\b30d\b|\bhistorical\s+baseline\b|\btypical\s+(?:behaviou?r|baseline)\b|"
    r"\bnormal\s+(?:behaviou?r|baseline)\b|\bmetrics\.[a-z_]+|\bpre[-\s]?computed\b|\brisk\s+metrics?\b)"
)
_METRIC_CUE_RX = _rx(
    r"\b(?:auth\w*|login\w*|logon\w*|credential\w*|dns|http\w*|web|proxy|network|outbound|egress|bytes|bandwidth|"
    r"process\w*|binar\w*|executions?|workspace|drive|downloads?|cloud|resource\w*|bucket|alerts?|edr)\b"
)
_INSIDER_RX = _rx(r"\b(?:insider|lateral|exfiltration|data\s+hoarding|unusual\s+access|privilege\s+surge)\b")
_LATERAL_RX = _rx(r"\b(?:lateral|breadth|expansion|unseen)\b")

# Catalog-metric inference from free text (Malachite catalog metric names, no `metrics.` prefix).
_AUTH_FAIL_RX = _rx(r"\b(?:spray\w*|brute\w*|fail(?:ed|ure|ures|s)?|lockouts?|stuffing)\b")
_AUTH_RX = _rx(r"\b(?:auth\w*|login\w*|logon\w*|credential\w*|password\w*|spray\w*|brute\w*)\b")
_DNS_RX = _rx(r"\b(?:dns|nxdomain|domain\s+resolution|resolver)\b")
_TUNNEL_RX = _rx(r"\b(?:tunnel\w*|exfil\w*)\b")
_HTTP_RX = _rx(r"\b(?:https?|web|proxy|user[-\s_]agent|url|uri)\b")
_WORKSPACE_METRIC_RX = _rx(r"\b(?:workspace|google\s+drive|drive|gmail|downloads?|documents?)\b")
_NETWORK_RX = _rx(r"\b(?:network|outbound|egress|bytes|bandwidth|exfil\w*|uploads?|transfers?|dumps?)\b")
_CLOUD_METRIC_RX = _rx(r"\b(?:cloud|buckets?|repositor\w*|resource_\w+|crud|iam)\b")
_PROCESS_RX = _rx(r"\b(?:process\w*|binar\w*|executions?|endpoint)\b")
_ALERT_RX = _rx(r"\b(?:alerts?|edr)\b")


class StrategyDecider:
  """Agentic Strategy Reasoner that formulates defended threat hypotheses and confidence-gated pivots."""

  # Threshold gates on the [0.00 - 1.00] hybrid confidence scale
  TIER_2A_AUTO_EXECUTE_THRESHOLD = 0.75
  TIER_2B_PIVOT_AUTO_EXECUTE_THRESHOLD = 0.80
  ANALYST_REVIEW_MIN_THRESHOLD = 0.45
  MAX_SECONDARY_HUNTS = 2

  # Skill homes (names from the harness adapter)
  RISK_METRICS_SKILL = harness_truth.RISK_METRICS_SKILL
  STATS_HUNTER_SKILL = harness_truth.STATS_HUNTER_SKILL
  BILATERAL_SKILLS = f"{harness_truth.RISK_METRICS_SKILL} + {harness_truth.STATS_HUNTER_SKILL}"
  DETECTION_ENGINEERING_SKILL = "secops-detection-engineering"

  # Tier 1 -> Tier 2 escalation heuristics (agentic_ueba policy, not harness constants). Significance always uses
  # the requested sensitivity tier's ueba_constants gates; the radar escalation screen runs at the HIGH_RECALL
  # tier's anomaly gate so sub-gate drift can still earn a confidence-gated deep dive.
  SCREEN_SENSITIVITY_TIER = "HIGH_RECALL"
  SUBTHRESHOLD_FLOOR_Z = 1.25
  DORMANT_AWAKENING_MIN_Z = 1.5
  DORMANT_BASELINE_MAX_MEAN = 1.0
  VARIANCE_MASK_STD_TO_MEAN = 1.5
  VARIANCE_MASK_MIN_STD = 5.0
  ZERO_SPOKE_MAX_Z = 1.0
  DEFAULT_MODE_C_DAYS = 7

  # Renamed models -> current names (risk-metrics v2.3.0 D1 / WS1-02 honest renames and StatisticalModel names;
  # secops-statistical-hunter canonical ModelArchetype names used by its SKILL.md routing table).
  MODEL_RENAMES: Dict[str, str] = {
      "MARKOV_TRANSITION_RARITY": "MARKOV_2GRAM_TRANSITION_RARITY",
      "SHANNON_CHARACTER_ENTROPY": "SHANNON_ENTROPY_CHARACTER",
      "ELEPHANT_FLOW_CONCENTRATION": "HYBRID_ENTROPY_CONCENTRATION",
      "MACD_MOMENTUM_VELOCITY": "ABOVE_HISTORICAL_MAX_Z",
      "MACD_MOMENTUM": "ABOVE_HISTORICAL_MAX_Z",
      "LONGITUDINAL_CUSUM_DRIFT": "LONGITUDINAL_CUSUM",
      "ASYMMETRIC_DIRECTIONAL_Z": "STANDARD_Z_SCORE",
  }

  # Retired model (harness registry key) -> (skill, active replacement). Each replacement is the model named by the
  # skill's own retirement message (harness_truth.retirement_message); tests keep the two in sync.
  RETIRED_MODEL_REDIRECTS: Dict[str, Tuple[str, str]] = {
      "CIRCADIAN_VON_MISES": (STATS_HUNTER_SKILL, "HOUR_OF_DAY_PROFILE"),
      "CIRCADIAN_VON_MISES_2STAGE": (STATS_HUNTER_SKILL, "HOUR_OF_DAY_PROFILE"),
      "HOURLY_TEMPORAL_ZSCORE": (STATS_HUNTER_SKILL, "HOUR_OF_DAY_PROFILE"),
      "IMPOSSIBLE_TRAVEL_GEO_VELOCITY": (STATS_HUNTER_SKILL, "HOUR_OF_DAY_PROFILE"),
      "IMPOSSIBLE_TRAVEL": (STATS_HUNTER_SKILL, "HOUR_OF_DAY_PROFILE"),
      "GEO_VELOCITY": (STATS_HUNTER_SKILL, "HOUR_OF_DAY_PROFILE"),
      "SUPERSONIC_TRAVEL": (STATS_HUNTER_SKILL, "HOUR_OF_DAY_PROFILE"),
      "PIECEWISE_CRI": (RISK_METRICS_SKILL, "STANDARD_Z_SCORE"),
      "ASYMMETRIC_Z": (RISK_METRICS_SKILL, "STANDARD_Z_SCORE"),
      "DIRECTIONAL_Z": (RISK_METRICS_SKILL, "STANDARD_Z_SCORE"),
      "FLEET_PREVALENCE_SHIELD": (RISK_METRICS_SKILL, "HYBRID_METRIC_FLEET_PREVALENCE_2STAGE"),
      "HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE": (RISK_METRICS_SKILL, "DUAL_SECTOR_FUSION_3STAGE"),
  }

  # Raw UDM micro-plane models (secops-statistical-hunter canonical archetypes; each maps to its own template).
  MICRO_PLANE_MODELS: FrozenSet[str] = frozenset({
      "C2_BEACONING_JITTER", "FLOW_GAP_RATIO_SCREEN", "POISSON_BURST_CLUSTERING", "POISSON_RARE_SURGE",
      "SHANNON_ENTROPY_CHARACTER", "LONG_STRING_SCREEN", "MARKOV_2GRAM_TRANSITION_RARITY", "ZIPFIAN_PROCESS_RARITY",
      "EWMA_BURST_VELOCITY", "BURST_Z_SCREEN", "HOUR_OF_DAY_PROFILE", "PRODUCER_CONSUMER_RATIO_INVERSION",
      "PRIVILEGED_LATERAL_EXPANSION", "HYBRID_ENTROPY_CONCENTRATION", "IQR_TUKEY_SKEW_FENCES", "DATA_EXFILTRATION_SPIKE",
      "DERIVED_CONTEXT_PREVALENCE", "DERIVED_CONTEXT_FILE_PREVALENCE", "DERIVED_CONTEXT_DOMAIN_PREVALENCE",
      "GLOBAL_THREAT_INTEL_ENRICHMENT", "ZSCORE_PROCESS_SURGE", "BAYESIAN_GAMMA_SHRINKAGE", "BETA_BINOMIAL_FAILURE",
      "LOG_NORMAL_VOLUME_SURGE", "MULTI_SECTOR_THREAT_FUSION",
  })
  # 30-day metrics.* macro-plane models (secops-risk-metrics-multistage StatisticalModel / PipelineArchitecture).
  MACRO_STATISTICAL_MODELS: FrozenSet[str] = frozenset({
      "STANDARD_Z_SCORE", "MAD", "LONGITUDINAL_CUSUM", "WINDOWED_SLACK_SUM", "QUANTILE_IQR_SKEW", "FIRST_SEEN_NOVELTY",
      "ABOVE_HISTORICAL_MAX_Z", "ADAPTIVE_CONTEXT_THRESHOLD",
  })
  MACRO_PIPELINE_MODELS: FrozenSet[str] = frozenset({
      "DUAL_SECTOR_FUSION_3STAGE", "MULTI_SECTOR_FUSION_4STAGE", "PART_OF_THE_WHOLE_MULTILEVEL",
      "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL", "DUAL_BASELINE_3STAGE", "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE",
      "HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE", "HYBRID_METRIC_FLEET_PREVALENCE_2STAGE",
      "HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE", "RARE_DESTINATION_ECG_3STAGE", "FUSION_RARE_DESTINATION_3STAGE",
  })
  # agentic_ueba macro labels executed by RiskMetricsEngine on risk-metrics templates.
  AGENTIC_MACRO_MODELS: FrozenSet[str] = frozenset({
      "360_DECOUPLED_RADAR", "CLOUD_CRUD_SURGE", "CLOUD_REPOSITORY_SCOPE", "FAILURE_RATIO_SURGE",
  })
  MACRO_PLANE_MODELS: FrozenSet[str] = MACRO_STATISTICAL_MODELS | MACRO_PIPELINE_MODELS | AGENTIC_MACRO_MODELS
  # Models defined in both skills; the plane is decided by the caller (30d metrics.* vs bounded raw window).
  SHARED_PLANE_MODELS: FrozenSet[str] = frozenset({"TWO_PART_HURDLE"})
  CUSUM_MODELS: FrozenSet[str] = frozenset({"LONGITUDINAL_CUSUM", "WINDOWED_SLACK_SUM"})
  PARAMETRIC_MACRO_MODELS: FrozenSet[str] = frozenset({
      "ABOVE_HISTORICAL_MAX_Z", "LONGITUDINAL_CUSUM", "WINDOWED_SLACK_SUM", "STANDARD_Z_SCORE",
  })
  # Micro models over high-volume NETWORK_CONNECTION timing / concentration: bounded 1h-24h windows by default.
  MICRO_ROLLING_24H_MODELS: FrozenSet[str] = frozenset({
      "C2_BEACONING_JITTER", "FLOW_GAP_RATIO_SCREEN", "HYBRID_ENTROPY_CONCENTRATION",
  })
  ENTITY_GRAPH_MARKERS: Tuple[str, ...] = (
      "DERIVED_", "WHOIS_", "RARE_DESTINATION", "FLEET_PREVALENCE", "ASSET_AGE", "GLOBAL_THREAT_INTEL",
      "DOMAIN_PREVALENCE", "FILE_PREVALENCE",
  )
  FLEET_SCOPE_ENTITIES: FrozenSet[str] = frozenset({"fleet", "all", "*", "enterprise", "fleet-wide", "fleetwide"})

  # Dispatch keys consumed by AutonomousHunterEngine / the engines (directive_query contract).
  MODEL_DIRECTIVE_QUERIES: Dict[str, str] = {
      "C2_BEACONING_JITTER": "c2_jitter",
      "POISSON_BURST_CLUSTERING": "poisson_burst",
      "POISSON_RARE_SURGE": "poisson_rare_surge",
      "SHANNON_ENTROPY_CHARACTER": "shannon_entropy",
      "MARKOV_2GRAM_TRANSITION_RARITY": "markov_transition",
      "ZIPFIAN_PROCESS_RARITY": "zipfian_rarity",
      "EWMA_BURST_VELOCITY": "ewma_burst",
      "HYBRID_ENTROPY_CONCENTRATION": "elephant_flow",
      "PRIVILEGED_LATERAL_EXPANSION": "lateral_expansion",
      "PRODUCER_CONSUMER_RATIO_INVERSION": "producer_consumer_inversion",
      "HOUR_OF_DAY_PROFILE": "hour_of_day_profile",
      "ABOVE_HISTORICAL_MAX_Z": "macd_momentum",
      "QUANTILE_IQR_SKEW": "quantile_iqr_skew",
      "DUAL_SECTOR_FUSION_3STAGE": "sector_fusion",
      "MULTI_SECTOR_FUSION_4STAGE": "sector_fusion",
      "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL": "workspace_triad",
      "CLOUD_CRUD_SURGE": "cloud_crud",
      "CLOUD_REPOSITORY_SCOPE": "cloud_repo_scope",
      "FAILURE_RATIO_SURGE": "failure_ratio_surge",
      "360_DECOUPLED_RADAR": "profile_360_risk",
      "GEMINI_REACT_AUTONOMOUS": "auto",
  }

  # Current display labels (risk-metrics template_router MODEL_DESCRIPTIONS / stats-hunter SKILL.md trigger catalog).
  MODEL_LABELS: Dict[str, str] = {
      "ABOVE_HISTORICAL_MAX_Z": "Above-Historical-Max Z",
      "LONGITUDINAL_CUSUM": "Multi-Day Cumulative Drift (Windowed Slack Sum)",
      "WINDOWED_SLACK_SUM": "Windowed Slack Sum Prefilter",
      "FIRST_SEEN_NOVELTY": "First-Seen 30-Day Boolean Novelty Flag",
      "ADAPTIVE_CONTEXT_THRESHOLD": "Off-Hours & Weekend Adaptive Context Threshold",
      "QUANTILE_IQR_SKEW": "Skewness-Adjusted Tukey Fence (Quantiles & Bowley Skewness)",
      "MAD": "Robust Modified Z (30-Day Median Absolute Deviation)",
      "HOUR_OF_DAY_PROFILE": "Learned 24-Bin Hour-of-Day Profile",
      "IQR_TUKEY_SKEW_FENCES": "Raw-Window Skewness-Adjusted Tukey Fences",
      "HYBRID_ENTROPY_CONCENTRATION": "Destination Diversity & Elephant-Flow Concentration",
      "MARKOV_2GRAM_TRANSITION_RARITY": "Markov 2-Gram Transition Rarity",
      "SHANNON_ENTROPY_CHARACTER": "Shannon Character Entropy",
      "C2_BEACONING_JITTER": "C2 Beaconing Jitter",
  }

  # Canonical mapping from 360° radar sector names to default metrics & UDM families
  SECTOR_TO_METRIC_USER: Dict[str, str] = {
      "Auth": "auth_attempts_fail",
      "Cloud": "resource_creation_total",
      "Workspace": "workspace_total_download_actions",
      "Egress": "network_bytes_outbound",
      "DNS": "dns_queries_fail",
      "Web": "http_queries_total",
  }

  SECTOR_TO_METRIC_ASSET: Dict[str, str] = {
      "Auth": "auth_attempts_fail",
      "Egress": "network_bytes_outbound",
      "DNS": "dns_queries_fail",
      "Flows": "network_flows_outbound",
      "Alerts": "alert_event_name_count",
      "Web": "http_queries_total",
      "Endpoint": "file_executions_total",
  }

  # Maps metric/model families to UDM event types and keywords for deterministic confidence scoring
  FAMILY_SIGNALS: Dict[str, Dict[str, Any]] = {
      "Auth": {
          "udm_events": {"USER_LOGIN", "USER_LOGOUT"},
          "keywords": {"login", "auth", "spray", "brute", "credential", "password", "mfa", "kerberos", "saml", "oauth"},
          "metrics": {"auth_attempts_total", "auth_attempts_fail", "auth_attempts_success", "workspace_auth_attempts_total"},
      },
      "Workspace": {
          "udm_events": {"USER_RESOURCE_ACCESS", "USER_RESOURCE_UPDATE_CONTENT"},
          "keywords": {"workspace", "drive", "download", "hoarding", "doc", "sheet", "gmail", "exfil"},
          "metrics": {
              "workspace_total_download_actions",
              "workspace_total_change_actions",
              "workspace_emails_sent_total",
              "workspace_network_bytes_outbound",
              "workspace_network_bytes_total",
          },
      },
      "Cloud": {
          "udm_events": {
              "RESOURCE_CREATION",
              "USER_RESOURCE_CREATION",
              "RESOURCE_DELETION",
              "USER_RESOURCE_DELETION",
              "RESOURCE_WRITTEN",
              "RESOURCE_READ",
              "RESOURCE_PERMISSIONS_CHANGE",
          },
          "keywords": {"cloud", "iam", "bucket", "resource_written", "resource_creation", "service account", "terraform", "gcp", "aws"},
          "metrics": {
              "resource_creation_total",
              "resource_creation_success",
              "resource_creation_fail",
              "resource_deletion_total",
              "resource_deletion_success",
              "resource_deletion_fail",
              "resource_read_total",
              "resource_read_success",
              "resource_read_fail",
              "resource_written_total",
              "resource_written_success",
              "resource_written_fail",
          },
      },
      "Egress": {
          "udm_events": {"NETWORK_CONNECTION", "NETWORK_FLOW"},
          "keywords": {"beacon", "jitter", "c2", "egress", "outbound", "exfil", "elephant", "bytes", "bandwidth", "rat"},
          "metrics": {
              "network_bytes_outbound",
              "network_bytes_inbound",
              "network_bytes_total",
              "network_flows_outbound",
              "network_flows_inbound",
              "network_flows_total",
          },
      },
      "DNS": {
          "udm_events": {"NETWORK_DNS"},
          "keywords": {"dns", "dga", "nxdomain", "tunneling", "subdomain", "domain"},
          "metrics": {"dns_queries_fail", "dns_queries_total", "dns_queries_success", "dns_bytes_outbound"},
      },
      "Web": {
          "udm_events": {"NETWORK_HTTP"},
          "keywords": {"http", "web", "proxy", "user_agent", "uri", "url", "scraping", "whois", "nrd"},
          "metrics": {"http_queries_total", "http_queries_fail", "http_queries_success"},
      },
      "Endpoint": {
          "udm_events": {"PROCESS_LAUNCH", "FILE_CREATION", "FILE_MODIFICATION"},
          "keywords": {"process", "binary", "sha256", "powershell", "cmd.exe", "lotl", "markov", "zipf", "entropy", "base64", "dropper"},
          "metrics": {"file_executions_total", "file_executions_success", "file_executions_fail"},
      },
      "Alerts": {
          "udm_events": {"SCAN_UNCATEGORIZED", "EDR_ALERT"},
          "keywords": {"edr", "crowdstrike", "sentinelone", "carbonblack", "alert_event_name_count"},
          "metrics": {"alert_event_name_count"},
      },
  }

  # ---------------------------------------------------------------------------
  # Harness truth: thresholds, model resolution, routing table and time modes
  # ---------------------------------------------------------------------------

  @classmethod
  def thresholds(cls, sensitivity: Optional[str] = None) -> Dict[str, Any]:
    """Tier-resolved significance gates from ueba_constants, plus the HIGH_RECALL radar escalation screen."""
    c = harness_truth.constants()
    tier, gates = c.resolve_sensitivity_thresholds(sensitivity)
    _, screen = c.resolve_sensitivity_thresholds(cls.SCREEN_SENSITIVITY_TIER)
    return {
        "tier": tier,
        "anomaly_threshold": gates["anomaly_threshold"],
        "robust_threshold": gates["robust_threshold"],
        "fusion_threshold_sq": gates["fusion_threshold_sq"],
        "fusion_distance": math.sqrt(float(gates["fusion_threshold_sq"])),
        "fold_change_threshold": gates["fold_change_threshold"],
        "screen_threshold": screen["anomaly_threshold"],
        "radar_fusion_distance": c.RADAR_FUSION_DISTANCE_THRESHOLD,
        "radar_composite_d": c.RADAR_COMPOSITE_D_THRESHOLD,
        "tukey_excess_threshold": c.DEFAULT_TUKEY_EXCESS_THRESHOLD,
        "min_baseline_days": harness_truth.min_baseline_days(),
    }

  @staticmethod
  def _normalize_model_token(name: Any) -> str:
    text = str(getattr(name, "value", name) or "").strip()
    if text.lower().endswith(".yl2"):
      text = text[:-4]
    return re.sub(r"[\s\-]+", "_", text).upper()

  @classmethod
  def canonical_model_name(cls, name: Any) -> str:
    """Current harness name for a model token (renamed models resolve to their current names)."""
    token = cls._normalize_model_token(name)
    return cls.MODEL_RENAMES.get(token, token)

  @staticmethod
  def _retirement(token: str) -> Tuple[Optional[str], Optional[str]]:
    """(registry key, skill message) when a model token or its template stem is retired in the harness."""
    registry = harness_truth.retired_models()
    if token in registry:
      return token, registry[token]
    stem = re.sub(r"_\d+STAGE$", "", token)
    if stem and stem != token and stem in registry:
      return stem, registry[stem]
    return None, None

  @classmethod
  def precedence_one_models(cls) -> FrozenSet[str]:
    """Routing-table Precedence 1 models (raw UDM micro plane; win even when the request mentions UEBA)."""
    return _precedence_one_models()

  @classmethod
  def canonical_routing_table(cls) -> str:
    """The canonical cross-skill routing table, verbatim from the skills' SKILL.md files."""
    return _canonical_routing_table()

  @classmethod
  def micro_model_gate(cls, model_name: str) -> Optional[str]:
    """The secops-statistical-hunter SKILL.md significance gate for a micro model, when the catalog lists it."""
    return _micro_trigger_gates().get(cls.canonical_model_name(model_name))

  @classmethod
  def _gate_text(cls, model_name: str) -> str:
    return cls.micro_model_gate(model_name) or f"the tier-calibrated `{cls.canonical_model_name(model_name)}` gate"

  @classmethod
  def model_home(cls, model_name: str) -> Optional[str]:
    """Skill owning a model on its canonical plane, or None for models defined on both planes."""
    if model_name in cls.precedence_one_models() or model_name in cls.MICRO_PLANE_MODELS:
      return cls.STATS_HUNTER_SKILL
    if model_name in cls.MACRO_PLANE_MODELS or model_name.startswith("KILLCHAIN_"):
      return cls.RISK_METRICS_SKILL
    return None

  @classmethod
  def is_known_model(cls, model_name: str) -> bool:
    return (
        model_name in cls.MODEL_DIRECTIVE_QUERIES
        or model_name in cls.MICRO_PLANE_MODELS
        or model_name in cls.MACRO_PLANE_MODELS
        or model_name in cls.SHARED_PLANE_MODELS
        or model_name.startswith("KILLCHAIN_")
    )

  @classmethod
  def directive_query_for(cls, model_name: str, selected_skill: Optional[str] = None) -> Optional[str]:
    """Dispatch key for a model (`dynamic_archetype` / `dynamic_metric` run a skill model by name)."""
    if model_name in cls.MODEL_DIRECTIVE_QUERIES:
      return cls.MODEL_DIRECTIVE_QUERIES[model_name]
    if model_name.startswith("KILLCHAIN_"):
      return "killchain_archetype"
    home = cls.model_home(model_name) or selected_skill
    if home == cls.STATS_HUNTER_SKILL:
      return "dynamic_archetype"
    if home == cls.RISK_METRICS_SKILL:
      return "dynamic_metric"
    return None

  @classmethod
  def resolve_model(cls, name: Any, selected_skill: Optional[str] = None, redirect: bool = True) -> Dict[str, Any]:
    """Resolves a model, archetype or template name (with or without .yl2) against the remediated harness.

    Renamed models resolve to their current names. Retired models redirect to the replacement named by the
    skill's retirement message, or raise ValueError with that message when `redirect` is False or no replacement
    is known. Models with a canonical plane are homed on their skill.
    """
    token = cls._normalize_model_token(name)
    retired_key, message = cls._retirement(token)
    model = cls.MODEL_RENAMES.get(token, token)
    if not retired_key and model != token:
      retired_key, message = cls._retirement(model)
    redirected_from = None
    skill = selected_skill
    if retired_key:
      replacement = cls.RETIRED_MODEL_REDIRECTS.get(retired_key)
      if not redirect or replacement is None:
        raise ValueError(message)
      skill, model = replacement
      redirected_from = retired_key
    skill = cls.model_home(model) or skill
    return {
        "model_name": model,
        "selected_skill": skill,
        "directive_query": cls.directive_query_for(model, skill),
        "redirected_from": redirected_from,
        "retirement_message": message,
    }

  @classmethod
  def _harness_fields(
      cls, model_name: str, selected_skill: Optional[str], directive_query: Optional[str]
  ) -> Tuple[str, Optional[str], str, Optional[str]]:
    """(model, skill, directive_query, redirected_from) after harness resolution; raises ValueError when refused."""
    resolved = cls.resolve_model(model_name, selected_skill)
    model = resolved["model_name"]
    query = directive_query or ""
    if resolved["directive_query"] and (
        resolved["redirected_from"] or model != model_name or cls.is_known_model(model)
    ):
      query = resolved["directive_query"]
    return model, resolved["selected_skill"] or selected_skill, query, resolved["redirected_from"]

  @classmethod
  def _apply_harness_policy(cls, item: Any) -> bool:
    """Resolves a StrategyDirective / CandidateHypothesis in place; False when its model is refused."""
    try:
      model, skill, query, redirected_from = cls._harness_fields(item.model_name, item.selected_skill, item.directive_query)
    except ValueError as retired_err:
      logger.info(f"Refusing retired model without a harness redirect: {retired_err}")
      return False
    item.model_name = model
    if skill:
      item.selected_skill = skill
    item.directive_query = query
    if redirected_from:
      note = (
          "Harness redirect: the requested model is retired in the remediated harness; "
          f"`{model}` (`{item.selected_skill}`) is the replacement the skill names."
      )
      if hasattr(item, "selection_rationale"):
        item.selection_rationale = f"{item.selection_rationale} {note}".strip()
      else:
        item.evidentiary_defense = f"{item.evidentiary_defense} {note}".strip()
    return True

  @classmethod
  def _is_entity_graph_model(cls, model_name: str) -> bool:
    return any(marker in model_name for marker in cls.ENTITY_GRAPH_MARKERS)

  @staticmethod
  def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")

  @classmethod
  def plan_evaluation_window(
      cls,
      model_name: str,
      selected_skill: Optional[str] = None,
      mode: Optional[str] = None,
      requested_days: Optional[int] = None,
      run_command_available: bool = True,
      now: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Evaluation mode and window for a model under the harness time model.

    Macro (secops-risk-metrics-multistage): Mode A defaults to the last complete UTC day
    (`harness_truth.mode_a_window`; Entity Graph joins use `ecg_window` with event stages pinned by
    `event_day_pin`); Mode B and Mode C are capped by `harness_truth.mode_caps()`, Mode B redirecting to Mode C
    when local scripts can run; LONGITUDINAL_CUSUM never runs in single-day Mode A (one query up to the CUSUM cap,
    longer horizons as Mode C shards). Micro (secops-statistical-hunter): Mode A is a rolling 24-hour raw-event
    window and Mode B a raw-event timeline capped by the telemetry-physics micro cap. `run_command_available`
    says whether the vetted helpers (timeline_assembler.py, cusum_helper.py) can run; agentic_ueba loads the
    skills' scripts in-process, so it defaults to True.
    """
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    resolved = cls.resolve_model(model_name, selected_skill)
    model = resolved["model_name"]
    skill = resolved["selected_skill"] or selected_skill or cls.RISK_METRICS_SKILL
    caps = harness_truth.mode_caps()
    requested = int(requested_days) if requested_days else None
    mode_req = str(mode).strip().upper().replace("MODE", "").strip() if mode else None
    notices: List[str] = []
    plan: Dict[str, Any] = {
        "model_name": model,
        "skill": skill,
        "requested_days": requested,
        "capped_from_days": None,
        "scored_day": None,
        "entity_graph": cls._is_entity_graph_model(model),
        "event_day_pin": None,
        "requires_run_command": False,
        "substituted_from": None,
        "notices": notices,
    }

    if skill == cls.STATS_HUNTER_SKILL:
      cap = caps["mode_b_micro_days"]
      plan["plane"] = "MICRO"
      if mode_req and mode_req not in ("A", "B"):
        notices.append(
            f"Raw-event hunts in `{cls.STATS_HUNTER_SKILL}` run as Mode A (rolling 24-hour) or Mode B (up to "
            f"{cap} days); Mode {mode_req} belongs to `{cls.RISK_METRICS_SKILL}`."
        )
        mode_req = None
      if mode_req is None:
        wants_timeline = bool(requested and requested > 1) or model not in cls.MICRO_ROLLING_24H_MODELS
        mode_req = "B" if wants_timeline else "A"
      if plan["entity_graph"]:
        notices.append("Entity Graph freshness: anchor DERIVED_CONTEXT stages at D-2 (`compute_ecg_search_window`).")
      if mode_req == "A":
        plan.update(
            mode="A", days=1, cap_days=cap, start_time=cls._iso(now - timedelta(hours=24)), end_time=cls._iso(now),
            label="Micro Mode A — rolling 24-hour raw-event window",
        )
        return plan
      days = max(requested or cap, 1)
      if days > cap:
        plan["capped_from_days"] = days
        notices.append(
            f"Telemetry physics guardrail: raw UDM windows are capped at {cap} days (requested {days}); 30-day "
            f"baselines over high-volume telemetry belong to `{cls.RISK_METRICS_SKILL}` metrics.*."
        )
        days = cap
      plan.update(
          mode="B", days=days, cap_days=cap, start_time=cls._iso(now - timedelta(days=days)), end_time=cls._iso(now),
          label=f"Micro Mode B — {days}-day raw-event timeline (telemetry-physics cap {cap} days)",
      )
      return plan

    plan["plane"] = "MACRO"
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    ecg = plan["entity_graph"]
    b_cap, c_cap = caps["mode_b_macro_days"], caps["mode_c_macro_days"]

    def _range_start(days: int, shards: bool = False) -> str:
      start = today - timedelta(days=days - 1)
      if ecg:
        start = start - timedelta(days=2) if shards else min(start, today - timedelta(days=2))
      return cls._iso(start)

    if model in cls.CUSUM_MODELS:
      cusum_cap = caps["mode_b_cusum_macro_days"]
      if mode_req == "A":
        notices.append(
            "LONGITUDINAL_CUSUM cannot run in single-day Mode A; sequential drift needs a multi-day window "
            f"(one query of at most {cusum_cap} days)."
        )
      days = max(requested or cusum_cap, 2)
      if model == "LONGITUDINAL_CUSUM" and not run_command_available:
        # scripts/cusum_helper.py D6 guardrail G5: Page CUSUM needs local scripts, and the stateless Windowed Slack Sum
        # prefilter (SKILL.md Answer 1 without run_command) is never substituted silently.
        notices.append(
            "Page CUSUM (`LONGITUDINAL_CUSUM`) needs a client that can run local scripts (`scripts/cusum_helper.py`); "
            "this plan explicitly substitutes the stateless `WINDOWED_SLACK_SUM` prefilter "
            "(`longitudinal_cusum_2stage.yl2`), which clears entities whose slack sum stays below h but cannot "
            "confirm drift on its own."
        )
        model = "WINDOWED_SLACK_SUM"
        plan.update(model_name=model, substituted_from="LONGITUDINAL_CUSUM")
      if model == "LONGITUDINAL_CUSUM" and days > cusum_cap:
        if days > c_cap:
          plan["capped_from_days"] = days
          notices.append(f"Mode C is capped at {c_cap} daily shards (requested {days}).")
          days = c_cap
        plan.update(
            mode="C", days=days, cap_days=c_cap, requires_run_command=True, start_time=_range_start(days, shards=True),
            end_time=cls._iso(now),
            label=(
                f"Mode C — {days} ungated per-day CUSUM shards re-standardized against Shard 1's fixed baseline by "
                f"`scripts/cusum_helper.py` (cap {c_cap} days; single-day Mode A blocked)"
            ),
        )
        return plan
      if days > cusum_cap:
        plan["capped_from_days"] = days
        longer = (
            "longer horizons need Page CUSUM Mode C shards (`scripts/cusum_helper.py`)"
            if model == "WINDOWED_SLACK_SUM"
            else "longer horizons need Mode C shards"
        )
        notices.append(
            f"The CUSUM family runs as one query of at most {cusum_cap} days (requested {days}); {longer}."
        )
        days = cusum_cap
      if model == "WINDOWED_SLACK_SUM":
        label = (
            f"Windowed Slack Sum prefilter — one stateless ≤{cusum_cap}-day query (`longitudinal_cusum_2stage.yl2`; "
            "single-day Mode A blocked)"
        )
      else:
        label = (
            f"Longitudinal CUSUM — one start-anchored ≤{cusum_cap}-day query (Windowed Slack Sum prefilter + "
            "`longitudinal_cusum_series_3stage.yl2` + `scripts/cusum_helper.py`; single-day Mode A blocked)"
        )
      plan.update(
          mode="B", days=days, cap_days=cusum_cap, requires_run_command=model == "LONGITUDINAL_CUSUM",
          start_time=_range_start(days), end_time=cls._iso(now), label=label,
      )
      return plan

    eff = mode_req if mode_req in ("A", "B", "C") else ("B" if requested and requested > 1 else "A")
    if eff == "A":
      day = harness_truth.mode_a_day(now)
      if ecg:
        start, end = harness_truth.ecg_window(day)
        plan["event_day_pin"] = harness_truth.event_day_pin(day)
      else:
        start, end = harness_truth.mode_a_window(day)
      label = (
          f"Mode A — last complete UTC day {day.isoformat()} vs the 30-day baseline "
          f"({harness_truth.min_baseline_days()}-active-day maturity gate)"
      )
      if ecg:
        label += f"; Entity Graph join window starts {start[:10]} with event stages pinned to {day.isoformat()}"
      plan.update(mode="A", days=1, cap_days=1, scored_day=day.isoformat(), start_time=start, end_time=end, label=label)
      return plan
    if eff == "C" and not run_command_available:
      notices.append(
          f"Mode C needs a client that can run local scripts (`scripts/timeline_assembler.py`); using Mode B "
          f"(cap {b_cap} days)."
      )
      eff = "B"
    days = max(requested or (b_cap if eff == "B" else cls.DEFAULT_MODE_C_DAYS), 2)
    if eff == "B" and days > b_cap:
      if run_command_available:
        notices.append(f"Mode B is capped at {b_cap} days (requested {days}); redirected to Mode C per-day shards.")
        eff = "C"
      else:
        plan["capped_from_days"] = days
        notices.append(
            f"Mode B is capped at {b_cap} days (requested {days}); per-day baselines and timelines longer than "
            f"{b_cap} days need a client that can run local scripts (`scripts/timeline_assembler.py`)."
        )
        days = b_cap
    if eff == "C":
      if days > c_cap:
        plan["capped_from_days"] = days
        notices.append(f"Mode C is capped at {c_cap} daily shards (requested {days}).")
        days = c_cap
      plan.update(
          mode="C", days=days, cap_days=c_cap, requires_run_command=True, start_time=_range_start(days, shards=True),
          end_time=cls._iso(now), label=f"Mode C — {days} per-day baseline shards (cap {c_cap} days)",
      )
      return plan
    plan.update(
        mode="B", days=days, cap_days=b_cap, start_time=_range_start(days), end_time=cls._iso(now),
        label=f"Mode B — {days}-day fixed-baseline timeline (cap {b_cap} days)",
    )
    return plan

  @classmethod
  def evaluation_horizon(cls, model_name: str, selected_skill: Optional[str] = None) -> str:
    """One-sentence evaluation horizon for narratives ('' when the model is refused)."""
    try:
      plan = cls.plan_evaluation_window(model_name, selected_skill)
    except ValueError:
      return ""
    return f"Evaluation horizon: {plan['label']}."

  @classmethod
  def _with_horizon(cls, text: str, model_name: str, selected_skill: Optional[str]) -> str:
    horizon = cls.evaluation_horizon(model_name, selected_skill)
    if not horizon or horizon in (text or ""):
      return text
    return f"{text} {horizon}".strip()

  # ---------------------------------------------------------------------------
  # Canonical cross-skill routing of case / analyst intents
  # ---------------------------------------------------------------------------

  @classmethod
  def _is_scheduled_exfiltration(cls, text: str) -> bool:
    """Nightly / multi-day scheduled exfiltration without a sub-day cron or jitter cadence (two-answer rule)."""
    if _SUBDAY_CADENCE_RX.search(text):
      return False
    return bool(_SCHEDULED_EXFIL_RX.search(text) or (_NIGHTLY_MULTIDAY_RX.search(text) and _EXFIL_CUE_RX.search(text)))

  @classmethod
  def _is_radar_360(cls, text: str) -> bool:
    return bool(_RADAR_360_RX.search(text)) and not _CRI_MENTION_RX.search(text)

  @classmethod
  def _is_fleet_scope(cls, text: str, target_entity: Optional[str]) -> bool:
    return str(target_entity or "").strip().lower() in cls.FLEET_SCOPE_ENTITIES or bool(_FLEET_SCOPE_RX.search(text or ""))

  @classmethod
  def _scheduled_exfiltration_answers(cls) -> List[Dict[str, Any]]:
    caps = harness_truth.mode_caps()
    return [
        {
            "answer": 1,
            "selected_skill": cls.RISK_METRICS_SKILL,
            "model_name": "LONGITUDINAL_CUSUM",
            "directive_query": cls.directive_query_for("LONGITUDINAL_CUSUM"),
            "zero_code": False,
            "rule": (
                "Longitudinal CUSUM Drift: Windowed Slack Sum prefilter + longitudinal_cusum_series_3stage.yl2 + "
                f"cusum_helper.py in one start-anchored query of at most {caps['mode_b_cusum_macro_days']} days "
                "(single-day Mode A blocked; longer horizons as ungated Mode C shards against Shard 1's fixed baseline, "
                f"up to {caps['mode_c_macro_days']} days; without local scripts, the stateless "
                "longitudinal_cusum_2stage.yl2 prefilter, disclosed as WINDOWED_SLACK_SUM)."
            ),
        },
        {
            "answer": 2,
            "selected_skill": cls.STATS_HUNTER_SKILL,
            "model_name": "C2_BEACONING_JITTER",
            "zero_code": True,
            "rule": "Zero-code Skill Handoff Card (no query text) for sub-day cron or jitter cadence.",
        },
    ]

  @classmethod
  def route_intent(
      cls,
      text: str,
      entity_type: str = "USER",
      udm_event_types: Optional[Sequence[str]] = None,
      outcome_metrics: Optional[Dict[str, Any]] = None,
      target_entity: Optional[str] = None,
      include_rules: bool = True,
  ) -> Dict[str, Any]:
    """Classifies a case / analyst intent against the canonical cross-skill routing table.

    Precedence 1 (raw UDM micro signals) stays in secops-statistical-hunter even when the text mentions UEBA;
    explicit CUSUM, 360 / risk-score and Scheduled Exfiltration (nightly / multi-day cadence, two answers) route
    to secops-risk-metrics-multistage; exploit / CTI UEBA co-executes both skills (Precedence 3); persistent rule
    authoring belongs to secops-detection-engineering (Precedence 4).
    """
    t = (text or "").lower()
    ent = str(entity_type or "USER").upper()
    events = set(udm_event_types or [])
    outcomes = outcome_metrics or {}
    risk, stats = cls.RISK_METRICS_SKILL, cls.STATS_HUNTER_SKILL

    def _route(intent: str, precedence: Optional[int], skill: Optional[str], model: Optional[str], rule: str,
               answers: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
      return {
          "intent": intent,
          "precedence": precedence,
          "target_skill": skill,
          "plane": {1: "MICRO", 2: "MACRO", 3: "BILATERAL", 4: "PERSISTENT_RULES"}.get(precedence),
          "model_name": model,
          "directive_query": cls.directive_query_for(model, skill) if model else None,
          "rule": rule,
          "answers": list(answers or []),
      }

    if include_rules and _RULE_AUTHORING_RX.search(t):
      return _route("PERSISTENT_RULE_AUTHORING", 4, cls.DETECTION_ENGINEERING_SKILL, None,
                    "Persistent rule authoring and deployment belong to secops-detection-engineering (zero-code handoff).")
    if cls._is_scheduled_exfiltration(t):
      return _route("SCHEDULED_EXFILTRATION", 2, risk, "LONGITUDINAL_CUSUM",
                    "Scheduled Exfiltration (nightly / multi-day cadence): offer both answers.",
                    answers=cls._scheduled_exfiltration_answers())
    if _CUSUM_RX.search(t):
      model = "WINDOWED_SLACK_SUM" if cls._is_fleet_scope(t, target_entity) else "LONGITUDINAL_CUSUM"
      return _route("CUSUM_DRIFT", 2, risk, model, "Page CUSUM drift over daily metrics.* (2-30d).")
    if cls._is_radar_360(t):
      return _route("RADAR_360", 2, risk, "360_DECOUPLED_RADAR", "360° health check / risk score over decoupled sector queries.")
    if _C2_RX.search(t) or (_C2_TOKEN_RX.search(t) and "ec2" not in t) or (
        _SUBDAY_CADENCE_RX.search(t) and _EXFIL_CUE_RX.search(t)
    ):
      return _route("C2_JITTER", 1, stats, "C2_BEACONING_JITTER", "C2 jitter / sub-second or sub-day cron timing.")
    if _SPRAY_RX.search(t) or ("USER_LOGIN" in events and ("fail" in t or "excessive" in t)) or (
        ent in ("USER", "USER_ID", "EMAIL") and _STEALER_RX.search(t)
    ):
      return _route("FANO_SPRAY", 1, stats, "POISSON_BURST_CLUSTERING", "Fano spray bursts over raw USER_LOGIN.")
    if _ENTROPY_RX.search(t):
      return _route("ENTROPY", 1, stats, "SHANNON_ENTROPY_CHARACTER", "Shannon entropy / DGA / CLI obfuscation.")
    if _MARKOV_RX.search(t):
      return _route("MARKOV_LINEAGE", 1, stats, "MARKOV_2GRAM_TRANSITION_RARITY", "Markov 2-gram process lineage.")
    if _ZIPF_RX.search(t) or "FILE" in events or "files" in events or _FILE_IOC_RX.search(t) or _MALWARE_FAMILY_RX.search(t):
      return _route("ZIPF_RARITY", 1, stats, "ZIPFIAN_PROCESS_RARITY", "Zipfian long-tail process rarity.")
    if _EWMA_RX.search(t):
      return _route("EWMA_BURST", 1, stats, "EWMA_BURST_VELOCITY", "Intraday EWMA burst velocity.")
    if _HOUR_OF_DAY_RX.search(t):
      return _route("HOUR_OF_DAY", 1, stats, "HOUR_OF_DAY_PROFILE", "24-bin circadian / hour-of-day profile.")
    if _TRAVEL_RX.search(t) or "kph" in outcomes:
      return _route("GEO_VELOCITY_RETIRED", 1, stats, "HOUR_OF_DAY_PROFILE",
                    "City-centroid geo-velocity is retired (D1); the skill routes this intent to HOUR_OF_DAY_PROFILE.")
    if _PCR_RX.search(t):
      return _route("PRODUCER_CONSUMER", 1, stats, "PRODUCER_CONSUMER_RATIO_INVERSION", "Producer-consumer byte ratio inversion.")
    if _ROBUST_RX.search(t):
      is_mad = bool(_MAD_RX.search(t)) and not _FENCE_RX.search(t)
      if _MACRO_WINDOW_RX.search(t) and not _RAW_WINDOW_RX.search(t):
        return _route("METRIC_ROBUST", 2, risk, "MAD" if is_mad else "QUANTILE_IQR_SKEW",
                      "30d metric MAD (mad_robust_z_4stage.yl2) / Tukey (quantile_iqr_skew_3stage.yl2).")
      return _route("RAW_ROBUST", 1, stats, "DATA_EXFILTRATION_SPIKE" if is_mad else "IQR_TUKEY_SKEW_FENCES",
                    "Raw-field or 1h-14d MAD / Tukey over raw UDM telemetry.")
    if _PEER_RX.search(t):
      return _route("PEER_COHORT", 2, risk, "PART_OF_THE_WHOLE_MULTILEVEL", "Peer cohorts (part_of_the_whole_*, dual baseline).")
    if _FIRST_SEEN_RX.search(t):
      return _route("FIRST_SEEN", 2, risk, "FIRST_SEEN_NOVELTY", "metrics.* first_seen novelty (first_seen_novelty_2stage.yl2).")
    if _WORKSPACE_RX.search(t):
      return _route("WORKSPACE", 2, risk, "ABOVE_HISTORICAL_MAX_Z", "30d Workspace baselines (above-max Z).")
    if _ABOVE_MAX_RX.search(t):
      return _route("ABOVE_MAX", 2, risk, "ABOVE_HISTORICAL_MAX_Z", "30d above-historical-max Z breakout.")
    if _CLOUD_RX.search(t):
      return _route("CLOUD_CRUD", 2, risk, "CLOUD_CRUD_SURGE", "30d Cloud CRUD baselines.")
    if _ELEPHANT_RX.search(t):
      return _route("ELEPHANT_FLOW", 1, stats, "HYBRID_ENTROPY_CONCENTRATION", "Destination diversity collapse & elephant flows.")
    if _BILATERAL_RX.search(t):
      return _route("BILATERAL_EXPLOIT", 3, cls.BILATERAL_SKILLS, "DUAL_SECTOR_FUSION_3STAGE",
                    "Exploit / CTI UEBA: 30d metrics.* + bounded raw pipelines + PLAYBOOK_BEHAVIORAL_HUNT_MATCH loopback.")
    if _MACRO_BASELINE_RX.search(t) and _METRIC_CUE_RX.search(t):
      return _route("MACRO_BASELINE", 2, risk, "STANDARD_Z_SCORE", "30d metrics.* baseline (standard_z_score_2stage.yl2).")
    if ent in ("USER", "USER_ID", "EMAIL") or _INSIDER_RX.search(t):
      return _route("INSIDER_360", 2, risk, "360_DECOUPLED_RADAR", "Insider / user behavioral drift across all 6 sectors.")
    return _route("AUTONOMOUS", None, stats, "GEMINI_REACT_AUTONOMOUS", "No canonical routing signal matched.")

  @classmethod
  def _infer_metric(cls, text: str, entity_type: str = "USER", default: Optional[str] = None) -> str:
    """Catalog metric implied by case text (situational selection; hosts never default to auth)."""
    t = (text or "").lower()
    is_host = str(entity_type).upper() in ("ASSET", "HOST", "IP")
    if _AUTH_RX.search(t):
      return "auth_attempts_fail" if _AUTH_FAIL_RX.search(t) else "auth_attempts_total"
    if _DNS_RX.search(t):
      return "dns_bytes_outbound" if _TUNNEL_RX.search(t) else "dns_queries_total"
    if _HTTP_RX.search(t):
      return "http_queries_total"
    if not is_host and _WORKSPACE_METRIC_RX.search(t):
      return "workspace_total_download_actions"
    if _NETWORK_RX.search(t):
      return "network_bytes_outbound"
    if _CLOUD_METRIC_RX.search(t):
      return "resource_read_total"
    if _PROCESS_RX.search(t):
      return "file_executions_total"
    if _ALERT_RX.search(t):
      return "alert_event_name_count"
    return default or ("network_bytes_outbound" if is_host else "auth_attempts_total")

  # ---------------------------------------------------------------------------
  # Families, signatures, 360° insights and confidence scoring
  # ---------------------------------------------------------------------------

  @classmethod
  def infer_family(
      cls,
      model_name: str,
      target_metric: Optional[str] = None,
      fusion_metrics: Optional[Sequence[str]] = None,
      outlier_vector: Optional[str] = None,
  ) -> str:
    """Infers primary telemetry sector family for confidence scoring and zero-telemetry lockout."""
    if outlier_vector and outlier_vector in cls.FAMILY_SIGNALS:
      return outlier_vector
    if target_metric:
      for fam, spec in cls.FAMILY_SIGNALS.items():
        if target_metric in spec["metrics"]:
          return fam
    if fusion_metrics:
      for m in fusion_metrics:
        for fam, spec in cls.FAMILY_SIGNALS.items():
          if m in spec["metrics"]:
            return fam
    try:
      m_up = cls.resolve_model(model_name or "")["model_name"]
    except ValueError:
      m_up = cls._normalize_model_token(model_name or "")
    if any(k in m_up for k in ("C2_", "ELEPHANT_FLOW", "DIVERSITY_DEFICIT", "HYBRID_ENTROPY", "FLOW_GAP", "PRODUCER_CONSUMER")):
      return "Egress"
    if any(k in m_up for k in ("POISSON_BURST", "BETA_BINOMIAL", "LATERAL_EXPANSION", "HOUR_OF_DAY")):
      return "Auth"
    if any(k in m_up for k in ("CLOUD_", "REPOSITORY")):
      return "Cloud"
    if any(k in m_up for k in ("MARKOV", "SHANNON", "ZIPFIAN", "FILE_PREVALENCE", "LONG_STRING")):
      return "Endpoint"
    if any(k in m_up for k in ("DOMAIN_PREVALENCE", "WHOIS", "HTTP_")):
      return "Web"
    return outlier_vector or "Egress"

  @classmethod
  def build_signature(
      cls,
      model_name: str,
      target_metric: Optional[str] = None,
      fusion_metrics: Optional[Sequence[str]] = None,
      target_entity: Optional[str] = None,
  ) -> str:
    """Builds a canonical deduplication signature for an executed hypothesis (renamed models share one signature)."""
    fusion_list = list(fusion_metrics or [])
    return f"{cls.canonical_model_name(model_name)}|{target_metric or ''}|{','.join(sorted(fusion_list))}"

  @classmethod
  def family_for_query(
      cls,
      directive_query: str,
      model_name: Optional[str] = None,
      target_metric: Optional[str] = None,
  ) -> str:
    """Maps a directive query identifier (plus model / metric when known) to its telemetry family for Zero-Telemetry lockout."""
    q = (directive_query or "").lower()
    # `circadian` is a legacy key kept for directives issued before the remediation retired that model.
    if "poisson" in q or "hour_of_day" in q or "circadian" in q or "lateral" in q:
      return "Auth"
    if "cloud" in q:
      return "Cloud"
    if "c2_jitter" in q or "elephant" in q or "ewma" in q:
      return "Egress"
    if "shannon" in q or "markov" in q or "zipf" in q:
      return "Endpoint"
    if model_name or target_metric:
      return cls.infer_family(model_name or "", target_metric)
    return "Egress"

  @classmethod
  def analyze_360_insights(
      cls,
      radar_result: Optional[Dict[str, Any]],
      ctx: Optional[Dict[str, Any]] = None,
      entity_type: str = "USER",
      sensitivity: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Synthesizes deeper UEBA insights from a Tier 1 360° Behavioral Radar report and case context.

    Identifies:
    1. Multi-sector MITRE ATT&CK Kill-Chain Archetypes (v1.9.1) across active & sub-threshold spokes.
    2. Dormant / Sparse Baseline Awakenings (observed > 0 on a 30d baseline mean < 1.0 -> TWO_PART_HURDLE), plus
       immature baselines (fewer active days than the harness maturity gate -> FIRST_SEEN_NOVELTY / TWO_PART_HURDLE).
    3. Variance-Masked Sub-Threshold Drift (sub-gate Z with high historical stddev -> 4-stage MAD).
    4. Cross-Entity Kill-Chain Bridge opportunities (companion USER <-> ASSET/IP in case telemetry).
    5. Explicit warrant assessment (`secondary_warranted` and `warrant_reasons`) for secondary UEBA hunts.

    The significance gate is the sensitivity tier's anomaly threshold and the escalation screen the HIGH_RECALL
    tier's (both from ueba_constants through `thresholds()`).
    """
    radar_result = radar_result or {}
    ctx = ctx or {}
    th = cls.thresholds(sensitivity or ctx.get("sensitivity_tier"))
    screen, gate = float(th["screen_threshold"]), float(th["anomaly_threshold"])
    floor = cls.SUBTHRESHOLD_FLOOR_Z
    sector_z = radar_result.get("sector_z_scores", {})
    sector_obs = radar_result.get("sector_observed_counts", {})
    sector_avg = radar_result.get("sector_baseline_avg", {})
    sector_std = radar_result.get("sector_baseline_std", {})
    sector_active_days = radar_result.get("sector_active_days", {}) or {}
    outlier_sectors = list(radar_result.get("outlier_sectors", []))
    if not outlier_sectors and sector_z:
      outlier_sectors = [s for s, z in sorted(sector_z.items(), key=lambda x: x[1], reverse=True) if abs(float(z)) >= screen]

    subthreshold_sectors = list(radar_result.get("subthreshold_sectors", []))
    if not subthreshold_sectors and sector_z:
      subthreshold_sectors = [
          s for s, z in sorted(sector_z.items(), key=lambda x: x[1], reverse=True) if floor <= float(z) < screen
      ]

    dormant_awakening_sectors = list(radar_result.get("dormant_awakening_sectors", []))
    if not dormant_awakening_sectors and sector_z and sector_avg:
      dormant_awakening_sectors = [
          s
          for s, z in sorted(sector_z.items(), key=lambda x: x[1], reverse=True)
          if sector_obs.get(s, 0) > 0
          and float(sector_avg.get(s, 0.0)) < cls.DORMANT_BASELINE_MAX_MEAN
          and float(z) >= cls.DORMANT_AWAKENING_MIN_Z
      ]

    immature_baseline_sectors = list(radar_result.get("immature_baseline_sectors", []))
    if not immature_baseline_sectors and sector_active_days:
      immature_baseline_sectors = [
          s for s, days in sector_active_days.items()
          if sector_obs.get(s, 0) > 0 and float(days or 0) < float(th["min_baseline_days"])
      ]
    for s in immature_baseline_sectors:
      if s not in dormant_awakening_sectors:
        dormant_awakening_sectors.append(s)

    variance_masked_sectors = list(radar_result.get("variance_masked_sectors", []))
    if not variance_masked_sectors and sector_z and sector_std:
      variance_masked_sectors = [
          s
          for s, z in sorted(sector_z.items(), key=lambda x: x[1], reverse=True)
          if floor <= float(z) < gate
          and float(sector_std.get(s, 0.0)) >= max(
              float(sector_avg.get(s, 0.0)) * cls.VARIANCE_MASK_STD_TO_MEAN, cls.VARIANCE_MASK_MIN_STD
          )
      ]

    elevated = set(outlier_sectors) | set(subthreshold_sectors)
    is_host_entity = str(entity_type).upper() in ("ASSET", "HOST", "IP")
    matched_archetypes: List[Dict[str, Any]] = []
    if "Cloud" in elevated and "Workspace" in elevated:
      matched_archetypes.append({
          "archetype": "CLOUD_DISCOVERY_TO_COLLECTION",
          "tactics": ["TA0007 Discovery", "TA0009 Collection"],
          "sectors": ["Cloud", "Workspace"],
          "fusion_metrics": ["resource_read_total", "workspace_total_download_actions"],
      })
    if "Alerts" in elevated and "Egress" in elevated:
      matched_archetypes.append({
          "archetype": "DEFENSE_EVASION_ALERT_TO_EXFILTRATION",
          "tactics": ["TA0005 Defense Evasion", "TA0010 Exfiltration"],
          "sectors": ["Alerts", "Egress"],
          "fusion_metrics": ["alert_event_name_count", "network_bytes_outbound"],
      })
    if "Auth" in elevated and "Web" in elevated:
      matched_archetypes.append({
          "archetype": "C2_BEACON_TO_RARE_DESTINATION_EXFIL" if is_host_entity else "INITIAL_ACCESS_TO_DISCOVERY",
          "tactics": ["TA0001 Initial Access", "TA0007 Discovery"],
          "sectors": ["Auth", "Web"],
          "fusion_metrics": ["auth_attempts_success", "http_queries_fail"],
      })
    if "Auth" in elevated and ("Flows" in elevated or "Egress" in elevated):
      matched_archetypes.append({
          "archetype": "CREDENTIAL_ACCESS_TO_LATERAL_MOVEMENT",
          "tactics": ["TA0006 Credential Access", "TA0008 Lateral Movement"],
          "sectors": ["Auth", "Flows" if "Flows" in elevated else "Egress"],
          "fusion_metrics": ["auth_attempts_fail", "network_flows_total"],
      })
    # The next two topologies have no KILLCHAIN_CATALOG archetype; decide_tier2_pivot runs them as metrics.* fusion.
    if "Workspace" in elevated and "Egress" in elevated:
      matched_archetypes.append({
          "archetype": "WORKSPACE_HOARDING_TO_EGRESS",
          "tactics": ["TA0009 Collection", "TA0010 Exfiltration"],
          "sectors": ["Workspace", "Egress"],
          "fusion_metrics": ["workspace_total_download_actions", "network_bytes_outbound"],
      })
    if "Workspace" in elevated and "Web" in elevated:
      matched_archetypes.append({
          "archetype": "EXFILTRATION_OVER_WEB_SERVICE",
          "tactics": ["TA0009 Collection", "TA0010 Exfiltration"],
          "sectors": ["Workspace", "Web"],
          "fusion_metrics": ["workspace_total_download_actions", "http_queries_total"],
      })
    if "Web" in elevated and "Auth" in elevated and is_host_entity:
      matched_archetypes.append({
          "archetype": "RECON_ENUMERATION_TO_INITIAL_ACCESS",
          "tactics": ["TA0043 Reconnaissance", "TA0001 Initial Access"],
          "sectors": ["Web", "Auth"],
          "fusion_metrics": ["http_queries_fail", "auth_attempts_success"],
      })
    if "Cloud" in elevated and "Endpoint" in elevated:
      matched_archetypes.append({
          "archetype": "RESOURCE_DEV_TO_EXECUTION",
          "tactics": ["TA0042 Resource Development", "TA0002 Execution"],
          "sectors": ["Cloud", "Endpoint"],
          "fusion_metrics": ["resource_creation_total", "file_executions_total"],
      })

    # Companion entities for cross-entity kill-chain bridging
    primary_ent = str(ctx.get("primary_entity") or radar_result.get("entity") or "").lower()
    ent_up = str(entity_type or ctx.get("entity_type") or "USER").upper()
    companion_entities: List[Dict[str, str]] = []
    if ent_up in ("USER", "USER_ID", "EMAIL", "SERVICE_ACCOUNT"):
      for h in ctx.get("extracted_hosts", []):
        if h and h.lower() != primary_ent:
          companion_entities.append({
              "entity": h,
              "entity_type": "ASSET",
              "bridge_path": (
                  "USER_WORKSPACE_HOARDING_TO_HOST_EGRESS"
                  if "Workspace" in elevated
                  else "USER_CREDENTIAL_TO_HOST_EXECUTION"
              ),
          })
      for ip in ctx.get("extracted_ips", []):
        if ip and ip.lower() != primary_ent:
          companion_entities.append({
              "entity": ip,
              "entity_type": "IP",
              "bridge_path": "USER_CREDENTIAL_TO_HOST_EXECUTION",
          })
    else:
      for u in ctx.get("extracted_users", []):
        if u and u.lower() != primary_ent:
          companion_entities.append({
              "entity": u,
              "entity_type": "USER",
              "bridge_path": "HOST_EXECUTION_TO_CLOUD_SA_ACCESS",
          })

    warrant_reasons: List[str] = []
    top_z = max((float(v) for v in sector_z.values()), default=0.0)
    composite_d = float(radar_result.get("composite_d", 0.0) or 0.0)
    cri = float(radar_result.get("calibrated_risk_index", 0.0) or 0.0)

    if outlier_sectors:
      warrant_reasons.append(
          f"Primary 360° sector breach in {', '.join(outlier_sectors)} (peak Z = {top_z:+.2f}σ; escalation screen "
          f"{_num(screen)}σ, {th['tier']} significance gate {_num(gate)}σ)."
      )
    if len(subthreshold_sectors) >= 2 and composite_d >= screen:
      warrant_reasons.append(
          f"Multi-spoke sub-threshold convergence across {', '.join(subthreshold_sectors)} (joint Euclidean D = {composite_d:.2f}σ)."
      )
    if variance_masked_sectors:
      warrant_reasons.append(
          f"Potential historical variance masking in {', '.join(variance_masked_sectors)} (high 30d stddev may suppress classical Z; 4-Stage Non-Parametric MAD warranted)."
      )
    if dormant_awakening_sectors:
      warrant_reasons.append(
          f"Dormant baseline awakening in {', '.join(dormant_awakening_sectors)} (sparse 30d baseline; Two-Part Hurdle / First-Seen Novelty warranted)."
      )
    if immature_baseline_sectors:
      warrant_reasons.append(
          f"Immature baseline in {', '.join(immature_baseline_sectors)} (fewer than {th['min_baseline_days']} active days, so "
          "σ-scores are gated; FIRST_SEEN_NOVELTY / TWO_PART_HURDLE warranted)."
      )
    if matched_archetypes:
      arch_names = [a["archetype"] for a in matched_archetypes]
      warrant_reasons.append(f"Multi-sector MITRE ATT&CK kill-chain topology matched: {', '.join(arch_names)}.")

    secondary_warranted = bool(
        radar_result.get("is_outlier")
        or top_z >= screen
        or harness_truth.recommended_action(cri) != "MONITOR"
        or (len(subthreshold_sectors) >= 2 and composite_d >= screen)
        or len(variance_masked_sectors) >= 1
        or len(dormant_awakening_sectors) >= 1
    )

    recommended_focus_sector = radar_result.get("top_sector") or "Auth"
    if not outlier_sectors:
      if variance_masked_sectors:
        recommended_focus_sector = variance_masked_sectors[0]
      elif dormant_awakening_sectors:
        recommended_focus_sector = dormant_awakening_sectors[0]
      elif subthreshold_sectors:
        recommended_focus_sector = subthreshold_sectors[0]

    return {
        "active_sectors": outlier_sectors,
        "subthreshold_sectors": subthreshold_sectors,
        "dormant_awakening_sectors": dormant_awakening_sectors,
        "immature_baseline_sectors": immature_baseline_sectors,
        "variance_masked_sectors": variance_masked_sectors,
        "matched_killchain_archetypes": matched_archetypes,
        "companion_entities": companion_entities,
        "secondary_warranted": secondary_warranted,
        "warrant_reasons": warrant_reasons,
        "recommended_focus_sector": recommended_focus_sector,
    }

  @classmethod
  def score_hypothesis_confidence(
      cls,
      model_name: str,
      target_metric: Optional[str] = None,
      fusion_metrics: Optional[Sequence[str]] = None,
      outlier_vector: Optional[str] = None,
      ctx: Optional[Dict[str, Any]] = None,
      radar_result: Optional[Dict[str, Any]] = None,
      is_pivot: bool = False,
      prior_refuted: bool = False,
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
      llm_proposed_confidence: Optional[float] = None,
      target_entity_override: Optional[str] = None,
      sensitivity: Optional[str] = None,
  ) -> Tuple[float, str, str]:
    """Computes an evidence-anchored confidence score [0.00 - 1.00], band, and breakdown string.

    Radar magnitude tiers use the sensitivity tier's anomaly gate and the HIGH_RECALL escalation screen.
    """
    ctx = ctx or {}
    fusion_list = list(fusion_metrics or [])
    sig = cls.build_signature(model_name, target_metric, fusion_list, target_entity_override)

    if executed_signatures and sig in executed_signatures:
      return 0.0, "SUPPRESSED", "VETO (0.00): Hypothesis signature already executed in this investigation."

    primary_family = cls.infer_family(model_name, target_metric, fusion_list, outlier_vector)
    if empty_families and primary_family in empty_families:
      return 0.10, "SUPPRESSED", f"VETO (0.10): Prior query confirmed 0 telemetry records in `{primary_family}` family."

    th = cls.thresholds(sensitivity or ctx.get("sensitivity_tier"))
    gate, screen = float(th["anomaly_threshold"]), float(th["screen_threshold"])
    score = 0.25  # Base prior for any structured hypothesis
    reasons: List[str] = ["Base(0.25)"]

    sector_z = (radar_result or {}).get("sector_z_scores", {})
    sector_obs = (radar_result or {}).get("sector_observed_counts", {})
    outlier_sectors = (radar_result or {}).get("outlier_sectors", [])
    subthreshold_sectors = (radar_result or {}).get("subthreshold_sectors", [])
    variance_masked = (radar_result or {}).get("variance_masked_sectors", [])
    dormant_awakening = (radar_result or {}).get("dormant_awakening_sectors", [])

    # 1. Tier 1 360° Spoke Magnitude Signal (+0.00 to +0.45)
    raw_z = sector_z.get(primary_family, sector_z.get(outlier_vector or "", None))
    if raw_z is None and outlier_vector and (primary_family == outlier_vector or not sector_z):
      raw_z = (screen + gate) / 2.0  # A named outlier vector without a radar Z sits between the screen and the gate
    target_z = abs(float(raw_z or 0.0))
    if target_z >= gate:
      score += 0.45
      reasons.append(f"Tier1_{primary_family}_Z={target_z:+.2f}σ(+0.45)")
    elif target_z >= screen:
      score += 0.35
      reasons.append(f"Tier1_{primary_family}_Z={target_z:+.2f}σ(+0.35)")
    elif target_z >= cls.DORMANT_AWAKENING_MIN_Z:
      score += 0.20
      reasons.append(f"Tier1_{primary_family}_Z={target_z:+.2f}σ(+0.20)")
    elif target_z >= cls.SUBTHRESHOLD_FLOOR_Z:
      score += 0.15
      reasons.append(f"Tier1_{primary_family}_SubThresholdZ={target_z:+.2f}σ(+0.15)")

    # Multi-Vector Fusion bonus when 2+ sectors are elevated in Tier 1
    if len(fusion_list) >= 2 and (len(outlier_sectors) >= 2 or len(outlier_sectors) + len(subthreshold_sectors) >= 2):
      score += 0.20
      elev_names = (list(outlier_sectors) + list(subthreshold_sectors))[:2]
      reasons.append(f"MultiSectorOutliers({','.join(elev_names)})(+0.20)")

    # Variance-Masked 4-Stage MAD bonus & Dormancy Awakening Two-Part Hurdle / First-Seen Novelty bonus
    m_up = cls.canonical_model_name(model_name)
    if m_up == "MAD" and (primary_family in variance_masked or (outlier_vector and outlier_vector in variance_masked)):
      score += 0.25
      reasons.append(f"VarianceMaskedBaseline({primary_family})(+0.25)")
    if m_up in ("TWO_PART_HURDLE", "FIRST_SEEN_NOVELTY", "BAYESIAN_GAMMA", "POISSON") and (
        primary_family in dormant_awakening or (outlier_vector and outlier_vector in dormant_awakening)
    ):
      score += 0.25
      reasons.append(f"DormantBaselineAwakening({primary_family})(+0.25)")
    if target_entity_override:
      score += 0.20
      reasons.append(f"CrossEntityBridge({target_entity_override})(+0.20)")

    # 2. Case / Alert UDM Touchpoint Alignment (+0.00 to +0.35)
    fam_spec = cls.FAMILY_SIGNALS.get(primary_family, {})
    udm_events = set(ctx.get("udm_event_types", []))
    text_corpus = (
        f"{ctx.get('case_title', '')} "
        f"{ctx.get('case_description', '')} "
        f"{' '.join(ctx.get('alerts', []))} "
        f"{' '.join(ctx.get('rule_generators', []))} "
        f"{' '.join(ctx.get('threat_associations', []))}"
    ).lower()

    if udm_events and fam_spec.get("udm_events") and (udm_events & fam_spec["udm_events"]):
      score += 0.30
      matched_ev = next(iter(udm_events & fam_spec["udm_events"]))
      reasons.append(f"UDM_Event({matched_ev})(+0.30)")
    elif any(kw in text_corpus for kw in fam_spec.get("keywords", set())):
      score += 0.22
      reasons.append(f"AlertSignal({primary_family})(+0.22)")
    elif primary_family in ("Web", "Endpoint", "Egress") and _BILATERAL_RX.search(text_corpus):
      score += 0.30
      reasons.append(f"BilateralHarnessSignal({primary_family})(+0.30)")

    # 3. Epistemic Pivot Signal (+0.15 when prior Tier 2A refuted H1 OR confirmed an outlier warranting 2nd-order progression)
    if is_pivot and (target_z >= screen or len(outlier_sectors) >= 1 or variance_masked or dormant_awakening):
      score += 0.15
      if prior_refuted:
        reasons.append("EpistemicRefutationPivot(+0.15)")
      else:
        reasons.append("ConfirmedOutlierProgressionPivot(+0.15)")

    # Blend modestly with LLM proposed confidence if provided, bounded by evidence
    if llm_proposed_confidence is not None:
      blended = (0.75 * score) + (0.25 * float(llm_proposed_confidence))
      score = blended

    # 4. Zero-Telemetry Dampener: If Tier 1 ran and observed 0 events in that spoke AND no UDM match
    if radar_result and primary_family in sector_obs and not target_entity_override:
      if (
          sector_obs.get(primary_family, 0) == 0
          and not (udm_events & fam_spec.get("udm_events", set()))
          and target_z < cls.ZERO_SPOKE_MAX_Z
      ):
        if primary_family != "Endpoint":  # Endpoint isn't always a User 360 spoke
          score = min(score, 0.35)
          reasons.append(f"ZeroSpokeEventsCap({primary_family}=0->max 0.35)")

    score = round(min(0.98, max(0.05, score)), 2)
    auto_gate = cls.TIER_2B_PIVOT_AUTO_EXECUTE_THRESHOLD if is_pivot else cls.TIER_2A_AUTO_EXECUTE_THRESHOLD

    if score >= auto_gate:
      band = "AUTO_EXECUTE"
    elif score >= cls.ANALYST_REVIEW_MIN_THRESHOLD:
      band = "ANALYST_REVIEW"
    else:
      band = "SUPPRESSED"

    breakdown = f"Score {score:.2f} (Gate {auto_gate:.2f}): " + " + ".join(reasons)
    return score, band, breakdown

  @classmethod
  def format_hypothesis_for_avenue(cls, cand: CandidateHypothesis) -> str:
    """Formats a CandidateHypothesis into a rich markdown string for Case Wall presentation."""
    badge = (
        "🟢 AUTO-EXECUTED"
        if cand.confidence_band == "AUTO_EXECUTE"
        else ("🟡 HELD FOR ANALYST REVIEW" if cand.confidence_band == "ANALYST_REVIEW" else "⚪ LOW CONFIDENCE")
    )
    metric_tag = (
        f"Fusion({', '.join(cand.fusion_metrics)})"
        if cand.fusion_metrics
        else (f"Metric: `{cand.target_metric}`" if cand.target_metric else f"Engine: `{cand.selected_skill}`")
    )
    return (
        f"**[{cand.confidence_score:.2f}/1.00 {badge}]** `{cand.model_name}` ({metric_tag}) — **{cand.hypothesis_title}**\n"
        f"   - **Hypothesis ($H_1$ vs $H_0$)**: *$H_1$: {cand.hypothesis_h1} | $H_0$: {cand.hypothesis_h0}*\n"
        f"   - **Defense of Hypothesis**: {cand.evidentiary_defense}\n"
        f"   - **Confidence Audit**: `{cand.confidence_breakdown}`"
    )

  @classmethod
  def decide_tier1_360(
      cls,
      target_entity: str,
      entity_type: str = "USER",
      case_id: Optional[str] = None,
      case_title: str = "",
      case_desc: str = "",
      alerts: Optional[List[Dict[str, Any]]] = None,
      sensitivity: Optional[str] = None,
  ) -> StrategyDirective:
    """Tier 1: Establishes a 6-spoke 360° multi-sector baseline across key entities."""
    th = cls.thresholds(sensitivity)
    gate, composite, screen = _num(th["anomaly_threshold"]), _num(th["radar_composite_d"]), _num(th["screen_threshold"])
    is_host = str(entity_type).upper() in ("ASSET", "HOST", "IP")
    if is_host:
      sector_queries = (
          "the decoupled canonical host sector queries (`templates/pipelines/radar_360_decoupled_sector.yl2` plus the "
          "`radar_360_sector_alert.yl2` and `radar_360_sector_web_http.yl2` shards)"
      )
      sectors = "Auth, Network Egress, DNS, Web & Proxy, Security & EDR Alerts, and Endpoint"
    else:
      sector_queries = (
          "the decoupled canonical user sector queries in `templates/radar_360/` (`user_1_auth_risk.yl2` through "
          "`user_6_web_risk.yl2`)"
      )
      sectors = "Auth, Cloud, Workspace, Egress, DNS, and Web"
    rationale = cls._with_horizon(
        "Initial 6-spoke baseline establishes ground truth across orthogonal telemetry domains before executing "
        "confidence-gated Tier 2 deep dives; CRI is computed in Python from each sector Z.",
        "360_DECOUPLED_RADAR",
        cls.RISK_METRICS_SKILL,
    )
    return StrategyDirective(
        selected_skill=cls.RISK_METRICS_SKILL,
        model_name="360_DECOUPLED_RADAR",
        directive_query="profile_360_risk",
        target_entity=target_entity,
        entity_type=entity_type,
        investigation_tier="TIER_1_BASELINE",
        confidence_score=0.95,
        confidence_band="AUTO_EXECUTE",
        confidence_breakdown="Score 0.95 (Mandatory Tier 1 6-Sector 30-Day Baseline Sweep)",
        evidentiary_defense=(
            f"Entity `{target_entity}` ({entity_type}) was extracted directly from case/alert telemetry. "
            f"Executing {sector_queries} establishes objective 30-day sector Z-scores across {sectors} "
            "before committing to narrow secondary models."
        ),
        threat_summary=f"Establish 30-day 6-sector behavioral baseline for {entity_type} `{target_entity}` across canonical telemetry families.",
        hypothesis_h0=(
            f"Activity for `{target_entity}` stays inside its 30-day baselines in all 6 canonical sectors "
            f"(every sector Z < {gate}σ and composite D < {composite}σ)."
        ),
        hypothesis_h1=(
            f"Target entity `{target_entity}` departs from its 30-day baseline: Z ≥ {gate}σ in at least one "
            f"behavioral sector or composite D ≥ {composite}σ."
        ),
        selection_rationale=rationale,
        flight_card_title=f"Tier 1 360° Behavioral Radar: `{target_entity}`",
        recommended_avenues=[
            (
                f"Evaluate all 6 sector Z-scores; launch a Tier 2 deep dive when a sector clears the {screen}σ "
                f"{cls.SCREEN_SENSITIVITY_TIER} escalation screen and a candidate hypothesis scores >= "
                f"{cls.TIER_2A_AUTO_EXECUTE_THRESHOLD:.2f} confidence."
            ),
            (
                "If 2+ orthogonal sectors are elevated, prioritize Cross-Vector or Roll-Up Sector Fusion "
                f"(rectified D = √(Σ max(0, Z_i)²), gate D² ≥ {_num(th['fusion_threshold_sq'])})."
            ),
            "Cross-reference observed sector volumes against approved change windows or scheduled batch workloads.",
        ],
    )

  @classmethod
  async def decide_tier2_deep_dive(
      cls,
      target_entity: str,
      entity_type: str,
      outlier_vector: str,
      case_info: Dict[str, Any],
      alerts: List[Dict[str, Any]],
      connector_events: List[Dict[str, Any]],
      radar_result: Optional[Dict[str, Any]] = None,
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
      sensitivity: Optional[str] = None,
  ) -> StrategyDirective:
    """Tier 2A: Formulates confidence-scored deep dive (single metric, fusion, or micro-math) from 360° radar + alert context."""
    return await cls.decide_agentic(
        case_info=case_info,
        alerts=alerts,
        connector_events=connector_events,
        default_entity=target_entity,
        default_entity_type=entity_type,
        tier="TIER_2_DEEP_DIVE",
        outlier_vector=outlier_vector,
        radar_result=radar_result,
        executed_signatures=executed_signatures,
        empty_families=empty_families,
        sensitivity=sensitivity,
    )

  @classmethod
  def _killchain_or_fusion(cls, arch_id: str) -> Tuple[str, str]:
    """(model_name, directive_query) for a MITRE topology.

    Archetypes in the risk-metrics KILLCHAIN_CATALOG run as kill-chain hunts; topologies outside it run as metrics.*
    dual-sector fusion on the same sector pair, so the engine never substitutes a different archetype.
    """
    if arch_id in _killchain_catalog_ids():
      return f"KILLCHAIN_{arch_id}", "killchain_archetype"
    return "DUAL_SECTOR_FUSION_3STAGE", "sector_fusion"

  @classmethod
  def decide_tier2_pivot(
      cls,
      target_entity: str,
      entity_type: str,
      tier2a_directive: StrategyDirective,
      tier2a_result: Dict[str, Any],
      radar_result: Optional[Dict[str, Any]] = None,
      case_info: Optional[Dict[str, Any]] = None,
      alerts: Optional[List[Dict[str, Any]]] = None,
      connector_events: Optional[List[Dict[str, Any]]] = None,
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
      secondary_hunts_run: int = 1,
      sensitivity: Optional[str] = None,
  ) -> Optional[StrategyDirective]:
    """Tier 2B Epistemic Pivot Reasoner: Evaluates Tier 2A outcome and sparks a high-confidence (>=0.80) pivot if warranted."""
    if secondary_hunts_run >= cls.MAX_SECONDARY_HUNTS:
      return None
    case_info = case_info or {}
    alerts = alerts or []
    connector_events = connector_events or []
    executed_signatures = executed_signatures or set()
    empty_families = empty_families or set()
    t2a_outlier = bool(tier2a_result.get("is_outlier", False))
    t2a_model = cls.canonical_model_name(tier2a_directive.model_name)
    t2a_metric = tier2a_directive.target_metric
    sector_z = (radar_result or {}).get("sector_z_scores", {})
    outlier_sectors = (radar_result or {}).get("outlier_sectors", [])
    sector_metrics = (radar_result or {}).get(
        "sector_metrics",
        cls.SECTOR_TO_METRIC_ASSET if entity_type.upper() in ("ASSET", "HOST", "IP") else cls.SECTOR_TO_METRIC_USER,
    )

    ctx = cls._build_context_summary(
        case_info=case_info,
        alerts=alerts,
        connector_events=connector_events,
        default_entity=target_entity,
        default_entity_type=entity_type,
        tier="TIER_2B_PIVOT",
        outlier_vector=tier2a_directive.outlier_vector,
        radar_result=radar_result,
        sensitivity=sensitivity,
    )
    th = cls.thresholds(ctx.get("sensitivity_tier"))
    gate, screen = _num(th["anomaly_threshold"]), float(th["screen_threshold"])
    fusion_sq, robust, tukey = _num(th["fusion_threshold_sq"]), _num(th["robust_threshold"]), _num(th["tukey_excess_threshold"])
    caps = harness_truth.mode_caps()
    radar_insights = ctx.get("radar_insights") or cls.analyze_360_insights(radar_result, ctx, entity_type)

    # Classify Tier 2A post-data outcome shape & MITRE progression (v1.9.1)
    stats_rows = int(tier2a_result.get("stats_rows", 0) or 0)
    active_sec = tier2a_directive.outlier_vector or (outlier_sectors[0] if outlier_sectors else "")
    if t2a_outlier:
      outcome_class = "FLEET_WAVE" if stats_rows >= 10 else "ACUTE_OUTLIER"
    elif active_sec in radar_insights.get("dormant_awakening_sectors", []):
      outcome_class = "SPARSE_BASELINE"
    else:
      outcome_class = "CLEAN_OR_SUBTHRESHOLD"
    tier2a_directive.post_data_outcome_class = outcome_class
    tier2a_directive.radar_insights = radar_insights

    candidates: List[CandidateHypothesis] = []

    def _score(model_name: str, target_metric: Optional[str] = None, fusion: Optional[List[str]] = None,
               vector: Optional[str] = None, refuted: bool = False, entity_override: Optional[str] = None):
      return cls.score_hypothesis_confidence(
          model_name=model_name,
          target_metric=target_metric,
          fusion_metrics=fusion,
          outlier_vector=vector,
          ctx=ctx,
          radar_result=radar_result,
          is_pivot=True,
          prior_refuted=refuted,
          executed_signatures=executed_signatures,
          empty_families=empty_families,
          target_entity_override=entity_override,
      )

    # CASE A: 2+ sectors in Tier 1 are anomalous -> Propose Cross-Vector / Roll-Up Fusion!
    if len(outlier_sectors) >= 2 and "FUSION" not in t2a_model and "KILLCHAIN" not in t2a_model:
      sec_a, sec_b = outlier_sectors[0], outlier_sectors[1]
      m_a = sector_metrics.get(sec_a, "workspace_total_download_actions")
      m_b = sector_metrics.get(sec_b, "network_bytes_outbound")
      z_a_val = sector_z.get(sec_a, 0.0)
      z_b_val = sector_z.get(sec_b, 0.0)
      pivot_why = (
          f"Tier 2A (`{t2a_model}`) evaluated `{sec_a}` in isolation, while Tier 1 360° Radar simultaneously flagged "
          f"orthogonal sector `{sec_b}` (Z = {z_b_val:+.2f}σ) alongside `{sec_a}` (Z = {z_a_val:+.2f}σ). "
          f"Fusing `{m_a}` and `{m_b}` (rectified D = √(Σ max(0, Z_i)²), gate D² ≥ {fusion_sq}) tests whether these "
          "two anomalies form a single multi-stage kill chain."
      )
      score, band, breakdown = _score("DUAL_SECTOR_FUSION_3STAGE", fusion=[m_a, m_b], vector=sec_a, refuted=not t2a_outlier)
      candidates.append(
          CandidateHypothesis(
              hypothesis_title=f"Cross-Vector Fusion: {sec_a} (`{m_a}`) × {sec_b} (`{m_b}`)",
              selected_skill=cls.RISK_METRICS_SKILL,
              model_name="DUAL_SECTOR_FUSION_3STAGE",
              directive_query="sector_fusion",
              target_metric=m_a,
              fusion_metrics=[m_a, m_b],
              hypothesis_h0=f"Concurrent elevations in `{m_a}` and `{m_b}` are independent benign operational fluctuations.",
              hypothesis_h1=f"Entity `{target_entity}` is executing a coupled multi-sector attack chain across `{m_a}` and `{m_b}` (D² ≥ {fusion_sq}).",
              evidentiary_defense=pivot_why,
              confidence_score=score,
              confidence_band=band,
              confidence_breakdown=breakdown,
              pivot_reason=pivot_why,
          )
      )

    # CASE A2: Matched MITRE ATT&CK Kill-Chain Archetype across active + sub-threshold sectors
    matched_archs = radar_insights.get("matched_killchain_archetypes", [])
    if matched_archs and len(outlier_sectors) < 2 and "KILLCHAIN" not in t2a_model and "FUSION" not in t2a_model:
      top_arch = matched_archs[0]
      arch_id = top_arch["archetype"]
      f_metrics = top_arch["fusion_metrics"]
      if arch_id != "WORKSPACE_HOARDING_TO_EGRESS":
        kc_model, kc_query = cls._killchain_or_fusion(arch_id)
        executed_as = (
            "multi-stage kill-chain fusion"
            if kc_query == "killchain_archetype"
            else "metrics.* dual-sector fusion (the topology has no KILLCHAIN_CATALOG archetype)"
        )
        pivot_why = (
            f"360° Radar topology matched MITRE ATT&CK kill-chain `{arch_id}` ({' -> '.join(top_arch['tactics'])}) "
            f"across `{', '.join(top_arch['sectors'])}`. Executing {executed_as} on `{f_metrics[0]}` + `{f_metrics[1]}`."
        )
        score, band, breakdown = _score(kc_model, f_metrics[0], f_metrics, active_sec, refuted=not t2a_outlier)
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"MITRE ATT&CK Kill-Chain Progression: `{arch_id}`",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name=kc_model,
                directive_query=kc_query,
                target_metric=f_metrics[0],
                fusion_metrics=f_metrics,
                killchain_archetype=arch_id,
                hypothesis_h0=f"Sub-threshold activity across {', '.join(top_arch['sectors'])} is uncorrelated background noise.",
                hypothesis_h1=f"Entity `{target_entity}` is progressing along MITRE ATT&CK kill-chain `{arch_id}`.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

    # CASE B: Tier 2A CONFIRMED an outlier (ACUTE_OUTLIER) -> Perform Second-Order Verification / Kill-Chain Progression!
    if t2a_outlier:
      # B-Conf-1: Confirmed Workspace Download Surge -> Pivot to Workspace Exfiltration Triad (Downloads + Changes + Emails vs Peer Cohort)
      if active_sec == "Workspace" and t2a_model != "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL":
        triad = ["workspace_total_download_actions", "workspace_total_change_actions", "workspace_emails_sent_total"]
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) confirmed an acute Workspace anomaly on `{target_entity}`. "
            "Pivoting to `PART_OF_THE_WHOLE_TRIAD_MULTILEVEL` verifies whether the user is simultaneously staging document modifications "
            "(`workspace_total_change_actions`) and outbound emails (`workspace_emails_sent_total`) relative to their enterprise peer cohort "
            "(Samuelson cohort-size cap applies to the triad D²)."
        )
        score, band, breakdown = _score("PART_OF_THE_WHOLE_TRIAD_MULTILEVEL", triad[0], triad, "Workspace")
        candidates.append(
            CandidateHypothesis(
                hypothesis_title="Workspace Exfiltration Triad vs Peer Cohort (Download + Change + Email)",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name="PART_OF_THE_WHOLE_TRIAD_MULTILEVEL",
                directive_query="workspace_triad",
                target_metric=triad[0],
                fusion_metrics=list(triad),
                hypothesis_h0="Confirmed download spike is an isolated administrative backup shared by the team cohort.",
                hypothesis_h1=f"User `{target_entity}` exhibits a coupled Workspace exfiltration triad departing from peer cohort norms.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # B-Conf-2: Confirmed Cloud CRUD Surge -> Pivot to Cloud Repository Scope & Caller IP Attribution
      elif active_sec == "Cloud" and t2a_model != "CLOUD_REPOSITORY_SCOPE":
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) confirmed a Cloud CRUD surge on `{target_entity}`. "
            "Pivoting to `CLOUD_REPOSITORY_SCOPE` attributes the exact target cloud resource (`target.resource.name`) and origin caller IP (`principal.ip`)."
        )
        score, band, breakdown = _score("CLOUD_REPOSITORY_SCOPE", "resource_read_total", vector="Cloud")
        candidates.append(
            CandidateHypothesis(
                hypothesis_title="Cloud Repository Scope & Caller IP Attribution (`cloud_repository_scope_dual_branch`)",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name="CLOUD_REPOSITORY_SCOPE",
                directive_query="cloud_repo_scope",
                target_metric="resource_read_total",
                outcome_mode="total",
                hypothesis_h0="Cloud CRUD surge targets standard CI/CD deployment buckets from known corporate IPs.",
                hypothesis_h1=f"Identity `{target_entity}` is accessing sensitive cloud repositories from an anomalous caller IP.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # B-Conf-3: Confirmed Egress / DNS / Web Outlier -> Pivot to Rare Destination Entity Context Graph Verification
      elif active_sec in ("Egress", "DNS", "Web") and "RARE_DESTINATION" not in t2a_model and "DOMAIN_PREVALENCE" not in t2a_model:
        ecg_model = (
            "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE"
            if active_sec == "Web"
            else "RARE_DESTINATION_ECG_3STAGE"
        )
        ecg_metric = (
            "http_queries_total"
            if active_sec == "Web"
            else ("dns_queries_total" if active_sec == "DNS" else "network_bytes_outbound")
        )
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) confirmed an outlier in `{active_sec}`. "
            f"Pivoting to `{ecg_model}` enriches the confirmed behavioral surge with Entity Context Graph `DERIVED_CONTEXT` "
            "to verify whether the destination domains/IPs have ultra-low enterprise fleet prevalence (`rolling_max <= 3`, "
            "`day_count = 10`); the Mode A join window starts at D-2 with event stages pinned to the scored UTC day."
        )
        score, band, breakdown = _score(ecg_model, ecg_metric, vector=active_sec)
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"Rare Destination Entity Graph Verification (`{ecg_model}`)",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name=ecg_model,
                directive_query="dynamic_metric",
                target_metric=ecg_metric,
                hypothesis_h0="Confirmed network/DNS/web surge communicates with established high-prevalence enterprise infrastructure.",
                hypothesis_h1=(
                    f"Confirmed `{active_sec}` outlier on `{target_entity}` is contacting rare external C2/exfiltration "
                    "destinations (`rolling_max <= 3`, `day_count = 10`)."
                ),
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # B-Conf-4: Confirmed Auth Outlier -> Pivot to Brute-Force-to-Compromise Dual-Sector Fusion (auth_attempts_fail + auth_attempts_success)
      elif active_sec == "Auth" and "FUSION" not in t2a_model:
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) confirmed an authentication anomaly on `{target_entity}`. "
            "Pivoting to `DUAL_SECTOR_FUSION_3STAGE` across `auth_attempts_fail` and `auth_attempts_success` verifies "
            "whether the credential attack culminated in a successful authentication breach (MITRE T1110 -> T1078)."
        )
        auth_pair = ["auth_attempts_fail", "auth_attempts_success"]
        score, band, breakdown = _score("DUAL_SECTOR_FUSION_3STAGE", auth_pair[0], auth_pair, "Auth")
        candidates.append(
            CandidateHypothesis(
                hypothesis_title="Credential Attack Breach Verification (`auth_attempts_fail` × `auth_attempts_success`)",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name="DUAL_SECTOR_FUSION_3STAGE",
                directive_query="sector_fusion",
                target_metric=auth_pair[0],
                fusion_metrics=list(auth_pair),
                hypothesis_h0="Authentication failures were blocked by IAM controls without any successful login breach.",
                hypothesis_h1=f"Credential attack on `{target_entity}` was followed by an anomalous surge in successful logins (`auth_attempts_success`).",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # B-Conf-5: Confirmed Alerts / Endpoint Outlier -> Pivot to MITRE Kill-Chain Execution/Alert-to-Exfiltration
      elif active_sec in ("Alerts", "Endpoint", "Flows") and "KILLCHAIN" not in t2a_model:
        kc_arch = (
            "DEFENSE_EVASION_ALERT_TO_EXFILTRATION"
            if active_sec == "Alerts"
            else "EXECUTION_TO_EXFILTRATION"
        )
        kc_metrics = (
            ["alert_event_name_count", "network_bytes_outbound"]
            if active_sec == "Alerts"
            else ["file_executions_total", "network_bytes_outbound"]
        )
        kc_model, kc_query = cls._killchain_or_fusion(kc_arch)
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) confirmed an endpoint/alert anomaly on `{target_entity}`. "
            f"Pivoting to MITRE Kill-Chain `{kc_arch}` tests whether the endpoint execution/alert surge triggered outbound data exfiltration."
        )
        score, band, breakdown = _score(kc_model, kc_metrics[0], kc_metrics, active_sec)
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"MITRE Kill-Chain Progression: `{kc_arch}`",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name=kc_model,
                directive_query=kc_query,
                target_metric=kc_metrics[0],
                fusion_metrics=kc_metrics,
                killchain_archetype=kc_arch,
                hypothesis_h0="Confirmed endpoint/alert activity remained local with no outbound network exfiltration.",
                hypothesis_h1=f"Endpoint anomaly on `{target_entity}` progressed to outbound data exfiltration (`network_bytes_outbound`).",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

    # CASE C: Tier 2A REFUTED H1 (is_outlier == False), but an active sector anomaly, variance-masked drift, or UDM signal remains unexplained!
    if not t2a_outlier:
      active_z = abs(float(sector_z.get(active_sec, 0.0)))
      variance_masked = radar_insights.get("variance_masked_sectors", [])
      dormant_awakening = radar_insights.get("dormant_awakening_sectors", [])

      # C1: If C2_BEACONING_JITTER refuted periodic beaconing on an Egress spike -> Pivot to Above-Historical-Max Z
      if t2a_model == "C2_BEACONING_JITTER" and (active_z >= screen or "Egress" in outlier_sectors):
        label = cls.MODEL_LABELS["ABOVE_HISTORICAL_MAX_Z"]
        pivot_why = (
            "Tier 2A (`C2_BEACONING_JITTER`) returned irregular inter-arrival timing, refuting periodic robotic C2 polling. "
            f"However, Tier 1 `Egress` volume remains anomalous (Z = {sector_z.get('Egress', active_z):+.2f}σ). "
            "Ruling out periodic beaconing implies the outbound spike is an acute bulk transfer; "
            f"pivoting to {label} (`ABOVE_HISTORICAL_MAX_Z`, `macd_momentum_velocity_2stage.yl2`) on `network_bytes_outbound` "
            "tests whether outbound bytes broke the entity's 30-day historical maximum."
        )
        score, band, breakdown = _score("ABOVE_HISTORICAL_MAX_Z", "network_bytes_outbound", vector="Egress", refuted=True)
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"Bulk Egress Breakout ({label})",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name="ABOVE_HISTORICAL_MAX_Z",
                directive_query="macd_momentum",
                target_metric="network_bytes_outbound",
                hypothesis_h0="Outbound byte volume stays below its 30-day historical maximum.",
                hypothesis_h1=(
                    f"Non-periodic outbound volume broke its 30-day historical maximum ({label} ≥ {gate}σ), "
                    "indicating acute bulk staging and exfiltration."
                ),
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # C2: If POISSON_BURST_CLUSTERING refuted credential spray on an Auth spike -> Pivot to HOUR_OF_DAY_PROFILE
      if t2a_model == "POISSON_BURST_CLUSTERING" and (active_z >= screen or "Auth" in outlier_sectors):
        hod_gate = cls._gate_text("HOUR_OF_DAY_PROFILE")
        pivot_why = (
            "Tier 2A (`POISSON_BURST_CLUSTERING`) found no high-frequency Fano burst dispersion, ruling out automated brute-force spraying. "
            f"Because Tier 1 `Auth` telemetry is still elevated (Z = {sector_z.get('Auth', active_z):+.2f}σ), "
            f"pivoting to `HOUR_OF_DAY_PROFILE` in `{cls.STATS_HUNTER_SKILL}` (learned 24-bin hour-of-day profile, {hod_gate}) "
            "tests whether valid or semi-valid credentials are being used at out-of-profile hours."
        )
        score, band, breakdown = _score("HOUR_OF_DAY_PROFILE", "auth_attempts_total", vector="Auth", refuted=True)
        candidates.append(
            CandidateHypothesis(
                hypothesis_title="Out-of-Profile Login Hours (Learned 24-Bin Hour-of-Day Profile)",
                selected_skill=cls.STATS_HUNTER_SKILL,
                model_name="HOUR_OF_DAY_PROFILE",
                directive_query="hour_of_day_profile",
                target_metric="auth_attempts_total",
                hypothesis_h0="Authentication hours match the entity's learned 24-bin hour-of-day profile.",
                hypothesis_h1=f"Compromised credentials or hijacked sessions authenticate at out-of-profile hours ({hod_gate}).",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # C3: If another anomalous sector exists in Tier 1 that wasn't the primary vector of Tier 2A
      for sec in outlier_sectors:
        if sec != active_sec:
          sec_metric = sector_metrics.get(sec, "http_queries_total")
          sec_z = sector_z.get(sec, 0.0)
          pivot_why = (
              f"Tier 2A (`{t2a_model}`) did not confirm $H_1$ on `{active_sec}`, but Tier 1 360° Radar identified a "
              f"separate significant anomaly in `{sec}` (Z = {sec_z:+.2f}σ on `{sec_metric}`). "
              f"Pivoting to `LONGITUDINAL_CUSUM` on `{sec_metric}` (Windowed Slack Sum prefilter + Page CUSUM series in one "
              f"≤{caps['mode_b_cusum_macro_days']}-day query; single-day Mode A blocked) directly evaluates this uninvestigated outlier vector."
          )
          score, band, breakdown = _score("LONGITUDINAL_CUSUM", sec_metric, vector=sec, refuted=True)
          candidates.append(
              CandidateHypothesis(
                  hypothesis_title=f"Secondary Outlier Sweep: {sec} (`{sec_metric}`)",
                  selected_skill=cls.RISK_METRICS_SKILL,
                  model_name="LONGITUDINAL_CUSUM",
                  directive_query="dynamic_metric",
                  target_metric=sec_metric,
                  hypothesis_h0=f"Elevated `{sec_metric}` count reflects routine operational workload.",
                  hypothesis_h1=f"Sustained cumulative drift in `{sec_metric}` (Z = {sec_z:+.2f}σ) indicates unauthorized activity.",
                  evidentiary_defense=pivot_why,
                  confidence_score=score,
                  confidence_band=band,
                  confidence_breakdown=breakdown,
                  pivot_reason=pivot_why,
              )
          )

      # C4: If CLOUD_CRUD_SURGE on total volume was refuted -> Pivot to CLOUD_REPOSITORY_SCOPE (outcome_mode="fail") for Access-Denied Recon
      if t2a_model == "CLOUD_CRUD_SURGE" or (active_sec == "Cloud" and t2a_model != "CLOUD_REPOSITORY_SCOPE"):
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) did not find a total-volume CRUD breach on `{target_entity}`. "
            "Pivoting to `CLOUD_REPOSITORY_SCOPE` in `fail` mode (`resource_*_fail`) tests whether the identity triggered "
            "Access-Denied reconnaissance spikes against restricted cloud repositories that were diluted in total CRUD counts."
        )
        score, band, breakdown = _score("CLOUD_REPOSITORY_SCOPE", "resource_read_fail", vector="Cloud", refuted=True)
        candidates.append(
            CandidateHypothesis(
                hypothesis_title="Cloud Access-Denied Reconnaissance (`CLOUD_REPOSITORY_SCOPE` fail mode)",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name="CLOUD_REPOSITORY_SCOPE",
                directive_query="cloud_repo_scope",
                target_metric="resource_read_fail",
                outcome_mode="fail",
                hypothesis_h0="Cloud access failures reflect benign misconfigured IAM bindings.",
                hypothesis_h1=f"Identity `{target_entity}` is enumerating restricted cloud repositories, generating anomalous `resource_*_fail` spikes.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # C5: Parametric Model Refuted on Variance-Masked or Elevated Sector -> Pivot to 4-Stage MAD, 3-Stage QUANTILE_IQR_SKEW
      #     and (network sectors) bounded raw-window IQR_TUKEY_SKEW_FENCES in secops-statistical-hunter.
      if t2a_model in cls.PARAMETRIC_MACRO_MODELS and (active_sec in variance_masked or active_z >= screen):
        mad_metric = t2a_metric or sector_metrics.get(active_sec, "network_bytes_outbound")
        pivot_why = (
            f"Parametric Tier 2A model (`{t2a_model}`) returned sub-threshold results on `{mad_metric}`. "
            "When historical bursts pollute the 30-day standard deviation (`stddev`), parametric Z-scores are compressed. "
            f"Pivoting to 4-Stage Non-Parametric `MAD` (`mad_robust_z_4stage.yl2`) scores `{mad_metric}` against the 30-day median and MAD scale (`$modified_z`) to unmask variance-suppressed outliers."
        )
        score, band, breakdown = _score("MAD", mad_metric, vector=active_sec, refuted=True)
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"Variance-Resistant 4-Stage Non-Parametric MAD (`{mad_metric}`)",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name="MAD",
                directive_query="dynamic_metric",
                target_metric=mad_metric,
                hypothesis_h0=f"Observed `{mad_metric}` volume is within normal median absolute deviation bounds (`$modified_z` < {robust}).",
                hypothesis_h1=f"Prior 30-day bursts inflated parametric `stddev` on `{mad_metric}`, masking a true median-anchored outlier (`$modified_z` ≥ {robust}).",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

        # C5B: 3-Stage Non-Parametric Quantiles (window.percentile), Bowley Skewness & Hubert-Vandervieren Tukey Fence
        q_why = (
            f"Parametric Tier 2A model (`{t2a_model}`) was compressed by heavy right-tail skewness on `{mad_metric}`. "
            "Pivoting to 3-Stage `QUANTILE_IQR_SKEW` (`quantile_iqr_skew_3stage.yl2`) computes a 1-stage empirical quantile envelope (`$p10, $q25, $q50, $q75, $p90`), "
            "Bowley quartile skewness (`$bowley_skew`), Moors tail heaviness (`$tail_heaviness`) and the skewness-adjusted Tukey upper fence (`$adj_upper_fence`)."
        )
        q_score, q_band, q_breakdown = _score("QUANTILE_IQR_SKEW", mad_metric, vector=active_sec, refuted=True)
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"3-Stage Empirical Quantiles, Bowley Skewness & Skew-Adjusted Tukey Fence (`{mad_metric}`)",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name="QUANTILE_IQR_SKEW",
                directive_query="quantile_iqr_skew",
                target_metric=mad_metric,
                hypothesis_h0=f"Observed `{mad_metric}` volume sits below the skewness-adjusted Tukey upper fence (`$tukey_excess_z` < {tukey}).",
                hypothesis_h1=f"Right-skewed historical bursts masked a true upper-fence breach on `{mad_metric}` (`$tukey_excess_z` ≥ {tukey}).",
                evidentiary_defense=q_why,
                confidence_score=q_score,
                confidence_band=q_band,
                confidence_breakdown=q_breakdown,
                pivot_reason=q_why,
            )
        )

        # C5C: Bounded raw-window skewness-adjusted Tukey fences (WS8-04 IQR handoff envelope) for network sectors
        if active_sec in ("Egress", "DNS", "Web", "Flows"):
          micro_cap = caps["mode_b_micro_days"]
          iqr_why = (
              f"The 30-day macro baseline on `{mad_metric}` is distorted by heavy-tailed skew; `{cls.STATS_HUNTER_SKILL}` "
              f"`IQR_TUKEY_SKEW_FENCES` (`iqr_tukey_skew_fences_3stage.yl2`) scores the raw UDM telemetry behind it inside a "
              f"bounded ≤{micro_cap}-day window (`$fence_z` against the template's tier-calibrated fence gate) instead of a "
              "30-day raw scan."
          )
          i_score, i_band, i_breakdown = _score("IQR_TUKEY_SKEW_FENCES", mad_metric, vector=active_sec, refuted=True)
          candidates.append(
              CandidateHypothesis(
                  hypothesis_title=f"Raw-Window Skewness-Adjusted Tukey Fences (`{mad_metric}`)",
                  selected_skill=cls.STATS_HUNTER_SKILL,
                  model_name="IQR_TUKEY_SKEW_FENCES",
                  directive_query="dynamic_archetype",
                  target_metric=mad_metric,
                  hypothesis_h0=f"Raw `{mad_metric}` activity stays inside the skewness-adjusted Tukey fences of its bounded window (`$fence_z` below the tier-calibrated fence gate).",
                  hypothesis_h1=f"Raw `{mad_metric}` activity breaches the skewness-adjusted Tukey upper fence (`$fence_z` at or above the tier-calibrated fence gate).",
                  evidentiary_defense=iqr_why,
                  confidence_score=i_score,
                  confidence_band=i_band,
                  confidence_breakdown=i_breakdown,
                  pivot_reason=iqr_why,
              )
          )

      # C6: Dormant / Sparse / Immature Baseline Sector -> Pivot to TWO_PART_HURDLE and FIRST_SEEN_NOVELTY
      if active_sec in dormant_awakening and t2a_model not in ("TWO_PART_HURDLE", "FIRST_SEEN_NOVELTY"):
        hurdle_metric = t2a_metric or sector_metrics.get(active_sec, "resource_creation_total")
        pivot_why = (
            f"360° Radar indicates `{active_sec}` (`{hurdle_metric}`) has a near-zero 30-day baseline (`SPARSE_BASELINE`). "
            "Pivoting to `TWO_PART_HURDLE` evaluates the Bernoulli probability of dormancy awakening alongside conditional (post-hurdle) intensity."
        )
        score, band, breakdown = _score("TWO_PART_HURDLE", hurdle_metric, vector=active_sec, refuted=True)
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"Dormancy Awakening Two-Part Hurdle (`{hurdle_metric}`)",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name="TWO_PART_HURDLE",
                directive_query="dynamic_metric",
                target_metric=hurdle_metric,
                hypothesis_h0=f"Sparse activity in `{hurdle_metric}` reflects normal periodic maintenance.",
                hypothesis_h1=f"Dormant baseline break on `{target_entity}` in `{hurdle_metric}` violates historical activation probability.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )
        fs_why = (
            f"Entities below the {th['min_baseline_days']}-active-day maturity gate cannot be scored with σ-statistics; "
            f"`FIRST_SEEN_NOVELTY` (`first_seen_novelty_2stage.yl2`) flags brand-new `{hurdle_metric}` activity from the 30-day "
            "`metrics.*` `first_seen` aggregate (boolean novelty flag, never a σ score)."
        )
        f_score, f_band, f_breakdown = _score("FIRST_SEEN_NOVELTY", hurdle_metric, vector=active_sec, refuted=True)
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"{cls.MODEL_LABELS['FIRST_SEEN_NOVELTY']} (`{hurdle_metric}`)",
                selected_skill=cls.RISK_METRICS_SKILL,
                model_name="FIRST_SEEN_NOVELTY",
                directive_query="dynamic_metric",
                target_metric=hurdle_metric,
                hypothesis_h0=f"`{hurdle_metric}` activity on `{target_entity}` was already present in the 30-day baseline (`first_seen` > 0).",
                hypothesis_h1=f"`{hurdle_metric}` activity on `{target_entity}` is brand new inside the 30-day window (novelty flag = 1).",
                evidentiary_defense=fs_why,
                confidence_score=f_score,
                confidence_band=f_band,
                confidence_breakdown=f_breakdown,
                pivot_reason=fs_why,
            )
        )

    # CASE D: Cross-Entity Kill-Chain Bridge when companion entities (USER <-> ASSET/IP) exist in Case Telemetry
    for comp in radar_insights.get("companion_entities", [])[:1]:
      comp_ent = comp["entity"]
      comp_type = comp["entity_type"]
      bridge_path = comp["bridge_path"]
      if comp_type in ("ASSET", "HOST", "IP"):
        bridge_model = "ZIPFIAN_PROCESS_RARITY"
        bridge_skill = cls.STATS_HUNTER_SKILL
        bridge_query = "zipfian_rarity"
        bridge_metric = "file_executions_total"
      else:
        bridge_model = "CLOUD_REPOSITORY_SCOPE"
        bridge_skill = cls.RISK_METRICS_SKILL
        bridge_query = "cloud_repo_scope"
        bridge_metric = "resource_read_total"
      pivot_why = (
          f"Case telemetry links primary {entity_type} `{target_entity}` to companion {comp_type} `{comp_ent}` (`{bridge_path}`). "
          f"Bridging the UEBA investigation across the entity boundary to `{comp_ent}` tests for multi-stage lateral/execution progression."
      )
      score, band, breakdown = _score(bridge_model, bridge_metric, vector=active_sec, refuted=not t2a_outlier,
                                      entity_override=comp_ent)
      candidates.append(
          CandidateHypothesis(
              hypothesis_title=f"Cross-Entity Kill-Chain Bridge (`{bridge_path}` -> `{comp_ent}`)",
              selected_skill=bridge_skill,
              model_name=bridge_model,
              directive_query=bridge_query,
              target_entity=comp_ent,
              entity_type=comp_type,
              target_metric=bridge_metric,
              hypothesis_h0=f"Companion {comp_type} `{comp_ent}` exhibits only routine baseline operations.",
              hypothesis_h1=f"Attack chain bridged from `{target_entity}` to companion {comp_type} `{comp_ent}` via `{bridge_path}`.",
              evidentiary_defense=pivot_why,
              confidence_score=score,
              confidence_band=band,
              confidence_breakdown=breakdown,
              pivot_reason=pivot_why,
          )
      )

    candidates = [c for c in candidates if cls._apply_harness_policy(c)]
    if not candidates:
      return None

    candidates.sort(key=lambda c: c.confidence_score, reverse=True)
    top = candidates[0]

    # Attach remaining candidates to tier2a_directive so they appear on the Case Wall even if < 0.80
    for c in candidates:
      if c.confidence_band != "SUPPRESSED":
        tier2a_directive.candidate_hypotheses.append(c)
        formatted = cls.format_hypothesis_for_avenue(c)
        if formatted not in tier2a_directive.recommended_avenues:
          tier2a_directive.recommended_avenues.insert(0, formatted)

    if top.confidence_score < cls.TIER_2B_PIVOT_AUTO_EXECUTE_THRESHOLD:
      return None

    remaining = [c for c in candidates[1:] if c.confidence_band != "SUPPRESSED"]
    piv_entity = top.target_entity or target_entity
    piv_entity_type = top.entity_type or entity_type
    return StrategyDirective(
        selected_skill=top.selected_skill,
        model_name=top.model_name,
        directive_query=top.directive_query,
        target_entity=piv_entity,
        entity_type=piv_entity_type,
        target_metric=top.target_metric,
        fusion_metrics=list(top.fusion_metrics),
        killchain_archetype=top.killchain_archetype,
        outcome_mode=top.outcome_mode,
        identifier_field=top.identifier_field,
        threat_summary=top.hypothesis_title,
        hypothesis_h0=top.hypothesis_h0,
        hypothesis_h1=top.hypothesis_h1,
        selection_rationale=cls._with_horizon(top.evidentiary_defense, top.model_name, top.selected_skill),
        evidentiary_defense=top.evidentiary_defense,
        confidence_score=top.confidence_score,
        confidence_band=top.confidence_band,
        confidence_breakdown=top.confidence_breakdown,
        pivot_reason=top.pivot_reason,
        flight_card_title=f"Tier 2B Autonomous Pivot — {top.hypothesis_title}: `{piv_entity}`",
        investigation_tier="TIER_2B_PIVOT",
        outlier_vector=tier2a_directive.outlier_vector,
        radar_insights=radar_insights,
        post_data_outcome_class=outcome_class,
        candidate_hypotheses=remaining,
        recommended_avenues=[cls.format_hypothesis_for_avenue(c) for c in remaining] or [
            f"Correlate `{piv_entity}` pivot findings with endpoint EDR and identity session logs.",
        ],
    )

  @classmethod
  def _build_context_summary(
      cls,
      case_info: Dict[str, Any],
      alerts: List[Dict[str, Any]],
      connector_events: List[Dict[str, Any]],
      default_entity: Optional[str] = None,
      default_entity_type: str = "USER",
      tier: str = "TIER_1_BASELINE",
      outlier_vector: Optional[str] = None,
      radar_result: Optional[Dict[str, Any]] = None,
      sensitivity: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Extracts structured UDM touchpoints from case, alerts, and connector events."""
    case_title = case_info.get("displayName") or case_info.get("title", "")
    case_desc = case_info.get("description", "")
    case_id = str(case_info.get("id") or case_info.get("name", "").split("/")[-1])

    alert_names = [a.get("displayName") or a.get("name", "") for a in alerts]
    rule_generators = [a.get("ruleGenerator", "") for a in alerts if a.get("ruleGenerator")]
    for a in alerts:
      if a.get("description") and a.get("description") not in case_desc:
        case_desc = f"{case_desc} {a.get('description')}".strip()

    udm_event_types = set()
    udm_log_types = set()
    target_apps = set()
    threat_associations = set()
    extracted_users = set()
    extracted_hosts = set()
    extracted_ips = set()
    outcome_metrics = {}

    for ev in connector_events:
      raw_str = ev.get("eventJsonData", {}).get("rawEvent") or "{}"
      try:
        raw_obj = json.loads(raw_str) if isinstance(raw_str, str) else raw_str
      except Exception:
        raw_obj = {}

      fields = raw_obj.get("_rawDataFields", {}) if isinstance(raw_obj, dict) else {}
      if fields.get("event_metadata_eventType"):
        udm_event_types.add(fields.get("event_metadata_eventType"))
      if fields.get("event_metadata_logType"):
        udm_log_types.add(fields.get("event_metadata_logType"))
      if fields.get("event_target_application"):
        target_apps.add(fields.get("event_target_application"))

      for k, v in fields.items():
        if "threat" in k and "name" in k and v:
          threat_associations.add(str(v))
        if "detection_outcomes" in k and v:
          short_k = k.replace("detection_outcomes_", "")
          outcome_metrics[short_k] = str(v)

      u = fields.get("event_target_user_emailAddresses_1") or fields.get("event_principal_user_userid")
      if u:
        extracted_users.add(str(u).lower())

      h = fields.get("event_principal_hostname") or fields.get("event_principal_asset_hostname")
      if h:
        extracted_hosts.add(str(h).lower())

      ip = fields.get("event_principal_asset_ip_1") or fields.get("event_principal_ip_1")
      if ip:
        extracted_ips.add(str(ip))

    for a in alerts:
      for ent in a.get("entities", []) or []:
        if isinstance(ent, dict):
          etype = str(ent.get("type") or ent.get("entityType") or "").upper()
          val = str(ent.get("value") or ent.get("identifier") or ent.get("name") or "").strip()
          if not val:
            continue
          if etype in ("USER", "USER_ID", "EMAIL"):
            extracted_users.add(val.lower())
          elif etype in ("ASSET", "HOST", "HOSTNAME", "MACHINE"):
            extracted_hosts.add(val.lower())
          elif etype in ("IP", "IP_ADDRESS"):
            extracted_ips.add(val)

    target_entity = default_entity
    entity_type = default_entity_type
    if not target_entity:
      if extracted_users:
        target_entity = next(iter(extracted_users))
        entity_type = "USER"
      elif extracted_hosts:
        target_entity = next(iter(extracted_hosts))
        entity_type = "ASSET"
      elif extracted_ips:
        target_entity = next(iter(extracted_ips))
        entity_type = "IP"
      else:
        target_entity = "unknown_entity"
        entity_type = "USER"

    base_ctx = {
        "case_id": case_id,
        "case_title": case_title,
        "case_description": case_desc,
        "alerts": alert_names,
        "rule_generators": rule_generators,
        "udm_event_types": list(udm_event_types),
        "udm_log_types": list(udm_log_types),
        "target_applications": list(target_apps),
        "threat_associations": list(threat_associations),
        "outcome_metrics": outcome_metrics,
        "extracted_users": sorted(extracted_users),
        "extracted_hosts": sorted(extracted_hosts),
        "extracted_ips": sorted(extracted_ips),
        "primary_entity": target_entity,
        "entity_type": entity_type,
        "investigation_tier": tier,
        "outlier_vector": outlier_vector,
        "radar_result": radar_result,
        "sensitivity_tier": cls.thresholds(sensitivity)["tier"],
    }
    if radar_result:
      base_ctx["radar_insights"] = cls.analyze_360_insights(
          radar_result=radar_result,
          ctx=base_ctx,
          entity_type=entity_type,
      )
    return base_ctx

  @classmethod
  async def decide_agentic(
      cls,
      case_info: Dict[str, Any],
      alerts: List[Dict[str, Any]],
      connector_events: List[Dict[str, Any]],
      default_entity: Optional[str] = None,
      default_entity_type: str = "USER",
      tier: str = "TIER_1_BASELINE",
      outlier_vector: Optional[str] = None,
      radar_result: Optional[Dict[str, Any]] = None,
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
      sensitivity: Optional[str] = None,
  ) -> StrategyDirective:
    """Agentically analyzes case, alert, 360° radar, and UDM telemetry to formulate a defended hunting directive."""
    context_summary = cls._build_context_summary(
        case_info=case_info,
        alerts=alerts,
        connector_events=connector_events,
        default_entity=default_entity,
        default_entity_type=default_entity_type,
        tier=tier,
        outlier_vector=outlier_vector,
        radar_result=radar_result,
        sensitivity=sensitivity,
    )

    if tier == "TIER_1_BASELINE" and not outlier_vector:
      return cls.decide_tier1_360(
          target_entity=context_summary["primary_entity"],
          entity_type=context_summary["entity_type"],
          case_id=context_summary["case_id"],
          case_title=context_summary["case_title"],
          case_desc=context_summary["case_description"],
          alerts=alerts,
          sensitivity=context_summary["sensitivity_tier"],
      )

    # 1. Attempt LLM Reasoning via Gemini 2.5 grounded in the remediated harness (routing table, caps, tiers)
    llm_directive = await cls._reason_with_gemini(
        context_summary,
        executed_signatures=executed_signatures,
        empty_families=empty_families,
    )
    if llm_directive:
      return llm_directive

    # 2. Deterministic Fallback Reasoner (UDM-aware, catalog-aware, canonical routing, confidence-calibrated)
    return cls._deterministic_reasoner(
        context_summary,
        executed_signatures=executed_signatures,
        empty_families=empty_families,
    )

  @classmethod
  def _build_reasoning_prompt(
      cls,
      ctx: Dict[str, Any],
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
  ) -> str:
    """Gemini prompt grounded in the skills: canonical routing table, harness caps, tier gates and current models."""
    th = cls.thresholds(ctx.get("sensitivity_tier"))
    caps = harness_truth.mode_caps()
    loop_hits, loop_sum_z_sq = harness_truth.loopback_thresholds()
    gate, robust = _num(th["anomaly_threshold"]), _num(th["robust_threshold"])
    fusion_sq, tukey, composite = _num(th["fusion_threshold_sq"]), _num(th["tukey_excess_threshold"]), _num(th["radar_composite_d"])
    risk, stats = cls.RISK_METRICS_SKILL, cls.STATS_HUNTER_SKILL
    retired = ", ".join(sorted(harness_truth.retired_models()))
    g = cls._gate_text
    return f"""You are a Lead SecOps Detection Engineer and UEBA Threat Hunter.
Analyze the following security incident context, alerts, Tier 1 360° radar results, and UDM connector event touchpoints:

{json.dumps(ctx, indent=2, default=str)}

Already Executed Signatures (DO NOT REPEAT): {list(executed_signatures or [])}
Empty Telemetry Families (DO NOT SELECT): {list(empty_families or [])}

### POSITIVE SITUATIONAL METRIC SELECTION (38-Metric Malachite Catalog)
Choose the metric(s) that match the actual situation in the case and Tier 1 360° radar — do NOT default to auth or network if the signal is in Workspace, Web/HTTP, DNS, Cloud CRUD, Endpoint Process Execution, or Security/EDR Alerts:
- **Workspace / SaaS (`principal.user.userid`)**: `workspace_total_download_actions`, `workspace_total_change_actions`, `workspace_emails_sent_total`, `workspace_network_bytes_outbound`, `workspace_auth_attempts_total`
- **Web & HTTP Proxy (`principal.user.userid` or `principal.asset.hostname`)**: `http_queries_total`, `http_queries_fail`, `http_queries_success`
- **DNS Resolution (`principal.user.userid` or `principal.asset.hostname`)**: `dns_queries_fail`, `dns_queries_total`, `dns_queries_success`, `dns_bytes_outbound`
- **Network Bytes & Flows (`principal.user.userid` or `principal.asset.hostname`)**: `network_bytes_outbound`, `network_bytes_inbound`, `network_bytes_total`, `network_flows_outbound`, `network_flows_inbound`, `network_flows_total`
- **Authentication (`target.user.userid` or `principal.asset.hostname`)**: `auth_attempts_fail`, `auth_attempts_success`, `auth_attempts_total`
- **Cloud Resource CRUD (Composite roll-up, `principal.user.userid`)**: `resource_creation_total`, `resource_deletion_total`, `resource_written_total`, `resource_read_total`
- **Endpoint Process Executions (Composite roll-up, `principal.asset.hostname`)**: `file_executions_total`, `file_executions_fail`
- **Security / EDR Alerts (Composite roll-up, `principal.asset.hostname`)**: `alert_event_name_count`

### CANONICAL CROSS-SKILL ROUTING TABLE (verbatim from both skills' SKILL.md)
{cls.canonical_routing_table()}

### HARNESS RULES
- Precedence 1 micro signals stay in `{stats}` even when the case mentions UEBA; 30-day `metrics.*` baselines, peer cohorts, 360° health / risk score and CUSUM drift belong to `{risk}`.
- Scheduled Exfiltration (nightly / multi-day cadence): offer both answers. Answer 1 = `LONGITUDINAL_CUSUM` in `{risk}` (Windowed Slack Sum prefilter + `longitudinal_cusum_series_3stage.yl2` + `cusum_helper.py`, one query of at most {caps['mode_b_cusum_macro_days']} days, never single-day Mode A; longer horizons as Mode C shards; without local scripts only the stateless `longitudinal_cusum_2stage.yl2` prefilter, disclosed as `WINDOWED_SLACK_SUM`). Answer 2 = a zero-code Skill Handoff Card to `{stats}` (`C2_BEACONING_JITTER`, no query text) for sub-day cron or jitter cadence. Sub-day cron timing alone is Precedence 1 (`C2_BEACONING_JITTER`).
- Telemetry physics: `{risk}` owns every 30-day `metrics.*` baseline; `{stats}` runs bounded raw windows only (Mode A rolling 24h, Mode B at most {caps['mode_b_micro_days']} days). Never plan a 30-day raw UDM scan over high-volume telemetry.
- Time modes: Mode A = last complete UTC day vs the 30-day baseline (Entity Graph joins start at D-2 with event stages pinned to the scored day); Mode B at most {caps['mode_b_macro_days']} days; Mode C at most {caps['mode_c_macro_days']} per-day shards; `LONGITUDINAL_CUSUM` never runs in single-day Mode A.
- Significance ({th['tier']} tier): Z ≥ {gate}σ; robust modified Z ≥ {robust}; fusion D² ≥ {fusion_sq}; Tukey scale-excess ≥ {tukey}; 360° composite D ≥ {composite}σ; baselines need ≥ {th['min_baseline_days']} active days (route immature or dormant baselines to `FIRST_SEEN_NOVELTY` / `TWO_PART_HURDLE`). CRI is computed in Python from the model score.
- Bilateral exploit / CTI UEBA: pair 30-day macro fusion with bounded micro structure models and `PLAYBOOK_BEHAVIORAL_HUNT_MATCH` loopback (≥ {loop_hits} distinct hits and ΣZ² ≥ {_num(loop_sum_z_sq)}).
RETIRED MODELS (never select; redirected automatically): {retired}

### Available Analytical Engines & Models (directive_query in parentheses):
1. **Engine: `{risk}` (30-Day `metrics.*` Baselines, Single-Metric & Cross-Vector Fusion DAGs)**
   - `DUAL_SECTOR_FUSION_3STAGE` / `MULTI_SECTOR_FUSION_4STAGE` (`sector_fusion`): 2+ elevated sectors or a case bridging two vectors; populate `fusion_metrics` (rectified D² ≥ {fusion_sq}).
   - `LONGITUDINAL_CUSUM` (`dynamic_metric`): {cls.MODEL_LABELS['LONGITUDINAL_CUSUM']} + Page CUSUM series for creeping multi-day accumulation; `WINDOWED_SLACK_SUM` (`dynamic_metric`) is the stateless fleet-wide prefilter.
   - `ABOVE_HISTORICAL_MAX_Z` (`macd_momentum`): {cls.MODEL_LABELS['ABOVE_HISTORICAL_MAX_Z']} — daily volume breaking the 30-day historical maximum (≥ {gate}σ).
   - `FIRST_SEEN_NOVELTY` (`dynamic_metric`): {cls.MODEL_LABELS['FIRST_SEEN_NOVELTY']} from `metrics.*` `first_seen` (never a σ score).
   - `MAD` (`dynamic_metric`, `mad_robust_z_4stage.yl2`) and `QUANTILE_IQR_SKEW` (`quantile_iqr_skew`, `quantile_iqr_skew_3stage.yl2`): variance-masked or heavy-tailed 30-day metric baselines.
   - `TWO_PART_HURDLE` (`dynamic_metric`): dormant or sparse baselines.
   - `PART_OF_THE_WHOLE_MULTILEVEL` / `DUAL_BASELINE_3STAGE` (`dynamic_metric`) and `PART_OF_THE_WHOLE_TRIAD_MULTILEVEL` (`workspace_triad`): peer cohorts (Samuelson cohort-size cap).
   - `ADAPTIVE_CONTEXT_THRESHOLD` (`dynamic_metric`): {cls.MODEL_LABELS['ADAPTIVE_CONTEXT_THRESHOLD']} on daily metrics.
   - `CLOUD_CRUD_SURGE` (`cloud_crud`), `CLOUD_REPOSITORY_SCOPE` (`cloud_repo_scope`), `FAILURE_RATIO_SURGE` (`failure_ratio_surge`).
   - `HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE` / `HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE` (strictly `http_queries_total`), `RARE_DESTINATION_ECG_3STAGE` / `FUSION_RARE_DESTINATION_3STAGE` (DNS volume or outbound bytes), `HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE` / `HYBRID_METRIC_FLEET_PREVALENCE_2STAGE` (`file_executions_total`) — all `dynamic_metric`, Entity Graph prevalence `rolling_max <= 3`, `day_count = 10`.
   - `360_DECOUPLED_RADAR` (`profile_360_risk`): 6-sector health check over the decoupled canonical sector queries.

2. **Engine: `{stats}` (Bounded-Window Raw UDM Micro-Math)**
   - `C2_BEACONING_JITTER` (`c2_jitter`; {g('C2_BEACONING_JITTER')}; screen `FLOW_GAP_RATIO_SCREEN`): periodic callbacks and sub-day cron cadence.
   - `POISSON_BURST_CLUSTERING` (`poisson_burst`; {g('POISSON_BURST_CLUSTERING')}): credential spray bursts.
   - `HYBRID_ENTROPY_CONCENTRATION` (`elephant_flow`; {g('HYBRID_ENTROPY_CONCENTRATION')}): destination diversity collapse and elephant flows.
   - `PRIVILEGED_LATERAL_EXPANSION` (`lateral_expansion`; {g('PRIVILEGED_LATERAL_EXPANSION')}): login breadth to previously unseen hosts.
   - `MARKOV_2GRAM_TRANSITION_RARITY` (`markov_transition`; {g('MARKOV_2GRAM_TRANSITION_RARITY')}): rare parent-child process lineage (web-to-shell, LotL).
   - `SHANNON_ENTROPY_CHARACTER` (`shannon_entropy`; {g('SHANNON_ENTROPY_CHARACTER')}; screen `LONG_STRING_SCREEN`): encoded command lines and DGA domains.
   - `ZIPFIAN_PROCESS_RARITY` (`zipfian_rarity`; {g('ZIPFIAN_PROCESS_RARITY')}): long-tail binaries.
   - `EWMA_BURST_VELOCITY` (`ewma_burst`; {g('EWMA_BURST_VELOCITY')}; screen `BURST_Z_SCREEN`): intraday rate bursts.
   - `HOUR_OF_DAY_PROFILE` (`hour_of_day_profile`; {g('HOUR_OF_DAY_PROFILE')}): off-hours or out-of-profile activity by hour of day.
   - `PRODUCER_CONSUMER_RATIO_INVERSION` (`producer_consumer_inversion`; {g('PRODUCER_CONSUMER_RATIO_INVERSION')}): workstation turned net data producer.
   - `IQR_TUKEY_SKEW_FENCES` / `DATA_EXFILTRATION_SPIKE` (`dynamic_archetype`): raw-field or bounded-window Tukey fences / MAD.
   - `DERIVED_CONTEXT_PREVALENCE` (`dynamic_archetype`; {g('DERIVED_CONTEXT_PREVALENCE')}): anomalous logins to brand-new assets.

Provide:
1. The primary hypothesis to execute (`hypothesis_h0`, `hypothesis_h1`, `evidentiary_defense` citing specific Tier 1 Z-scores and UDM touchpoints, and `confidence_score` between 0.0 and 1.0).
2. 2 to 3 additional `candidate_hypotheses` with full H0, H1, `evidentiary_defense`, `target_metric` / `fusion_metrics`, and `confidence_score`.

Output valid JSON matching this schema:
{{
  "selected_skill": "{risk}" | "{stats}",
  "model_name": "<EXACT_MODEL_NAME>",
  "directive_query": "<directive_query_key>",
  "target_entity": "{ctx['primary_entity']}",
  "entity_type": "{ctx['entity_type']}",
  "target_metric": "<metric_name_from_38_catalog_or_null>",
  "fusion_metrics": ["<metric_a>", "<metric_b>"],
  "investigation_tier": "{ctx.get('investigation_tier', 'TIER_2_DEEP_DIVE')}",
  "outlier_vector": "{ctx.get('outlier_vector') or ''}",
  "threat_summary": "<concise summary of identified threat problem and UDM touchpoints>",
  "hypothesis_h0": "<the benign baseline explanation being tested>",
  "hypothesis_h1": "<the attacker threat pivot hypothesis being tested>",
  "selection_rationale": "<why this mathematical model and metric were chosen>",
  "evidentiary_defense": "<detailed defense citing Tier 1 Z-scores, UDM event types, and alert context>",
  "confidence_score": 0.85,
  "flight_card_title": "<professional title for SOC Case Wall card>",
  "candidate_hypotheses": [
    {{
      "hypothesis_title": "<short title>",
      "selected_skill": "{risk}" | "{stats}",
      "model_name": "<MODEL_NAME>",
      "directive_query": "<directive_query_key>",
      "target_metric": "<metric_name_or_null>",
      "fusion_metrics": [],
      "hypothesis_h0": "<null hypothesis>",
      "hypothesis_h1": "<alternative threat hypothesis>",
      "evidentiary_defense": "<why this follow-up hunt is warranted by the evidence>",
      "confidence_score": 0.68
    }}
  ]
}}
"""

  @classmethod
  async def _reason_with_gemini(
      cls,
      ctx: Dict[str, Any],
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
  ) -> Optional[StrategyDirective]:
    """Uses Gemini to reason about UDM touchpoints, select situational metrics/fusions, and defend hypotheses.

    Every proposed model is resolved against the remediated harness: renamed models take their current names,
    retired models are redirected to the replacement the skill names, and a retired model without a replacement
    hands the decision back to the deterministic reasoner.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
      return None

    try:
      client = genai.Client()
      prompt = cls._build_reasoning_prompt(ctx, executed_signatures, empty_families)
      resp = client.models.generate_content(
          model="gemini-2.5-flash",
          contents=prompt,
          config=types.GenerateContentConfig(
              response_mime_type="application/json",
              temperature=0.1,
          ),
      )
      if resp and resp.text:
        data = json.loads(resp.text)
        raw_cands = data.pop("candidate_hypotheses", []) or []
        llm_conf = data.get("confidence_score", 0.80)
        try:
          model, skill, query, redirected_from = cls._harness_fields(
              data.get("model_name", ""), data.get("selected_skill"), data.get("directive_query")
          )
        except ValueError as retired_err:
          logger.info(f"Gemini proposed a retired model without a harness replacement; using the deterministic reasoner: {retired_err}")
          return None
        data["model_name"] = model
        data["directive_query"] = query
        if skill:
          data["selected_skill"] = skill
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name=model,
            target_metric=data.get("target_metric"),
            fusion_metrics=data.get("fusion_metrics"),
            outlier_vector=data.get("outlier_vector") or ctx.get("outlier_vector"),
            ctx=ctx,
            radar_result=ctx.get("radar_result"),
            executed_signatures=executed_signatures,
            empty_families=empty_families,
            llm_proposed_confidence=llm_conf,
        )
        data["confidence_score"] = score
        data["confidence_band"] = band
        data["confidence_breakdown"] = breakdown
        if not data.get("evidentiary_defense"):
          data["evidentiary_defense"] = data.get("selection_rationale", "")

        scored_cands: List[CandidateHypothesis] = []
        for rc in raw_cands:
          if not isinstance(rc, dict):
            continue
          try:
            c_model, c_skill, c_query, _ = cls._harness_fields(
                rc.get("model_name", ""), rc.get("selected_skill"), rc.get("directive_query")
            )
          except ValueError:
            continue
          rc["model_name"] = c_model
          rc["directive_query"] = c_query
          if c_skill:
            rc["selected_skill"] = c_skill
          c_score, c_band, c_break = cls.score_hypothesis_confidence(
              model_name=c_model,
              target_metric=rc.get("target_metric"),
              fusion_metrics=rc.get("fusion_metrics"),
              outlier_vector=ctx.get("outlier_vector"),
              ctx=ctx,
              radar_result=ctx.get("radar_result"),
              executed_signatures=executed_signatures,
              empty_families=empty_families,
              llm_proposed_confidence=rc.get("confidence_score"),
          )
          rc["confidence_score"] = c_score
          rc["confidence_band"] = c_band
          rc["confidence_breakdown"] = c_break
          try:
            cand_obj = CandidateHypothesis(**rc)
          except Exception as cand_err:
            logger.debug(f"Skipping malformed Gemini candidate hypothesis: {cand_err}")
            continue
          if cand_obj.confidence_band != "SUPPRESSED":
            scored_cands.append(cand_obj)

        scored_cands.sort(key=lambda x: x.confidence_score, reverse=True)
        data["candidate_hypotheses"] = scored_cands
        if scored_cands and not data.get("recommended_avenues"):
          data["recommended_avenues"] = [cls.format_hypothesis_for_avenue(c) for c in scored_cands]
        directive = StrategyDirective(**data)
        if redirected_from:
          directive.selection_rationale = (
              f"{directive.selection_rationale} Harness redirect: the requested model is retired in the remediated "
              f"harness; `{directive.model_name}` (`{directive.selected_skill}`) is the replacement the skill names."
          ).strip()
        directive.selection_rationale = cls._with_horizon(
            directive.selection_rationale, directive.model_name, directive.selected_skill
        )
        return directive
    except Exception as e:
      logger.debug(f"Gemini strategy reasoning bypassed: {e}")
      return None

  @classmethod
  def _finalize_directive_with_confidence(
      cls,
      directive: StrategyDirective,
      ctx: Dict[str, Any],
      secondary_candidates: List[CandidateHypothesis],
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
  ) -> StrategyDirective:
    """Applies harness resolution and evidence-anchored confidence scoring to a primary directive and its follow-up hypotheses."""
    if not cls._apply_harness_policy(directive):
      raise ValueError(f"Model '{directive.model_name}' is retired in the remediated harness and has no replacement.")
    radar_result = ctx.get("radar_result")
    th = cls.thresholds(ctx.get("sensitivity_tier"))
    score, band, breakdown = cls.score_hypothesis_confidence(
        model_name=directive.model_name,
        target_metric=directive.target_metric,
        fusion_metrics=directive.fusion_metrics,
        outlier_vector=directive.outlier_vector,
        ctx=ctx,
        radar_result=radar_result,
        executed_signatures=executed_signatures,
        empty_families=empty_families,
    )
    directive.confidence_score = score
    directive.confidence_band = band
    directive.confidence_breakdown = breakdown
    if not directive.evidentiary_defense:
      directive.evidentiary_defense = directive.selection_rationale
    directive.selection_rationale = cls._with_horizon(directive.selection_rationale, directive.model_name, directive.selected_skill)

    valid_cands: List[CandidateHypothesis] = []
    for cand in secondary_candidates:
      if not cls._apply_harness_policy(cand):
        continue
      c_score, c_band, c_break = cls.score_hypothesis_confidence(
          model_name=cand.model_name,
          target_metric=cand.target_metric,
          fusion_metrics=cand.fusion_metrics,
          outlier_vector=cand.outlier_vector if hasattr(cand, "outlier_vector") else directive.outlier_vector,
          ctx=ctx,
          radar_result=radar_result,
          executed_signatures=executed_signatures,
          empty_families=empty_families,
          llm_proposed_confidence=cand.confidence_score,
      )
      cand.confidence_score = c_score
      cand.confidence_band = c_band
      cand.confidence_breakdown = c_break
      if cand.confidence_band != "SUPPRESSED":
        valid_cands.append(cand)

    if len(valid_cands) < 2:
      existing_models = {directive.model_name} | {c.model_name for c in valid_cands}
      base_metric = directive.target_metric or "network_bytes_outbound"
      companion_metric = "auth_attempts_fail" if base_metric != "auth_attempts_fail" else "network_bytes_outbound"
      hod_gate = cls._gate_text("HOUR_OF_DAY_PROFILE")
      fallback_pool = [
          CandidateHypothesis(
              hypothesis_title=f"Cross-Vector Sector Fusion (`{base_metric}` + `{companion_metric}`)",
              selected_skill=cls.RISK_METRICS_SKILL,
              model_name="DUAL_SECTOR_FUSION_3STAGE",
              directive_query="sector_fusion",
              target_metric=base_metric,
              fusion_metrics=[base_metric, companion_metric],
              hypothesis_h0=f"Observed `{base_metric}` deviation is an isolated single-sector fluctuation.",
              hypothesis_h1=f"Anomalous `{base_metric}` activity is correlated with `{companion_metric}` in a multi-stage kill chain.",
              evidentiary_defense=(
                  f"Evaluates the rectified Euclidean threat distance D = √(Σ max(0, Z_i)²) across `{base_metric}` and "
                  f"`{companion_metric}` for `{directive.target_entity}` (gate D² ≥ {_num(th['fusion_threshold_sq'])})."
              ),
              confidence_score=0.72,
          ),
          CandidateHypothesis(
              hypothesis_title=f"Out-of-Profile Hours ({cls.MODEL_LABELS['HOUR_OF_DAY_PROFILE']})",
              selected_skill=cls.STATS_HUNTER_SKILL,
              model_name="HOUR_OF_DAY_PROFILE",
              directive_query="hour_of_day_profile",
              target_metric="auth_attempts_total",
              hypothesis_h0="Entity activity aligns with its learned 24-bin hour-of-day profile.",
              hypothesis_h1=f"Activity occurred at out-of-profile hours indicative of session abuse ({hod_gate}).",
              evidentiary_defense=(
                  f"Scores each hour of `{directive.target_entity}` out-of-sample against its learned 24-bin hour-of-day "
                  "profile over a bounded raw-event window."
              ),
              confidence_score=0.68,
          ),
          CandidateHypothesis(
              hypothesis_title="Derived Context Domain Prevalence (`HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE`)",
              selected_skill=cls.RISK_METRICS_SKILL,
              model_name="HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE",
              directive_query="dynamic_metric",
              target_metric="http_queries_total",
              hypothesis_h0="Outbound destinations are widely prevalent across the enterprise fleet.",
              hypothesis_h1="Entity is communicating with rare or first-seen domains (`rolling_max <= 3`, `day_count = 10` in `DERIVED_CONTEXT`).",
              evidentiary_defense=f"Enriches `{directive.target_entity}` network activity with Entity Graph `DERIVED_CONTEXT` prevalence.",
              confidence_score=0.65,
          ),
      ]
      for fb in fallback_pool:
        if len(valid_cands) >= 2:
          break
        if fb.model_name in existing_models:
          continue
        fb_score, fb_band, fb_break = cls.score_hypothesis_confidence(
            model_name=fb.model_name,
            target_metric=fb.target_metric,
            fusion_metrics=fb.fusion_metrics,
            outlier_vector=directive.outlier_vector,
            ctx=ctx,
            radar_result=radar_result,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
            llm_proposed_confidence=fb.confidence_score,
        )
        fb.confidence_score = fb_score
        fb.confidence_band = fb_band
        fb.confidence_breakdown = fb_break
        valid_cands.append(fb)
        existing_models.add(fb.model_name)

    valid_cands.sort(key=lambda x: x.confidence_score, reverse=True)
    directive.candidate_hypotheses = valid_cands
    if valid_cands:
      directive.recommended_avenues = [cls.format_hypothesis_for_avenue(c) for c in valid_cands]
    if radar_result and not directive.radar_insights:
      directive.radar_insights = ctx.get("radar_insights") or cls.analyze_360_insights(
          radar_result=radar_result,
          ctx=ctx,
          entity_type=directive.entity_type,
      )
    if directive.target_metric and not directive.killchain_progression:
      try:
        from src.pipeline_runner import PipelineRunner
        fmt_cls = PipelineRunner().get_triage_formatter()
        if fmt_cls:
          directive.killchain_progression = fmt_cls.get_mitre_progression(directive.target_metric)
      except Exception:
        pass
    return directive

  # ---------------------------------------------------------------------------
  # Deterministic reasoner
  # ---------------------------------------------------------------------------

  @classmethod
  def _new_directive(
      cls,
      ctx: Dict[str, Any],
      model: str,
      skill: str,
      query: str,
      *,
      summary: str,
      h0: str,
      h1: str,
      defense: str,
      title: str,
      metric: Optional[str] = None,
      fusion: Optional[List[str]] = None,
      outlier_vector: Optional[str] = None,
      killchain: Optional[str] = None,
      outcome_mode: Optional[str] = None,
  ) -> StrategyDirective:
    """StrategyDirective bound to the context's entity and investigation tier."""
    return StrategyDirective(
        selected_skill=skill,
        model_name=model,
        directive_query=query,
        target_entity=ctx.get("primary_entity", "unknown"),
        entity_type=ctx.get("entity_type", "USER"),
        target_metric=metric,
        fusion_metrics=list(fusion or []),
        killchain_archetype=killchain,
        outcome_mode=outcome_mode,
        investigation_tier=ctx.get("investigation_tier", "TIER_2_DEEP_DIVE" if ctx.get("outlier_vector") else "TIER_1_BASELINE"),
        outlier_vector=outlier_vector,
        threat_summary=summary,
        hypothesis_h0=h0,
        hypothesis_h1=h1,
        selection_rationale=defense,
        evidentiary_defense=defense,
        flight_card_title=title,
    )

  @staticmethod
  def _cand(
      title: str,
      skill: str,
      model: str,
      query: str,
      *,
      h0: str,
      h1: str,
      defense: str,
      confidence: float,
      metric: Optional[str] = None,
      fusion: Optional[List[str]] = None,
      killchain: Optional[str] = None,
      outcome_mode: Optional[str] = None,
  ) -> CandidateHypothesis:
    return CandidateHypothesis(
        hypothesis_title=title,
        selected_skill=skill,
        model_name=model,
        directive_query=query,
        target_metric=metric,
        fusion_metrics=list(fusion or []),
        killchain_archetype=killchain,
        outcome_mode=outcome_mode,
        hypothesis_h0=h0,
        hypothesis_h1=h1,
        evidentiary_defense=defense,
        confidence_score=confidence,
    )

  @classmethod
  def _scheduled_exfiltration_directive(
      cls,
      ctx: Dict[str, Any],
      text_corpus: str,
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
  ) -> StrategyDirective:
    """Scheduled Exfiltration two-answer rule: Answer 1 Longitudinal CUSUM + Answer 2 zero-code Skill Handoff Card."""
    target_entity = ctx.get("primary_entity", "unknown")
    entity_type = ctx.get("entity_type", "USER")
    th = cls.thresholds(ctx.get("sensitivity_tier"))
    gate = _num(th["anomaly_threshold"])
    caps = harness_truth.mode_caps()
    metric = cls._infer_metric(text_corpus, entity_type, default="network_bytes_outbound")
    jitter_gate = cls._gate_text("C2_BEACONING_JITTER")
    defense = (
        f"Scheduled Exfiltration (nightly / multi-day cadence) on `{target_entity}`: the canonical two-answer rule applies. "
        f"Answer 1 — Longitudinal CUSUM Drift in `{cls.RISK_METRICS_SKILL}` on `{metric}`: Windowed Slack Sum prefilter "
        "(`templates/pipelines/longitudinal_cusum_2stage.yl2`) plus the Page CUSUM series "
        "(`templates/pipelines/longitudinal_cusum_series_3stage.yl2` + `scripts/cusum_helper.py`) in one query of at most "
        f"{caps['mode_b_cusum_macro_days']} days (single-day Mode A blocked; longer horizons run as Mode C shards up to "
        f"{caps['mode_c_macro_days']} days against Shard 1's fixed baseline; a client that cannot run local scripts gets "
        "the stateless prefilter alone, disclosed as `WINDOWED_SLACK_SUM`). "
        f"Answer 2 — a zero-code Skill Handoff Card to `{cls.STATS_HUNTER_SKILL}` (no query text) for sub-day cron or "
        f"jitter cadence (`C2_BEACONING_JITTER`, {jitter_gate})."
    )
    directive = cls._new_directive(
        ctx,
        "LONGITUDINAL_CUSUM",
        cls.RISK_METRICS_SKILL,
        "dynamic_metric",
        metric=metric,
        outlier_vector=ctx.get("outlier_vector"),
        summary=f"Scheduled exfiltration (nightly / multi-day cadence) suspected from `{target_entity}` (`{metric}`).",
        h0=f"Daily `{metric}` stays inside its 30-day baseline with no sustained positive drift (Windowed Slack Sum below the {gate}σ gate).",
        h1=(
            f"Recurring scheduled transfers accumulate sustained positive drift in `{metric}` (Windowed Slack Sum ≥ {gate}σ "
            "over at least two drift days; Page CUSUM alarm)."
        ),
        defense=defense,
        title=f"Scheduled Exfiltration — Answer 1: {cls.MODEL_LABELS['LONGITUDINAL_CUSUM']} (`{metric}`): `{target_entity}`",
    )
    directive = cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)
    handoff = cls._cand(
        f"Answer 2 — Zero-Code Skill Handoff Card → `{cls.STATS_HUNTER_SKILL}` (sub-day cron / jitter cadence)",
        cls.STATS_HUNTER_SKILL,
        "C2_BEACONING_JITTER",
        "c2_jitter",
        metric="network_bytes_outbound",
        h0="Transfers follow irregular, human-driven timing.",
        h1=f"Transfers run on a robotic sub-day cron cadence ({jitter_gate}).",
        defense=(
            f"Zero-code handoff: the card carries no query text; `{cls.STATS_HUNTER_SKILL}` owns the `C2_BEACONING_JITTER` "
            "template (screen `FLOW_GAP_RATIO_SCREEN`) and its gate, because daily `metrics.*` rollups cannot measure "
            "inter-arrival timing."
        ),
        confidence=cls.ANALYST_REVIEW_MIN_THRESHOLD,
    )
    h_score, _, h_break = cls.score_hypothesis_confidence(
        model_name=handoff.model_name,
        target_metric=handoff.target_metric,
        ctx=ctx,
        radar_result=ctx.get("radar_result"),
        executed_signatures=executed_signatures,
        empty_families=empty_families,
    )
    handoff.confidence_score = max(h_score, cls.ANALYST_REVIEW_MIN_THRESHOLD)
    handoff.confidence_band = "ANALYST_REVIEW"
    handoff.confidence_breakdown = f"{h_break} | Mandatory two-answer offer (zero-code handoff; never auto-executed)"
    directive.candidate_hypotheses = [handoff] + [
        c for c in directive.candidate_hypotheses if c.model_name != "C2_BEACONING_JITTER"
    ]
    directive.recommended_avenues = [cls.format_hypothesis_for_avenue(c) for c in directive.candidate_hypotheses]
    return directive

  @classmethod
  def _deterministic_reasoner(
      cls,
      ctx: Dict[str, Any],
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
  ) -> StrategyDirective:
    """Robust, regex-safe, UDM-aware and 38-metric-aware heuristic reasoner with hypothesis defense.

    Radar outlier vectors are dispatched first; otherwise the case / alert intent is classified by `route_intent`
    (canonical cross-skill routing table). Every directive is finalized through `_finalize_directive_with_confidence`
    (harness model resolution, confidence scoring and evaluation horizon).
    """
    text_corpus = (
        f"{ctx.get('case_title', '')} "
        f"{ctx.get('case_description', '')} "
        f"{' '.join(ctx.get('alerts', []))} "
        f"{' '.join(ctx.get('rule_generators', []))} "
        f"{' '.join(ctx.get('threat_associations', []))}"
    ).lower()

    udm_events = ctx.get("udm_event_types", [])
    target_entity = ctx.get("primary_entity", "unknown")
    entity_type = ctx.get("entity_type", "USER")
    threats = ctx.get("threat_associations", [])
    outcomes = ctx.get("outcome_metrics", {})

    outlier_vector = ctx.get("outlier_vector")
    radar_result = ctx.get("radar_result") or {}
    radar_insights = ctx.get("radar_insights") or (
        cls.analyze_360_insights(radar_result, ctx, entity_type) if radar_result else {}
    )
    outlier_sectors = radar_result.get("outlier_sectors", [])
    variance_masked_sectors = radar_result.get("variance_masked_sectors", []) or radar_insights.get("variance_masked_sectors", [])
    dormant_awakening_sectors = radar_result.get("dormant_awakening_sectors", []) or radar_insights.get("dormant_awakening_sectors", [])
    sector_z = radar_result.get("sector_z_scores", {})
    sector_avg = radar_result.get("sector_baseline_avg", {})
    sector_std = radar_result.get("sector_baseline_std", {})
    is_host = str(entity_type).upper() in ("ASSET", "HOST", "IP")
    sector_metrics = radar_result.get(
        "sector_metrics",
        cls.SECTOR_TO_METRIC_ASSET if is_host else cls.SECTOR_TO_METRIC_USER,
    )
    th = cls.thresholds(ctx.get("sensitivity_tier"))
    gate, robust, fusion_sq = _num(th["anomaly_threshold"]), _num(th["robust_threshold"]), _num(th["fusion_threshold_sq"])
    tukey, composite = _num(th["tukey_excess_threshold"]), _num(th["radar_composite_d"])
    caps = harness_truth.mode_caps()
    risk, stats = cls.RISK_METRICS_SKILL, cls.STATS_HUNTER_SKILL
    above_max = cls.MODEL_LABELS["ABOVE_HISTORICAL_MAX_Z"]

    def _final(directive: StrategyDirective, cands: Optional[List[CandidateHypothesis]] = None) -> StrategyDirective:
      return cls._finalize_directive_with_confidence(directive, ctx, list(cands or []), executed_signatures, empty_families)

    def _new(model: str, skill: str, query: str, **kwargs: Any) -> StrategyDirective:
      return cls._new_directive(ctx, model, skill, query, **kwargs)

    def _radar(reason: str) -> StrategyDirective:
      queries = (
          "the decoupled canonical host sector queries (`radar_360_decoupled_sector.yl2` plus the alert and web shards)"
          if is_host
          else "the decoupled canonical user sector queries in `templates/radar_360/`"
      )
      sectors = (
          "Auth, Network Egress, DNS, Web & Proxy, Security & EDR Alerts, and Endpoint"
          if is_host
          else "Auth, Cloud, Workspace, Egress, DNS, and Web"
      )
      defense = f"{reason} Running the 6-spoke `360_DECOUPLED_RADAR` over {queries} establishes 30-day Z-scores across {sectors}."
      directive = _new(
          "360_DECOUPLED_RADAR", risk, "profile_360_risk",
          summary=f"Behavioral departure investigation across {entity_type} `{target_entity}` telemetry.",
          h0=f"Activity across {sectors} conforms to the 30-day baselines (every sector Z < {gate}σ, composite D < {composite}σ).",
          h1="Multi-sector behavioral drift indicating insider threat, token theft, or lateral account movement.",
          defense=defense,
          title=f"360° Decoupled Behavioral Radar: `{target_entity}`",
      )
      return _final(directive)

    # --- 0. Multi-Vector Cross-Sector or Roll-Up Fusion when 2+ sectors are outliers in Tier 1 ---
    if len(outlier_sectors) >= 2 and re.search(r"\b(fusion|multi[-\s]?sector|kill[-\s]?chain|correlat)\b", text_corpus):
      sec_a, sec_b = outlier_sectors[0], outlier_sectors[1]
      m_a = sector_metrics.get(sec_a, "workspace_total_download_actions")
      m_b = sector_metrics.get(sec_b, "network_bytes_outbound")
      z_a = sector_z.get(sec_a, th["anomaly_threshold"])
      z_b = sector_z.get(sec_b, th["screen_threshold"])
      defense = (
          "Tier 1 360° Radar surfaced concurrent anomalies across two orthogonal sectors: "
          f"`{sec_a}` (`{m_a}`, Z = {z_a:+.2f}σ) and `{sec_b}` (`{m_b}`, Z = {z_b:+.2f}σ). "
          "Executing a 3-stage Cross-Vector Fusion computes the rectified joint Euclidean threat distance "
          f"D = √(Σ max(0, Z_i)²) against the {th['tier']} gate D² ≥ {fusion_sq}."
      )
      directive = _new(
          "DUAL_SECTOR_FUSION_3STAGE", risk, "sector_fusion", metric=m_a, fusion=[m_a, m_b], outlier_vector=sec_a,
          summary=f"Multi-vector behavioral anomaly on `{target_entity}` spanning `{m_a}` and `{m_b}`.",
          h0=f"Concurrent deviations in `{m_a}` and `{m_b}` reflect unrelated routine activity.",
          h1=f"Coordinated multi-sector attack chain combining `{m_a}` and `{m_b}` on `{target_entity}` (D² ≥ {fusion_sq}).",
          defense=defense,
          title=f"Tier 2 Cross-Vector Fusion ({sec_a} × {sec_b}): `{target_entity}`",
      )
      return _final(directive)

    # --- 0b. Scheduled Exfiltration (nightly / multi-day cadence): canonical two-answer rule ---
    if cls._is_scheduled_exfiltration(text_corpus):
      return cls._scheduled_exfiltration_directive(ctx, text_corpus, executed_signatures, empty_families)

    # --- Outlier Vector Priority Dispatch for Tier 2 Secondary Sweeps ---
    if outlier_vector:
      z_val = sector_z.get(outlier_vector, (th["screen_threshold"] + th["anomaly_threshold"]) / 2.0)
      m_for_vec = sector_metrics.get(outlier_vector, "network_bytes_outbound")

      # Sub-Threshold Variance-Masked Drift -> 4-Stage Non-Parametric MAD
      if outlier_vector in variance_masked_sectors and outlier_vector not in outlier_sectors:
        std_val = sector_std.get(outlier_vector, 10.0)
        avg_val = sector_avg.get(outlier_vector, 1.0)
        defense = (
            f"Tier 1 360° Radar flagged a variance-masked sub-threshold anomaly in `{outlier_vector}` "
            f"(`{m_for_vec}`, Z = {z_val:+.2f}σ, μ = {avg_val:.2f}, σ = {std_val:.2f}). "
            "Because historical standard deviation is inflated by heavy-tailed variance, executing 4-Stage Non-Parametric "
            "`MAD` (`mad_robust_z_4stage.yl2` over 30d) tests median-based robust deviation ($Z_{mod} = 0.6745 |x - \\text{median}| / \\text{MAD}$)."
        )
        cands = [
            cls._cand(
                f"{cls.MODEL_LABELS['LONGITUDINAL_CUSUM']} on `{m_for_vec}`", risk, "LONGITUDINAL_CUSUM", "dynamic_metric",
                metric=m_for_vec,
                h0=f"Sub-threshold `{m_for_vec}` volume reflects stationary background noise.",
                h1=f"Multi-day cumulative drift in `{m_for_vec}` is accumulating under the parametric Z-score gate.",
                defense=f"Complements 4-stage `MAD` with Windowed Slack Sum + Page CUSUM tracking across `{m_for_vec}`.",
                confidence=0.78,
            ),
        ]
        directive = _new(
            "MAD", risk, "dynamic_metric", metric=m_for_vec, outlier_vector=outlier_vector,
            summary=f"Secondary Deep Dive: Variance-masked sub-threshold drift in `{outlier_vector}` (`{m_for_vec}`, Z = {z_val:+.2f}σ, σ = {std_val:.2f}) on `{target_entity}`.",
            h0=f"Elevated `{m_for_vec}` volume is within normal heavy-tailed operational variance.",
            h1=f"True outlier in `{m_for_vec}` masked by inflated parametric standard deviation (`$modified_z` ≥ {robust}).",
            defense=defense,
            title=f"Tier 2 Non-Parametric 4-Stage MAD (`{m_for_vec}`): `{target_entity}`",
        )
        return _final(directive, cands)

      # Sub-Threshold Dormant / Immature Baseline Awakening -> TWO_PART_HURDLE (+ FIRST_SEEN_NOVELTY)
      if outlier_vector in dormant_awakening_sectors and outlier_vector not in outlier_sectors:
        avg_val = sector_avg.get(outlier_vector, 0.05)
        defense = (
            f"Tier 1 360° Radar detected a dormant baseline awakening in `{outlier_vector}` "
            f"(`{m_for_vec}`, Z = {z_val:+.2f}σ, historical μ = {avg_val:.2f}). "
            "Applying `TWO_PART_HURDLE` (`two_part_hurdle.yl2`) explicitly evaluates zero-inflated dormancy awakening "
            "combined with post-hurdle volume intensity; entities below the "
            f"{th['min_baseline_days']}-active-day maturity gate are screened with `FIRST_SEEN_NOVELTY` instead of σ-scores."
        )
        cands = [
            cls._cand(
                f"{cls.MODEL_LABELS['FIRST_SEEN_NOVELTY']} on `{m_for_vec}`", risk, "FIRST_SEEN_NOVELTY", "dynamic_metric",
                metric=m_for_vec,
                h0=f"`{m_for_vec}` activity was already present in the 30-day baseline (`first_seen` > 0).",
                h1=f"`{m_for_vec}` activity on `{target_entity}` is brand new inside the 30-day window (novelty flag = 1).",
                defense="Boolean novelty flag from the 30-day `metrics.*` `first_seen` aggregate (never a σ score).",
                confidence=0.77,
            ),
            cls._cand(
                f"4-Stage Non-Parametric MAD on `{m_for_vec}`", risk, "MAD", "dynamic_metric", metric=m_for_vec,
                h0=f"Activity in `{m_for_vec}` conforms to median historical behavior.",
                h1=f"Post-awakening activity in `{m_for_vec}` exceeds robust median absolute deviation bounds (`$modified_z` ≥ {robust}).",
                defense=f"Provides non-parametric corroboration for dormant baseline awakening on `{m_for_vec}`.",
                confidence=0.76,
            ),
        ]
        directive = _new(
            "TWO_PART_HURDLE", risk, "dynamic_metric", metric=m_for_vec, outlier_vector=outlier_vector,
            summary=f"Secondary Deep Dive: Dormant baseline awakening in `{outlier_vector}` (`{m_for_vec}`, μ = {avg_val:.2f}) on `{target_entity}`.",
            h0=f"Sporadic `{m_for_vec}` activity represents benign infrequent usage.",
            h1=f"Zero-inflated dormant vector `{m_for_vec}` awakened with anomalous intensity (`TWO_PART_HURDLE`).",
            defense=defense,
            title=f"Tier 2 Dormant Baseline Hurdle (`{m_for_vec}`): `{target_entity}`",
        )
        return _final(directive, cands)

      if outlier_vector == "Workspace":
        ws_metric = "workspace_total_change_actions" if "change" in text_corpus else "workspace_total_download_actions"
        defense = (
            f"Tier 1 360° Radar flagged a significant outlier in the `Workspace` sector (Z = {z_val:+.2f}σ on `{ws_metric}`). "
            f"{above_max} (`ABOVE_HISTORICAL_MAX_Z`, `macd_momentum_velocity_2stage.yl2`) tests whether `{ws_metric}` broke "
            f"the entity's 30-day historical maximum (gate {gate}σ); pairing `{ws_metric}` with `network_bytes_outbound` via "
            "`DUAL_SECTOR_FUSION_3STAGE` tests whether Google Drive/Workspace document access is staging exfiltration."
        )
        cands = [
            cls._cand(
                f"Workspace × Network Outbound Exfiltration Fusion (`{ws_metric}` + `network_bytes_outbound`)",
                risk, "DUAL_SECTOR_FUSION_3STAGE", "sector_fusion", metric=ws_metric,
                fusion=[ws_metric, "network_bytes_outbound"],
                h0="Workspace file downloads are local productivity actions without outbound network staging.",
                h1=f"Downloaded Workspace assets (`{ws_metric}`) are being actively exfiltrated over outbound network flows (`network_bytes_outbound`).",
                defense=f"Correlates the observed `{ws_metric}` spike (Z = {z_val:+.2f}σ) with outbound byte volume for `{target_entity}` (D² ≥ {fusion_sq}).",
                confidence=0.82,
            ),
            cls._cand(
                f"Peer Cohort Multilevel Comparison on `{ws_metric}`", risk, "PART_OF_THE_WHOLE_MULTILEVEL", "dynamic_metric",
                metric=ws_metric,
                h0=f"Elevated `{ws_metric}` volume is shared across the enterprise fleet (e.g. company-wide policy doc).",
                h1=f"User `{target_entity}` is an isolated fleet-wide outlier in `{ws_metric}` (`$z_vs_enterprise` ≥ {gate}σ).",
                defense=(
                    f"Distinguishes isolated insider hoarding of `{ws_metric}` from legitimate department-wide document "
                    "distribution (Samuelson cohort-size cap applies)."
                ),
                confidence=0.72,
            ),
            cls._cand(
                "Workspace Insider Triad Multilevel Decomposition (Downloads + Changes + Emails)",
                risk, "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL", "workspace_triad", metric="workspace_total_download_actions",
                fusion=["workspace_total_download_actions", "workspace_total_change_actions", "workspace_emails_sent_total"],
                h0="Workspace activity is confined to a single routine productivity channel.",
                h1="Coordinated insider hoarding across Workspace downloads, permission modifications, and external email forwarding.",
                defense=f"Decomposes the Workspace Z = {z_val:+.2f}σ signal across all 3 Workspace insider vectors against enterprise peers.",
                confidence=0.79,
            ),
        ]
        directive = _new(
            "ABOVE_HISTORICAL_MAX_Z", risk, "macd_momentum", metric=ws_metric, outlier_vector=outlier_vector,
            summary=f"Secondary Deep Dive: Workspace sector outlier (`{ws_metric}`, Z = {z_val:+.2f}σ) on `{target_entity}`.",
            h0=f"Observed `{ws_metric}` count stays below its 30-day historical maximum (routine document collaboration).",
            h1=(
                f"`{ws_metric}` broke its 30-day historical maximum ({above_max} ≥ {gate}σ), indicating bulk Workspace "
                "data hoarding prior to exfiltration."
            ),
            defense=defense,
            title=f"Tier 2 Workspace {above_max} (`{ws_metric}`): `{target_entity}`",
        )
        return _final(directive, cands)

      elif outlier_vector == "Web":
        web_metric = "http_queries_fail" if ("fail" in text_corpus or "error" in text_corpus or "404" in text_corpus) else "http_queries_total"
        defense = (
            f"Tier 1 360° Radar identified an outlier in `Web & Proxy Activity` (`{web_metric}`, Z = {z_val:+.2f}σ). "
            f"Evaluating `{web_metric}` with {above_max} (`ABOVE_HISTORICAL_MAX_Z`) tests whether web request volume broke "
            "its 30-day historical maximum (automated web scraping, proxy probing, or C2 over HTTP)."
        )
        cands = [
            cls._cand(
                "First-Contact / Rare Destination HTTP Domain Prevalence (`http_queries_total`)",
                risk, "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE", "dynamic_metric", metric="http_queries_total",
                h0="HTTP requests target established enterprise SaaS domains.",
                h1=f"Host/User `{target_entity}` is sending `http_queries_total` traffic to rare domains (`rolling_max <= 3`, `day_count = 10`).",
                defense=(
                    f"Combines the `http_queries_total` 30-day baseline (Z = {z_val:+.2f}σ) with Entity Graph `DERIVED_CONTEXT` "
                    "domain prevalence; the Mode A join window starts at D-2 with event stages pinned to the scored UTC day."
                ),
                confidence=0.78,
            ),
            cls._cand(
                "HTTP Error Ratio Surge (`http_queries_fail` / `http_queries_total`)",
                risk, "FAILURE_RATIO_SURGE", "failure_ratio_surge", metric="http_queries_fail",
                fusion=["http_queries_fail", "http_queries_total"],
                h0="HTTP requests maintain a normal success-to-failure ratio.",
                h1="Elevated HTTP failure ratio indicating web directory brute-forcing, vulnerability scanning, or dead C2 endpoints.",
                defense=f"Evaluates `FAILURE_RATIO_SURGE` across `http_queries_fail` and `http_queries_total` for `{target_entity}`.",
                confidence=0.76,
            ),
        ]
        directive = _new(
            "ABOVE_HISTORICAL_MAX_Z", risk, "macd_momentum", metric=web_metric, outlier_vector=outlier_vector,
            summary=f"Secondary Deep Dive: Web/HTTP sector outlier (`{web_metric}`, Z = {z_val:+.2f}σ) on `{target_entity}`.",
            h0=f"Elevated `{web_metric}` traffic stems from standard browser or CDN requests below the 30-day historical maximum.",
            h1=f"`{web_metric}` broke its 30-day historical maximum ({above_max} ≥ {gate}σ), driven by automated web reconnaissance or HTTP exfiltration.",
            defense=defense,
            title=f"Tier 2 Web & Proxy {above_max} (`{web_metric}`): `{target_entity}`",
        )
        return _final(directive, cands)

      elif outlier_vector == "Egress":
        if _ELEPHANT_VECTOR_RX.search(text_corpus):
          conc_gate = cls._gate_text("HYBRID_ENTROPY_CONCENTRATION")
          defense = (
              f"Tier 1 `Egress` sector is anomalous (Z = {z_val:+.2f}σ on `network_bytes_outbound`) and case context references bulk data extraction. "
              f"Evaluating `HYBRID_ENTROPY_CONCENTRATION` tests destination diversity collapse and single-flow byte concentration ({conc_gate}) over a bounded raw window."
          )
          directive = _new(
              "HYBRID_ENTROPY_CONCENTRATION", stats, "elephant_flow", metric="network_bytes_outbound", outlier_vector=outlier_vector,
              summary=f"Secondary Deep Dive: Egress volume surge on `{target_entity}` with suspected destination concentration (elephant flows).",
              h0="Egress volume surge reflects standard batch analytical ETL query jobs spread across normal destinations.",
              h1=f"Outbound bytes collapse onto few destinations with heavy single-flow concentration ({conc_gate}), indicating unauthorized table dumping.",
              defense=defense,
              title=f"Tier 2 {cls.MODEL_LABELS['HYBRID_ENTROPY_CONCENTRATION']}: `{target_entity}`",
          )
          return _final(directive)

        jitter_gate = cls._gate_text("C2_BEACONING_JITTER")
        defense = (
            f"Tier 1 360° Radar flagged a significant `Egress` outlier (Z = {z_val:+.2f}σ on `network_bytes_outbound`). "
            f"Testing `C2_BEACONING_JITTER` first determines whether the outbound traffic is driven by automated periodic C2 polling ({jitter_gate}; "
            "vetted `micro_python_helpers.py c2-jitter`, or the `FLOW_GAP_RATIO_SCREEN` screen when local scripts are unavailable); "
            f"if refuted, the engine will pivot to {above_max} or Cross-Vector Fusion."
        )
        cands = [
            cls._cand(
                f"Bulk Outbound Breakout ({above_max}, `network_bytes_outbound`)", risk, "ABOVE_HISTORICAL_MAX_Z", "macd_momentum",
                metric="network_bytes_outbound",
                h0="Outbound bytes stay below their 30-day historical maximum (routine background transfers).",
                h1="Non-periodic outbound byte surge broke the 30-day historical maximum (acute staging and bulk exfiltration).",
                defense=(
                    f"If `C2_BEACONING_JITTER` rules out periodic polling, the Z = {z_val:+.2f}σ `network_bytes_outbound` spike "
                    "must be evaluated against the 30-day historical maximum."
                ),
                confidence=0.76,
            ),
        ]
        directive = _new(
            "C2_BEACONING_JITTER", stats, "c2_jitter", metric="network_bytes_outbound", outlier_vector=outlier_vector,
            summary=f"Secondary Deep Dive: Outlier in Network Egress (Z = {z_val:+.2f}σ) on `{target_entity}`; evaluating robotic periodic beaconing.",
            h0="Outbound network connections originate from stochastic application background traffic.",
            h1=f"Host established automated, low-jitter periodic polling to external C2 exfiltration infrastructure ({jitter_gate}).",
            defense=defense,
            title=f"Tier 2 C2 Beaconing Jitter Analysis: `{target_entity}`",
        )
        return _final(directive, cands)

      elif outlier_vector == "Auth":
        if _LATERAL_RX.search(text_corpus):
          lat_gate = cls._gate_text("PRIVILEGED_LATERAL_EXPANSION")
          defense = (
              f"Tier 1 `Auth` sector is anomalous (Z = {z_val:+.2f}σ) with lateral movement indicators in the case text. "
              f"Evaluating `PRIVILEGED_LATERAL_EXPANSION` ({lat_gate}) tests whether the account is authenticating to previously unseen endpoints."
          )
          directive = _new(
              "PRIVILEGED_LATERAL_EXPANSION", stats, "lateral_expansion", metric="auth_attempts_success", outlier_vector=outlier_vector,
              summary=f"Secondary Deep Dive: Auth outlier on `{target_entity}`; evaluating privileged lateral machine expansion.",
              h0="Logins reflect routine administrative access across normal host baseline.",
              h1=f"Compromised account expanding authentication radius across previously unaccessed target machines ({lat_gate}).",
              defense=defense,
              title=f"Tier 2 Lateral Expansion Analysis: `{target_entity}`",
          )
          return _final(directive)

        spray_gate = cls._gate_text("POISSON_BURST_CLUSTERING")
        hod_gate = cls._gate_text("HOUR_OF_DAY_PROFILE")
        defense = (
            f"Tier 1 360° Radar flagged an `Auth` sector anomaly (Z = {z_val:+.2f}σ on `auth_attempts_fail`). "
            f"Testing `POISSON_BURST_CLUSTERING` evaluates whether failures occur in high-dispersion automated spray waves ({spray_gate}); "
            f"if refuted, a pivot to `HOUR_OF_DAY_PROFILE` ({hod_gate}) will test for out-of-profile session abuse."
        )
        cands = [
            cls._cand(
                f"Out-of-Profile Authentication Hours ({cls.MODEL_LABELS['HOUR_OF_DAY_PROFILE']}, `auth_attempts_total`)",
                stats, "HOUR_OF_DAY_PROFILE", "hour_of_day_profile", metric="auth_attempts_total",
                h0="Logins occur within the user's learned 24-bin hour-of-day profile.",
                h1=f"Authentication activity occurs at out-of-profile hours indicative of stolen credentials ({hod_gate}).",
                defense=f"Tests hour-of-day departure on authentication events given the Tier 1 Auth Z = {z_val:+.2f}σ deviation.",
                confidence=0.74,
            ),
        ]
        directive = _new(
            "POISSON_BURST_CLUSTERING", stats, "poisson_burst", metric="auth_attempts_fail", outlier_vector=outlier_vector,
            summary=f"Secondary Deep Dive: Authentication failure surge (Z = {z_val:+.2f}σ) targeting `{target_entity}`; testing Poisson dispersion.",
            h0="Failures stem from benign user password expiration or expired cached credentials.",
            h1=f"Identity subjected to automated, high-dispersion Poisson credential spray bursts ({spray_gate}).",
            defense=defense,
            title=f"Tier 2 Poisson Burst Clustering: `{target_entity}`",
        )
        return _final(directive, cands)

      elif outlier_vector == "Cloud":
        defense = (
            f"Tier 1 360° Radar flagged a `Cloud` sector outlier (Z = {z_val:+.2f}σ on `resource_creation_total`). "
            "Executing `CLOUD_CRUD_SURGE` evaluates 30-day resource creation and deletion baselines across vendor/product companions."
        )
        cands = [
            cls._cand(
                "Cloud Resource × Auth Roll-Up Sector Fusion (`resource_creation_total` + `auth_attempts_fail`)",
                risk, "DUAL_SECTOR_FUSION_3STAGE", "sector_fusion", metric="resource_creation_total",
                fusion=["resource_creation_total", "auth_attempts_fail"],
                h0="Cloud provisioning is an authorized CI/CD deployment.",
                h1="Cloud resource creation surge is coupled with anomalous authentication activity on the same identity.",
                defense=(
                    f"Rolls up composite `resource_creation_total` (Z = {z_val:+.2f}σ) and fuses it with the identity "
                    f"authentication baseline (D² ≥ {fusion_sq})."
                ),
                confidence=0.71,
            ),
            cls._cand(
                "Cloud Repository Scope & Permission Recon (`CLOUD_REPOSITORY_SCOPE`)",
                risk, "CLOUD_REPOSITORY_SCOPE", "cloud_repo_scope", metric="resource_read_total",
                outcome_mode="fail" if ("fail" in text_corpus or "denied" in text_corpus) else "total",
                h0="Cloud resource reads align with normal service account scope.",
                h1="Identity is enumerating cloud buckets/repositories outside its historical behavioral scope.",
                defense=f"Evaluates `cloud_repository_scope_dual_branch.yl2` on `{target_entity}` following the Cloud Z = {z_val:+.2f}σ signal.",
                confidence=0.77,
            ),
        ]
        directive = _new(
            "CLOUD_CRUD_SURGE", risk, "cloud_crud", metric="resource_creation_total", outlier_vector=outlier_vector,
            summary=f"Secondary Deep Dive: Cloud sector outlier (Z = {z_val:+.2f}σ) on `{target_entity}`; testing IAM and resource mutation velocity.",
            h0="Administrative modifications reflect normal Infrastructure-as-Code deployments.",
            h1="Compromised credentials generating unauthorized service account keys or escalating IAM permissions.",
            defense=defense,
            title=f"Tier 2 Cloud Infrastructure CRUD Surge: `{target_entity}`",
        )
        return _final(directive, cands)

      elif outlier_vector == "DNS":
        dns_metric = "dns_bytes_outbound" if "tunnel" in text_corpus else "dns_queries_fail"
        if re.search(r"\b(entropy|dga|obfuscated)\b", text_corpus):
          ent_gate = cls._gate_text("SHANNON_ENTROPY_CHARACTER")
          defense = (
              f"Tier 1 `DNS` sector is anomalous (Z = {z_val:+.2f}σ) and alert context indicates algorithmic domain generation. "
              f"Testing `SHANNON_ENTROPY_CHARACTER` ({ent_gate}; screen `LONG_STRING_SCREEN`) measures character randomness in queried domain strings."
          )
          directive = _new(
              "SHANNON_ENTROPY_CHARACTER", stats, "shannon_entropy", metric=dns_metric, outlier_vector=outlier_vector,
              summary=f"Secondary Deep Dive: DNS query outlier on `{target_entity}`; testing algorithmic DGA query entropy.",
              h0="Query strings conform to normal enterprise domain resolution patterns.",
              h1=f"Adversary utilizing Domain Generation Algorithms (DGA) with high character entropy to establish C2 ({ent_gate}).",
              defense=defense,
              title=f"Tier 2 DNS DGA Entropy Analysis: `{target_entity}`",
          )
          return _final(directive)

        defense = (
            f"Tier 1 360° Radar flagged a `DNS` sector outlier (Z = {z_val:+.2f}σ on `{dns_metric}`). "
            f"Applying `LONGITUDINAL_CUSUM` (Windowed Slack Sum prefilter + Page CUSUM series) to `{dns_metric}` evaluates whether "
            "NXDOMAIN / DNS traffic is accumulating over a multi-day tunneling or C2 reconnaissance horizon."
        )
        cands = [
            cls._cand(
                f"Rare Destination DNS ECG Filter (`{dns_metric}` via `network.dns.questions.name`)",
                risk, "RARE_DESTINATION_ECG_3STAGE", "dynamic_metric", metric=dns_metric,
                h0="DNS queries resolve high-prevalence enterprise domains.",
                h1=f"DNS surge (`{dns_metric}`) contacts low-prevalence domains (`rolling_max <= 3`, `day_count = 10`) in Entity Graph `DERIVED_CONTEXT`.",
                defense=(
                    "Uses `rare_destination_ecg_3stage.yl2` keyed on `network.dns.questions.name`; the Mode A join window starts "
                    "at D-2 with event stages pinned to the scored UTC day."
                ),
                confidence=0.75,
            ),
            cls._cand(
                f"DNS × Network Outbound Fusion (`{dns_metric}` + `network_bytes_outbound`)",
                risk, "DUAL_SECTOR_FUSION_3STAGE", "sector_fusion", metric=dns_metric,
                fusion=[dns_metric, "network_bytes_outbound"],
                h0="DNS failures are isolated resolver misconfigurations.",
                h1=f"DNS resolution anomalies (`{dns_metric}`) are paired with active outbound data transfer (`network_bytes_outbound`).",
                defense=f"Tests whether the DNS Z = {z_val:+.2f}σ anomaly correlates with outbound byte exfiltration (D² ≥ {fusion_sq}).",
                confidence=0.73,
            ),
        ]
        directive = _new(
            "LONGITUDINAL_CUSUM", risk, "dynamic_metric", metric=dns_metric, outlier_vector=outlier_vector,
            summary=f"Secondary Deep Dive: DNS surge (`{dns_metric}`, Z = {z_val:+.2f}σ) on `{target_entity}`; testing longitudinal CUSUM drift.",
            h0="DNS failures conform to benign transient network misconfigurations.",
            h1=f"Low-and-slow creeping DNS tunneling or domain reconnaissance accumulates sustained positive drift in `{dns_metric}`.",
            defense=defense,
            title=f"Tier 2 Longitudinal CUSUM Drift (`{dns_metric}`): `{target_entity}`",
        )
        return _final(directive, cands)

      elif outlier_vector in ("Flows", "Alerts"):
        target_m = "alert_event_name_count" if outlier_vector == "Alerts" else "network_flows_outbound"
        ewma_gate = cls._gate_text("EWMA_BURST_VELOCITY")
        defense = (
            f"Tier 1 360° Radar flagged a significant `{outlier_vector}` outlier (Z = {z_val:+.2f}σ on `{target_m}`). "
            f"Testing `EWMA_BURST_VELOCITY` ({ewma_gate}; screen `BURST_Z_SCREEN`) captures intraday kinetic acceleration "
            "over a bounded raw window while preparing a Roll-Up Fusion if corroborated."
        )
        kc_model, kc_query = cls._killchain_or_fusion("DEFENSE_EVASION_ALERT_TO_EXFILTRATION")
        cands = [
            cls._cand(
                f"Roll-Up Sector Fusion (`{target_m}` + `network_bytes_outbound`)",
                risk, "DUAL_SECTOR_FUSION_3STAGE", "sector_fusion", metric=target_m, fusion=[target_m, "network_bytes_outbound"],
                h0=f"Elevated `{target_m}` is an isolated scanner or noisy rule.",
                h1=f"Anomalous `{target_m}` activity on `{target_entity}` coincides with outbound data exfiltration (`network_bytes_outbound`).",
                defense=f"Fuses `{target_m}` (Z = {z_val:+.2f}σ) with `network_bytes_outbound` using roll-up fusion (D² ≥ {fusion_sq}).",
                confidence=0.77,
            ),
            cls._cand(
                "MITRE ATT&CK Kill-Chain: Defense Evasion Alert to Exfiltration",
                risk, kc_model, kc_query, metric="alert_event_name_count",
                fusion=["alert_event_name_count", "network_bytes_outbound"],
                killchain="DEFENSE_EVASION_ALERT_TO_EXFILTRATION",
                h0="Security alerts on host are uncoupled from outbound network bytes.",
                h1="Security/EDR alert surge (`alert_event_name_count`) is coupled with active outbound data exfiltration (`network_bytes_outbound`).",
                defense=f"Executes the `DEFENSE_EVASION_ALERT_TO_EXFILTRATION` kill-chain archetype on `{target_entity}`.",
                confidence=0.79,
            ),
        ]
        directive = _new(
            "EWMA_BURST_VELOCITY", stats, "ewma_burst", metric=target_m, outlier_vector=outlier_vector,
            summary=f"Secondary Deep Dive: Kinetic rate burst on `{target_entity}` ({outlier_vector} sector, `{target_m}`).",
            h0="Telemetry surge reflects scheduled backup operations or batch sync jobs.",
            h1=f"Kinetic acceleration indicating automated data staging or aggressive scanning ({ewma_gate}).",
            defense=defense,
            title=f"Tier 2 EWMA Kinetic Burst Velocity: `{target_entity}`",
        )
        return _final(directive, cands)

      elif outlier_vector == "Endpoint":
        zipf_gate = cls._gate_text("ZIPFIAN_PROCESS_RARITY")
        defense = (
            f"Tier 1 360° Radar flagged an `Endpoint` process-execution outlier (Z = {z_val:+.2f}σ on `file_executions_total`). "
            f"`ZIPFIAN_PROCESS_RARITY` ({zipf_gate}) tests whether the surge comes from long-tail binaries over a bounded raw window; "
            "Markov 2-gram lineage and Shannon character entropy test how they were launched."
        )
        cands = [
            cls._cand(
                f"{cls.MODEL_LABELS['MARKOV_2GRAM_TRANSITION_RARITY']} (`file_executions_total`)",
                stats, "MARKOV_2GRAM_TRANSITION_RARITY", "markov_transition", metric="file_executions_total",
                h0="Process parent-child spawns match standard daemon/worker lineage.",
                h1=f"Rare parent-child transitions on `{target_entity}` ({cls._gate_text('MARKOV_2GRAM_TRANSITION_RARITY')}).",
                defense="Bounded-window parent-to-child process lineage that daily `metrics.*` counters cannot measure.",
                confidence=0.76,
            ),
            cls._cand(
                f"{cls.MODEL_LABELS['SHANNON_ENTROPY_CHARACTER']} (command lines)",
                stats, "SHANNON_ENTROPY_CHARACTER", "shannon_entropy", metric="file_executions_total",
                h0="Command lines conform to normal character distribution.",
                h1=f"Encoded or obfuscated command lines on `{target_entity}` ({cls._gate_text('SHANNON_ENTROPY_CHARACTER')}).",
                defense="Bounded-window character entropy over `target.process.command_line`.",
                confidence=0.72,
            ),
        ]
        directive = _new(
            "ZIPFIAN_PROCESS_RARITY", stats, "zipfian_rarity", metric="file_executions_total", outlier_vector=outlier_vector,
            summary=f"Secondary Deep Dive: Endpoint process-execution outlier (Z = {z_val:+.2f}σ) on `{target_entity}`.",
            h0="Executed binaries conform to widely adopted enterprise software baselines.",
            h1=f"Long-tail rare binaries are executing on `{target_entity}` ({zipf_gate}).",
            defense=defense,
            title=f"Tier 2 Zipfian Long-Tail Process Rarity: `{target_entity}`",
        )
        return _final(directive, cands)

    # --- Direct Case/Alert Situational Dispatch (canonical cross-skill routing table) ---
    route = cls.route_intent(
        text_corpus, entity_type, udm_events, outcomes, target_entity=target_entity, include_rules=False
    )
    intent = route["intent"]

    if intent == "CUSUM_DRIFT":
      model = route["model_name"]
      metric = cls._infer_metric(text_corpus, entity_type)
      if model == "WINDOWED_SLACK_SUM":
        method = (
            "the stateless Windowed Slack Sum prefilter (`templates/pipelines/longitudinal_cusum_2stage.yl2`) narrows the "
            "fleet before the Page CUSUM series runs on the surviving entities"
        )
      else:
        method = (
            "the Page CUSUM series (`templates/pipelines/longitudinal_cusum_series_3stage.yl2` + `scripts/cusum_helper.py`) "
            "runs behind the Windowed Slack Sum prefilter"
        )
      defense = (
          f"Case context describes low-and-slow cumulative drift on `{target_entity}`. On `{metric}`, {method}, in one query of "
          f"at most {caps['mode_b_cusum_macro_days']} days (single-day Mode A blocked; longer horizons as Mode C shards against "
          "Shard 1's fixed baseline)."
      )
      cands = [
          cls._cand(
              f"4-Stage Non-Parametric MAD on `{metric}`", risk, "MAD", "dynamic_metric", metric=metric,
              h0=f"Daily `{metric}` stays within median absolute deviation bounds.",
              h1=f"A median-anchored outlier day hides inside the drift on `{metric}` (`$modified_z` ≥ {robust}).",
              defense="Robust single-day corroboration for cumulative drift.",
              confidence=0.70,
          ),
          cls._cand(
              f"{above_max} on `{metric}`", risk, "ABOVE_HISTORICAL_MAX_Z", "macd_momentum", metric=metric,
              h0=f"`{metric}` stays below its 30-day historical maximum.",
              h1=f"`{metric}` broke its 30-day historical maximum ({above_max} ≥ {gate}σ).",
              defense="Separates a slow creep from a single breakout day.",
              confidence=0.66,
          ),
      ]
      directive = _new(
          model, risk, "dynamic_metric", metric=metric,
          summary=f"Low-and-slow cumulative drift investigation on `{target_entity}` (`{metric}`).",
          h0=f"Daily `{metric}` stays inside its 30-day baseline with no sustained positive drift.",
          h1=f"Sustained positive drift accumulates in `{metric}` below single-day gates (Windowed Slack Sum ≥ {gate}σ over at least two drift days).",
          defense=defense,
          title=f"{cls.MODEL_LABELS[model]} (`{metric}`): `{target_entity}`",
      )
      return _final(directive, cands)

    if intent == "RADAR_360":
      return _radar(f"Case context requests a 360° health check or entity risk score for `{target_entity}`.")

    # 1. Network / C2 Beaconing Indicators and sub-day cron timing
    if intent == "C2_JITTER":
      threat_label = threats[0] if threats else "Command & Control"
      jitter_gate = cls._gate_text("C2_BEACONING_JITTER")
      defense = (
          f"Alert telemetry on `{target_entity}` references {threat_label} periodic communication or sub-day cron timing. "
          f"Applying `C2_BEACONING_JITTER` measures inter-arrival timing variance ({jitter_gate}) across outbound flows "
          "(vetted `micro_python_helpers.py c2-jitter`, or the `FLOW_GAP_RATIO_SCREEN` screen when local scripts are unavailable)."
      )
      directive = _new(
          "C2_BEACONING_JITTER", stats, "c2_jitter", metric="network_bytes_outbound",
          summary=f"Host `{target_entity}` associated with {threat_label} periodic network communication or C2 telemetry.",
          h0="Outbound network connections originate from stochastic application background traffic.",
          h1=f"Host established automated, low-jitter periodic polling to external C2 exfiltration infrastructure ({jitter_gate}).",
          defense=defense,
          title=f"C2 Beaconing Jitter Analysis: `{target_entity}`",
      )
      return _final(directive)

    # 2. Credential Spray / Burst Login Indicators
    if intent == "FANO_SPRAY":
      spray_gate = cls._gate_text("POISSON_BURST_CLUSTERING")
      defense = (
          f"Case telemetry for `{target_entity}` contains authentication failure / credential theft indicators (`USER_LOGIN`). "
          f"Evaluating `POISSON_BURST_CLUSTERING` tests whether login failures violate Poisson randomness ({spray_gate})."
      )
      directive = _new(
          "POISSON_BURST_CLUSTERING", stats, "poisson_burst", metric="auth_attempts_fail",
          summary=f"Excessive authentication failures or credential spray attempts targeting `{target_entity}`.",
          h0="Failures stem from benign user password expiration or expired cached credentials.",
          h1=f"Identity subjected to automated, high-dispersion Poisson credential spray bursts ({spray_gate}).",
          defense=defense,
          title=f"Poisson Burst Clustering: `{target_entity}`",
      )
      return _final(directive)

    # 3. Information-Theoretic: Obfuscated Command Line / DGA / High Entropy
    if intent == "ENTROPY":
      ent_gate = cls._gate_text("SHANNON_ENTROPY_CHARACTER")
      is_dga = bool(_DGA_RX.search(text_corpus))
      surface = "queried domain strings" if is_dga else "command-line strings"
      defense = (
          f"Alert context on `{target_entity}` indicates encoded, obfuscated or algorithmically generated strings. "
          f"Applying `SHANNON_ENTROPY_CHARACTER` quantifies character randomness in {surface} ({ent_gate}; vetted "
          "`micro_python_helpers.py shannon`, or the `LONG_STRING_SCREEN` screen when local scripts are unavailable)."
      )
      directive = _new(
          "SHANNON_ENTROPY_CHARACTER", stats, "shannon_entropy", metric="dns_queries_total" if is_dga else "file_executions_total",
          summary=f"High-entropy {surface} or Base64 obfuscation detected on `{target_entity}`.",
          h0="Strings reflect benign administrative scripts, package installer hashes or established enterprise domains.",
          h1=f"Adversary executing obfuscated payloads or algorithmic domains to evade signature rules ({ent_gate}).",
          defense=defense,
          title=f"Shannon Character Entropy: `{target_entity}`",
      )
      return _final(directive)

    # 4. Process Parent-Child Transitions / Living off the Land
    if intent == "MARKOV_LINEAGE":
      mk_gate = cls._gate_text("MARKOV_2GRAM_TRANSITION_RARITY")
      defense = (
          f"Alert context on `{target_entity}` indicates anomalous parent-child process lineage. "
          f"Applying `MARKOV_2GRAM_TRANSITION_RARITY` computes Laplace-smoothed 2-gram transition surprisal ({mk_gate})."
      )
      directive = _new(
          "MARKOV_2GRAM_TRANSITION_RARITY", stats, "markov_transition", metric="file_executions_total",
          summary=f"Rare process parent-child execution sequence on `{target_entity}`.",
          h0="Process lineage represents scheduled maintenance scripts or approved enterprise tools.",
          h1=f"Anomalous transition surprisal sequence characteristic of Living-off-the-Land execution chaining ({mk_gate}).",
          defense=defense,
          title=f"{cls.MODEL_LABELS['MARKOV_2GRAM_TRANSITION_RARITY']}: `{target_entity}`",
      )
      return _final(directive)

    # 5. Zipfian Power-Law / Long-Tail Rare Administrative Tools & File IoC Ingress
    if intent == "ZIPF_RARITY":
      threat_label = threats[0] if threats else "Malware Dropper / IoC"
      zipf_gate = cls._gate_text("ZIPFIAN_PROCESS_RARITY")
      defense = (
          f"Case telemetry on `{target_entity}` indicates binary dropper or file IoC activity ({threat_label}). "
          f"Applying `ZIPFIAN_PROCESS_RARITY` evaluates fleet-wide power-law prevalence of executed binaries ({zipf_gate})."
      )
      cands = [
          cls._cand(
              "Process Execution × Outbound Network Roll-Up Fusion (`file_executions_total` + `network_bytes_outbound`)",
              risk, "DUAL_SECTOR_FUSION_3STAGE", "sector_fusion", metric="file_executions_total",
              fusion=["file_executions_total", "network_bytes_outbound"],
              h0="Executed binary is a standalone local utility with no external network callback.",
              h1="Anomalous process execution (`file_executions_total` roll-up) is paired with outbound C2/exfiltration bytes (`network_bytes_outbound`).",
              defense=(
                  "Uses roll-up sector fusion (`rollup_sector_fusion_4stage.yl2`) to correlate rare binary execution on the host "
                  f"with outbound network bytes (D² ≥ {fusion_sq})."
              ),
              confidence=0.79,
          ),
      ]
      directive = _new(
          "ZIPFIAN_PROCESS_RARITY", stats, "zipfian_rarity", metric="file_executions_total",
          summary=f"File IoC or malicious payload delivery ({threat_label}) targeting `{target_entity}`.",
          h0="Executable binaries on host conform to widely adopted enterprise software baselines.",
          h1=f"Adversary executed long-tail rare binaries or subordinate tools associated with {threat_label} intrusion.",
          defense=defense,
          title=f"Zipfian Long-Tail Process Rarity: `{target_entity}`",
      )
      return _final(directive, cands)

    # 6. Intraday Kinetic Burst / EWMA Acceleration
    if intent == "EWMA_BURST":
      ewma_gate = cls._gate_text("EWMA_BURST_VELOCITY")
      defense = (
          f"Alert telemetry on `{target_entity}` indicates acute intraday rate acceleration; evaluating `EWMA_BURST_VELOCITY` "
          f"({ewma_gate}; vetted `micro_python_helpers.py ewma`, or the `BURST_Z_SCREEN` screen when local scripts are unavailable)."
      )
      directive = _new(
          "EWMA_BURST_VELOCITY", stats, "ewma_burst",
          summary=f"Rapid rate acceleration and kinetic volume burst detected on `{target_entity}`.",
          h0="Telemetry surge reflects scheduled backup operations or batch sync jobs.",
          h1=f"Kinetic acceleration indicating automated data staging or aggressive scanning ({ewma_gate}).",
          defense=defense,
          title=f"EWMA Kinetic Burst Velocity: `{target_entity}`",
      )
      return _final(directive)

    # 7. Off-Hours / Out-of-Profile Hours (and travel-velocity intents, whose geo-velocity model is retired)
    if intent in ("HOUR_OF_DAY", "GEO_VELOCITY_RETIRED"):
      hod_gate = cls._gate_text("HOUR_OF_DAY_PROFILE")
      hod_metric = "workspace_total_download_actions" if "workspace" in text_corpus else "auth_attempts_total"
      cands = [
          cls._cand(
              f"{cls.MODEL_LABELS['ADAPTIVE_CONTEXT_THRESHOLD']} (`{hod_metric}`)",
              risk, "ADAPTIVE_CONTEXT_THRESHOLD", "dynamic_metric", metric=hod_metric,
              h0=f"Daily `{hod_metric}` stays inside its 30-day business-hours / weekend baseline.",
              h1=f"Daily `{hod_metric}` departs from its 30-day baseline under the off-hours adaptive gate.",
              defense="Pairs the raw hour-of-day profile with the 30-day `metrics.*` business-hours Z on the macro plane.",
              confidence=0.70,
          ),
      ]
      if intent == "GEO_VELOCITY_RETIRED":
        kph = outcomes.get("kph", "anomalous")
        dist = outcomes.get("distance_kilometers", "geographic")
        lead = (
            f"UDM detection outcomes on `{target_entity}` report travel velocity (`kph={kph}`, `distance={dist}`), but "
            "city-centroid geo-velocity scoring is retired in the remediated harness (D1: VPN egress and city centroids produce "
            "systematic false positives); the skill routes this intent to the learned hour-of-day profile and Derived Context "
            "asset prevalence."
        )
        cands.insert(0, cls._cand(
            "Logins to Brand-New Assets (`DERIVED_CONTEXT_PREVALENCE`)",
            stats, "DERIVED_CONTEXT_PREVALENCE", "dynamic_archetype", metric="auth_attempts_success",
            h0="Logins target established assets with a long Entity Graph history.",
            h1=f"Logins target brand-new or unestablished assets ({cls._gate_text('DERIVED_CONTEXT_PREVALENCE')}).",
            defense="Uses Entity Graph `DERIVED_CONTEXT` asset `first_seen_time` to separate routine logins from unestablished endpoints.",
            confidence=0.74,
        ))
      else:
        lead = f"Case context on `{target_entity}` describes off-hours or out-of-profile activity."
      defense = (
          f"{lead} `HOUR_OF_DAY_PROFILE` in `{stats}` scores each hour out-of-sample against the entity's learned 24-bin "
          f"hour-of-day profile ({hod_gate}); daily `metrics.*` baselines cannot profile hours of the day."
      )
      directive = _new(
          "HOUR_OF_DAY_PROFILE", stats, "hour_of_day_profile", metric=hod_metric,
          summary=f"Out-of-profile activity hours on `{target_entity}` (`{hod_metric}`).",
          h0="Activity hours match the entity's learned 24-bin hour-of-day profile.",
          h1=f"Stolen session token or compromised credential used at out-of-profile hours ({hod_gate}).",
          defense=defense,
          title=f"{cls.MODEL_LABELS['HOUR_OF_DAY_PROFILE']} (`{hod_metric}`): `{target_entity}`",
      )
      return _final(directive, cands)

    # 8. Producer-Consumer Byte Ratio Inversion (Workstation / Endpoint Role Inversion)
    if intent == "PRODUCER_CONSUMER":
      pcr_gate = cls._gate_text("PRODUCER_CONSUMER_RATIO_INVERSION")
      defense = (
          f"Case telemetry on `{target_entity}` indicates a client/endpoint role inversion (`PRODUCER_CONSUMER_RATIO_INVERSION`, {pcr_gate}), "
          "where a historically net-consumer asset shifts to a net outbound byte producer."
      )
      cands = [
          cls._cand(
              "30-Day Macro Outbound vs Inbound Byte Fusion (`network_bytes_outbound` + `network_bytes_inbound`)",
              risk, "DUAL_SECTOR_FUSION_3STAGE", "sector_fusion", metric="network_bytes_outbound",
              fusion=["network_bytes_outbound", "network_bytes_inbound"],
              h0="Outbound and inbound byte volumes remain within the asset's 30-day macro baseline.",
              h1="30-day macro `network_bytes_outbound` diverges sharply from `network_bytes_inbound`.",
              defense="Pairs bounded-window PCR role inversion with 30-day `metrics.*` byte baselines per the Bilateral UEBA Harness.",
              confidence=0.81,
          ),
      ]
      directive = _new(
          "PRODUCER_CONSUMER_RATIO_INVERSION", stats, "producer_consumer_inversion", metric="network_bytes_outbound",
          summary=f"Producer-Consumer byte ratio inversion detected on `{target_entity}`.",
          h0="Endpoint maintains normal client consumer-to-producer byte symmetry.",
          h1="Endpoint inverted its historical role into a net outbound data producer (staging/exfiltration server).",
          defense=defense,
          title=f"Producer-Consumer Ratio Inversion: `{target_entity}`",
      )
      return _final(directive, cands)

    # 9. Raw-field / bounded-window robust statistics (Precedence 1 MAD / Tukey)
    if intent == "RAW_ROBUST":
      model = route["model_name"]
      metric = cls._infer_metric(text_corpus, entity_type)
      if model == "DATA_EXFILTRATION_SPIKE":
        score_var, template = "`$m_z_score`", "mad_modified_z_4stage.yl2"
      else:
        score_var, template = "`$fence_z`", "iqr_tukey_skew_fences_3stage.yl2"
      defense = (
          f"Case context asks for a raw-field / custom-window robust outlier test on `{target_entity}`. `{model}` (`{template}`) "
          f"in `{stats}` scores raw UDM telemetry inside a bounded window of at most {caps['mode_b_micro_days']} days "
          f"({score_var} against the tier-calibrated gate); 30-day `metrics.*` robust baselines stay in `{risk}`."
      )
      cands = [
          cls._cand(
              f"30-Day Metric-Catalog Tukey Fence (`{metric}`)", risk, "QUANTILE_IQR_SKEW", "quantile_iqr_skew", metric=metric,
              h0=f"Daily `{metric}` sits below the 30-day skewness-adjusted Tukey upper fence (`$tukey_excess_z` < {tukey}).",
              h1=f"Daily `{metric}` breaches the 30-day skewness-adjusted Tukey upper fence (`$tukey_excess_z` ≥ {tukey}).",
              defense="Macro-plane companion over the 30-day metric baseline (`quantile_iqr_skew_3stage.yl2`).",
              confidence=0.70,
          ),
      ]
      directive = _new(
          model, stats, "dynamic_archetype", metric=metric,
          summary=f"Bounded-window robust outlier test on `{target_entity}` (`{metric}`).",
          h0=f"Raw activity stays inside its robust bounded-window envelope ({score_var} below the gate).",
          h1=f"Raw activity breaches the robust upper bound of its bounded window ({score_var} at or above the gate).",
          defense=defense,
          title=f"{cls.MODEL_LABELS.get(model, model)}: `{target_entity}`",
      )
      return _final(directive, cands)

    # 10. 30-day metric-catalog robust statistics (Precedence 2 MAD / Tukey)
    if intent == "METRIC_ROBUST":
      model = route["model_name"]
      metric = cls._infer_metric(text_corpus, entity_type)
      if model == "MAD":
        gate_text, template, query = f"`$modified_z` ≥ {robust}", "mad_robust_z_4stage.yl2", "dynamic_metric"
        companion = ("QUANTILE_IQR_SKEW", "quantile_iqr_skew", f"`$tukey_excess_z` ≥ {tukey}")
      else:
        gate_text, template, query = f"`$tukey_excess_z` ≥ {tukey}", "quantile_iqr_skew_3stage.yl2", "quantile_iqr_skew"
        companion = ("MAD", "dynamic_metric", f"`$modified_z` ≥ {robust}")
      defense = (
          f"Case context asks for a 30-day metric-catalog robust baseline on `{target_entity}`. `{model}` (`{template}`) builds "
          f"its robust envelope from the ~30-day raw window of `{metric}` while `$in_scoring_window` gates the scored day ({gate_text})."
      )
      cands = [
          cls._cand(
              f"{cls.MODEL_LABELS[companion[0]]} (`{metric}`)", risk, companion[0], companion[1], metric=metric,
              h0=f"Daily `{metric}` stays inside its robust 30-day envelope.",
              h1=f"Daily `{metric}` breaches its robust 30-day envelope ({companion[2]}).",
              defense="Second robust lens on the same 30-day metric baseline.",
              confidence=0.70,
          ),
      ]
      directive = _new(
          model, risk, query, metric=metric,
          summary=f"Robust 30-day metric-catalog outlier test on `{target_entity}` (`{metric}`).",
          h0=f"Daily `{metric}` stays inside its robust 30-day envelope.",
          h1=f"Heavy-tailed history masked a true outlier day on `{metric}` ({gate_text}).",
          defense=defense,
          title=f"{cls.MODEL_LABELS[model]} (`{metric}`): `{target_entity}`",
      )
      return _final(directive, cands)

    # 11. Peer Cohort Comparison
    if intent == "PEER_COHORT":
      metric = cls._infer_metric(text_corpus, entity_type)
      defense = (
          f"Case context compares `{target_entity}` with its peers. `PART_OF_THE_WHOLE_MULTILEVEL` "
          f"(`part_of_the_whole_multilevel.yl2`) scores `{metric}` against team and enterprise cohorts (`$z_vs_enterprise` ≥ "
          f"{gate}σ); the Samuelson cohort-size cap (N − 1)/√N must reach the gate, otherwise the cohort is reported as too small."
      )
      cands = [
          cls._cand(
              f"Dual-Baseline Delta-Z vs Fleet (`{metric}`)", risk, "DUAL_BASELINE_3STAGE", "dynamic_metric", metric=metric,
              h0=f"`{metric}` moved with the fleet (e.g. a company-wide rollout).",
              h1=f"`{target_entity}` departs from its own baseline beyond the fleet-wide shift in `{metric}`.",
              defense="Subtracts the mature-cohort fleet shift from the personal surge (`dual_baseline_delta_z_3stage.yl2`).",
              confidence=0.74,
          ),
      ]
      directive = _new(
          "PART_OF_THE_WHOLE_MULTILEVEL", risk, "dynamic_metric", metric=metric,
          summary=f"Peer-cohort comparison for `{target_entity}` on `{metric}`.",
          h0=f"`{target_entity}` behaves like its team and enterprise cohort on `{metric}`.",
          h1=f"`{target_entity}` is an isolated outlier against its peers on `{metric}` (`$z_vs_enterprise` ≥ {gate}σ).",
          defense=defense,
          title=f"Peer Cohort Multilevel Comparison (`{metric}`): `{target_entity}`",
      )
      return _final(directive, cands)

    # 12. First-Seen Novelty
    if intent == "FIRST_SEEN":
      metric = cls._infer_metric(text_corpus, entity_type)
      defense = (
          f"Case context reports first-seen activity on `{target_entity}`. `FIRST_SEEN_NOVELTY` (`first_seen_novelty_2stage.yl2`) "
          f"flags brand-new `(entity, target)` pairs for `{metric}` from the 30-day `metrics.*` `first_seen` aggregate "
          "(boolean novelty flag with volume gating, never a σ score)."
      )
      network_metric = metric.startswith(("network_", "dns_", "http_"))
      companion = (
          cls._cand(
              f"Rare Destination Entity Graph Filter (`{metric}`)", risk, "RARE_DESTINATION_ECG_3STAGE", "dynamic_metric", metric=metric,
              h0="Destinations are established high-prevalence enterprise infrastructure.",
              h1="Destinations have ultra-low enterprise prevalence (`rolling_max <= 3`, `day_count = 10`).",
              defense="Entity Graph `DERIVED_CONTEXT` prevalence; the Mode A join window starts at D-2 with event stages pinned to the scored UTC day.",
              confidence=0.72,
          )
          if network_metric
          else cls._cand(
              f"Dormancy Awakening Two-Part Hurdle (`{metric}`)", risk, "TWO_PART_HURDLE", "dynamic_metric", metric=metric,
              h0=f"Sparse `{metric}` activity reflects normal periodic usage.",
              h1=f"Dormant `{metric}` awakened with anomalous intensity.",
              defense="Zero-inflated dormancy awakening plus post-hurdle intensity.",
              confidence=0.70,
          )
      )
      directive = _new(
          "FIRST_SEEN_NOVELTY", risk, "dynamic_metric", metric=metric,
          summary=f"First-seen activity on `{target_entity}` (`{metric}`).",
          h0=f"`{metric}` activity on `{target_entity}` was already present in the 30-day baseline (`first_seen` > 0).",
          h1=f"`{metric}` activity on `{target_entity}` is brand new inside the 30-day window (novelty flag = 1).",
          defense=defense,
          title=f"{cls.MODEL_LABELS['FIRST_SEEN_NOVELTY']} (`{metric}`): `{target_entity}`",
      )
      return _final(directive, [companion])

    # 13. Workspace / Google Drive Hoarding or Change Surge (Situational Non-Auth/Non-Network Metric Selection!)
    if intent == "WORKSPACE":
      ws_metric = "workspace_total_change_actions" if "change" in text_corpus else "workspace_total_download_actions"
      defense = (
          f"Case context specifically implicates Google Workspace / Drive activity on `{target_entity}`. "
          f"Selecting `{ws_metric}` (rather than generic auth/network) and applying {above_max} (`ABOVE_HISTORICAL_MAX_Z`) "
          "tests the 30-day Workspace baseline and its historical maximum."
      )
      cands = [
          cls._cand(
              f"Workspace × Network Outbound Fusion (`{ws_metric}` + `network_bytes_outbound`)",
              risk, "DUAL_SECTOR_FUSION_3STAGE", "sector_fusion", metric=ws_metric, fusion=[ws_metric, "network_bytes_outbound"],
              h0="Workspace downloads remain local to corporate managed storage.",
              h1=f"Workspace hoarding (`{ws_metric}`) is coupled with outbound network exfiltration (`network_bytes_outbound`).",
              defense=f"Correlates `{ws_metric}` with `network_bytes_outbound` via 3-stage Cross-Vector Fusion (D² ≥ {fusion_sq}).",
              confidence=0.80,
          ),
      ]
      directive = _new(
          "ABOVE_HISTORICAL_MAX_Z", risk, "macd_momentum", metric=ws_metric,
          summary=f"Google Workspace data hoarding / download breakout (`{ws_metric}`) on `{target_entity}`.",
          h0=f"Workspace `{ws_metric}` activity reflects normal project file access below the 30-day historical maximum.",
          h1=f"User `{target_entity}` broke the 30-day historical maximum of `{ws_metric}` ({above_max} ≥ {gate}σ), indicative of insider data hoarding.",
          defense=defense,
          title=f"Workspace {above_max} (`{ws_metric}`): `{target_entity}`",
      )
      return _final(directive, cands)

    # 14. Above-Historical-Max Z breakout (volume beyond the 30-day historical maximum)
    if intent == "ABOVE_MAX":
      chosen_metric = "http_queries_total" if "http" in text_corpus else ("dns_queries_total" if "dns" in text_corpus else "network_bytes_outbound")
      defense = (
          f"Alert describes a volume breakout on `{target_entity}`; evaluating {above_max} (`ABOVE_HISTORICAL_MAX_Z`, "
          f"`macd_momentum_velocity_2stage.yl2`) on `{chosen_metric}` scores linear peak exceedance above the 30-day historical maximum."
      )
      directive = _new(
          "ABOVE_HISTORICAL_MAX_Z", risk, "macd_momentum", metric=chosen_metric,
          summary=f"Volume breakout above the 30-day historical maximum (`{chosen_metric}`) on `{target_entity}`.",
          h0="Volume conforms to legitimate scheduled workload operations below the 30-day historical maximum.",
          h1=f"`{chosen_metric}` broke its 30-day historical maximum ({above_max} ≥ {gate}σ), revealing active staging of unauthorized egress.",
          defense=defense,
          title=f"{above_max} (`{chosen_metric}`): `{target_entity}`",
      )
      return _final(directive)

    # 15. Cloud Infrastructure / IAM Indicators
    if intent == "CLOUD_CRUD":
      defense = (
          f"Case telemetry on `{target_entity}` indicates cloud resource or IAM mutations. "
          "Applying `CLOUD_CRUD_SURGE` evaluates `resource_creation_total` and `resource_deletion_total` against 30-day baselines."
      )
      directive = _new(
          "CLOUD_CRUD_SURGE", risk, "cloud_crud", metric="resource_creation_total",
          summary=f"Anomalous Cloud API reconnaissance or IAM modifications by `{target_entity}`.",
          h0="Administrative modifications reflect normal Infrastructure-as-Code deployments.",
          h1="Compromised credentials generating unauthorized service account keys or escalating IAM permissions.",
          defense=defense,
          title=f"Cloud Infrastructure CRUD Surge: `{target_entity}`",
      )
      return _final(directive)

    # 16. Elephant Flow / Destination Concentration (Mass Data Extraction)
    if intent == "ELEPHANT_FLOW":
      conc_gate = cls._gate_text("HYBRID_ENTROPY_CONCENTRATION")
      defense = (
          f"Case telemetry on `{target_entity}` indicates bulk table dumping or elephant-flow concentration; "
          f"`HYBRID_ENTROPY_CONCENTRATION` tests destination diversity collapse and single-flow byte concentration ({conc_gate})."
      )
      directive = _new(
          "HYBRID_ENTROPY_CONCENTRATION", stats, "elephant_flow", metric="network_bytes_outbound",
          summary=f"Mass data extraction or anomalous egress concentration detected on `{target_entity}`.",
          h0="Data access represents standard batch analytical ETL query jobs spread across normal destinations.",
          h1=f"Outbound bytes collapse onto few destinations with heavy single-flow concentration ({conc_gate}), indicating unauthorized table dumping.",
          defense=defense,
          title=f"{cls.MODEL_LABELS['HYBRID_ENTROPY_CONCENTRATION']}: `{target_entity}`",
      )
      return _final(directive)

    # 17. Bilateral UEBA Harness: Web-to-Shell Exploit / CTI / Shadow AI / Multi-Horizon Detection Gaps
    if intent == "BILATERAL_EXPLOIT":
      is_shadow_ai = bool(_SHADOW_AI_RX.search(text_corpus))
      macro_metric = "http_queries_total" if is_shadow_ai else "http_queries_fail"
      fusion_pair = [macro_metric, "network_bytes_outbound"] if is_shadow_ai else ["http_queries_fail", "file_executions_total"]
      loop_hits, loop_sum_z_sq = harness_truth.loopback_thresholds()
      micro_cap = caps["mode_b_micro_days"]
      defense = (
          f"Bilateral UEBA Harness engaged for `{target_entity}`: pairs the 30-day Macro Plane (`{risk}` "
          f"`DUAL_SECTOR_FUSION_3STAGE` across `{fusion_pair[0]}` + `{fusion_pair[1]}`, D² ≥ {fusion_sq}) with the bounded-window "
          f"Micro Plane (`{stats}` `MARKOV_2GRAM_TRANSITION_RARITY`, `SHANNON_ENTROPY_CHARACTER`, and `C2_BEACONING_JITTER`, "
          f"at most {micro_cap} days) and `PlaybookRunner` loopback (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`, ≥ {loop_hits} distinct hits "
          f"and ΣZ² ≥ {_num(loop_sum_z_sq)})."
      )
      cands = [
          cls._cand(
              "Micro Plane: Bounded-Window Markov 2-Gram Process Lineage (`MARKOV_2GRAM_TRANSITION_RARITY`)",
              stats, "MARKOV_2GRAM_TRANSITION_RARITY", "markov_transition", metric="file_executions_total",
              h0="Process parent-child spawns match standard daemon/worker lineage.",
              h1=f"Web/application daemon or autonomous agent spawned rare shell/interpreter children ({cls._gate_text('MARKOV_2GRAM_TRANSITION_RARITY')}).",
              defense="Supplies bounded-window parent-to-child process lineage that daily `metrics.*` counters cannot measure.",
              confidence=0.86,
          ),
          cls._cand(
              "Micro Plane: Bounded-Window CLI/URI Shannon Entropy (`SHANNON_ENTROPY_CHARACTER`)",
              stats, "SHANNON_ENTROPY_CHARACTER", "shannon_entropy", metric="file_executions_total",
              h0="Command-line and URI arguments conform to normal character distribution.",
              h1=f"High character-class Shannon entropy indicating encoded exploit payloads or API token strings ({cls._gate_text('SHANNON_ENTROPY_CHARACTER')}).",
              defense="Evaluates bounded-window character entropy over `target.process.command_line` / `target.url`.",
              confidence=0.83,
          ),
          cls._cand(
              "Micro Plane: Bounded-Window Outbound Callback Jitter (`C2_BEACONING_JITTER`)",
              stats, "C2_BEACONING_JITTER", "c2_jitter", metric="network_bytes_outbound",
              h0="Outbound connections follow irregular human-driven arrival intervals.",
              h1=f"Sub-hour low-jitter periodic callback or autonomous agent polling loop ({cls._gate_text('C2_BEACONING_JITTER')}).",
              defense="Measures sub-hour inter-arrival timing regularity over a bounded window.",
              confidence=0.80,
          ),
      ]
      directive = _new(
          "DUAL_SECTOR_FUSION_3STAGE", risk, "sector_fusion", metric=fusion_pair[0], fusion=fusion_pair,
          summary=f"Bilateral UEBA Harness investigation on `{target_entity}` combining 30d Macro Fusion (`{fusion_pair[0]}` + `{fusion_pair[1]}`) and Micro structural models.",
          h0=f"30-day macro baselines across `{fusion_pair[0]}` and `{fusion_pair[1]}` and short-window process/network structures are nominal.",
          h1=f"Multi-horizon exploit or autonomous agent signature spanning 30d macro `{fusion_pair[0]}` + `{fusion_pair[1]}` deformation and bounded-window micro anomalies.",
          defense=defense,
          title=f"Bilateral UEBA Harness ({fusion_pair[0]} × {fusion_pair[1]}): `{target_entity}`",
      )
      return _final(directive, cands)

    # 18. 30-day metrics.* baseline requests (telemetry physics: macro plane only)
    if intent == "MACRO_BASELINE":
      metric = cls._infer_metric(text_corpus, entity_type)
      defense = (
          f"Case context asks how `{target_entity}` compares with its 30-day behavior. `STANDARD_Z_SCORE` "
          f"(`standard_z_score_2stage.yl2`) scores `{metric}` against the pre-computed `metrics.*` baseline (Z ≥ {gate}σ after "
          f"the {th['min_baseline_days']}-active-day maturity gate); 30-day baselines over high-volume telemetry never run as raw "
          f"scans in `{stats}`."
      )
      cands = [
          cls._cand(
              f"{above_max} on `{metric}`", risk, "ABOVE_HISTORICAL_MAX_Z", "macd_momentum", metric=metric,
              h0=f"`{metric}` stays below its 30-day historical maximum.",
              h1=f"`{metric}` broke its 30-day historical maximum ({above_max} ≥ {gate}σ).",
              defense="Adds the 30-day historical maximum to the mean/stddev baseline.",
              confidence=0.70,
          ),
          cls._cand(
              f"4-Stage Non-Parametric MAD on `{metric}`", risk, "MAD", "dynamic_metric", metric=metric,
              h0=f"`{metric}` stays within median absolute deviation bounds.",
              h1=f"`{metric}` breaches its robust 30-day envelope (`$modified_z` ≥ {robust}).",
              defense="Robust companion when the 30-day history is heavy-tailed.",
              confidence=0.68,
          ),
      ]
      directive = _new(
          "STANDARD_Z_SCORE", risk, "dynamic_metric", metric=metric,
          summary=f"30-day `metrics.*` baseline comparison for `{target_entity}` (`{metric}`).",
          h0=f"`{metric}` for `{target_entity}` stays inside its 30-day baseline (Z < {gate}σ).",
          h1=f"`{metric}` for `{target_entity}` departs from its 30-day baseline (Z ≥ {gate}σ).",
          defense=defense,
          title=f"30-Day Baseline Z-Score (`{metric}`): `{target_entity}`",
      )
      return _final(directive, cands)

    # 19. User Entity / General Insider Threat / Baseline Drift
    if intent == "INSIDER_360":
      return _radar(f"Entity `{target_entity}` shows general behavioral risk indicators.")

    # 20. Generic Fallback
    defense = f"Autonomous investigation across UDM telemetry for `{target_entity}`."
    directive = _new(
        "GEMINI_REACT_AUTONOMOUS", stats, "auto",
        summary=f"Investigation into alert activity on `{target_entity}`.",
        h0="Telemetry conforms to benign operational activity.",
        h1="Telemetry contains statistical outliers or unauthorized access patterns.",
        defense=defense,
        title=f"Autonomous Security Triage: `{target_entity}`",
    )
    return _final(directive)

  @staticmethod
  def decide(
      case_title: str = "",
      alert_name: str = "",
      alert_desc: str = "",
      entity_type: str = "USER",
      sensitivity: Optional[str] = None,
  ) -> Tuple[str, str, str]:
    """Synchronous backward-compatibility method."""
    ctx = {
        "case_title": case_title,
        "alerts": [alert_name],
        "case_description": alert_desc,
        "entity_type": entity_type,
        "primary_entity": "target_entity",
        "sensitivity_tier": sensitivity,
    }
    directive = StrategyDecider._deterministic_reasoner(ctx)
    return directive.selected_skill, directive.directive_query, directive.model_name

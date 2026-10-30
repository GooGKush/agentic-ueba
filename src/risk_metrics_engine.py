# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Deterministic Risk Metrics Execution Engine for Agentic UEBA.

Executes 30-day macro-behavioral baselining, decoupled 6-spoke 360° risk radars,
cross-vector / roll-up sector fusions, and dynamic single-metric pipelines across all
38 Malachite Risk Analytics metrics via Chronicle OneMCP without LLM hallucination.

Harness alignment (secops-risk-metrics-multistage, read at runtime):

* Queries come from the skill: templates/ (radar_360/, pipelines/), MultiStageTemplateRouter and
  ChainedHuntRouter. The few sector queries built here (host 360° spokes, fleet sweep sectors and
  the identity probe) take their event filters, observed aggregations and metric arguments from the
  skill's metric catalog and follow the same platform rules: math.sqrt, at most 20 outcome variables
  per block, no compound arithmetic inside if() branches, count / byte dispersion floors and the
  7-active-day maturity gate. Retired models and templates are refused with the skill's own message.
* Windows: Mode A scores the last complete UTC day [D, D+1); multi-day requests run as a
  fixed-baseline Mode B timeline capped by the skill; Entity Graph joins start at D-2 with every
  event stage pinned to D.
* Gates, CRI, verdicts and score semantics come from src.harness_truth: each model's native score is
  mapped onto the canonical Z-equivalent scale before the CRI is computed (never inside the query).
"""

import asyncio
from datetime import date, datetime, timedelta, timezone
import logging
import math
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
from mcp import ClientSession

from src import harness_truth
from src.pipeline_runner import PipelineRunner
from src.config import TenantConfig

logger = logging.getLogger("RiskMetricsEngine")

# Provenance header carried by every query this module builds itself (all others are skill-rendered).
INLINE_QUERY_SOURCE = (
    "// Query source: agentic_ueba RiskMetricsEngine (inline; event filters, observed aggregations and "
    "metric args from the secops-risk-metrics-multistage catalog)"
)

_EVENT_DAY_PIN_RE = re.compile(
    r'timestamp\.get_date\(metadata\.event_timestamp\.seconds\)\s*=\s*"\d{4}-\d{2}-\d{2}"'
)
_ECG_RE = re.compile(r"\bgraph\.(?:entity|metadata|relations)\b")
_MATURITY_GATE_RE = re.compile(r"\$((?:raw_|host_|hist_|historical_)?active(?:_baseline)?_days)\s*>=\s*\d+")
_GATE_CLAUSE_RE = re.compile(r"\$([A-Za-z0-9_]+)\s*>=?\s*-?\d+(?:\.\d+)?")
_DATA_TABLE_IDENT_RE = re.compile(r"[A-Za-z0-9_]+")


def _escape_literal(value: Any) -> str:
  """Escapes a value for a YARA-L double-quoted string literal."""
  return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _iso(dt: datetime) -> str:
  return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _midnight_iso(day: date) -> str:
  return f"{day.isoformat()}T00:00:00Z"


def _code_only(query: str) -> str:
  """Query text without // and /* */ comments."""
  no_block = re.sub(r"/\*.*?\*/", "", query, flags=re.S)
  return "\n".join(re.sub(r"//[^\n]*", "", ln) for ln in no_block.splitlines())


class RiskMetricsEngine:
  """Executes pre-computed 30-day UEBA risk metric pipelines across all 38 catalog metrics."""

  SKILL_NAME = "secops-risk-metrics-multistage"

  # Canonical single-entity USER 360° sectors: templates/radar_360/ (copied verbatim, entity substituted).
  USER_SECTOR_TEMPLATES: Dict[str, str] = {
      "Auth": "radar_360/user_1_auth_risk.yl2",
      "Cloud": "radar_360/user_2_cloud_risk.yl2",
      "Workspace": "radar_360/user_3_workspace_risk.yl2",
      "Egress": "radar_360/user_4_egress_risk.yl2",
      "DNS": "radar_360/user_5_dns_risk.yl2",
      "Web": "radar_360/user_6_web_risk.yl2",
  }

  # Representative catalog metric per radar sector (what each USER radar sector measures; Cloud scores
  # all 4 CRUD families and reports resource_creation_total as its representative table).
  USER_SECTOR_METRICS: Dict[str, str] = {
      "Auth": "auth_attempts_total",
      "Cloud": "resource_creation_total",
      "Workspace": "workspace_total_download_actions",
      "Egress": "network_bytes_outbound",
      "DNS": "dns_queries_total",
      "Web": "http_queries_total",
  }

  ASSET_SECTOR_METRICS: Dict[str, str] = {
      "Auth": "auth_attempts_fail",
      "Egress": "network_bytes_outbound",
      "DNS": "dns_queries_fail",
      "Flows": "network_flows_outbound",
      "Alerts": "alert_event_name_count",
      "Web": "http_queries_total",
  }

  # Fleet sweep sector metrics (fleetwide decoupled sectors evaluated by run_fleet_360_sweep).
  FLEET_USER_SECTOR_METRICS: Dict[str, str] = {
      "Auth": "auth_attempts_fail",
      "Cloud": "resource_creation_total",
      "Workspace": "workspace_total_download_actions",
      "Egress": "network_bytes_outbound",
      "DNS": "dns_queries_fail",
      "Web": "http_queries_total",
  }

  # Canonical skill sector templates reused for host / fleet spokes.
  ASSET_ALERT_SECTOR_TEMPLATE = "radar_360_sector_alert.yl2"
  USER_WEB_FLEET_TEMPLATE = "radar_360_sector_web_http.yl2"

  # Sectors without a canonical template: (stage name, title); built from the metric catalog.
  _ASSET_INLINE_SECTORS: Dict[str, Tuple[str, str]] = {
      "Auth": ("auth_risk", "Asset Authentication"),
      "Egress": ("egress_risk", "Asset Network Outbound Volume"),
      "DNS": ("dns_risk", "Asset DNS Failures"),
      "Flows": ("flows_risk", "Asset Outbound Network Flows"),
      "Web": ("web_risk", "Asset Web & Proxy Activity"),
  }
  _USER_INLINE_SECTORS: Dict[str, Tuple[str, str]] = {
      "Auth": ("auth_risk", "User IAM & Authentication"),
      "Workspace": ("workspace_risk", "User Workspace & Drive Data"),
      "Egress": ("egress_risk", "User Network Egress Volume"),
      "DNS": ("dns_risk", "User DNS Failures"),
  }

  # Result-label normalization kept from earlier releases (the query model is resolved by the skill).
  _MODEL_LABEL_ALIASES: Dict[str, str] = {
      "CUSUM": "LONGITUDINAL_CUSUM_DRIFT",
      "LONGITUDINAL_CUSUM": "LONGITUDINAL_CUSUM_DRIFT",
      "ZSCORE": "STANDARD_Z_SCORE",
      "Z_SCORE": "STANDARD_Z_SCORE",
  }

  # Engine model names that the skill's resolve_statistical_model does not know.
  _STAT_MODEL_ALIASES: Dict[str, str] = {
      "LONGITUDINAL_CUSUM_DRIFT": "LONGITUDINAL_CUSUM",
      "QUANTILE_IQR_SKEW_3STAGE": "QUANTILE_IQR_SKEW",
  }

  # run_sector_fusion's result labels -> its four_stage flag. Roll-up vs cross-vector fusion is decided by the
  # metrics, so the 4-stage roll-up is the 3-stage fusion plus its roll-up stage.
  _SECTOR_FUSION_LABELS: Dict[str, bool] = {
      "DUAL_SECTOR_FUSION_3STAGE": False,
      "MULTI_SECTOR_FUSION_4STAGE": True,
      "ROLLUP_SECTOR_FUSION_4STAGE": False,
      "ROLLUP_SECTOR_FUSION_5STAGE": True,
  }

  # Model / pipeline name -> PipelineArchitecture member rendered by MultiStageTemplateRouter.
  _PIPELINE_ALIASES: Dict[str, str] = {
      "MACD_MOMENTUM_VELOCITY": "MACD_MOMENTUM_VELOCITY_2STAGE",
      "MACD_MOMENTUM_VELOCITY_2STAGE": "MACD_MOMENTUM_VELOCITY_2STAGE",
      "PART_OF_THE_WHOLE_MULTILEVEL": "PART_OF_THE_WHOLE_MULTILEVEL",
      "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL": "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL",
      "DUAL_BASELINE_3STAGE": "DUAL_BASELINE_3STAGE",
      "EMPIRICAL_BAYES_3STAGE": "EMPIRICAL_BAYES_3STAGE",
      "CLOUD_REPOSITORY_SCOPE": "CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH",
      "CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH": "CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH",
      "HTTP_ERROR_RATIO_SURGE_2STAGE": "HTTP_ERROR_RATIO_SURGE_2STAGE",
      "HTTP_TARGET_SURGE_2STAGE": "HTTP_TARGET_SURGE_2STAGE",
      "HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE": "HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE",
      "HYBRID_METRIC_RAW_ENRICHMENT_2STAGE": "HYBRID_METRIC_RAW_ENRICHMENT_2STAGE",
      "HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE": "HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE",
      "DESTINATION_DIVERSITY_CONCENTRATION_2STAGE": "HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE",
      "DIVERSITY_DEFICIT": "HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE",
      "DIVERSITY_DEFICIT_ENTROPY": "HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE",
      "ELEPHANT_FLOW": "HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE",
      "ELEPHANT_FLOW_CONCENTRATION": "HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE",
      "HYBRID_METRIC_FLEET_PREVALENCE_2STAGE": "HYBRID_METRIC_FLEET_PREVALENCE_2STAGE",
      "FLEET_PREVALENCE_NORMALIZATION": "HYBRID_METRIC_FLEET_PREVALENCE_2STAGE",
      "HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE": "HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE",
      "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE": "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE",
      "HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE": "HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE",
      "HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE": "HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE",
      "FIRST_SEEN_NOVELTY_2STAGE": "FIRST_SEEN_NOVELTY_2STAGE",
  }

  # Score columns searched when a row lacks the variable its query's root gate tests. Squared norms
  # are reported as the distance D and scored on the harness squared scale.
  _SCORE_PRIORITY: Tuple[str, ...] = (
      "modified_z", "tukey_excess_z", "macd_z", "above_max_z", "bayesian_z", "beta_binomial_z",
      "adaptive_z", "fold_change", "surge_ratio", "rel_dev_z_equiv", "fano_factor", "cusum_drift_score",
      "windowed_slack_sum", "hurdle_threat_score", "composite_risk", "delta_z", "z_vs_enterprise",
      "z_vs_team", "z_sector", "target_z", "alert_z", "fail_z", "recon_score", "macro_z_score", "macro_z",
      "poisson_z", "dest_z", "threat_score", "fused_threat_score", "normalized_odds_score",
      "target_risk_score", "personal_z", "z_score", "z", "novelty_flag", "composite_threat_norm_sq",
      "d_sq", "d_vs_fleet_sq", "d_vs_team_sq", "threat_distance_sq", "personal_norm_sq",
  )
  _OBSERVED_KEYS: Tuple[str, ...] = (
      "observed", "a_observed", "hourly_observed", "observed_hour", "daily_observed", "observed_val",
      "observed_24h", "obs_24h", "observed_queries", "observed_execs", "macro_observed", "obs_intensity",
      "m1_observed", "obs", "k", "entity_obs", "observed_fails", "total_alerts", "observed_flows",
      "originating_hosts", "affected_hosts",
  )
  _BASELINE_KEYS: Tuple[str, ...] = (
      "median_val", "q50_val", "q50", "expected_hourly_mean", "hist_avg_daily", "daily_mean", "hist_avg",
      "baseline_avg", "baseline_mean", "mean", "mean_queries", "mean_execs", "macro_mean",
      "macro_baseline_mean", "host_avg", "e_avg", "lambda", "avg_hourly", "historical_avg",
      "historical_flow_avg", "avg", "personal_avg",
  )
  _DISPERSION_KEYS: Tuple[str, ...] = (
      "hist_stddev", "historical_stddev", "baseline_stddev", "stddev", "macro_stddev", "stddev_queries",
      "stddev_execs", "host_std", "std",
  )

  def __init__(self, tenant_config: Optional[TenantConfig] = None):
    self.runner = PipelineRunner(tenant_config)

  # ---------------------------------------------------------------------------
  # Evaluation windows (src.harness_truth: Mode A day, Entity Graph window, Mode B / C caps)
  # ---------------------------------------------------------------------------

  @staticmethod
  def _now(now_utc: Optional[datetime] = None) -> datetime:
    now = now_utc or datetime.now(timezone.utc)
    return now if now.tzinfo else now.replace(tzinfo=timezone.utc)

  def _evaluation_window(
      self,
      lookback_days: int = 1,
      *,
      kind: str = "standard",
      ecg: bool = False,
      today_so_far: bool = False,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Execution window for a request, per the skill's Time Model.

    * Mode A (lookback <= 1): the last complete UTC day D, [D, D+1) (harness_truth.mode_a_window).
    * Mode B (lookback >= 2): a fixed-baseline timeline [today - (n-1), now), n capped at the skill's
      Mode B ceiling (harness_truth.mode_caps(); the CUSUM ceiling for kind="cusum", which never runs
      as a single-day Mode A query).
    * kind="robust" (MAD / QUANTILE_IQR_SKEW): the raw search window spans 30 days so the empirical
      median / quantiles see the history; the router's $in_scoring_window gate scores only the
      scored days, ending at `scoring_end_date`.
    * ecg=True: Entity Graph joins run Mode A from D-2 (harness_truth.ecg_window) with every event
      stage pinned to D (harness_truth.event_day_pin); the graph-joined templates score one day.
    * today_so_far=True: the explicit, labelled partial-day option (see _mode_a_today_window).
    """
    now = self._now(now_utc)
    day = harness_truth.mode_a_day(now)
    today = day + timedelta(days=1)
    requested = max(1, int(lookback_days or 1))
    base: Dict[str, Any] = {
        "requested_days": requested,
        "capped_from_days": None,
        "entity_graph": False,
        "event_day_pin": None,
        "is_partial_day": False,
    }
    if ecg:
      start, end = harness_truth.ecg_window(day)
      base.update({
          "mode": "A",
          "label": f"Mode A: Last Complete UTC Day ({day.isoformat()}), Entity Graph window from D-2",
          "start": start,
          "end": end,
          "scored_day": day.isoformat(),
          "first_scored_day": day.isoformat(),
          "scored_days": 1,
          "scoring_end_date": day.isoformat(),
          "capped_from_days": requested if requested > 1 else None,
          "entity_graph": True,
          "event_day_pin": harness_truth.event_day_pin(day),
      })
      return base
    if today_so_far:
      start, end, bucket = self._mode_a_today_window(now)
      partial = bucket == today.isoformat()
      base.update({
          "mode": "A",
          "label": ("Mode A: Today So Far (Partial UTC Day — Low-Biased vs Full-Day Baseline)"
                    if partial else f"Mode A: Last Complete UTC Day ({bucket})"),
          "start": start,
          "end": end,
          "scored_day": bucket,
          "first_scored_day": bucket,
          "scored_days": 1,
          "scoring_end_date": bucket,
          "is_partial_day": partial,
      })
      return base
    cusum = kind == "cusum"
    if requested <= 1 and not cusum:
      start, end = harness_truth.mode_a_window(day)
      if kind == "robust":
        start = _midnight_iso(day - timedelta(days=29))
      base.update({
          "mode": "A",
          "label": f"Mode A: Last Complete UTC Day ({day.isoformat()})",
          "start": start,
          "end": end,
          "scored_day": day.isoformat(),
          "first_scored_day": day.isoformat(),
          "scored_days": 1,
          "scoring_end_date": day.isoformat(),
      })
      return base
    caps = harness_truth.mode_caps()
    cap = caps["mode_b_cusum_macro_days"] if cusum else caps["mode_b_macro_days"]
    n = max(2, min(requested, cap))
    anchor = today - timedelta(days=n - 1)
    start_day = today - timedelta(days=max(29, n - 1)) if kind == "robust" else anchor
    base.update({
        "mode": "B",
        "label": f"Mode B: {n}d Fixed-Baseline Timeline ({anchor.isoformat()}..{today.isoformat()})",
        "start": _midnight_iso(start_day),
        "end": _iso(now),
        "scored_day": today.isoformat(),
        "first_scored_day": anchor.isoformat(),
        "scored_days": n,
        "scoring_end_date": today.isoformat(),
        "capped_from_days": requested if requested > n else None,
    })
    return base

  def _iso_window(self, lookback_days: int, is_entity_graph: bool = False) -> Tuple[str, str]:
    """(startTime, endTime) for a request; see _evaluation_window."""
    win = self._evaluation_window(lookback_days, ecg=is_entity_graph)
    return win["start"], win["end"]

  @staticmethod
  def _pin_event_day(query: str, day: date) -> str:
    """Pins every Entity Graph event-stage date filter to the scored UTC day."""
    pin = harness_truth.event_day_pin(day)
    return _EVENT_DAY_PIN_RE.sub(lambda _m: pin, query)

  @staticmethod
  def _uses_entity_graph(query: str) -> bool:
    return bool(_ECG_RE.search(_code_only(query)))

  def _apply_ecg_window(self, query: str, lookback_days: int, now_utc: Optional[datetime],
                        win: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Switches a graph-joined query to the Entity Graph Mode A window and pins its event stages to D."""
    if not self._uses_entity_graph(query):
      return query, win
    ecg_win = self._evaluation_window(lookback_days, ecg=True, now_utc=now_utc)
    return self._pin_event_day(query, date.fromisoformat(ecg_win["scored_day"])), ecg_win

  # ---------------------------------------------------------------------------
  # Gates, templates and catalog helpers
  # ---------------------------------------------------------------------------

  def gate_thresholds(self) -> Dict[str, float]:
    """Root significance gates from the harness sensitivity tier (default tier when the tenant sets none)."""
    c = harness_truth.constants()
    tier = getattr(self.runner.tenant, "sensitivity_tier", None)
    _, thresholds = c.resolve_sensitivity_thresholds(tier)
    thresholds.setdefault("tukey_excess_threshold", c.DEFAULT_TUKEY_EXCESS_THRESHOLD)
    return thresholds

  @staticmethod
  def _unfilled_placeholders(query: str) -> List[str]:
    return sorted(set(re.findall(r"\{\{(\w+)\}\}", _code_only(query))))

  def _render(self, template_name: str, params: Dict[str, Any]) -> str:
    """Renders a skill template; refuses retired templates and any unfilled placeholder."""
    harness_truth.assert_not_retired(template_name)
    path = self.runner.find_template(self.SKILL_NAME, template_name)
    merged: Dict[str, Any] = dict(self.gate_thresholds())
    merged["min_baseline_days"] = harness_truth.min_baseline_days()
    merged.update(params)
    rendered = self.runner.render_template(path, merged)
    missing = self._unfilled_placeholders(rendered)
    if missing:
      raise ValueError(f"Template {template_name} left placeholders unfilled: {missing}")
    return rendered

  def _byte_floor(self, metric: Optional[str]) -> Optional[float]:
    """The skill's per-metric byte dispersion floor (D8 / WS1-04), or None for count metrics."""
    if not metric:
      return None
    self.runner._ensure_skill_path()
    from scripts.template_router import resolve_byte_dispersion_floor
    return resolve_byte_dispersion_floor(metric)

  def _apply_byte_floor(self, query: str, metric: Optional[str], floor_vars: Sequence[str]) -> str:
    """Replaces a template's count floor (math.sqrt(...)) with the byte floor on byte metrics."""
    floor = self._byte_floor(metric)
    if floor is None:
      return query
    for var in floor_vars:
      name = re.escape(var.lstrip("$"))
      query = re.sub(rf"(\${name}\s*=\s*)math\.sqrt\([^\n]+\)", lambda m: f"{m.group(1)}{floor}", query)
    return query

  def _fallback_z(self, observed: float, baseline: float, dispersion: Optional[float],
                  metric: Optional[str] = None) -> float:
    """Z from observed / baseline / dispersion with the skill's floors (count or byte)."""
    floor = self._byte_floor(metric)
    if floor is None:
      floor = math.sqrt(max(baseline, 1.0))
    denom = max(dispersion or 0.0, floor)
    return (observed - baseline) / denom if denom > 0 else 0.0

  def _resolve_entity_enum(self, entity_type: str) -> Any:
    """Maps string entity_type ('USER', 'ASSET', 'HOST', 'IP') to skill EntityType enum."""
    EntityType, _, _, _ = self.runner.get_validator_enums()
    if self._is_asset(entity_type):
      return EntityType.ASSET
    return EntityType.USER

  @staticmethod
  def _is_asset(entity_type: Any) -> bool:
    return str(entity_type or "").upper() in ("ASSET", "HOST", "IP", "HOSTNAME", "DEVICE")

  def _scope(self, query: str, entity: Optional[str], entity_type: Optional[str] = None) -> str:
    """Scopes a skill-rendered query to one entity (string literal escaped)."""
    if not entity:
      return query
    return self.runner.scope_query_to_entity(query, _escape_literal(entity), entity_type=entity_type)

  @staticmethod
  def _with_root_gate(query: str, expression: str) -> str:
    """Adds a root condition to a NO-GATE sector template (fleet sweep pruning)."""
    gate = (
        "// Fleet sweep pruning gate (agentic_ueba): keep rows at or above the spoke-inclusion floor.\n"
        f"condition:\n  {expression}\n\norder:"
    )
    out, count = re.subn(
        r"(?:^//[^\n]*NO-GATE[^\n]*\n(?://[^\n]*\n)*)?^order:", lambda _m: gate, query, count=1, flags=re.M
    )
    if not count:
      raise ValueError("Sector template has no root order: section")
    return out

  # ---------------------------------------------------------------------------
  # Python-side scoring: Z-equivalent semantics, maturity gate, CRI (src.harness_truth)
  # ---------------------------------------------------------------------------

  @staticmethod
  def _num(row: Dict[str, Any], *keys: Optional[str]) -> Optional[float]:
    """First finite numeric value among `keys` (bare or $-prefixed), else None."""
    for key in keys:
      if not key:
        continue
      for k in (key, f"${key}"):
        if k not in row:
          continue
        val = row[k]
        if isinstance(val, list):
          val = val[0] if val else None
        if val is None or val == "" or isinstance(val, bool):
          continue
        try:
          num = float(val)
        except (TypeError, ValueError):
          continue
        if math.isfinite(num):
          return num
    return None

  def _root_condition(self, query: str) -> Optional[str]:
    return self.runner.get_template_router().root_condition(query)

  def _primary_score_key(self, query: str) -> Optional[str]:
    """The model's score: the variable its root significance gate tests, else its order: variable."""
    registry = harness_truth.constants().SCORE_SEMANTICS_REGISTRY
    for var in _GATE_CLAUSE_RE.findall(self._root_condition(query) or ""):
      if var in registry or var.endswith(("_sq", "_z")):
        return var
    m = re.search(r"^order:\s*\n\s*\$([A-Za-z0-9_]+)", query, re.M)
    return m.group(1) if m else None

  def _maturity_gate_column(self, query: str) -> Optional[str]:
    """Active-day column the query's root condition gates on (mirrored in Python), if any."""
    m = _MATURITY_GATE_RE.search(self._root_condition(query) or "")
    return m.group(1) if m else None

  @staticmethod
  def _cri(z_equivalent: Optional[float]) -> int:
    """Canonical CRI (harness_truth.calculate_cri); 0 when nothing was observed."""
    cri = harness_truth.calculate_cri(z_equivalent)
    return 0 if cri is None else int(cri)

  @staticmethod
  def _outlier_verdicts() -> Tuple[str, ...]:
    """Verdicts that warrant investigation: the harness MEDIUM / HIGH / CRITICAL bands (CRI >= 46)."""
    return tuple(harness_truth.BAND_VERDICTS[code] for code in ("MEDIUM", "HIGH", "CRITICAL"))

  def _score(
      self,
      row: Dict[str, Any],
      primary_key: Optional[str] = None,
      *,
      extra_keys: Sequence[str] = (),
      maturity_column: Optional[str] = None,
      use_priority: bool = True,
  ) -> Dict[str, Any]:
    """Native score -> canonical Z-equivalent (ueba_constants.score_to_z_equivalent) -> CRI and verdict.

    A row whose `maturity_column` is below the harness active-day floor scores 0 (the query's own
    maturity gate, mirrored). Squared norms are reported as the distance D.
    """
    c = harness_truth.constants()
    keys: List[str] = []
    for key in (primary_key, *extra_keys, *(self._SCORE_PRIORITY if use_priority else ())):
      if key and key not in keys:
        keys.append(key)
    score_key, raw = None, None
    for key in keys:
      val = self._num(row, key)
      if val is not None:
        score_key, raw = key, val
        break
    days = self._num(row, maturity_column) if maturity_column else None
    mature = days is None or days >= harness_truth.min_baseline_days()

    if score_key is None:
      display, z_eq, true_sigma, shown = 0.0, 0.0, False, "N/A"
      novelty = None
    else:
      sem = c.get_score_semantics(score_key)
      novelty = raw >= sem.threshold if sem.kind == "boolean_flag" else None
      squared = sem.kind == "squared"
      display = math.sqrt(max(0.0, raw)) if squared else raw
      z_eq = None if novelty is not None else c.score_to_z_equivalent(score_key, raw)
      if z_eq is not None and not mature:
        z_eq = 0.0
      true_sigma = bool(c.is_true_sigma_key(score_key)) and not squared
      shown = c.format_score_with_unit(None if squared else score_key, display)

    cri = 0 if z_eq is None else self._cri(z_eq)
    verdict = harness_truth.verdict_for(None if novelty is not None else cri)
    return {
        "score_key": score_key,
        "score": display,
        "z_equivalent": None if z_eq is None else round(z_eq, 6),
        "is_true_sigma": true_sigma,
        "score_display": shown,
        "calibrated_risk_index": cri,
        "cri_applicable": novelty is None,
        "verdict": verdict,
        "severity": self.derive_cri_severity(cri if novelty is None else None),
        "is_outlier": bool(novelty) if novelty is not None else verdict in self._outlier_verdicts(),
        "baseline_mature": mature,
        "active_days": None if days is None else int(days),
    }

  @staticmethod
  def _score_fields(score: Dict[str, Any]) -> Dict[str, Any]:
    """Result keys shared by every hunt (CRI semantics from src.harness_truth)."""
    return {
        "calibrated_risk_index": score["calibrated_risk_index"],
        "is_outlier": score["is_outlier"],
        "verdict": score["verdict"],
        "severity": score["severity"],
        "score_key": score["score_key"],
        "z_equivalent": score["z_equivalent"],
        "is_true_sigma": score["is_true_sigma"],
        "score_display": score["score_display"],
        "baseline_mature": score["baseline_mature"],
    }

  # ---------------------------------------------------------------------------
  # Sector queries without a canonical template (built from the skill's metric catalog)
  # ---------------------------------------------------------------------------

  def _inline_sector_query(
      self,
      metric: str,
      stage: str,
      title: str,
      entity_type: str,
      entity: Optional[str] = None,
      gate: Optional[str] = None,
  ) -> str:
    """One decoupled 360° sector: catalog filter / aggregation / metric arg, maturity-gated Z.

    The raw stage only aggregates; the floor, Z and maturity gate are computed in the root, so the
    query reads the same in both skills' dialects. Single-entity sectors are NO-GATE (fused
    client-side); fleet sectors carry `gate` as their root condition.
    """
    mc = self.runner.get_malachite_catalog()
    EntityType, _, _, PreFlightValidator = self.runner.get_validator_enums()
    sem = mc.baseline_semantics(metric)
    ent_enum = EntityType.ASSET if self._is_asset(entity_type) else EntityType.USER
    field = PreFlightValidator.resolve_identifier_field(metric, ent_enum, None)
    var = "host" if ent_enum == EntityType.ASSET else "user"
    min_days = harness_truth.min_baseline_days()

    def metric_call(agg: str) -> str:
      return (f"max(metrics.{metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: {agg}, "
              f"{field}: {field}))")

    binding = (
        [f"    {field} = ${var}", f'    ${var} != ""']
        if entity is None
        else [f'    {field} = "{_escape_literal(entity)}"', f"    ${var} = {field}"]
    )
    floor = self._byte_floor(metric)
    safe_std = (
        [f"  $safe_std = if($dispersion > {floor}, $dispersion, {floor})"]
        if floor is not None
        else ["  $floor = math.sqrt(if($baseline > 1.0, $baseline, 1.0))",
              "  $safe_std = if($dispersion > $floor, $dispersion, $floor)"]
    )
    lines = [
        f"// Sector: {title}",
        INLINE_QUERY_SOURCE,
        f"// Goal: {'Fleetwide' if entity is None else 'Single-entity'} 30-day {metric} baseline departure",
        "// Statistical Model: STANDARD_Z_SCORE (dispersion floor, "
        f"{min_days}-active-day maturity gate)",
        f"stage {stage} {{",
        *[f"    {line}" for line in sem.observed_filter],
        *binding,
        "",
        "  match:",
        f"    ${var} by 1d",
        "",
        "  outcome:",
        f"    $obs = {sem.observed_agg}",
        f"    $avg = {metric_call('avg')}",
        f"    $std = {metric_call('stddev')}",
        f"    $days = {metric_call('num_metric_periods')}",
        "}",
        "",
        f"${var} = ${stage}.{var}",
        "",
        "match:",
        f"  ${var} by 1d",
        "",
        "outcome:",
        f"  $observed = max(${stage}.obs)",
        f"  $baseline = max(${stage}.avg)",
        f"  $dispersion = max(${stage}.std)",
        f"  $active_days = max(${stage}.days)",
        *safe_std,
        "  $raw_z = ($observed - $baseline) / $safe_std",
        f"  $z = if($active_days >= {min_days}, $raw_z, 0.0)",
        "",
    ]
    if gate:
      lines += ["condition:", f"  {gate}", ""]
    else:
      lines += ["// NO-GATE: 360 radar sector micro-query; every sector is reported and fused client-side."]
    lines += ["order:", "  $z desc", ""]
    return "\n".join(lines)

  def _fleet_cloud_sector_query(self, gate: str) -> str:
    """Fleetwide Cloud CRUD sector: the 4 resource_* families, count floors and maturity gates.

    Mirrors templates/radar_360/user_2_cloud_risk.yl2 (per-family Z on the user / vendor / product
    baseline, peak family wins) for every user, with AD machine accounts ($) excluded.
    """
    mc = self.runner.get_malachite_catalog()
    min_days = harness_truth.min_baseline_days()
    families = (
        ("read", "r", "resource_read_total"),
        ("write", "w", "resource_written_total"),
        ("create", "c", "resource_creation_total"),
        ("delete", "d", "resource_deletion_total"),
    )
    dims = ("principal.user.userid: principal.user.userid, metadata.vendor_name: metadata.vendor_name, "
            "metadata.product_name: metadata.product_name")
    filters = {fam: " and ".join(mc.baseline_semantics(metric).observed_filter) for fam, _, metric in families}
    stage_outcome: List[str] = []
    for fam, _, metric in families:
      stage_outcome.append(f"    ${fam}_obs = sum(if({filters[fam]}, 1, 0))")
      for agg, suffix in (("avg", "avg"), ("stddev", "std"), ("num_metric_periods", "days")):
        stage_outcome.append(
            f"    ${fam}_{suffix} = max(metrics.{metric}(period: 1d, window: 30d, metric: event_count_sum, "
            f"agg: {agg}, {dims}))")

    def rollup(stage: str, pair: Sequence[Tuple[str, str, str]]) -> List[str]:
      out = [f"stage {stage} {{", "    $user = $cloud_risk.user", "", "  match:", "    $user by 1d", "",
             "  outcome:"]
      for fam, p, _ in pair:
        out += [
            f"    ${p}_obs = max($cloud_risk.{fam}_obs)",
            f"    ${p}_avg = max($cloud_risk.{fam}_avg)",
            f"    ${p}_std = max($cloud_risk.{fam}_std)",
            f"    ${p}_days = max($cloud_risk.{fam}_days)",
            f"    ${p}_flr = math.sqrt(if(${p}_avg > 1.0, ${p}_avg, 1.0))",
            f"    ${p}_sd = if(${p}_std > ${p}_flr, ${p}_std, ${p}_flr)",
            f"    $z{p}_u = (${p}_obs - ${p}_avg) / ${p}_sd",
            f"    $z_{fam} = if(${p}_days >= {min_days}, $z{p}_u, 0.0)",
        ]
      a, b = pair[0][1], pair[1][1]
      out += [
          f"    ${a}{b}_obs = ${a}_obs + ${b}_obs",
          f"    ${a}{b}_avg = ${a}_avg + ${b}_avg",
          f"    ${a}{b}_std = ${a}_std + ${b}_std",
          "}",
          "",
      ]
      return out

    union = " or\n        ".join(filters[fam] for fam, _, _ in families)
    lines = [
        "// Fleetwide Sector 2: User Cloud Infrastructure CRUD (4-Family Read, Write, Create, Delete)",
        INLINE_QUERY_SOURCE,
        "// Goal: Fleetwide per-family resource_* baseline departure (peak family Z)",
        f"// Statistical Model: STANDARD_Z_SCORE per family (count floor, {min_days}-active-day maturity gate)",
        "stage cloud_risk {",
        "    (",
        f"        {union}",
        "    )",
        "    principal.user.userid = $user",
        "    metadata.vendor_name = $v",
        "    metadata.product_name = $p",
        '    $user != ""',
        '    not re.regex(principal.user.userid, "\\\\$$")',
        "",
        "  match:",
        "    $user, $v, $p by 1d",
        "",
        "  outcome:",
        *stage_outcome,
        "}",
        "",
        *rollup("cloud_rw", families[:2]),
        *rollup("cloud_cd", families[2:]),
        "$user = $cloud_rw.user",
        "$user = $cloud_cd.user",
        "",
        "match:",
        "  $user by 1d",
        "",
        "outcome:",
        "  $z_read = max($cloud_rw.z_read)",
        "  $z_write = max($cloud_rw.z_write)",
        "  $z_create = max($cloud_cd.z_create)",
        "  $z_delete = max($cloud_cd.z_delete)",
        "  $z_rw = if($z_read >= $z_write, $z_read, $z_write)",
        "  $z_cd = if($z_create >= $z_delete, $z_create, $z_delete)",
        "  $z = if($z_rw >= $z_cd, $z_rw, $z_cd)",
        "  $observed = max($cloud_rw.rw_obs) + max($cloud_cd.cd_obs)",
        "  $baseline = max($cloud_rw.rw_avg) + max($cloud_cd.cd_avg)",
        "  $dispersion = max($cloud_rw.rw_std) + max($cloud_cd.cd_std)",
        "",
        "condition:",
        f"  {gate}",
        "",
        "order:",
        "  $z desc",
        "",
    ]
    return "\n".join(lines)

  def _radar_sector_queries(self, entity: str, is_host: bool) -> Dict[str, str]:
    """The 6 single-entity 360° sector queries.

    USER: the canonical templates/radar_360/ files, verbatim except for the entity. ASSET: the
    canonical alert spoke (radar_360_sector_alert.yl2, scoped to the host) plus catalog-driven
    spokes for the sectors that have no canonical host template.
    """
    if not is_host:
      esc = _escape_literal(entity)
      return {sector: self._render(tpl, {"entity_id": esc}) for sector, tpl in self.USER_SECTOR_TEMPLATES.items()}
    queries: Dict[str, str] = {}
    for sector, metric in self.ASSET_SECTOR_METRICS.items():
      if sector == "Alerts":
        queries[sector] = self._scope(self._render(self.ASSET_ALERT_SECTOR_TEMPLATE, {}), entity, "ASSET")
      else:
        stage, title = self._ASSET_INLINE_SECTORS[sector]
        queries[sector] = self._inline_sector_query(metric, stage, title, "ASSET", entity=entity)
    return queries

  # ---------------------------------------------------------------------------
  # Identity resolution and fusion specs
  # ---------------------------------------------------------------------------

  @staticmethod
  def extract_email_local_part(identifier: str) -> Optional[str]:
    """Returns the local username part of a corporate email address (excluding GCP service accounts)."""
    raw = (identifier or "").strip()
    if "@" not in raw:
      return None
    local_part, domain = raw.split("@", 1)
    local_part = local_part.strip()
    domain_lower = domain.strip().lower()
    if not local_part or not domain_lower:
      return None
    if domain_lower.endswith(".gserviceaccount.com") or domain_lower.endswith(".iam") or ".iam." in domain_lower:
      return None
    return local_part

  async def resolve_user_identifier(
      self,
      session: ClientSession,
      username: str,
      lookback_days: int = 14,
  ) -> str:
    """Resolves a corporate email address to its canonical UDM user.userid (identity spot-check).

    The spot-check covers the trailing `lookback_days` up to now (it identifies the entity; it is not
    a scored window) and matches case-insensitively, as the skill's 14-day UDM spot-check does.
    """
    local_part = self.extract_email_local_part(username)
    if not local_part:
      return username
    now = self._now()
    start_iso = _iso(now - timedelta(days=max(1, int(lookback_days or 14))))
    end_iso = _iso(now)
    esc = _escape_literal(username)
    probe_query = "\n".join([
        INLINE_QUERY_SOURCE,
        f'(principal.user.userid = "{esc}" nocase or principal.user.email_addresses = "{esc}" nocase or '
        f'target.user.userid = "{esc}" nocase or target.user.email_addresses = "{esc}" nocase)',
        "$uid = strings.coalesce(principal.user.userid, target.user.userid)",
        '$uid != ""',
        "match:",
        "  $uid",
        "outcome:",
        "  $cnt = count(metadata.id)",
        "order:",
        "  $cnt desc",
        "limit: 5",
    ])
    try:
      resp = await self.runner.execute_query_via_mcp(session, probe_query, start_iso, end_iso)
      rows = self.runner.parse_stats_response(resp)
      for row in rows:
        uid = str(row.get("uid") or row.get("$uid") or "").strip()
        if uid and uid.lower() != username.lower():
          logger.info(f"Resolved email '{username}' -> user.userid '{uid}' via UDM identity probe.")
          return uid
        if uid:
          return uid
    except Exception as err:
      logger.debug(f"Identity resolution probe failed for '{username}' ({err}); falling back to '{local_part}'.")
    return local_part

  def resolve_compatible_fusion_specs(
      self,
      metrics: Sequence[str],
      entity_type: str = "USER",
      identifier_field: Optional[str] = None,
  ) -> Tuple[Any, Any]:
    """Resolves two metric names into validated, leaf-aligned SectorSpec instances for fusion."""
    mc = self.runner.get_malachite_catalog()
    router = self.runner.get_template_router()
    ent_enum = self._resolve_entity_enum(entity_type)

    if len(metrics) < 2:
      metrics = list(router.DEFAULT_FUSION_METRICS)
    m_a, m_b = metrics[0], metrics[1]

    field_a = router._sector_entity_field(m_a, ent_enum, identifier_field)
    field_b = router._sector_entity_field(m_b, ent_enum, identifier_field)

    # Auto-align identifier leaf across user/device fields if needed (e.g. userid <-> userid)
    leaf_a = field_a.rsplit(".", 1)[-1] if "." in field_a else ""
    leaf_b = field_b.rsplit(".", 1)[-1] if "." in field_b else ""
    if leaf_a and leaf_b and leaf_a != leaf_b:
      try:
        candidate_b = mc.with_identifier(field_b, leaf_a)
        field_b = router._sector_entity_field(m_b, ent_enum, candidate_b)
      except Exception:
        pass

    spec_a = mc.SectorSpec(m_a, field_a)
    spec_b = mc.SectorSpec(m_b, field_b)
    check = mc.check_fusion_pair(spec_a, spec_b)
    if not check.ok:
      raise ValueError("Incompatible fusion pair: " + " ".join(check.errors))
    return spec_a, spec_b

  # ---------------------------------------------------------------------------
  # 360° behavioral radar and sector fusion
  # ---------------------------------------------------------------------------

  async def run_360_behavioral_radar(
      self,
      session: ClientSession,
      username: str,
      lookback_days: int = 14,
      entity_type: str = "USER",
      prefer_latest_day: bool = False,
      today_so_far: bool = False,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Profiles a user or host across the 6 canonical 360° sectors via decoupled micro-queries.

    USER sectors run the canonical templates/radar_360/ queries; host sectors run the canonical alert
    spoke plus catalog-driven spokes. Sector Z-scores (maturity-gated, dispersion-floored) are fused
    client-side into D = sqrt(sum max(0, Z_i)^2) and the harness CRI(D).
    """
    win = self._evaluation_window(lookback_days, today_so_far=today_so_far, now_utc=now_utc)
    start_iso, end_iso = win["start"], win["end"]
    default_bucket_date = win["scored_day"]
    is_host = self._is_asset(entity_type)
    sector_metric_map = self.ASSET_SECTOR_METRICS if is_host else self.USER_SECTOR_METRICS
    sector_queries = self._radar_sector_queries(username, is_host)
    min_days = harness_truth.min_baseline_days()
    gates = self.gate_thresholds()
    spoke_z = float(getattr(self.runner.tenant, "fleet_360_spoke_inclusion_z", 2.0))

    SectorRow = Tuple[str, float, int, Optional[float], Optional[float], Optional[float]]

    def _parse_sector_row(sector: str, row: Dict[str, Any]) -> SectorRow:
      raw_tb = str(
          row.get("TIME_BUCKET")
          or row.get("time_bucket")
          or row.get("bucket_date")
          or row.get("$TIME_BUCKET")
          or ""
      ).strip()
      row_day = (
          raw_tb[:10]
          if len(raw_tb) >= 10 and raw_tb[4] == "-" and raw_tb[7] == "-"
          else ""
      )
      obs_val = self._num(row, "observed", "obs") or 0.0
      avg_val = self._num(row, "baseline", "avg", "baseline_avg")
      std_val = self._num(row, "dispersion", "std", "baseline_std")
      days_val = self._num(row, "active_days", "days")
      z_val = self._num(row, "z", "z_score")
      if z_val is None:
        z_val = (
            self._fallback_z(obs_val, avg_val, std_val, sector_metric_map.get(sector))
            if avg_val is not None
            else 0.0
        )
      if days_val is not None and days_val < min_days:
        z_val = 0.0  # immature baseline: mirrors the sector query's $active_days gate
      return row_day, z_val, int(obs_val), avg_val, std_val, days_val

    async def _query_sector(sector_name: str, q_str: str) -> Tuple[str, List[SectorRow]]:
      try:
        resp = await self.runner.execute_query_via_mcp(session, q_str, start_iso, end_iso)
        rows = self.runner.parse_stats_response(resp)
        if rows:
          return sector_name, [_parse_sector_row(sector_name, r) for r in rows]
      except Exception as err:
        logger.warning(f"Sector query failed for {sector_name} ({err}); defaulting to 0.0")
      return sector_name, []

    # Execute queries sequentially to preserve single MCP stream stability
    sector_rows_map: Dict[str, List[SectorRow]] = {}
    for name, q_str in sector_queries.items():
      s_name, parsed_rows = await _query_sector(name, q_str)
      sector_rows_map[s_name] = parsed_rows

    # Align sector vectors on a single synchronous calendar day when TIME_BUCKET is present
    day_sector_map: Dict[str, Dict[str, Tuple[float, int, Optional[float], Optional[float], Optional[float]]]] = {}
    for s_name, parsed_rows in sector_rows_map.items():
      for row_day, z_val, obs_val, avg_val, std_val, days_val in parsed_rows:
        if row_day:
          day_bucket = day_sector_map.setdefault(row_day, {})
          if s_name not in day_bucket or z_val > day_bucket[s_name][0]:
            day_bucket[s_name] = (z_val, obs_val, avg_val, std_val, days_val)

    empty = (0.0, 0, None, None, None)
    if day_sector_map:
      if prefer_latest_day:
        evaluated_day = max(day_sector_map.keys())
      else:
        evaluated_day = max(
            day_sector_map.keys(),
            key=lambda d: (
                round(
                    self.runner.compute_euclidean_distance(
                        {s: vals[0] for s, vals in day_sector_map[d].items()}
                    ),
                    6,
                ),
                d,
            ),
        )
      chosen = {name: day_sector_map[evaluated_day].get(name, empty) for name in sector_queries}
    else:
      evaluated_day = default_bucket_date
      chosen = {
          name: (sector_rows_map[name][0][1:] if sector_rows_map.get(name) else empty)
          for name in sector_queries
      }

    z_scores = {name: vals[0] for name, vals in chosen.items()}
    observed_counts = {name: vals[1] for name, vals in chosen.items()}
    baseline_avgs = {name: vals[2] for name, vals in chosen.items()}
    baseline_stds = {name: vals[3] for name, vals in chosen.items()}
    active_days = {name: (None if vals[4] is None else int(vals[4])) for name, vals in chosen.items()}

    composite_d = self.runner.compute_euclidean_distance(z_scores)
    cri = self._cri(composite_d)
    verdict = harness_truth.verdict_for(cri)
    sorted_sectors = sorted(z_scores.items(), key=lambda x: x[1], reverse=True)
    top_sector = sorted_sectors[0][0] if sorted_sectors else "Auth"
    outlier_sectors = [s_name for s_name, z_val in sorted_sectors if z_val >= spoke_z]
    subthreshold_sectors = [s_name for s_name, z_val in sorted_sectors if 1.25 <= z_val < spoke_z]
    dormant_awakening_sectors = [
        s_name
        for s_name, z_val in sorted_sectors
        if observed_counts.get(s_name, 0) > 0
        and baseline_avgs.get(s_name) is not None
        and baseline_avgs[s_name] < 1.0
        and z_val >= 1.5
    ]
    variance_masked_sectors = [
        s_name
        for s_name, z_val in sorted_sectors
        if 1.25 <= z_val < gates["anomaly_threshold"]
        and baseline_stds.get(s_name) is not None
        and baseline_stds[s_name] >= max((baseline_avgs.get(s_name) or 0.0) * 1.5, 5.0)
    ]

    return {
        "entity": username,
        "entity_type": entity_type.upper(),
        "evaluated_day": evaluated_day,
        "composite_d": round(composite_d, 2),
        "calibrated_risk_index": cri,
        "top_sector": top_sector,
        "outlier_sectors": outlier_sectors,
        "subthreshold_sectors": subthreshold_sectors,
        "dormant_awakening_sectors": dormant_awakening_sectors,
        "variance_masked_sectors": variance_masked_sectors,
        "sector_metrics": dict(sector_metric_map),
        "is_outlier": verdict in self._outlier_verdicts(),
        "sector_z_scores": {k: round(v, 2) for k, v in z_scores.items()},
        "sector_cri_scores": {k: self._cri(v) for k, v in z_scores.items()},
        "sector_observed_counts": observed_counts,
        "sector_baseline_avg": {k: round(v or 0.0, 2) for k, v in baseline_avgs.items()},
        "sector_baseline_std": {k: round(v or 0.0, 2) for k, v in baseline_stds.items()},
        "sector_active_days": active_days,
        "verdict": verdict,
        "severity": self.derive_cri_severity(cri),
        "evaluation_window": win,
        "executed_queries": dict(sector_queries),
    }

  async def run_sector_fusion(
      self,
      session: ClientSession,
      entity: str,
      entity_type: str = "USER",
      fusion_metrics: Optional[Sequence[str]] = None,
      four_stage: bool = False,
      identifier_field: Optional[str] = None,
      lookback_days: int = 14,
      hypothesis_goal: Optional[str] = None,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Executes generic 3-stage/4-stage Cross-Vector or Roll-Up Sector Fusion for ANY two compatible metrics."""
    router = self.runner.get_template_router()
    spec_a, spec_b = self.resolve_compatible_fusion_specs(
        fusion_metrics or router.DEFAULT_FUSION_METRICS,
        entity_type=entity_type,
        identifier_field=identifier_field,
    )
    gates = self.gate_thresholds()
    rendered = router.build_sector_fusion_query(
        sector_a=spec_a,
        sector_b=spec_b,
        four_stage=four_stage,
        min_baseline_days=harness_truth.min_baseline_days(),
        hypothesis_goal=hypothesis_goal or f"Cross-Vector Fusion ({spec_a.metric} + {spec_b.metric}) for {entity}",
        fusion_threshold_sq=gates["fusion_threshold_sq"],
    )
    rendered = self._scope(rendered, entity, entity_type)
    win = self._evaluation_window(lookback_days, now_utc=now_utc)
    rendered, win = self._apply_ecg_window(rendered, lookback_days, now_utc, win)

    resp = await self.runner.execute_query_via_mcp(session, rendered, win["start"], win["end"])
    rows = self.runner.parse_stats_response(resp)
    top_row = dict(rows[0]) if rows else {}
    z_a = self._num(top_row, "z_a_gated", "z_a", "sector_a_z")
    z_b = self._num(top_row, "z_b_gated", "z_b", "sector_b_z")
    obs_a = self._num(top_row, "a_observed") or 0.0
    obs_b = self._num(top_row, "b_observed") or 0.0
    primary = self._primary_score_key(rendered) or "composite_threat_norm_sq"
    if rows and self._num(top_row, primary, "fleet_adjusted_threat_norm_sq") is None:
      direct_d = self._num(top_row, "composite_threat_score")
      if direct_d is not None:
        top_row[primary] = direct_d * direct_d
      elif z_a is not None or z_b is not None:
        # Rectified Euclidean fusion: quiet (negative) sectors never inflate D.
        top_row[primary] = max(0.0, z_a or 0.0) ** 2 + max(0.0, z_b or 0.0) ** 2
    score = self._score(top_row, primary, extra_keys=("fleet_adjusted_threat_norm_sq",), use_priority=False)
    composite_d = score["score"]
    is_rollup = spec_a.is_rollup or spec_b.is_rollup
    if is_rollup:
      model_label = "ROLLUP_SECTOR_FUSION_5STAGE" if four_stage else "ROLLUP_SECTOR_FUSION_4STAGE"
      template_name = "rollup_sector_fusion_5stage.yl2" if four_stage else "rollup_sector_fusion_4stage.yl2"
    else:
      model_label = "MULTI_SECTOR_FUSION_4STAGE" if four_stage else "DUAL_SECTOR_FUSION_3STAGE"
      template_name = "multi_sector_fusion_4stage.yl2" if four_stage else "dual_sector_fusion_3stage.yl2"

    return {
        "entity": entity,
        "entity_type": entity_type,
        "model": model_label,
        "template_name": template_name,
        "fusion_metrics": [spec_a.metric, spec_b.metric],
        "is_rollup": is_rollup,
        "z_a": round(z_a or 0.0, 2),
        "z_b": round(z_b or 0.0, 2),
        "sector_a_z": round(z_a or 0.0, 2),
        "sector_b_z": round(z_b or 0.0, 2),
        "a_observed": obs_a,
        "b_observed": obs_b,
        "composite_d": round(composite_d, 2),
        "composite_threat_score": round(composite_d, 2),
        "top_z_score": round(composite_d, 2),
        **self._score_fields(score),
        "stats_rows": len(rows),
        "advisories": list(getattr(router, "last_advisories", [])),
        "evaluation_window": win,
        "executed_query": rendered,
    }

  def _render_rare_destination_ecg_query(
      self,
      target_metric: str = "dns_queries_total",
      host_field: str = "principal.asset.hostname",
      max_fleet_prevalence: int = 3,
      hypothesis_goal: Optional[str] = None,
      scored_day: Optional[date] = None,
  ) -> str:
    """Renders rare_destination_ecg_3stage.yl2 for DNS / HTTP / outbound-IP destinations.

    Event stages are pinned to the scored UTC day (Mode A D by default); run it over
    harness_truth.ecg_window(D). Byte metrics use the skill's byte dispersion floor.
    """
    mc = self.runner.get_malachite_catalog()
    sem = mc.baseline_semantics(target_metric)
    sector_filter = "\n    ".join(sem.observed_filter)

    def metric_func(agg: str) -> str:
      return (f"metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: {agg}, "
              f"{host_field}: {host_field})")

    if "dns" in target_metric:
      contact_sem = mc.baseline_semantics("dns_queries_total")
      dest_field = "network.dns.questions.name"
      ecg_entity_type = '"DOMAIN_NAME"'
      ecg_key_path = "entity.domain.name"
      ecg_prevalence_path = "entity.domain.prevalence"
    elif "http" in target_metric:
      contact_sem = mc.baseline_semantics("http_queries_total")
      dest_field = "target.hostname"
      ecg_entity_type = '"DOMAIN_NAME"'
      ecg_key_path = "entity.domain.name"
      ecg_prevalence_path = "entity.domain.prevalence"
    else:
      contact_sem = mc.baseline_semantics("network_bytes_outbound")
      dest_field = "target.ip"
      ecg_entity_type = '"IP_ADDRESS"'
      ecg_key_path = "entity.artifact.ip"
      ecg_prevalence_path = "entity.artifact.prevalence"

    day = scored_day or harness_truth.mode_a_day()
    rendered = self._render(
        "rare_destination_ecg_3stage.yl2",
        {
            "sector_filter": sector_filter,
            "host_field": host_field,
            "sector_observation_agg": sem.observed_agg,
            "sector_metric_func_avg": metric_func("avg"),
            "sector_metric_func_stddev": metric_func("stddev"),
            "sector_metric_func_active_days": metric_func("num_metric_periods"),
            "contact_filter": "\n    ".join(contact_sem.observed_filter),
            "dest_field": dest_field,
            "ecg_entity_type": ecg_entity_type,
            "ecg_key_path": ecg_key_path,
            "ecg_prevalence_path": ecg_prevalence_path,
            "max_fleet_prevalence": str(max_fleet_prevalence),
            "today_date": day.isoformat(),
        },
    )
    rendered = self._apply_byte_floor(rendered, target_metric, ("$dispersion_floor",))
    if hypothesis_goal:
      rendered = f"// Goal: {hypothesis_goal}\n" + rendered
    return rendered

  def _render_fusion_rare_destination_query(
      self,
      sector_a_metric: str = "dns_queries_total",
      sector_b_metric: str = "http_queries_total",
      host_field: str = "principal.asset.hostname",
      max_fleet_prevalence: int = 3,
      hypothesis_goal: Optional[str] = None,
      scored_day: Optional[date] = None,
  ) -> str:
    """Renders fusion_rare_destination_3stage.yl2 (sector A + per-destination sector B + Entity Graph)."""
    mc = self.runner.get_malachite_catalog()
    sem_a = mc.baseline_semantics(sector_a_metric)
    sem_b = mc.baseline_semantics(sector_b_metric)
    dest_field = "network.dns_domain" if "dns" in sector_b_metric else "target.hostname"

    def func_a(agg: str) -> str:
      return (f"metrics.{sector_a_metric}(period: 1d, window: 30d, metric: {sem_a.metric_arg}, agg: {agg}, "
              f"{host_field}: {host_field})")

    def func_b(agg: str) -> str:
      return (f"metrics.{sector_b_metric}(period: 1d, window: 30d, metric: {sem_b.metric_arg}, agg: {agg}, "
              f"{host_field}: {host_field}, {dest_field}: {dest_field})")

    day = scored_day or harness_truth.mode_a_day()
    rendered = self._render(
        "fusion_rare_destination_3stage.yl2",
        {
            "host_field": host_field,
            "sector_a_filter": "\n    ".join(sem_a.observed_filter),
            "sector_a_observation_agg": sem_a.observed_agg,
            "sector_a_metric_func_avg": func_a("avg"),
            "sector_a_metric_func_stddev": func_a("stddev"),
            "sector_a_metric_func_active_days": func_a("num_metric_periods"),
            "sector_b_filter": "\n    ".join(sem_b.observed_filter),
            "dest_field": dest_field,
            "sector_b_observation_agg": sem_b.observed_agg,
            "sector_b_metric_func_avg": func_b("avg"),
            "sector_b_metric_func_stddev": func_b("stddev"),
            "sector_b_metric_func_active_days": func_b("num_metric_periods"),
            "ecg_entity_type": '"DOMAIN_NAME"',
            "ecg_key_path": "entity.domain.name",
            "ecg_prevalence_path": "entity.domain.prevalence",
            "max_fleet_prevalence": str(max_fleet_prevalence),
            "today_date": day.isoformat(),
        },
    )
    rendered = self._apply_byte_floor(rendered, sector_a_metric, ("$a_floor",))
    rendered = self._apply_byte_floor(rendered, sector_b_metric, ("$b_floor",))
    if hypothesis_goal:
      rendered = f"// Goal: {hypothesis_goal}\n" + rendered
    return rendered

  # ---------------------------------------------------------------------------
  # Dynamic single-metric models and multi-stage pipelines
  # ---------------------------------------------------------------------------

  @staticmethod
  def _normalize_model_name(name: Any) -> str:
    return str(getattr(name, "value", name) or "").strip().upper().replace("-", "_").replace(" ", "_")

  def _resolve_statistical_model(self, model_upper: str) -> Tuple[str, Any]:
    """(request passed to the router, StatisticalModel) via the skill's own resolver.

    Unknown names, hand-off aliases (circadian / jitter) and retired models raise the skill's ValueError;
    there is no silent fallback to another model.
    """
    request = self._STAT_MODEL_ALIASES.get(model_upper, model_upper)
    resolved = self.runner.get_hybrid_engine().resolve_statistical_model(request)
    return request, resolved

  def _sector_fusion_shape(self, model_upper: str) -> Optional[bool]:
    """run_sector_fusion's four_stage flag when `model_upper` names a sector-fusion model, else None.

    Sector-fusion names are run_sector_fusion's own labels plus the skill's sector-fusion aliases
    (ueba_hybrid_engine.MODEL_IMPLIED_ARCHITECTURE -> "sector_fusion"). Any other name that merely contains
    FUSION (e.g. a secops-statistical-hunter archetype) is not a sector fusion: it goes to the skill's resolver,
    which refuses unknown models.
    """
    if model_upper in self._SECTOR_FUSION_LABELS:
      return self._SECTOR_FUSION_LABELS[model_upper]
    if self.runner.get_hybrid_engine().MODEL_IMPLIED_ARCHITECTURE.get(model_upper) == "sector_fusion":
      return "MULTI" in model_upper
    return None

  async def run_dynamic_metric_pipeline(
      self,
      session: ClientSession,
      entity: str,
      entity_type: str = "USER",
      target_metric: str = "workspace_total_download_actions",
      model_name: str = "LONGITUDINAL_CUSUM_DRIFT",
      identifier_field: Optional[str] = None,
      fusion_metrics: Optional[Sequence[str]] = None,
      lookback_days: int = 14,
      hypothesis_goal: Optional[str] = None,
      metric_name: Optional[str] = None,
      model: Optional[str] = None,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Dynamically builds and executes ANY 2-stage math model or multi-stage pipeline on ANY catalog metric.

    Retired models are refused with the skill's message before any query runs, and unknown model names raise
    (the skill's resolver decides; nothing silently falls back to another model). The score is the variable
    the rendered query's root gate tests, mapped onto the harness Z-equivalent scale for the CRI.
    """
    if metric_name:
      target_metric = metric_name
    if model:
      model_name = model

    model_upper = self._normalize_model_name(model_name or "STANDARD_Z_SCORE")
    harness_truth.assert_not_retired(model_upper)
    model_upper = self._MODEL_LABEL_ALIASES.get(model_upper, model_upper)

    EntityType, PipelineArchitecture, StatisticalModel, _ = self.runner.get_validator_enums()
    mc = self.runner.get_malachite_catalog()
    router = self.runner.get_template_router()
    ent_enum = self._resolve_entity_enum(entity_type)
    gates = self.gate_thresholds()
    min_days = harness_truth.min_baseline_days()

    # 1. Cross-Vector or Roll-Up Sector Fusion, for sector-fusion model names only
    #    (FUSION_RARE_DESTINATION_3STAGE uses the Entity Graph path below).
    four_stage = self._sector_fusion_shape(model_upper)
    if four_stage is not None:
      metrics_pair = list(fusion_metrics) if fusion_metrics and len(fusion_metrics) >= 2 else [
          target_metric or "workspace_total_download_actions",
          "network_bytes_outbound" if target_metric != "network_bytes_outbound" else "http_queries_total",
      ]
      return await self.run_sector_fusion(
          session=session,
          entity=entity,
          entity_type=entity_type,
          fusion_metrics=metrics_pair,
          four_stage=four_stage,
          identifier_field=identifier_field,
          lookback_days=lookback_days,
          hypothesis_goal=hypothesis_goal,
          now_utc=now_utc,
      )

    # Validate / fallback target_metric against catalog & entity_type
    if target_metric not in mc.known_metrics():
      target_metric = "workspace_total_download_actions" if ent_enum == EntityType.USER else "http_queries_total"

    # Derived-prevalence & hybrid pipeline metric-compatibility guards:
    # - HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE is strictly for HTTP request counts (http_queries_total).
    #   DNS volume (dns_*) or outbound bytes (network_bytes_*) against rare destinations route to RARE_DESTINATION_ECG_3STAGE.
    pipeline_name = self._PIPELINE_ALIASES.get(model_upper)
    if pipeline_name == "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE":
      if not target_metric.startswith("http_"):
        model_upper = "RARE_DESTINATION_ECG_3STAGE"
        pipeline_name = None
      else:
        ent_enum = EntityType.ASSET
    elif pipeline_name in ("HYBRID_METRIC_FLEET_PREVALENCE_2STAGE", "HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE"):
      if not target_metric.startswith("file_executions_"):
        target_metric = "file_executions_total"
    elif pipeline_name == "HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE":
      if not (target_metric.startswith("http_queries_") or target_metric.startswith("dns_queries_")):
        target_metric = "http_queries_total"
      ent_enum = EntityType.ASSET
    elif pipeline_name in ("HTTP_TARGET_SURGE_2STAGE", "HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE"):
      target_metric = "http_queries_total"
      ent_enum = EntityType.ASSET
    elif pipeline_name == "HTTP_ERROR_RATIO_SURGE_2STAGE":
      if not target_metric.endswith("_fail"):
        target_metric = "http_queries_fail"
      ent_enum = EntityType.ASSET
    elif model_upper in ("HYBRID_DATA_TABLE_BRIDGE_2STAGE", "DATA_TABLE_BRIDGE"):
      target_metric = "network_bytes_outbound"
      ent_enum = EntityType.ASSET
    elif pipeline_name == "HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE":
      from scripts.preflight_validator import METRIC_CATALOG as _MC_CAT
      if EntityType.ASSET not in _MC_CAT[target_metric].supported_entity_types or mc.is_composite_only(target_metric):
        target_metric = "auth_attempts_total"
      ent_enum = EntityType.ASSET

    # Ensure entity_type is supported for target_metric; adjust if needed
    from scripts.preflight_validator import METRIC_CATALOG
    if ent_enum not in METRIC_CATALOG[target_metric].supported_entity_types:
      ent_enum = METRIC_CATALOG[target_metric].supported_entity_types[0]

    # 2. Route: Entity Graph renders, data-table bridge, router pipelines, or a Stage 2 statistical model
    stat_request: Any = None
    stat_enum: Any = None
    kind = "standard"
    if model_upper in ("RARE_DESTINATION_ECG_3STAGE", "RARE_DESTINATION_ECG"):
      route = "rare_destination"
    elif model_upper in ("FUSION_RARE_DESTINATION_3STAGE", "FUSION_RARE_DESTINATION"):
      route = "fusion_rare_destination"
    elif model_upper in ("HYBRID_DATA_TABLE_BRIDGE_2STAGE", "DATA_TABLE_BRIDGE"):
      route = "data_table_bridge"
    elif pipeline_name:
      # The router validates metric / pipeline compatibility itself (composite-only metrics such as
      # resource_* and file_executions_* are what the repository-scope and prevalence pipelines need).
      route = "pipeline"
    else:
      route = "model"
      stat_request, stat_enum = self._resolve_statistical_model(model_upper)
      if stat_enum in (StatisticalModel.MAD, StatisticalModel.QUANTILE_IQR_SKEW):
        kind = "robust"
      elif stat_enum == StatisticalModel.LONGITUDINAL_CUSUM:
        kind = "cusum"

    win = self._evaluation_window(lookback_days, kind=kind, now_utc=now_utc)
    model_label = stat_enum.value if stat_enum is not None else model_upper
    goal = hypothesis_goal or f"{model_label} on {target_metric} for {entity}"

    if route in ("rare_destination", "fusion_rare_destination"):
      ecg_win = self._evaluation_window(lookback_days, ecg=True, now_utc=now_utc)
      scored_day = date.fromisoformat(ecg_win["scored_day"])
      host_f = identifier_field if identifier_field and "asset" in identifier_field else "principal.asset.hostname"
      if route == "rare_destination":
        rendered = self._render_rare_destination_ecg_query(
            target_metric=target_metric,
            host_field=host_f,
            hypothesis_goal=hypothesis_goal or f"RARE_DESTINATION_ECG_3STAGE on {target_metric} for {entity}",
            scored_day=scored_day,
        )
      else:
        pair = list(fusion_metrics) if fusion_metrics and len(fusion_metrics) >= 2 else [target_metric, "http_queries_total"]
        rendered = self._render_fusion_rare_destination_query(
            sector_a_metric=pair[0],
            sector_b_metric=pair[1],
            host_field=host_f,
            hypothesis_goal=hypothesis_goal or f"FUSION_RARE_DESTINATION_3STAGE ({pair[0]} + {pair[1]}) for {entity}",
            scored_day=scored_day,
        )
    elif route == "data_table_bridge":
      rendered = self.runner.get_chained_hunt_router().build_data_table_bridge_query(
          entity_type=EntityType.ASSET,
          target_metric=target_metric,
          anomaly_threshold=gates["anomaly_threshold"],
          min_baseline_days=min_days,
      )
    elif route == "pipeline":
      pipe_arch = PipelineArchitecture[pipeline_name]
      rendered = router.build_pipeline_query(
          pipeline_type=pipe_arch,
          target_metric=target_metric,
          entity_type=ent_enum,
          hypothesis_goal=goal,
          target_entity=entity if pipe_arch in (
              PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL,
              PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
          ) else None,
          service_account=entity if pipe_arch == PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH else None,
          target_metrics=list(fusion_metrics) if fusion_metrics else None,
          identifier_field=identifier_field,
          anomaly_threshold=gates["anomaly_threshold"],
          fold_change_threshold=gates["fold_change_threshold"],
          fusion_threshold_sq=gates["fusion_threshold_sq"],
          tukey_excess_threshold=gates["tukey_excess_threshold"],
          min_baseline_days=min_days,
      )
    else:
      rendered = router.build_query(
          target_metric=target_metric,
          entity_type=ent_enum,
          statistical_model=stat_request,
          hypothesis_goal=goal,
          identifier_field=identifier_field,
          anomaly_threshold=gates["anomaly_threshold"],
          fold_change_threshold=gates["fold_change_threshold"],
          robust_threshold=gates["robust_threshold"],
          tukey_excess_threshold=gates["tukey_excess_threshold"],
          min_baseline_days=min_days,
          scoring_days=win["scored_days"],
          scoring_end_date=win["scoring_end_date"],
      )

    rendered = self._scope(rendered, entity, entity_type)
    rendered, win = self._apply_ecg_window(rendered, lookback_days, now_utc, win)
    resp = await self.runner.execute_query_via_mcp(session, rendered, win["start"], win["end"])
    rows = self.runner.parse_stats_response(resp)

    top_row = rows[0] if rows else {}
    maturity_column = self._maturity_gate_column(rendered)
    score = self._score(top_row, self._primary_score_key(rendered), maturity_column=maturity_column)
    if rows and score["score_key"] is None:
      obs = self._num(top_row, *self._OBSERVED_KEYS)
      avg = self._num(top_row, *self._BASELINE_KEYS)
      if obs is not None and avg is not None:
        fallback_row = {"z_score": self._fallback_z(obs, avg, self._num(top_row, *self._DISPERSION_KEYS), target_metric)}
        if maturity_column and self._num(top_row, maturity_column) is not None:
          fallback_row[maturity_column] = self._num(top_row, maturity_column)
        score = self._score(fallback_row, "z_score", maturity_column=maturity_column, use_priority=False)

    observed_val = self._num(top_row, *self._OBSERVED_KEYS) or 0.0
    hist_avg = self._num(top_row, *self._BASELINE_KEYS) or 0.0
    modified_z = self._num(top_row, "modified_z")
    result_dict: Dict[str, Any] = {
        "entity": entity,
        "entity_type": entity_type,
        "model": model_upper,
        "statistical_model": stat_enum.value if stat_enum is not None else None,
        "model_label": router.MODEL_DESCRIPTIONS.get(stat_enum) if stat_enum is not None else None,
        "target_metric": target_metric,
        "top_z_score": round(score["score"], 2),
        "modified_z": round(modified_z, 2) if modified_z is not None else None,
        "z_gap": round(self._num(top_row, "z_gap") or 0.0, 2),
        "observed_value": observed_val,
        "baseline_avg": round(hist_avg, 2),
        **self._score_fields(score),
        "active_days": score["active_days"],
        "stats_rows": len(rows),
        "advisories": list(getattr(router, "last_advisories", [])),
        "evaluation_window": win,
        "executed_query": rendered,
    }
    for q_key in ("tukey_excess_z", "tukey_fence_ratio", "bowley_skew", "tail_heaviness", "adj_upper_fence",
                  "robust_scale", "q25_val", "q50_val", "q75_val", "iqr", "personal_z"):
      q_val = self._num(top_row, q_key)
      if q_val is not None:
        result_dict[q_key] = round(q_val, 3)
    drift_days = self._num(top_row, "drift_days")
    if drift_days is not None:
      result_dict["drift_days"] = int(drift_days)
    max_daily_z = self._num(top_row, "max_daily_z")
    if max_daily_z is not None:
      result_dict["max_daily_z"] = round(max_daily_z, 2)
    novelty = self._num(top_row, "novelty_flag")
    if novelty is not None:
      result_dict["novelty_flag"] = int(novelty)
      result_dict["cri_applicable"] = score["cri_applicable"]
    return result_dict

  async def run_quantile_iqr_skew(
      self,
      session: ClientSession,
      entity: str,
      entity_type: str = "ASSET",
      target_metric: str = "network_bytes_outbound",
      identifier_field: Optional[str] = None,
      lookback_days: int = 30,
      hypothesis_goal: Optional[str] = None,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Executes the 3-Stage Empirical Quantiles (window.percentile), Bowley Skewness & Skew-Adjusted Tukey pipeline.

    The raw search window always spans the 30-day empirical baseline; `lookback_days` sets the scored
    days (Mode A for 1, Mode B otherwise, capped by the skill). Scored as $tukey_excess_z.
    """
    return await self.run_dynamic_metric_pipeline(
        session=session,
        entity=entity,
        entity_type=entity_type,
        target_metric=target_metric,
        model_name="QUANTILE_IQR_SKEW",
        identifier_field=identifier_field,
        lookback_days=lookback_days,
        hypothesis_goal=hypothesis_goal
        or f"3-Stage Quantile IQR, Bowley Skewness & Hubert-Vandervieren Tukey Fence ({target_metric}) for {entity}",
        now_utc=now_utc,
    )

  async def run_circadian_von_mises(
      self,
      session: ClientSession,
      entity: str,
      metric_name: str = "auth_attempts_total",
      event_type: str = "USER_LOGIN",
      dimension_key: str = "target.user.userid",
      lookback_days: int = 14,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Retired (skill v2.3.0 D1 / PF-10): always refuses with the skill's retirement message.

    Daily metrics.* baselines carry no per-hour circadian state; off-hours profiling is
    secops-statistical-hunter HOUR_OF_DAY_PROFILE. No query is built or dispatched.
    """
    del session, entity, metric_name, event_type, dimension_key, lookback_days, now_utc
    harness_truth.assert_not_retired("circadian_von_mises_2stage.yl2")
    harness_truth.assert_not_retired("CIRCADIAN_VON_MISES")
    raise ValueError(
        "CIRCADIAN_VON_MISES is not provided by secops-risk-metrics-multistage; hand off to "
        "secops-statistical-hunter HOUR_OF_DAY_PROFILE."
    )

  async def run_macd_momentum_velocity(
      self,
      session: ClientSession,
      entity: str,
      metric_name: str = "network_bytes_outbound",
      event_type: str = "NETWORK_CONNECTION",
      dimension_key: str = "principal.user.userid",
      lookback_days: int = 14,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Above-Historical-Max Z (formerly MACD Momentum Velocity; skill v2.3.0 D1 / WS1-02).

    Renders macd_momentum_velocity_2stage.yl2 through the skill router: personal Z plus the linear
    exceedance above the 30-day historical maximum, gated on the 7-active-day maturity floor. The
    catalog's observed event filter is used, so `event_type` is not needed. `fast_z` / `slow_z` are
    kept as transitional aliases of `personal_z` / `above_max_z` for existing case-wall cards.
    """
    del event_type
    EntityType, PipelineArchitecture, StatisticalModel, _ = self.runner.get_validator_enums()
    router = self.runner.get_template_router()
    key = (dimension_key or "").lower()
    ent_enum = EntityType.ASSET if ("asset" in key or "hostname" in key or key.endswith(".ip")) else EntityType.USER
    gates = self.gate_thresholds()
    rendered = router.build_pipeline_query(
        PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
        target_metric=metric_name,
        entity_type=ent_enum,
        identifier_field=dimension_key,
        anomaly_threshold=gates["anomaly_threshold"],
        min_baseline_days=harness_truth.min_baseline_days(),
        hypothesis_goal=f"Above-Historical-Max Z on {metric_name} for {entity}",
    )
    rendered = self._scope(rendered, entity, ent_enum.value)
    win = self._evaluation_window(lookback_days, now_utc=now_utc)
    resp = await self.runner.execute_query_via_mcp(session, rendered, win["start"], win["end"])
    rows = self.runner.parse_stats_response(resp)

    top_row = rows[0] if rows else {}
    score = self._score(top_row, self._primary_score_key(rendered),
                        maturity_column=self._maturity_gate_column(rendered))
    macd_z = self._num(top_row, "macd_z", "macd_momentum_score")
    personal_z = self._num(top_row, "personal_z") or 0.0
    above_max_z = self._num(top_row, "above_max_z") or 0.0
    return {
        "entity": entity,
        "model": "ABOVE_HISTORICAL_MAX_Z",
        "statistical_model": StatisticalModel.MACD_MOMENTUM_VELOCITY.value,
        "model_label": router.MODEL_DESCRIPTIONS.get(StatisticalModel.MACD_MOMENTUM_VELOCITY),
        "target_metric": metric_name,
        "macd_z": round(macd_z or 0.0, 2),
        "macd_momentum_score": round(macd_z or 0.0, 2),
        "personal_z": round(personal_z, 2),
        "above_max_z": round(above_max_z, 2),
        "fast_z": round(personal_z, 2),
        "slow_z": round(above_max_z, 2),
        "observed_value": self._num(top_row, "observed") or 0.0,
        "baseline_avg": round(self._num(top_row, "hist_avg") or 0.0, 2),
        "top_z_score": round(score["score"], 2),
        **self._score_fields(score),
        "stats_rows": len(rows),
        "evaluation_window": win,
        "executed_query": rendered,
    }

  async def run_hybrid_enrichment(
      self,
      session: ClientSession,
      username: str,
      macro_metric_avg: str = "metrics.auth_attempts_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: target.user.userid)",
      macro_metric_std: str = "metrics.auth_attempts_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: target.user.userid)",
      raw_signature_field: str = "principal.ip",
      lookback_days: int = 14,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Fuses 30-day macro baseline deviation with raw UDM micro-telemetry signatures.

    Fills hybrid_metric_raw_enrichment_2stage.yl2 (USER_LOGIN slot guidance: principal.ip /
    principal.asset.hostname signature) with the harness gate and maturity floor.
    """
    default_avg = "metrics.auth_attempts_total(period: 1d, window: 30d, metric: event_count_sum, agg: avg, target.user.userid: target.user.userid)"
    default_std = "metrics.auth_attempts_total(period: 1d, window: 30d, metric: event_count_sum, agg: stddev, target.user.userid: target.user.userid)"
    if "target.user.userid:" not in macro_metric_avg and "principal." not in macro_metric_avg:
      macro_metric_avg = default_avg
    if "target.user.userid:" not in macro_metric_std and "principal." not in macro_metric_std:
      macro_metric_std = default_std
    macro_metric_active = (
        macro_metric_avg.replace("agg: avg", "agg: num_metric_periods")
        if "agg: avg" in macro_metric_avg
        else default_avg.replace("agg: avg", "agg: num_metric_periods")
    )
    mc = self.runner.get_malachite_catalog()
    sem = mc.baseline_semantics("auth_attempts_total")
    esc = _escape_literal(username)
    gates = self.gate_thresholds()
    rendered = self._render(
        "hybrid_metric_raw_enrichment_2stage.yl2",
        {
            "macro_entity_field": "target.user.userid",
            "macro_event_filter": "\n    ".join([*sem.observed_filter, f'target.user.userid = "{esc}"']),
            "macro_observed_agg": sem.observed_agg,
            "target_metric_func_avg": macro_metric_avg,
            "target_metric_func_stddev": macro_metric_std,
            "target_metric_func_active_days": macro_metric_active,
            "raw_event_type": "USER_LOGIN",
            "raw_entity_field": "target.user.userid",
            "raw_event_filter": f'target.user.userid = "{esc}"',
            "raw_signature_field": raw_signature_field,
            "anomaly_threshold": gates["anomaly_threshold"],
            "min_baseline_days": harness_truth.min_baseline_days(),
            "min_raw_events": "5",
            "max_signature_diversity": "3",
        },
    )
    win = self._evaluation_window(lookback_days, now_utc=now_utc)
    resp = await self.runner.execute_query_via_mcp(session, rendered, win["start"], win["end"])
    rows = self.runner.parse_stats_response(resp)

    top_row = rows[0] if rows else {}
    score = self._score(top_row, self._primary_score_key(rendered),
                        maturity_column=self._maturity_gate_column(rendered))
    distinct_sigs = self._num(top_row, "signature_diversity", "distinct_signatures") or 0.0
    return {
        "entity": username,
        "model": "DUAL_PLANE_HYBRID_ENRICHMENT",
        "macro_z_score": round(score["score"], 2),
        "top_z_score": round(score["score"], 2),
        "distinct_micro_signatures": int(distinct_sigs),
        **self._score_fields(score),
        "stats_rows": len(rows),
        "evaluation_window": win,
        "executed_query": rendered,
    }

  async def run_data_table_bridge(
      self,
      session: ClientSession,
      entity: str = "*",
      data_table_name: str = "ueba_hunt_bridge",
      column_name: str = "entity",
      lookback_days: int = 14,
      target_metric: str = "network_bytes_outbound",
      entity_type: str = "ASSET",
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Scores 30-day behavioral metric departures for a bridged cohort stored in a SecOps Data Table.

    Built by the skill's ChainedHuntRouter.build_data_table_bridge_query; the canonical bridge column is
    `%ueba_hunt_bridge.entity` (skill v2.3.0 WS8-05).
    """
    table = str(data_table_name or "").strip().lstrip("%")
    column = str(column_name or "").strip()
    if not _DATA_TABLE_IDENT_RE.fullmatch(table) or not _DATA_TABLE_IDENT_RE.fullmatch(column):
      raise ValueError(f"Invalid SecOps Data Table reference '%{table}.{column}' (use %<table>.<column>).")
    gates = self.gate_thresholds()
    rendered = self.runner.get_chained_hunt_router().build_data_table_bridge_query(
        entity_type=self._resolve_entity_enum(entity_type),
        target_metric=target_metric,
        anomaly_threshold=gates["anomaly_threshold"],
        min_baseline_days=harness_truth.min_baseline_days(),
        data_table_name=table,
        data_table_column=column,
    )
    rendered = self._scope(rendered, entity, entity_type)
    win = self._evaluation_window(lookback_days, now_utc=now_utc)
    resp = await self.runner.execute_query_via_mcp(session, rendered, win["start"], win["end"])
    rows = self.runner.parse_stats_response(resp)

    top_row = rows[0] if rows else {}
    score = self._score(top_row, self._primary_score_key(rendered),
                        maturity_column=self._maturity_gate_column(rendered))
    return {
        "entity": entity,
        "model": "HYBRID_DATA_TABLE_BRIDGE_2STAGE",
        "data_table": f"%{table}.{column}",
        "target_metric": target_metric,
        "personal_z": round(score["score"], 2),
        "top_z_score": round(score["score"], 2),
        "observed_24h": self._num(top_row, "observed_24h") or 0.0,
        "baseline_mean": round(self._num(top_row, "baseline_mean") or 0.0, 2),
        "active_days": int(self._num(top_row, "active_days") or 0),
        **self._score_fields(score),
        "stats_rows": len(rows),
        "evaluation_window": win,
        "executed_query": rendered,
    }

  async def run_cloud_crud_surge(
      self,
      session: ClientSession,
      username: str,
      lookback_days: int = 14,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Profiles user cloud resource activity across all 4 CRUD families (read, write, delete, create).

    Runs the canonical Cloud CRUD sector (templates/radar_360/user_2_cloud_risk.yl2): each family's
    observed count is scored against its own resource_*_total baseline on the PRINCIPAL_USER +
    PRODUCT_NAME + VENDOR_NAME dimension set, with count dispersion floors and the 7-active-day
    maturity gate; the peak family Z is the sector score. Every metrics.* call passes direct UDM field
    paths (<field>: <field>).
    """
    win = self._evaluation_window(lookback_days, now_utc=now_utc)
    query = self._render(self.USER_SECTOR_TEMPLATES["Cloud"], {"entity_id": _escape_literal(username)})
    resp = await self.runner.execute_query_via_mcp(session, query, win["start"], win["end"])
    rows = self.runner.parse_stats_response(resp)

    families = ("read", "write", "delete", "create")
    row = dict(rows[0]) if rows else {}
    family_raw = {fam: self._num(row, f"z_{fam}") for fam in families}
    family_z = {fam: round(val or 0.0, 2) for fam, val in family_raw.items()}
    top_family = max(families, key=lambda fam: family_raw[fam] if family_raw[fam] is not None else float("-inf"))
    if rows and self._num(row, "z") is None and any(v is not None for v in family_raw.values()):
      row["z"] = max(v for v in family_raw.values() if v is not None)
    score = self._score(row, "z", use_priority=False)
    observed = int(self._num(row, "observed") or 0)
    family_baselines: Dict[str, Dict[str, float]] = {}
    for fam, prefix in (("create", "c"), ("delete", "d")):
      avg = self._num(row, f"{prefix}_avg")
      std = self._num(row, f"{prefix}_std")
      if avg is not None or std is not None:
        family_baselines[fam] = {"avg": round(avg or 0.0, 2), "std": round(std or 0.0, 2)}
    top_baseline = family_baselines.get(top_family, {})
    return {
        "entity": username,
        "model": "CLOUD_INFRASTRUCTURE_CRUD_SURGE",
        "family_z_scores": family_z,
        "top_family": top_family,
        "top_z_score": round(score["score"], 2),
        "z_score": round(score["score"], 2),
        "observed_events": observed,
        "observed_count": observed,
        "baseline_avg": top_baseline.get("avg", 0.0),
        "baseline_std": top_baseline.get("std", 0.0),
        "family_baselines": family_baselines,
        **self._score_fields(score),
        "stats_rows": len(rows),
        "evaluation_window": win,
        "executed_query": query,
    }

  async def run_killchain_archetype(
      self,
      session: ClientSession,
      entity: str,
      archetype_name: str = "CREDENTIAL_ACCESS_TO_EXECUTION",
      entity_type: str = "USER",
      four_stage: bool = False,
      identifier_field: Optional[str] = None,
      lookback_days: int = 14,
      archetype: Optional[str] = None,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Executes a canonical MITRE ATT&CK Multi-Stage Kill-Chain Archetype Fusion hunt."""
    KillChainArchetype, catalog = self.runner.get_killchain_archetypes()
    router = self.runner.get_template_router()
    ent_enum = self._resolve_entity_enum(entity_type)

    raw_arch = (archetype or archetype_name or "CREDENTIAL_ACCESS_TO_EXECUTION").strip().upper()
    if raw_arch.startswith("KILLCHAIN_"):
      raw_arch = raw_arch[len("KILLCHAIN_"):]
    try:
      arch_enum = KillChainArchetype(raw_arch)
    except ValueError as err:
      raise ValueError(
          f"Unknown kill-chain archetype '{raw_arch}'. Valid archetypes: {[a.value for a in KillChainArchetype]}"
      ) from err

    spec = catalog.get(arch_enum, {})
    supported = spec.get("supported_entities", (ent_enum,))
    if ent_enum not in supported and supported:
      ent_enum = supported[0]

    rendered = router.build_killchain_hunt_query(
        archetype=arch_enum,
        entity_type=ent_enum,
        four_stage=four_stage,
        fusion_threshold_sq=self.gate_thresholds()["fusion_threshold_sq"],
        hypothesis_goal=f"MITRE ATT&CK Kill-Chain ({arch_enum.value}) on {entity}",
        identifier_field=identifier_field,
    )
    rendered = self._scope(rendered, entity, entity_type)
    win = self._evaluation_window(lookback_days, now_utc=now_utc)
    rendered, win = self._apply_ecg_window(rendered, lookback_days, now_utc, win)
    resp = await self.runner.execute_query_via_mcp(session, rendered, win["start"], win["end"])
    rows = self.runner.parse_stats_response(resp)

    top_row = dict(rows[0]) if rows else {}
    z_a = self._num(top_row, "z_a_gated", "z_a", "sector_a_z", "z_sector_a")
    z_b = self._num(top_row, "z_b_gated", "z_b", "sector_b_z", "z_sector_b")
    primary = self._primary_score_key(rendered) or "composite_threat_norm_sq"
    if rows and self._num(top_row, primary, "composite_threat_norm_sq", "d_sq") is None:
      direct_d = self._num(top_row, "composite_threat_score")
      if direct_d is not None:
        top_row[primary] = direct_d * direct_d
      elif z_a is not None or z_b is not None:
        top_row[primary] = max(0.0, z_a or 0.0) ** 2 + max(0.0, z_b or 0.0) ** 2
    score = self._score(top_row, primary, extra_keys=("composite_threat_norm_sq", "d_sq"), use_priority=False)
    composite_d = score["score"]
    tactics = list(spec.get("mitre_tactics", ()))
    return {
        "entity": entity,
        "entity_type": entity_type,
        "model": f"KILLCHAIN_{arch_enum.value}",
        "archetype": arch_enum.value,
        "killchain_archetype": arch_enum.value,
        "mitre_tactics": tactics,
        "fusion_metrics": [spec.get("sector_a", ""), spec.get("sector_b", "")],
        "sector_a_z": round(z_a or 0.0, 2),
        "sector_b_z": round(z_b or 0.0, 2),
        "composite_d": round(composite_d, 2),
        "composite_threat_score": round(composite_d, 2),
        "top_z_score": round(composite_d, 2),
        **self._score_fields(score),
        "stats_rows": len(rows),
        "evaluation_window": win,
        "executed_query": rendered,
    }

  async def run_alert_surge(
      self,
      session: ClientSession,
      entity: str,
      entity_type: str = "ASSET",
      lookback_days: int = 14,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Executes the 2-Stage Security & EDR Alert Surge pipeline (alert_event_name_count)."""
    router = self.runner.get_template_router()
    ent_enum = self._resolve_entity_enum(entity_type)
    rendered = router.build_alert_surge_query(
        entity_type=ent_enum,
        anomaly_threshold=self.gate_thresholds()["anomaly_threshold"],
        hypothesis_goal=f"Security & EDR Alert Surge (alert_event_name_count) for {entity}",
    )
    rendered = self._scope(rendered, entity, entity_type)
    win = self._evaluation_window(lookback_days, now_utc=now_utc)
    resp = await self.runner.execute_query_via_mcp(session, rendered, win["start"], win["end"])
    rows = self.runner.parse_stats_response(resp)

    top_row = rows[0] if rows else {}
    score = self._score(top_row, self._primary_score_key(rendered),
                        maturity_column=self._maturity_gate_column(rendered))
    total_alerts = int(self._num(top_row, "total_alerts", "observed") or 0)
    return {
        "entity": entity,
        "entity_type": entity_type,
        "model": "ALERT_SURGE",
        "target_metric": "alert_event_name_count",
        "alert_z": round(score["score"], 2),
        "top_z_score": round(score["score"], 2),
        "total_alerts": total_alerts,
        "observed_alerts": total_alerts,
        "distinct_rules": int(self._num(top_row, "distinct_rules") or 0),
        "novel_rules": int(self._num(top_row, "novel_rules") or 0),
        **self._score_fields(score),
        "stats_rows": len(rows),
        "evaluation_window": win,
        "executed_query": rendered,
    }

  async def run_failure_ratio_surge(
      self,
      session: ClientSession,
      entity: str,
      fail_metric: str = "auth_attempts_fail",
      entity_type: str = "USER",
      identifier_field: Optional[str] = None,
      lookback_days: int = 14,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Executes the 2-Stage Failure-to-Total Ratio Surge pipeline across any of the 8 *_fail families."""
    router = self.runner.get_template_router()
    ent_enum = self._resolve_entity_enum(entity_type)
    if not fail_metric or not fail_metric.endswith("_fail"):
      fail_metric = "auth_attempts_fail" if ent_enum.value == "USER" else "http_queries_fail"

    from scripts.preflight_validator import METRIC_CATALOG
    if fail_metric in METRIC_CATALOG and ent_enum not in METRIC_CATALOG[fail_metric].supported_entity_types:
      ent_enum = METRIC_CATALOG[fail_metric].supported_entity_types[0]

    rendered = router.build_failure_ratio_surge_query(
        fail_metric=fail_metric,
        entity_type=ent_enum,
        anomaly_threshold=self.gate_thresholds()["anomaly_threshold"],
        min_fail_ratio=0.40,
        hypothesis_goal=f"Failure-to-Total Ratio Surge ({fail_metric}) for {entity}",
        identifier_field=identifier_field,
    )
    rendered = self._scope(rendered, entity, entity_type)
    win = self._evaluation_window(lookback_days, now_utc=now_utc)
    resp = await self.runner.execute_query_via_mcp(session, rendered, win["start"], win["end"])
    rows = self.runner.parse_stats_response(resp)

    top_row = rows[0] if rows else {}
    maturity_column = self._maturity_gate_column(rendered)
    fail_score = self._score(top_row, self._primary_score_key(rendered), maturity_column=maturity_column)
    score = fail_score
    if self._num(top_row, "recon_score") is not None:
      recon_score = self._score(top_row, "recon_score", maturity_column=maturity_column, use_priority=False)
      if (recon_score["z_equivalent"] or 0.0) > (fail_score["z_equivalent"] or 0.0):
        score = recon_score
    fail_z = self._num(top_row, "fail_z") or 0.0
    fail_ratio = self._num(top_row, "fail_ratio") or 0.0
    recon = self._num(top_row, "recon_score")
    return {
        "entity": entity,
        "entity_type": entity_type,
        "model": "FAILURE_RATIO_SURGE",
        "target_metric": fail_metric,
        "total_metric": fail_metric.replace("_fail", "_total"),
        "fail_z": round(fail_z, 2),
        "fail_ratio": round(fail_ratio, 3),
        "failure_ratio": round(fail_ratio, 3),
        "recon_score": round(recon if recon is not None else fail_z, 2),
        "observed_fails": int(self._num(top_row, "observed_fails") or 0),
        "total_events": int(self._num(top_row, "total_events") or 0),
        "top_z_score": round(score["score"], 2),
        **self._score_fields(score),
        "stats_rows": len(rows),
        "evaluation_window": win,
        "executed_query": rendered,
    }

  async def run_cloud_repository_scope(
      self,
      session: ClientSession,
      username: str = "",
      outcome_mode: str = "total",
      lookback_days: int = 14,
      entity: Optional[str] = None,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Executes the Cloud Repository Scope Dual-Branch pipeline (supports 'fail', 'success', 'total')."""
    target_user = entity or username
    router = self.runner.get_template_router()
    mode_clean = (outcome_mode or "total").strip().lower()
    if mode_clean == "fail":
      target_metric = "resource_read_fail"
    elif mode_clean == "success":
      target_metric = "resource_read_success"
    else:
      target_metric = "resource_read_total"
      mode_clean = "total"

    rendered = router.build_cloud_repository_scope_query(
        service_account=target_user,
        anomaly_threshold=self.gate_thresholds()["anomaly_threshold"],
        hypothesis_goal=f"Cloud Repository Scope & Origin IP Attribution (mode={mode_clean}) for {target_user}",
        target_metric=target_metric,
    )
    win = self._evaluation_window(lookback_days, now_utc=now_utc)
    resp = await self.runner.execute_query_via_mcp(session, rendered, win["start"], win["end"])
    rows = self.runner.parse_stats_response(resp)

    top_row = rows[0] if rows else {}
    score = self._score(top_row, self._primary_score_key(rendered),
                        maturity_column=self._maturity_gate_column(rendered))
    observed_events = self._num(
        top_row, "obs", "observed", "observed_reads", "obs_writes", "obs_deletes", "obs_creates") or 0.0
    result = {
        "entity": target_user,
        "entity_type": "USER",
        "model": "CLOUD_REPOSITORY_SCOPE",
        "outcome_mode": mode_clean,
        "metric": target_metric,
        "target_metric": target_metric,
        "target_resource": str(top_row.get("resource") or top_row.get("target_resource") or "N/A"),
        "caller_ip": str(top_row.get("caller_ip") or top_row.get("ip") or "N/A"),
        "observed_events": round(observed_events, 1),
        "composite_risk": round(score["score"], 2),
        "top_z_score": round(score["score"], 2),
        **self._score_fields(score),
        "stats_rows": len(rows),
        "evaluation_window": win,
        "executed_query": rendered,
    }
    for z_key in ("dest_z", "write_z", "del_z", "create_z", "origin_z"):
      z_val = self._num(top_row, z_key)
      if z_val is not None:
        result[z_key] = round(z_val, 2)
    fold = self._num(top_row, "fold_change", "surge_ratio")
    if fold is not None:
      result["fold_change"] = round(fold, 2)
    return result

  async def run_workspace_triad(
      self,
      session: ClientSession,
      username: str = "",
      lookback_days: int = 14,
      entity: Optional[str] = None,
      target_metrics: Optional[Sequence[str]] = None,
      now_utc: Optional[datetime] = None,
  ) -> Dict[str, Any]:
    """Executes the Part-of-the-Whole Triad Multilevel pipeline across Workspace Activity vectors."""
    target_user = entity or username
    EntityType, PipelineArchitecture, _, _ = self.runner.get_validator_enums()
    router = self.runner.get_template_router()
    gates = self.gate_thresholds()
    triad_metrics = list(
        target_metrics
        or [
            "workspace_auth_attempts_total",
            "workspace_total_download_actions",
            "workspace_total_change_actions",
        ]
    )
    rendered = router.build_pipeline_query(
        pipeline_type=PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
        entity_type=EntityType.USER,
        target_entity=target_user,
        target_metrics=triad_metrics,
        anomaly_threshold=gates["anomaly_threshold"],
        fusion_threshold_sq=gates["fusion_threshold_sq"],
        min_baseline_days=harness_truth.min_baseline_days(),
        hypothesis_goal=f"Workspace Exfiltration Triad ({' + '.join(triad_metrics)}) vs Peer Cohort for {target_user}",
    )
    win = self._evaluation_window(lookback_days, now_utc=now_utc)
    resp = await self.runner.execute_query_via_mcp(session, rendered, win["start"], win["end"])
    rows = self.runner.parse_stats_response(resp)

    top_row = dict(rows[0]) if rows else {}
    # z1..z3 follow the requested metric order (m1..m3 in the triad template).
    metric_z = {}
    for idx, metric in enumerate(triad_metrics[:3], start=1):
      z_val = self._num(top_row, f"z{idx}_vs_enterprise")
      if z_val is not None:
        metric_z[metric] = round(z_val, 2)
    primary = self._primary_score_key(rendered) or "d_vs_fleet_sq"
    score = self._score(top_row, primary, extra_keys=("d_vs_team_sq", "composite_z_score", "z_vs_enterprise"),
                        use_priority=False)
    if score["score_key"] is None and metric_z:
      norm_sq = sum(max(0.0, z) ** 2 for z in metric_z.values())
      score = self._score({primary: norm_sq}, primary, use_priority=False)
    m_obs_sum = sum(self._num(top_row, f"m{i}_observed") or 0.0 for i in (1, 2, 3))
    obs_val = self._num(top_row, "observed", "total_actions") or m_obs_sum
    return {
        "entity": target_user,
        "entity_type": "USER",
        "model": "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL",
        "target_metric": "workspace_total_download_actions",
        "fusion_metrics": list(triad_metrics),
        "triad_metrics": triad_metrics,
        "metric_z_scores": metric_z,
        "composite_z_score": round(score["score"], 2),
        "observed_value": round(obs_val, 1),
        "auth_z": metric_z.get("workspace_auth_attempts_total", 0.0),
        "download_z": metric_z.get("workspace_total_download_actions", 0.0),
        "change_z": metric_z.get("workspace_total_change_actions", 0.0),
        "email_z": metric_z.get("workspace_emails_sent_total", 0.0),
        "top_z_score": round(score["score"], 2),
        **self._score_fields(score),
        "stats_rows": len(rows),
        "evaluation_window": win,
        "executed_query": rendered,
    }

  @staticmethod
  def derive_cri_severity(cri: Any) -> str:
    """Maps a CRI [0-100] to the UDM SecurityResult severity of its harness CRI band (26/46/70/90).

    A missing or invalid CRI (harness band N/A) maps to UNKNOWN_SEVERITY.
    """
    code = harness_truth.cri_band(cri)[0]
    return "UNKNOWN_SEVERITY" if code == "N/A" else code

  @staticmethod
  def _mode_a_today_window(now_utc: Optional[datetime] = None) -> Tuple[str, str, str]:
    """Explicit "Today So Far" window (today 00:00:00Z -> now_utc), a labelled partial-day option.

    Not the Mode A default (the last complete UTC day, see _evaluation_window). If invoked within the
    first 30 minutes after midnight UTC (00:00Z-00:29Z), evaluates yesterday's completed 24h UTC bucket
    so late-night spikes are not lost across the UTC date boundary.
    """
    now_dt = now_utc or datetime.now(timezone.utc)
    today_midnight = datetime(now_dt.year, now_dt.month, now_dt.day, tzinfo=timezone.utc)
    if now_dt.hour == 0 and now_dt.minute < 30:
      start_dt = today_midnight - timedelta(days=1)
      end_dt = today_midnight - timedelta(seconds=1)
    else:
      start_dt = today_midnight
      end_dt = now_dt
    return (
        start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        start_dt.strftime("%Y-%m-%d"),
    )

  def build_fleet_360_sector_queries(
      self,
      entity_type: str = "USER",
      min_z: float = 2.0,
      min_obs: int = 5,
  ) -> Dict[str, str]:
    """Builds the 6 fleetwide decoupled 360° sector queries (all entities).

    Pushes `condition: $z >= min_z and $observed >= min_obs` into the root stage to prune nominal fleet
    rows server-side and stay well below Chronicle's 10,000-row stats limit while preserving secondary
    elevated spokes for Euclidean distance D calculation. Sector Z-scores are maturity-gated and
    dispersion-floored in the query (count: max(sd, sqrt(max(avg, 1))); bytes: the skill's byte floor).
    Canonical skill sector templates are used where they exist (user Web, host Alerts).
    """
    is_host = self._is_asset(entity_type)
    z_gate = f"{float(min_z):.2f}"
    obs_gate = int(max(1, min_obs))
    gate = f"$z >= {z_gate} and $observed >= {obs_gate}"
    queries: Dict[str, str] = {}
    if is_host:
      for sector, metric in self.ASSET_SECTOR_METRICS.items():
        if sector == "Alerts":
          queries[sector] = self._with_root_gate(
              self._render(self.ASSET_ALERT_SECTOR_TEMPLATE, {}), f"$z >= {z_gate} and $observed >= 1")
        else:
          stage, title = self._ASSET_INLINE_SECTORS[sector]
          queries[sector] = self._inline_sector_query(metric, stage, f"Fleetwide {title}", "ASSET", gate=gate)
      return queries
    for sector, metric in self.FLEET_USER_SECTOR_METRICS.items():
      if sector == "Cloud":
        queries[sector] = self._fleet_cloud_sector_query(gate)
      elif sector == "Web":
        queries[sector] = self._with_root_gate(self._render(self.USER_WEB_FLEET_TEMPLATE, {}), gate)
      else:
        stage, title = self._USER_INLINE_SECTORS[sector]
        queries[sector] = self._inline_sector_query(metric, stage, f"Fleetwide {title}", "USER", gate=gate)
    return queries

  # Fixed identity shared by every event the 360 sweep ingests. One event per
  # outlier entity; the catch-all rule keys on product_name + event_type.
  RADAR_360_EVENT_METADATA: Dict[str, str] = {
      "product_name": "SecOps Risk Metrics Hunter",
      "vendor_name": "Google SecOps",
      "event_type": "GENERIC_EVENT",
      "product_event_type": "BEHAVIORAL_RISK_RADAR_360",
  }

  RADAR_360_CATEGORY_BY_SECTOR: Dict[str, str] = {
      "AUTH": "AUTH_VIOLATION",
      "EGRESS": "DATA_EXFILTRATION",
      "WORKSPACE": "DATA_EXFILTRATION",
      "CLOUD": "ACL_VIOLATION",
      "DNS": "NETWORK_SUSPICIOUS",
      "WEB": "NETWORK_SUSPICIOUS",
      "FLOWS": "NETWORK_SUSPICIOUS",
      "ALERTS": "SOFTWARE_SUSPICIOUS",
  }

  def build_360_outlier_udm_event(
      self,
      entity_id: str,
      entity_type: str,
      sectors: Dict[str, Dict[str, float]],
      composite_d: float,
      composite_cri: int,
      campaign_id: str,
      run_timestamp_iso: str,
      evaluated_day: str,
      spike_threshold_z: float = 3.0,
  ) -> Dict[str, Any]:
    """Builds the single 360 Radar UDM event for one outlier entity.

    Carries unbundled roll-up labels (`Peak Vector`, `Peak CRI`, `Peak Z`,
    `Breached Vectors`) in `target.resource.attribute.labels`, the composite
    roll-up in `security_result[0]` (`rule_type = "COMPOSITE_360"`), and one
    `SECTOR_VECTOR` entry per non-zero vector in `security_result[1..N]` sorted
    descending by Z-score with native `risk_score` (CRI) and `confidence_score` (Z).
    CRI values and severities come from src.harness_truth.
    """
    is_asset = self._is_asset(entity_type)
    norm_type = "ASSET" if is_asset else "USER"
    sector_map = self.ASSET_SECTOR_METRICS if is_asset else self.USER_SECTOR_METRICS

    vectors = []
    for sec in sector_map:
      z_val = float((sectors.get(sec) or {}).get("z", 0.0) or 0.0)
      vectors.append((sec.upper(), z_val, self._cri(z_val)))

    peak_name, peak_z, peak_cri = max(vectors, key=lambda v: v[1])
    sorted_vectors = sorted(vectors, key=lambda v: v[1], reverse=True)
    breached = [v[0] for v in sorted_vectors if v[1] >= spike_threshold_z]
    if not breached and composite_d >= spike_threshold_z:
      breached = [v[0] for v in sorted_vectors if v[1] >= 2.0]
    active_vectors = [(name, z, cri) for name, z, cri in sorted_vectors if z > 0.0 and cri > 0]

    labels = [
        {"key": "Hunt Campaign ID", "value": campaign_id},
        {"key": "Evaluated Day", "value": evaluated_day},
        {"key": "Composite CRI", "value": str(composite_cri)},
        {"key": "Composite D", "value": f"{composite_d:.2f}"},
        {"key": "Peak Vector", "value": peak_name},
        {"key": "Peak CRI", "value": str(peak_cri)},
        {"key": "Peak Z", "value": f"{peak_z:.2f}"},
        {"key": "Breached Vectors", "value": ", ".join(breached) or "none"},
    ]

    principal = (
        {"hostname": entity_id, "asset": {"hostname": entity_id}}
        if is_asset
        else {"user": {"userid": entity_id}}
    )
    summary = (
        f"{norm_type} {entity_id}: Composite CRI {composite_cri} (D={composite_d:.2f}σ); "
        f"breached {', '.join(breached) or 'none'}; peak {peak_name} CRI {peak_cri} (Z {peak_z:.2f})."
    )

    security_results: List[Dict[str, Any]] = [
        {
            "rule_name": "360 Behavioral Risk Radar",
            "rule_type": "COMPOSITE_360",
            "category": [self.RADAR_360_CATEGORY_BY_SECTOR.get(peak_name, "POLICY_VIOLATION")],
            "action": ["UNKNOWN_ACTION"],
            "risk_score": int(composite_cri),
            "severity": self.derive_cri_severity(composite_cri),
            "summary": summary,
        }
    ]
    for vec_name, vec_z, vec_cri in active_vectors:
      security_results.append({
          "rule_name": f"360 Vector: {vec_name}",
          "rule_type": "SECTOR_VECTOR",
          "threat_name": vec_name,
          "category": [self.RADAR_360_CATEGORY_BY_SECTOR.get(vec_name, "POLICY_VIOLATION")],
          "action": ["UNKNOWN_ACTION"],
          "risk_score": int(vec_cri),
          "confidence_score": round(float(vec_z), 2),
          "severity": self.derive_cri_severity(vec_cri),
          "threat_status": "ACTIVE" if vec_name in breached else "CLEARED",
          "summary": f"Vector {vec_name}: CRI {vec_cri} | Z {vec_z:.2f}σ",
      })

    return {
        "metadata": {
            "event_timestamp": run_timestamp_iso,
            **self.RADAR_360_EVENT_METADATA,
            "description": summary,
            "ingestion_labels": [
                {"key": "hunt_campaign_id", "value": campaign_id},
                {"key": "source_skill", "value": self.SKILL_NAME},
            ],
        },
        "observer": {
            "hostname": "secops-risk-metrics-hunter",
            "application": "Google SecOps Multi-Stage Risk Analytics",
        },
        "principal": principal,
        "target": {
            "resource": {
                "name": self.RADAR_360_EVENT_METADATA["product_event_type"],
                "attribute": {"labels": labels},
            }
        },
        "security_result": security_results,
    }

  def ingest_udm_events(
      self,
      udm_events: Sequence[Dict[str, Any]],
      batch_size: int = 200,
      access_token: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Validates and ingests UDM events in batches via Chronicle IngestionService.ImportEvents."""
    if not udm_events:
      return {"status": "NO_EVENTS", "events_ingested": 0, "batches": 0}

    self.runner._ensure_skill_path()
    from scripts import chronicle_ingest

    validation_errors = chronicle_ingest.validate_events(udm_events)
    if validation_errors:
      raise ValueError(f"UDM validation failed: {validation_errors}")

    token = access_token
    if not token:
      try:
        auth_headers = self.runner.tenant.get_auth_headers()
        auth_val = auth_headers.get("Authorization", "")
        if auth_val.startswith("Bearer "):
          token = auth_val[len("Bearer "):].strip()
      except Exception:
        token = None

    total_ingested = 0
    batches = 0
    for idx in range(0, len(udm_events), batch_size):
      chunk = udm_events[idx : idx + batch_size]
      chronicle_ingest.import_events(
          udm_events=chunk,
          project_id=self.runner.tenant.project_id,
          region=self.runner.tenant.region,
          customer_id=self.runner.tenant.customer_id,
          access_token=token,
      )
      total_ingested += len(chunk)
      batches += 1

    return {
        "status": "SUCCESS",
        "events_ingested": total_ingested,
        "batches": batches,
    }

  async def async_ingest_udm_events(
      self,
      udm_events: Sequence[Dict[str, Any]],
      batch_size: Optional[int] = None,
      access_token: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Offloads synchronous UDM validation and Chronicle ImportEvents HTTP calls to a worker thread."""
    kwargs: Dict[str, Any] = {}
    if batch_size is not None:
      kwargs["batch_size"] = batch_size
    if access_token is not None:
      kwargs["access_token"] = access_token
    return await self.runner.run_in_io_thread(
        self.ingest_udm_events,
        udm_events,
        **kwargs,
    )

  async def run_fleet_360_sweep(
      self,
      session: ClientSession,
      entity_type: str = "USER",
      spike_threshold_z: Optional[float] = None,
      spoke_inclusion_z: Optional[float] = None,
      min_observed: Optional[int] = None,
      max_outliers_per_sector: Optional[int] = None,
      inter_query_delay_sec: Optional[float] = None,
      ingest_events: Optional[bool] = None,
      should_emit_fn: Optional[Any] = None,
      record_emit_fn: Optional[Any] = None,
      now_utc: Optional[datetime] = None,
      lookback_days: int = 1,
      today_so_far: bool = False,
  ) -> Dict[str, Any]:
    """Executes the 6 decoupled 360° sector reports across ALL entities (Mode A: last complete UTC day vs 30d).

    - Evaluates all entities in 6 sequential fleetwide queries (O(1) API calls).
    - Mode A (default) scores the last complete UTC day [D, D+1) (src.harness_truth); `today_so_far`
      opts into the labelled partial-day window instead.
    - Supports multi-day historical backfills via `lookback_days` using Chronicle's `by 1d` TIME_BUCKET.
    - Computes Euclidean Distance D = sqrt(sum max(0, Z_i)^2) and the harness Composite CRI.
    - For any entity with >= 1 vector above `spike_threshold_z` (3.0σ), emits ONE
      `BEHAVIORAL_RISK_RADAR_360` UDM event stamped with the sweep's run time.
    """
    t_cfg = self.runner.tenant
    spike_threshold_z = (
        float(spike_threshold_z)
        if spike_threshold_z is not None
        else float(getattr(t_cfg, "fleet_360_spike_threshold_z", 3.0))
    )
    spoke_inclusion_z = (
        float(spoke_inclusion_z)
        if spoke_inclusion_z is not None
        else float(getattr(t_cfg, "fleet_360_spoke_inclusion_z", 2.0))
    )
    min_observed = (
        int(min_observed)
        if min_observed is not None
        else int(getattr(t_cfg, "fleet_360_min_observed", 5))
    )
    max_outliers_per_sector = (
        int(max_outliers_per_sector)
        if max_outliers_per_sector is not None
        else int(getattr(t_cfg, "fleet_360_max_outliers_per_sector", 250))
    )
    inter_query_delay_sec = (
        float(inter_query_delay_sec)
        if inter_query_delay_sec is not None
        else float(getattr(t_cfg, "fleet_360_inter_query_delay_sec", 1.5))
    )
    ingest_events = (
        bool(ingest_events)
        if ingest_events is not None
        else bool(getattr(t_cfg, "fleet_360_ingest_events", True))
    )

    # Every event from this sweep is stamped with the moment its queries started.
    stamp_dt = now_utc or datetime.now(timezone.utc)
    run_timestamp_iso = stamp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    is_multi_day = bool(lookback_days and int(lookback_days) > 1)
    if is_multi_day:
      # Historical backfill: one fixed-baseline query bucketed `by 1d`, bounded by the Mode C horizon.
      now_dt = self._now(now_utc)
      n_days = min(int(lookback_days), harness_truth.mode_caps()["mode_c_macro_days"])
      end_midnight = datetime(now_dt.year, now_dt.month, now_dt.day, tzinfo=timezone.utc)
      start_dt = end_midnight - timedelta(days=n_days - 1)
      start_iso = start_dt.strftime("%Y-%m-%dT00:00:00Z")
      end_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
      bucket_date = end_midnight.strftime("%Y-%m-%d")
    elif today_so_far:
      start_iso, end_iso, bucket_date = self._mode_a_today_window(now_utc)
    else:
      scored_day = harness_truth.mode_a_day(self._now(now_utc))
      start_iso, end_iso = harness_truth.mode_a_window(scored_day)
      bucket_date = scored_day.isoformat()

    is_asset = self._is_asset(entity_type)
    norm_type = "ASSET" if is_asset else "USER"

    fleet_queries = self.build_fleet_360_sector_queries(
        entity_type=norm_type,
        min_z=spoke_inclusion_z,
        min_obs=min_observed,
    )

    entity_vectors: Dict[Tuple[str, str], Dict[str, Dict[str, float]]] = {}
    display_ids: Dict[str, Tuple[float, str]] = {}
    sector_row_counts: Dict[str, int] = {}
    circuit_breaker_tripped: List[str] = []
    queries_executed = 0
    min_days = harness_truth.min_baseline_days()

    def _extract_num(row: Dict[str, Any], keys: Sequence[str]) -> float:
      for k in keys:
        if k in row and row[k] is not None:
          try:
            return float(row[k])
          except (TypeError, ValueError):
            pass
      return 0.0

    sector_items = list(fleet_queries.items())
    logger.info(
        f"Fleet 360 [{norm_type}] sweep started: window={start_iso}..{end_iso}, "
        f"sectors={len(sector_items)}, spike_threshold_z={spike_threshold_z}, "
        f"spoke_inclusion_z={spoke_inclusion_z}, min_obs={min_observed}."
    )
    for idx, (sector_name, q_str) in enumerate(sector_items):
      try:
        resp = await self.runner.execute_query_via_mcp(session, q_str, start_iso, end_iso)
        queries_executed += 1
        rows = self.runner.parse_stats_response(resp)
        sector_row_counts[sector_name] = len(rows)

        high_spike_rows = [
            r for r in rows
            if _extract_num(r, ("z", "z_score", "$z")) >= spike_threshold_z
        ]
        if max_outliers_per_sector > 0 and len(high_spike_rows) > max_outliers_per_sector:
          logger.warning(
              f"Macro-rollout circuit breaker tripped for {norm_type} sector {sector_name}: "
              f"{len(high_spike_rows)} entities >= {spike_threshold_z}σ (cap={max_outliers_per_sector})."
          )
          circuit_breaker_tripped.append(sector_name)
          continue

        for row in rows:
          ent_id = str(
              row.get("user")
              or row.get("$user")
              or row.get("host")
              or row.get("$host")
              or row.get("asset")
              or row.get("$asset")
              or row.get("entity")
              or row.get("$entity")
              or ""
          ).strip()
          if not ent_id:
            continue
          # Merge case variants of one entity across sectors on a lowercase key, but
          # emit the ID exactly as the source telemetry spelled it (spelling from the
          # highest-Z sector wins) so exact-match pivots to raw events still work.
          ent_key = ent_id.lower()
          row_z = _extract_num(row, ("z", "z_score", "$z"))
          if ent_key not in display_ids or row_z > display_ids[ent_key][0]:
            display_ids[ent_key] = (row_z, ent_id)
          ent_id = ent_key
          raw_tb = str(
              row.get("TIME_BUCKET")
              or row.get("time_bucket")
              or row.get("bucket_date")
              or ""
          ).strip()
          row_day = (
              raw_tb[:10]
              if len(raw_tb) >= 10 and raw_tb[4] == "-" and raw_tb[7] == "-"
              else bucket_date
          )
          z_val = _extract_num(row, ("z", "z_score", "$z"))
          days_val = self._num(row, "active_days")
          if days_val is not None and days_val < min_days:
            z_val = 0.0  # immature baseline: mirrors the sector query's $active_days gate
          vector = entity_vectors.setdefault((row_day, ent_id), {})
          # Rule-keyed sectors (alerts) return one row per (entity, rule): keep the peak.
          if sector_name in vector and vector[sector_name]["z"] >= z_val:
            continue
          vector[sector_name] = {
              "z": z_val,
              "obs": _extract_num(row, ("observed", "obs", "$observed", "$obs")),
              "avg": _extract_num(row, ("baseline", "avg", "baseline_avg", "$baseline", "$avg")),
              "std": _extract_num(row, ("dispersion", "std", "baseline_std", "$dispersion", "$std")),
          }
      except Exception as err:
        logger.warning(f"Fleet 360 query failed on {norm_type} sector {sector_name}: {err}")
        sector_row_counts[sector_name] = 0

      if inter_query_delay_sec > 0 and idx < len(sector_items) - 1:
        await asyncio.sleep(inter_query_delay_sec)

    campaign_id = f"sweep-360-{norm_type.lower()}-{bucket_date}-{stamp_dt.strftime('%H%M%S')}"
    udm_events_to_ingest: List[Dict[str, Any]] = []
    outliers: List[Dict[str, Any]] = []
    suppressed_duplicates = 0
    total_detected = 0

    for (day_bucket, ent_id), sec_map in sorted(entity_vectors.items()):
      max_spoke_z = max((v["z"] for v in sec_map.values()), default=0.0)
      z_scores = {s: v["z"] for s, v in sec_map.items()}
      composite_d = self.runner.compute_euclidean_distance(z_scores)
      if max_spoke_z < spike_threshold_z and composite_d < spike_threshold_z:
        continue

      total_detected += 1
      composite_cri = self._cri(composite_d)
      breached_sectors = sorted(
          [s for s, v in sec_map.items() if v["z"] >= spike_threshold_z],
          key=lambda s: sec_map[s]["z"],
          reverse=True,
      )
      if not breached_sectors and composite_d >= spike_threshold_z:
        breached_sectors = sorted(
            [s for s, v in sec_map.items() if v["z"] >= spoke_inclusion_z],
            key=lambda s: sec_map[s]["z"],
            reverse=True,
        )
      primary_sector = breached_sectors[0] if breached_sectors else max(sec_map, key=lambda s: sec_map[s]["z"])

      if should_emit_fn is not None:
        if not should_emit_fn(day_bucket, norm_type, ent_id, breached_sectors, composite_d):
          suppressed_duplicates += 1
          continue

      day_campaign_id = f"sweep-360-{norm_type.lower()}-{day_bucket}-{stamp_dt.strftime('%H%M%S')}"

      udm_event = self.build_360_outlier_udm_event(
          entity_id=display_ids.get(ent_id, (0.0, ent_id))[1],
          entity_type=norm_type,
          sectors=sec_map,
          composite_d=composite_d,
          composite_cri=composite_cri,
          campaign_id=day_campaign_id,
          run_timestamp_iso=run_timestamp_iso,
          evaluated_day=day_bucket,
          spike_threshold_z=spike_threshold_z,
      )
      udm_events_to_ingest.append(udm_event)

      if record_emit_fn is not None:
        record_emit_fn(day_bucket, norm_type, ent_id, breached_sectors, composite_d, composite_cri)

      vector_cri_map = {s: self._cri(v["z"]) for s, v in sec_map.items()}
      outliers.append({
          "bucket_date": day_bucket,
          "entity": display_ids.get(ent_id, (0.0, ent_id))[1],
          "entity_type": norm_type,
          "composite_d": round(composite_d, 2),
          "composite_cri": composite_cri,
          "severity": self.derive_cri_severity(composite_cri),
          "verdict": harness_truth.verdict_for(composite_cri),
          "primary_vector": primary_sector.upper(),
          "max_spoke_z": round(max_spoke_z, 2),
          "breached_sectors": [s.upper() for s in breached_sectors],
          "sector_z_scores": {s: round(v["z"], 2) for s, v in sec_map.items()},
          "sector_cri_scores": vector_cri_map,
      })

    outliers.sort(key=lambda x: (x["composite_d"], x.get("bucket_date", "")), reverse=True)

    ingestion_result: Dict[str, Any] = {
        "status": "SKIPPED" if not ingest_events else "NO_EVENTS",
        "events_ingested": 0,
        "batches": 0,
    }
    if ingest_events and udm_events_to_ingest:
      try:
        ingestion_result = await self.async_ingest_udm_events(udm_events_to_ingest)
        logger.info(
            f"Fleet 360 [{norm_type}] UDM ingestion succeeded: "
            f"events_ingested={ingestion_result.get('events_ingested', 0)}, "
            f"batches={ingestion_result.get('batches', 0)}, campaign={campaign_id}."
        )
      except Exception as ing_err:
        logger.error(f"Fleet 360 UDM ingestion failed: {ing_err}")
        ingestion_result = {
            "status": "ERROR",
            "error": str(ing_err),
            "events_ingested": 0,
            "batches": 0,
        }

    outlier_preview = (
        ", ".join(
            f"{o['entity']}(CRI={o['composite_cri']},D={o['composite_d']:.2f}σ,{o['primary_vector']})"
            for o in outliers[:10]
        )
        if outliers
        else "none"
    )
    logger.info(
        f"Fleet 360 [{norm_type}] sweep complete: campaign={campaign_id}, window={start_iso}..{end_iso}, "
        f"queries={queries_executed}/{len(sector_items)}, sector_rows={sector_row_counts}, "
        f"candidates_above_floor={len(entity_vectors)}, outliers_detected={total_detected}, "
        f"outliers_emitted={len(outliers)}, suppressed_dedup={suppressed_duplicates}, "
        f"udm_events={len(udm_events_to_ingest)}, ingestion_status={ingestion_result.get('status')} "
        f"(ingested={ingestion_result.get('events_ingested', 0)}), outliers=[{outlier_preview}]."
    )

    return {
        "status": "SUCCESS",
        "campaign_id": campaign_id,
        "entity_type": norm_type,
        "window": {
            "start": start_iso,
            "end": end_iso,
            "bucket_date": bucket_date,
            "lookback_days": int(lookback_days or 1),
        },
        "queries_executed": queries_executed,
        "sector_row_counts": sector_row_counts,
        "circuit_breaker_tripped_sectors": circuit_breaker_tripped,
        "suppressed_sectors": circuit_breaker_tripped,
        "entities_above_inclusion_floor": len(entity_vectors),
        "outliers_detected": total_detected,
        "outliers_emitted": len(outliers),
        "outliers_flagged": len(outliers),
        "outliers_suppressed_dedup": suppressed_duplicates,
        "suppressed_intraday_duplicates": suppressed_duplicates,
        "udm_events_generated": len(udm_events_to_ingest),
        "ingestion": ingestion_result,
        "outliers": outliers,
        "udm_events": udm_events_to_ingest,
    }

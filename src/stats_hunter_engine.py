# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Deterministic Statistical Hunter Execution Engine for Agentic UEBA.

Executes ad-hoc multi-stage statistical anomaly detection over raw UDM telemetry
(C2 beaconing jitter, Poisson burst dispersion, rare event surges, and admin lateral expansion)
directly via Chronicle OneMCP.

Applies the remediated secops-statistical-hunter harness:

* Every query is the skill's current template rendered by the skill's own
  MultiStageTemplateRouter (slot defaults, tier thresholds, target-entity binding,
  D-2 Entity Graph anchoring) and validated with PipelineRunner.validate_ast before
  dispatch.
* EWMA_BURST_VELOCITY, SHANNON_ENTROPY_CHARACTER and C2_BEACONING_JITTER are scored by
  the skill's vetted scripts/micro_python_helpers.py over the raw udm_search payload
  (D6 guardrails G1-G5); malformed payloads fail closed.
* CRI, verdicts, retired models, the Mode A day and the micro-plane window cap come
  from src.harness_truth; nothing is re-declared here.
"""

from datetime import datetime, timedelta, timezone
import logging
import math
import re
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

from mcp import ClientSession

from src import harness_truth as ht
from src.config import TenantConfig
from src.pipeline_runner import PipelineRunner
from src.query_integrity_gate import QueryValidationError

logger = logging.getLogger("StatsHunterEngine")

# Outliers are CRI >= 46: the Medium, High and Critical bands (ARCHITECTURE.md Statistical Gate).
_OUTLIER_BANDS = ("MEDIUM", "HIGH", "CRITICAL")
_IP_LITERAL_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})$")
_ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"
_BUCKET_UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86400}


class HuntPlan(NamedTuple):
  """A rendered, validated stats-hunter query and the window it must be dispatched over."""

  archetype: str  # canonical archetype (the template's sensitivity key)
  template: str  # template file name
  query: str
  start: str  # dispatch window [start, end), ISO 8601 UTC
  end: str
  tier: str  # micro sensitivity tier (CONSERVATIVE / BALANCED / AGGRESSIVE)


def _num(value: Any) -> Optional[float]:
  """A finite float, or None."""
  if value is None or isinstance(value, bool):
    return None
  try:
    out = float(value)
  except (TypeError, ValueError):
    return None
  return out if math.isfinite(out) else None


def _round(value: Any, digits: int = 2) -> Optional[float]:
  num = _num(value)
  return None if num is None else round(num, digits)


def _cell(row: Dict[str, Any], key: str) -> Any:
  return row.get(key, row.get(f"${key}"))


def _root_section(query: str) -> str:
  blocks = list(re.finditer(r"stage\s+[a-zA-Z0-9_]+\s*\{[^}]*\}", query, flags=re.DOTALL))
  return query[blocks[-1].end():] if blocks else query


def _assessment(cri: Any, z_equiv: Any) -> Dict[str, Any]:
  """CRI, band, verdict and outlier flag from the harness; Z-equivalent on the common 3.0 scale."""
  cri_val = ht.coerce_cri(cri)
  band = ht.cri_band(cri_val)[0]
  return {
      "top_z_score": _round(z_equiv),
      "calibrated_risk_index": cri_val,
      "cri_band": band,
      "verdict": ht.verdict_for(cri_val),
      "is_outlier": band in _OUTLIER_BANDS,
  }


def _nominal_assessment() -> Dict[str, Any]:
  """Zero matching rows: nominal baseline (Z = 0.00, CRI 0), never an invented score."""
  return _assessment(ht.calculate_cri(0.0), 0.0)


def _score_assessment(score_key: Optional[str], value: Optional[float]) -> Dict[str, Any]:
  """Z-equivalent and CRI of a model's native score via the skill's score-semantics registry."""
  c = ht.constants()
  if score_key is None or value is None:
    return _assessment(None, None)
  return _assessment(c.cri_from_model_score(score_key, value), c.score_to_z_equivalent(score_key, value))


def _helper_summary(helper: Dict[str, Any], *extra: str) -> Dict[str, Any]:
  keys = ("model", "status", "parameters", "warnings", "provenance") + extra
  return {k: helper.get(k) for k in keys}


class StatsHunterEngine:
  """Executes ad-hoc raw UDM multi-stage statistical pipelines."""

  SKILL_NAME = ht.STATS_HUNTER_SKILL

  def __init__(self, tenant_config: Optional[TenantConfig] = None):
    self.runner = PipelineRunner(tenant_config)

  # ---------------------------------------------------------------------------
  # Telemetry Physics Guardrail and windows
  # ---------------------------------------------------------------------------

  @staticmethod
  def max_raw_lookback_days() -> int:
    """Raw UDM micro-plane window cap in days (ueba_constants.MAX_MODE_B_DAYS_MICRO).

    Strict Telemetry Physics Guardrail: raw UDM statistical hunts are bounded to this cap (30-day
    baselines over high-volume telemetry belong strictly to secops-risk-metrics-multistage).
    """
    return ht.mode_caps()["mode_b_micro_days"]

  @classmethod
  def enforce_telemetry_physics_window(cls, lookback_days: int) -> int:
    """Clamps raw UDM lookback windows to the micro-plane cap (30-day baselines belong to risk metrics)."""
    cap = cls.max_raw_lookback_days()
    days = max(1, int(lookback_days or 7))
    if days > cap:
      logger.info(
          f"Telemetry Physics Guardrail: clamping raw UDM lookback_days={days} to {cap}d "
          "(30d baselines belong strictly to secops-risk-metrics-multistage)."
      )
      return cap
    return days

  def _iso_window(self, lookback_days: int) -> Tuple[str, str]:
    """`[start, end)` of whole UTC days ending at the Mode A boundary (end of the last complete day D)."""
    days = self.enforce_telemetry_physics_window(lookback_days)
    _, end_iso = ht.mode_a_window()
    end_dt = datetime.strptime(end_iso, _ISO_FMT).replace(tzinfo=timezone.utc)
    return (end_dt - timedelta(days=days)).strftime(_ISO_FMT), end_iso

  # ---------------------------------------------------------------------------
  # Skill scripts, rendering and validation
  # ---------------------------------------------------------------------------

  def _get_stats_hunter_builder(self) -> Any:
    """secops-statistical-hunter multistage_query_builder, loaded by file path (no `scripts` collision)."""
    return self.runner.get_stats_hunter_builder()

  def _router(self) -> Any:
    builder = self._get_stats_hunter_builder()
    return builder.MultiStageTemplateRouter(
        template_dir=self.runner.skills_root / self.SKILL_NAME / "templates" / "pipelines"
    )

  @staticmethod
  def _router_entity_type(entity: Optional[str], entity_type: Optional[str] = None) -> str:
    """The router's entity type (host / user / ip) for an agentic_ueba entity."""
    kind = (entity_type or "").strip().upper()
    if kind in ("USER", "ACCOUNT", "IDENTITY", "PRINCIPAL_USER"):
      return "user"
    if kind == "IP" or _IP_LITERAL_RE.match(str(entity or "").strip()):
      return "ip"
    return "host"

  def _validated(self, query: str, source: str) -> str:
    """Raises QueryValidationError unless the query is fully rendered and passes the skills' validators."""
    self.runner.assert_fully_rendered(query, source=source)
    errors = self.runner.validate_ast(query, skill=self.SKILL_NAME)
    if errors:
      raise QueryValidationError(errors, query=query)
    return query

  def plan_hunt(
      self,
      archetype: str,
      entity: Optional[str] = None,
      entity_type: Optional[str] = None,
      lookback_days: int = 7,
      tier: Optional[str] = None,
      event_type: Optional[str] = None,
      entity_field: Optional[str] = None,
      token_field: Optional[str] = None,
      bucket_size: Optional[str] = None,
  ) -> HuntPlan:
    """Renders the skill's current template for `archetype` with the skill's router and validates it.

    Retired archetypes raise ValueError with the skill's own message. Entity Graph templates are anchored
    at D-2 (compute_ecg_search_window) with $in_scoring_window pinned to the requested window.
    """
    ht.assert_not_retired(archetype)
    builder = self._get_stats_hunter_builder()
    router = self._router()
    template = router.get_template_filename(archetype)
    canonical = router.TEMPLATE_TO_SENSITIVITY_KEY.get(template, str(archetype).strip().upper())
    days = self.enforce_telemetry_physics_window(lookback_days)
    start, end = self._iso_window(days)
    kwargs: Dict[str, Any] = {
        "archetype": archetype,
        "tier": tier,
        "entity_type": self._router_entity_type(entity, entity_type),
        "window_hours": days * 24.0,
        "start_time": start,
        "end_time": end,
        "target_entity_value": entity,
    }
    for key, value in (("event_type", event_type), ("entity_field", entity_field),
                       ("token_field", token_field), ("bucket_size", bucket_size)):
      if value:
        kwargs[key] = value
    dispatch_start, dispatch_end = start, end
    ecg_alias = builder.ECG_TEMPLATE_EVENT_ALIASES.get(template)
    if ecg_alias:
      window = builder.compute_ecg_search_window(start, end, event_alias=ecg_alias)
      kwargs["ecg_scoring_start_epoch"] = window["ecg_scoring_start_epoch"]
      kwargs["ecg_scoring_end_epoch"] = window["ecg_scoring_end_epoch"]
      dispatch_start, dispatch_end = window["effective_start_time"], window["effective_end_time"]
    query = self._validated(router.build_query(**kwargs), source=template)
    micro_tier = ht.constants().resolve_micro_sensitivity_tier(tier)
    return HuntPlan(canonical, template, query, dispatch_start, dispatch_end, micro_tier)

  def _tier_threshold(self, plan: HuntPlan, key: str) -> Any:
    """A tier threshold for the plan's archetype from the skill's SENSITIVITY_MAP."""
    return self._get_stats_hunter_builder().SENSITIVITY_MAP[plan.archetype][plan.tier][key]

  async def _dispatch(self, session: ClientSession, plan: HuntPlan) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    resp = await self.runner.execute_query_via_mcp(session, plan.query, plan.start, plan.end)
    return resp, self.runner.parse_stats_response(resp)

  def _primary_score(self, plan: HuntPlan, row: Dict[str, Any]) -> Tuple[Optional[str], Optional[float]]:
    """The template's ranking score (its root `order:` variable), else the skill's PRIMARY_SCORE_KEYS order."""
    order = re.search(r"^order:\s*\n\s*\$([A-Za-z0-9_]+)", _root_section(plan.query), flags=re.MULTILINE)
    keys: List[str] = [order.group(1)] if order else []
    keys += [k for k in self._get_stats_hunter_builder().PRIMARY_SCORE_KEYS if k not in keys]
    for key in keys:
      value = _num(_cell(row, key))
      if value is not None:
        return key, value
    return None, None

  @staticmethod
  def _base_result(plan: HuntPlan, entity: Optional[str], rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "entity": entity,
        "model": plan.archetype,
        "template": plan.template,
        "sensitivity_tier": plan.tier,
        "stats_rows": len(rows),
        "executed_query": plan.query,
        "start_time": plan.start,
        "end_time": plan.end,
    }

  async def _run_template_model(
      self, session: ClientSession, plan: HuntPlan, entity: Optional[str]
  ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Dispatches a template whose root emits its own score; returns (result, top_row)."""
    _, rows = await self._dispatch(session, plan)
    top = rows[0] if rows else {}
    score_key, score = self._primary_score(plan, top) if rows else (None, None)
    result = self._base_result(plan, entity, rows)
    result["score_metric"] = score_key
    result["primary_score"] = score
    result.update(_score_assessment(score_key, score) if rows else _nominal_assessment())
    return result, top

  # ---------------------------------------------------------------------------
  # D6 vetted Python helper models
  # ---------------------------------------------------------------------------

  async def run_c2_beaconing_jitter(
      self,
      session: ClientSession,
      src_ip: str,
      cv_threshold: Optional[float] = None,
      lookback_days: int = 7,
      tier: Optional[str] = None,
      entity_type: Optional[str] = None,
  ) -> Dict[str, Any]:
    """C2 beaconing: consecutive inter-arrival CV over stitched hourly timestamp arrays (WS6-04).

    c2_beaconing_jitter_2stage.yl2 extracts array_distinct(event_timestamps) for persistent, low-prevalence
    external pairs (RFC1918, loopback, multicast, broadcast and link-local destinations excluded) and
    scripts/micro_python_helpers.py c2-jitter computes CV = sigma_dt / mu_dt (beaconing at CV <= the tier cv).
    """
    plan = self.plan_hunt("C2_BEACONING_JITTER", entity=src_ip, entity_type=entity_type,
                          lookback_days=lookback_days, tier=tier, event_type="NETWORK_CONNECTION")
    resp, rows = await self._dispatch(session, plan)
    max_cv = float(cv_threshold) if cv_threshold is not None else float(self._tier_threshold(plan, "cv"))
    helper = self.runner.get_micro_python_helpers().run_c2_jitter_helper(
        resp, query_text=plan.query, max_cv=max_cv)
    pairs = helper.get("pair_results") or []  # sorted by CV, most regular first
    top = pairs[0] if pairs else None
    result = self._base_result(plan, src_ip, rows)
    result.update({
        "source_ip": src_ip,
        "score_metric": "cv",
        "primary_score": top["cv"] if top else None,
        "is_beaconing": bool(top and top["cv"] <= max_cv),
        "coefficient_of_variation": _round(top["cv"], 3) if top else None,
        "target_destination": top["dst_ip"] if top else None,
        "periodicity_score": _round(top["periodicity_score"], 3) if top else None,
        "interval_count": top["interval_count"] if top else 0,
        "array_distinct_cap_hit": bool(top and top["array_distinct_cap_hit"]),
        "max_cv": max_cv,
        "helper": _helper_summary(helper, "skipped_non_external_destinations", "skipped_insufficient_intervals"),
    })
    if top:
      result.update(_assessment(top["cri"], top["z_equiv"]))
    elif helper.get("skipped_insufficient_intervals"):
      # Pairs came back but none had enough consecutive intervals to measure jitter: not evaluated.
      result.update(_assessment(None, None))
      result["not_evaluated_reason"] = "C2_INSUFFICIENT_INTERVALS: no external pair met the helper's min_intervals"
    else:
      result.update(_nominal_assessment())
    return result

  async def run_shannon_character_entropy(
      self,
      session: ClientSession,
      entity: str,
      event_type: str = "PROCESS_LAUNCH",
      entity_field: Optional[str] = None,
      token_field: Optional[str] = None,
      lookback_days: int = 7,
      tier: Optional[str] = None,
      z_threshold: Optional[float] = None,
      entity_type: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Obfuscated command lines / DGA strings: exact per-character Shannon entropy (WS6-03).

    shannon_entropy_character_2stage.yl2 extracts ungated candidate and multi-host benign strings on the
    {{token_field}} slot (default principal.process.command_line) and scripts/micro_python_helpers.py
    shannon standardizes each rare string against length-matched benign strings (Z_H).
    """
    plan = self.plan_hunt("SHANNON_ENTROPY_CHARACTER", entity=entity, entity_type=entity_type,
                          lookback_days=lookback_days, tier=tier, event_type=event_type,
                          entity_field=entity_field, token_field=token_field)
    resp, rows = await self._dispatch(session, plan)
    min_length = int(self._tier_threshold(plan, "min_length"))
    z_thr = float(z_threshold) if z_threshold is not None else float(ht.constants().DEFAULT_ANOMALY_THRESHOLD)
    result = self._base_result(plan, entity, rows)
    result["score_metric"] = "shannon_z"
    result["z_threshold"] = z_thr
    try:
      helper = self.runner.get_micro_python_helpers().run_shannon_helper(
          resp, query_text=plan.query, min_length=min_length, z_threshold=z_thr)
    except ValueError as exc:
      if not str(exc).startswith("INSUFFICIENT_BENIGN_LENGTH_COHORT"):
        raise  # G1/G2: malformed or non-Chronicle payloads fail closed
      # Rare strings came back but there is no benign reference cohort to standardize them against.
      result.update({"primary_score": None, "shannon_entropy_score": None, "shannon_z": None,
                     "sample_token": None, "not_evaluated_reason": str(exc)})
      result.update(_assessment(None, None))
      return result
    candidates = helper.get("candidate_results") or []  # sorted by Z_H, highest first
    top = candidates[0] if candidates else None
    result.update({
        "primary_score": top["shannon_z"] if top else None,
        "shannon_entropy_score": _round(top["entropy_bits"]) if top else None,
        "shannon_z": _round(top["shannon_z"]) if top else None,
        "sample_token": top["token"] if top else None,
        "token_length": top["length"] if top else None,
        "cohort_mode": top["cohort_mode"] if top else None,
        "helper": _helper_summary(helper, "benign_cohort_count"),
    })
    result.update(_assessment(top["cri"], top["z_equiv"]) if top else _nominal_assessment())
    return result

  run_shannon_entropy = run_shannon_character_entropy

  async def run_ewma_burst_velocity(
      self,
      session: ClientSession,
      entity: str,
      event_type: str = "NETWORK_CONNECTION",
      entity_field: Optional[str] = None,
      lookback_days: int = 7,
      tier: Optional[str] = None,
      control_l: Optional[float] = None,
      entity_type: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Acute intraday rate shifts: recursive EWMA control chart over the dense zero-filled grid (WS6-02).

    ewma_burst_velocity_2stage.yl2 extracts the ungated bucketed series and scripts/micro_python_helpers.py
    ewma evaluates S_t against UCL = mu_0 + L * sigma_0 * sqrt(lambda / (2 - lambda)), L = the tier
    velocity threshold.
    """
    plan = self.plan_hunt("EWMA_BURST_VELOCITY", entity=entity, entity_type=entity_type,
                          lookback_days=lookback_days, tier=tier, event_type=event_type,
                          entity_field=entity_field)
    resp, rows = await self._dispatch(session, plan)
    level = float(control_l) if control_l is not None else float(self._tier_threshold(plan, "velocity_threshold"))
    bucket = re.search(r"\bby\s+(\d+)([mhd])\b", _root_section(plan.query))
    if not bucket:
      raise QueryValidationError(["EWMA_BUCKET_UNRESOLVED: root match: has no 'by <n><m|h|d>' bucket"], plan.query)
    helper = self.runner.get_micro_python_helpers().run_ewma_helper(
        resp, query_text=plan.query, start_time=plan.start, end_time=plan.end, control_l=level,
        bucket_seconds=int(bucket.group(1)) * _BUCKET_UNIT_SECONDS[bucket.group(2)])
    series = helper.get("entity_results") or []
    top = max(series, key=lambda r: r["ewma_z"]) if series else None
    result = self._base_result(plan, entity, rows)
    result.update({
        "score_metric": "ewma_z",
        "primary_score": top["ewma_z"] if top else None,
        "ewma_velocity_score": _round(top["ewma_z"]) if top else None,
        "velocity_score": _round(top["ewma_z"]) if top else None,
        "peak_ewma": _round(top["peak_ewma"]) if top else None,
        "ucl": _round(top["ucl"]) if top else None,
        "peak_window": top["window_label"] if top else None,
        "control_limit_l": level,
        "helper": _helper_summary(helper),
    })
    result.update(_assessment(top["cri"], top["z_equiv"]) if top else _nominal_assessment())
    return result

  run_ewma_velocity = run_ewma_burst_velocity

  # ---------------------------------------------------------------------------
  # Template-scored models
  # ---------------------------------------------------------------------------

  async def run_poisson_burst_clustering(
      self,
      session: ClientSession,
      entity: str,
      event_type: str = "USER_LOGIN",
      lookback_days: int = 7,
      tier: Optional[str] = None,
      entity_type: Optional[str] = "USER",
  ) -> Dict[str, Any]:
    """Intermittent credential spray bursts via the zero-inclusive Fano factor (F = sigma^2 / mu)."""
    plan = self.plan_hunt("POISSON_BURST_CLUSTERING", entity=entity, entity_type=entity_type,
                          lookback_days=lookback_days, tier=tier, event_type=event_type)
    result, _ = await self._run_template_model(session, plan, entity)
    fano = result["primary_score"] if result["score_metric"] == "fano_factor" else None
    result.update({
        "fano_factor": _round(fano),
        "top_fano": _round(fano),
        "is_burst": result["is_outlier"],
    })
    return result

  # Aliases for backward compatibility
  run_poisson_burst_spray = run_poisson_burst_clustering
  run_fano_burst_hunting = run_poisson_burst_clustering

  async def run_poisson_rare_surge(
      self,
      session: ClientSession,
      entity: str,
      event_type: str = "PROCESS_LAUNCH",
      entity_field: Optional[str] = "principal.user.userid",
      lookback_days: int = 7,
      tier: Optional[str] = None,
      entity_type: Optional[str] = "USER",
  ) -> Dict[str, Any]:
    """Acute arrival rarity of sensitive commands on historically quiet baselines (Poisson deviance)."""
    plan = self.plan_hunt("POISSON_RARE_SURGE", entity=entity, entity_type=entity_type,
                          lookback_days=lookback_days, tier=tier, event_type=event_type,
                          entity_field=entity_field)
    result, top = await self._run_template_model(session, plan, entity)
    z_sq = result["primary_score"] if result["score_metric"] == "poisson_z_sq" else None
    result.update({
        "poisson_z_sq": _round(z_sq),
        "poisson_z": _round(math.sqrt(max(0.0, z_sq))) if z_sq is not None else None,
        "rare_tool": _cell(top, "tool"),
    })
    return result

  async def run_markov_transition_rarity(
      self,
      session: ClientSession,
      host: Optional[str] = None,
      event_type: str = "PROCESS_LAUNCH",
      entity_field: Optional[str] = None,
      bucket_size: Optional[str] = None,
      lookback_days: int = 7,
      tier: Optional[str] = None,
      entity: Optional[str] = None,
      entity_type: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Rare parent-child process transitions via whole-window Laplace-smoothed Markov 2-gram surprisal."""
    target = host if host is not None else entity
    plan = self.plan_hunt("MARKOV_2GRAM_TRANSITION_RARITY", entity=target, entity_type=entity_type,
                          lookback_days=lookback_days, tier=tier, event_type=event_type,
                          entity_field=entity_field, bucket_size=bucket_size)
    result, top = await self._run_template_model(session, plan, target)
    score = result["primary_score"] if result["score_metric"] == "markov_threat_score" else None
    result.update({
        "markov_threat_score": _round(score),
        # The template's threat score is the information surprisal ln((N_parent + V) / (N_pair + 1)).
        "surprisal_score": _round(score),
        "transition_probability": _num(_cell(top, "transition_prob")),
        "parent_process": _cell(top, "parent"),
        "child_process": _cell(top, "child"),
    })
    return result

  run_markov_process_transition = run_markov_transition_rarity

  async def run_zipfian_process_rarity(
      self,
      session: ClientSession,
      host: Optional[str] = None,
      event_type: str = "PROCESS_LAUNCH",
      entity_field: Optional[str] = None,
      bucket_size: Optional[str] = None,
      lookback_days: int = 7,
      tier: Optional[str] = None,
      entity: Optional[str] = None,
      entity_type: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Rare binaries in the enterprise Zipfian long tail via host-prevalence IDF ln(N_fleet / H)."""
    target = host if host is not None else entity
    plan = self.plan_hunt("ZIPFIAN_PROCESS_RARITY", entity=target, entity_type=entity_type,
                          lookback_days=lookback_days, tier=tier, event_type=event_type,
                          entity_field=entity_field, bucket_size=bucket_size)
    result, top = await self._run_template_model(session, plan, target)
    score = result["primary_score"] if result["score_metric"] == "zipf_rarity_score" else None
    result.update({
        "zipf_rarity_score": _round(score),
        "rare_binary": _cell(top, "binary"),
        "adopter_hosts": _num(_cell(top, "adopter_hosts")),
    })
    return result

  run_zipf_rarity = run_zipfian_process_rarity

  async def run_producer_consumer_inversion(
      self,
      session: ClientSession,
      hostname: str = "*",
      lookback_days: int = 14,
      tier: Optional[str] = None,
      event_type: str = "NETWORK_CONNECTION",
      entity_type: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Endpoint role inversion: leave-one-out producer-ratio Z (rho = sent / (sent + received + 1))."""
    plan = self.plan_hunt("PRODUCER_CONSUMER_RATIO_INVERSION", entity=hostname, entity_type=entity_type,
                          lookback_days=lookback_days, tier=tier, event_type=event_type)
    result, top = await self._run_template_model(session, plan, hostname)
    z = result["primary_score"] if result["score_metric"] == "z_score" else None
    result.update({
        "pcr_z_score": _round(z),
        "producer_ratio": _round(_cell(top, "producer_ratio"), 3),
    })
    return result

  async def run_impossible_travel_velocity(
      self,
      session: ClientSession,
      user_id: str = "*",
      lookback_days: int = 14,
      tier: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Retired (secops-statistical-hunter D1): always refuses with the skill's retirement message.

    City-centroid geo-velocity and VPN egress produce systematic false positives; the skill names
    HOUR_OF_DAY_PROFILE (run_hour_of_day_profile) or DERIVED_CONTEXT_PREVALENCE instead. Nothing is planned
    or dispatched.
    """
    del session, user_id, lookback_days, tier
    ht.assert_not_retired("IMPOSSIBLE_TRAVEL_GEO_VELOCITY")
    raise ValueError(
        "IMPOSSIBLE_TRAVEL_GEO_VELOCITY is not provided by agentic_ueba; use HOUR_OF_DAY_PROFILE "
        "(run_hour_of_day_profile) or DERIVED_CONTEXT_PREVALENCE."
    )

  async def run_hour_of_day_profile(
      self,
      session: ClientSession,
      entity: str,
      entity_type: str = "USER",
      event_type: Optional[str] = None,
      lookback_days: int = 7,
      tier: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Learned 24-bin hour-of-day profile, scored out-of-sample (HOUR_OF_DAY_PROFILE, WS5-HOD)."""
    return await self.run_dynamic_archetype_pipeline(
        session, entity=entity, archetype="HOUR_OF_DAY_PROFILE", entity_type=entity_type,
        event_type=event_type, lookback_days=lookback_days, tier=tier)

  async def run_dynamic_archetype_pipeline(
      self,
      session: ClientSession,
      entity: str = "*",
      archetype: str = "ZSCORE_PROCESS_SURGE",
      entity_type: str = "ASSET",
      event_type: Optional[str] = None,
      lookback_days: int = 7,
      tier: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Executes any active secops-statistical-hunter template (retired archetypes are refused).

    EWMA_BURST_VELOCITY, SHANNON_ENTROPY_CHARACTER and C2_BEACONING_JITTER are routed to their vetted
    Python helpers; every other template is scored on its own ranking column.
    """
    ht.assert_not_retired(archetype)
    router = self._router()
    canonical = router.TEMPLATE_TO_SENSITIVITY_KEY.get(router.get_template_filename(archetype))
    if canonical in router.PYTHON_HELPER_SCREEN_ALTERNATIVES:
      if canonical == "C2_BEACONING_JITTER":
        result = await self.run_c2_beaconing_jitter(
            session, src_ip=entity, lookback_days=lookback_days, tier=tier, entity_type=entity_type)
      elif canonical == "SHANNON_ENTROPY_CHARACTER":
        result = await self.run_shannon_character_entropy(
            session, entity=entity, event_type=event_type or "PROCESS_LAUNCH", lookback_days=lookback_days,
            tier=tier, entity_type=entity_type)
      else:
        result = await self.run_ewma_burst_velocity(
            session, entity=entity, event_type=event_type or "NETWORK_CONNECTION", lookback_days=lookback_days,
            tier=tier, entity_type=entity_type)
    else:
      plan = self.plan_hunt(archetype, entity=entity, entity_type=entity_type, lookback_days=lookback_days,
                            tier=tier, event_type=event_type)
      result, _ = await self._run_template_model(session, plan, entity)
    result["entity_type"] = entity_type
    result["requested_archetype"] = archetype
    return result

  async def run_iqr_tukey_skew_fences(
      self,
      session: ClientSession,
      entity: str,
      entity_type: str = "ASSET",
      event_type: str = "NETWORK_CONNECTION",
      lookback_days: int = 14,
      tier: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Non-parametric quantiles, Bowley skewness (1.35 recalibration) and scale-invariant Tukey fence Z."""
    return await self.run_dynamic_archetype_pipeline(
        session=session,
        entity=entity,
        archetype="IQR_TUKEY_SKEW_FENCES",
        entity_type=entity_type,
        event_type=event_type,
        lookback_days=lookback_days,
        tier=tier,
    )

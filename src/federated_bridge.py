# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Federated Bridge for Two-Phase Chained Threat Hunting (Bilateral Framework).

Implements the cross-hemisphere handoff connecting Macro Risk Metrics to Micro Statistical Hunter:
Phase 1: Macro 30-Day Volumetric Outlier Sieve (Risk Metrics)
Bridge Contract: Extracts technical bridge keys ($user, $caller_ip, $target_ip, $timestamp)
Phase 2: Targeted Micro-Analysis (Stats Hunter drill-down on specific IP/host)
Verdict: Fuses macro baseline departure with micro attack physics into a unified Clean Hand-Off.

Bands, verdicts, recommended actions, the CRI formula, score semantics and the
Option 3 loopback thresholds all come from the remediated UEBA harness via
`src.harness_truth`; the bridge declares none of them. Recommended actions are
recommendations only: the bridge never executes containment.
"""

import logging
import math
from typing import Any, Dict, List, Optional
from mcp import ClientSession

from src import harness_truth
from src.config import TenantConfig
from src.risk_metrics_engine import RiskMetricsEngine
from src.stats_hunter_engine import StatsHunterEngine
from src.models import CleanHandOffPayload, MetricEvaluation, TriageSummary

logger = logging.getLogger("FederatedBridge")

# Domain containment recommendation for a chained threat; harness_truth.recommended_action
# returns it only at the Critical band (INVESTIGATE at High/Medium, MONITOR otherwise).
CONTAINMENT_ACTION = "ISOLATE_HOST_AND_REVOKE_TOKENS"

# Phase-result fields the bridge reads as a phase score, in priority order, each paired with the
# skills' SCORE_SEMANTICS_REGISTRY key that maps it onto the canonical Z-equivalent scale
# (ueba_constants.score_to_z_equivalent). Native micro scores (Fano, CV, Markov surprisal) come
# first so they are never read as raw sigma; a phase with no score maps its CRI back to Z.
_PHASE_SCORE_FIELDS = (
    ("poisson_z", "poisson_z"),
    ("fano_factor", "fano_factor"),
    ("coefficient_of_variation", "cv"),
    ("markov_threat_score", "markov_threat_score"),
    ("top_z_score", "z_score"),
    ("composite_d", "composite_threat_distance"),
    ("calibrated_risk_index", "cri"),
)


def _alertable(cri: Any) -> bool:
  """True when the harness recommends more than monitoring (Medium band and above)."""
  return harness_truth.recommended_action(cri) != "MONITOR"


def _phase_z_equivalent(phase: Optional[Dict[str, Any]]) -> float:
  """Rectified Z-equivalent of a phase result (0.0 when it carries no usable score)."""
  if not phase:
    return 0.0
  semantics = harness_truth.constants()
  for field, score_key in _PHASE_SCORE_FIELDS:
    if phase.get(field) is None:
      continue
    z_equiv = semantics.score_to_z_equivalent(score_key, phase[field])
    if z_equiv is not None:
      return max(0.0, float(z_equiv))
  return 0.0


def _decision_fields(cri: Optional[int]) -> Dict[str, Any]:
  """Harness verdict, recommended action and guidance for a CRI (missing CRI never escalates)."""
  return {
      "verdict": harness_truth.verdict_for(cri),
      "recommended_action": harness_truth.recommended_action(cri, containment_action=CONTAINMENT_ACTION),
      "action_guidance": harness_truth.action_guidance(cri),
      "recommendation_note": harness_truth.RECOMMENDATION_NOTE,
  }


class FederatedBridge:
  """Bilateral bridge orchestrating two-phase chained threat hunts across the UEBA Harness."""

  def __init__(self, tenant_config: Optional[TenantConfig] = None):
    self.tenant = tenant_config or TenantConfig()
    self.risk_engine = RiskMetricsEngine(self.tenant)
    self.stats_engine = StatsHunterEngine(self.tenant)

  async def run_two_phase_chained_hunt(
      self,
      session: ClientSession,
      username: str,
      macro_vector: str = "360",
      lookback_days: int = 14,
  ) -> Dict[str, Any]:
    """Executes an autonomous macro-to-micro federated threat hunt across the Bilateral UEBA Harness."""
    logger.info(f"Phase 1: Running Macro Baseline Sieve for {username} ({macro_vector})")
    vec_norm = (macro_vector or "360").strip().lower()

    # 1. Phase 1: Macro Volumetric Baseline (30d pre-computed metrics.*)
    if vec_norm == "cloud":
      macro_res = await self.risk_engine.run_cloud_crud_surge(session, username, lookback_days)
      top_vector = "cloud_crud_surge"
    else:
      macro_res = await self.risk_engine.run_360_behavioral_radar(session, username, lookback_days)
      if vec_norm in ("web_exploit", "http2shell", "exploit", "web_to_shell"):
        top_vector = "web_exploit"
      elif vec_norm in ("shadow_ai", "unsanctioned_ai"):
        top_vector = "shadow_ai"
      else:
        top_vector = macro_res.get("top_sector", "auth")
    macro_cri = harness_truth.coerce_cri(macro_res.get("calibrated_risk_index"))

    # Below the harness alertable band (or not evaluated): stop before the expensive micro probes.
    if not _alertable(macro_cri):
      logger.info(
          f"Phase 1 returned no alertable macro outlier (CRI={harness_truth.format_cri(macro_cri)}). Hunt complete."
      )
      return {
          "status": "NOT_EVALUATED" if macro_cri is None else "NOMINAL_BASELINE",
          "entity": username,
          "calibrated_risk_index": macro_cri,
          **_decision_fields(macro_cri),
          "macro_phase": macro_res,
          "micro_phase": None,
          "is_chained_threat": False,
      }

    # 2. Phase 2: Bridge Contract -> Micro Drill-Down (bounded <= 14d per Telemetry Physics Guardrail)
    logger.info(f"Phase 1 Outlier Detected (CRI={macro_cri}). Triggering Phase 2 Micro Drill-down...")
    micro_days = self.stats_engine.enforce_telemetry_physics_window(min(int(lookback_days or 7), 7))

    # Select micro-pipeline based on the macro vector that spiked
    micro_res = None
    tv_low = top_vector.lower()
    if tv_low in ("web_exploit", "http2shell", "exploit", "web_to_shell") or "endpoint" in tv_low or "process" in tv_low:
      # Spiking web/process exploitation -> check Markov 2-gram parent->child process lineage
      micro_res = await self.stats_engine.run_markov_transition_rarity(
          session, entity=username, lookback_days=micro_days
      )
    elif tv_low in ("shadow_ai", "unsanctioned_ai") or "egress" in tv_low or "dns" in tv_low or "web" in tv_low:
      # Spiking network/DNS/Shadow AI egress -> check for C2/agentic loop beaconing jitter
      micro_res = await self.stats_engine.run_c2_beaconing_jitter(
          session, src_ip=username, lookback_days=micro_days
      )
    elif "cloud" in tv_low:
      # Spiking cloud writes -> check for rare command/admin surges
      micro_res = await self.stats_engine.run_poisson_rare_surge(
          session, entity=username, lookback_days=micro_days
      )
    else:
      # Spiking auth -> check for Poisson burst/spray clustering
      micro_res = await self.stats_engine.run_poisson_burst_clustering(
          session, entity=username, lookback_days=micro_days
      )

    micro_cri = harness_truth.coerce_cri(micro_res.get("calibrated_risk_index")) if micro_res else None
    macro_z = _phase_z_equivalent(macro_res)
    micro_z = _phase_z_equivalent(micro_res)
    combined_norm_sq = round(macro_z * macro_z + micro_z * micro_z, 2)
    combined_z = round(math.sqrt(combined_norm_sq), 2)

    # 3. Verdict Fusion: rectified Euclidean norm D = sqrt(sum max(0, Z_i)^2) -> harness CRI, and
    #    Option 3 UDM Loopback eligibility (>= min distinct hits and sum Z_i^2 >= threshold).
    fused_cri = harness_truth.calculate_cri(math.sqrt(macro_z * macro_z + micro_z * micro_z))
    distinct_hits = sum(1 for phase_cri in (macro_cri, micro_cri) if _alertable(phase_cri))
    is_confirmed_threat = _alertable(macro_cri) and _alertable(micro_cri)
    min_hits, sum_z_sq_threshold = harness_truth.loopback_thresholds()
    loopback_eligible = distinct_hits >= min_hits and combined_norm_sq >= sum_z_sq_threshold

    return {
        "status": "CHAINED_THREAT_CONFIRMED" if is_confirmed_threat else "MACRO_OUTLIER_UNVERIFIED_MICRO",
        "entity": username,
        "calibrated_risk_index": fused_cri,
        **_decision_fields(fused_cri),
        "primary_vector": top_vector,
        "macro_phase": macro_res,
        "micro_phase": micro_res,
        "combined_z": combined_z,
        "combined_norm_sq": combined_norm_sq,
        "distinct_hits": distinct_hits,
        "loopback_eligible": loopback_eligible,
        "is_chained_threat": is_confirmed_threat,
    }

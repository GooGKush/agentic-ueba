# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Federated Bridge for Two-Phase Chained Threat Hunting (Bilateral Framework).

Implements the cross-hemisphere handoff connecting Macro Risk Metrics to Micro Statistical Hunter:
Phase 1: Macro 30-Day Volumetric Outlier Sieve (Risk Metrics)
Bridge Contract: Extracts technical bridge keys ($user, $caller_ip, $target_ip, $timestamp)
Phase 2: Targeted Micro-Analysis (Stats Hunter drill-down on specific IP/host)
Verdict: Fuses macro baseline departure with micro attack physics into a unified Clean Hand-Off.
"""

import logging
from typing import Any, Dict, List, Optional
from mcp import ClientSession

from src.config import TenantConfig
from src.risk_metrics_engine import RiskMetricsEngine
from src.stats_hunter_engine import StatsHunterEngine
from src.models import CleanHandOffPayload, MetricEvaluation, TriageSummary

logger = logging.getLogger("FederatedBridge")


class FederatedBridge:
  """Bilateral bridge orchestrating two-phase chained threat hunts."""

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
    """Executes an autonomous macro-to-micro federated threat hunt."""
    logger.info(f"Phase 1: Running Macro Baseline Sieve for {username} ({macro_vector})")
    
    # 1. Phase 1: Macro Volumetric Baseline
    if macro_vector == "cloud":
      macro_res = await self.risk_engine.run_cloud_crud_surge(session, username, lookback_days)
      macro_cri = macro_res.get("calibrated_risk_index", 0)
      top_vector = "cloud_crud_surge"
    else:
      macro_res = await self.risk_engine.run_360_behavioral_radar(session, username, lookback_days)
      macro_cri = macro_res.get("calibrated_risk_index", 0)
      top_vector = macro_res.get("top_sector", "auth")

    # If nominal at macro level, return early without expensive micro probes
    if macro_cri < 46:
      logger.info(f"Phase 1 returned nominal baseline (CRI={macro_cri}). Hunt complete.")
      return {
          "status": "NOMINAL_BASELINE",
          "entity": username,
          "calibrated_risk_index": macro_cri,
          "verdict": "NOMINAL_BASELINE",
          "macro_phase": macro_res,
          "micro_phase": None,
          "is_chained_threat": False,
      }

    # 2. Phase 2: Bridge Contract -> Micro Drill-Down
    logger.info(f"Phase 1 Outlier Detected (CRI={macro_cri}). Triggering Phase 2 Micro Drill-down...")
    
    # Select micro-pipeline based on the macro vector that spiked
    micro_res = None
    if "egress" in top_vector.lower() or "dns" in top_vector.lower():
      # Spiking network/DNS -> check for C2 beaconing jitter
      micro_res = await self.stats_engine.run_c2_beaconing_jitter(session, src_ip=username, lookback_days=7)
    elif "cloud" in top_vector.lower():
      # Spiking cloud writes -> check for rare command/admin surges
      micro_res = await self.stats_engine.run_poisson_rare_surge(session, entity=username, lookback_days=7)
    else:
      # Spiking auth -> check for Poisson burst/spray clustering
      micro_res = await self.stats_engine.run_poisson_burst_clustering(session, entity=username, lookback_days=7)

    micro_cri = micro_res.get("calibrated_risk_index", 0) if micro_res else 0

    # 3. Verdict Fusion: Joint Probability / CRI Escalation
    fused_cri = min(100, round(macro_cri * 0.6 + micro_cri * 0.4))
    is_confirmed_threat = macro_cri >= 46 and micro_cri >= 46

    verdict = "CRITICAL_OUTLIER" if fused_cri >= 80 else ("HIGH_OUTLIER" if fused_cri >= 60 else "MEDIUM_OUTLIER")

    return {
        "status": "CHAINED_THREAT_CONFIRMED" if is_confirmed_threat else "MACRO_OUTLIER_UNVERIFIED_MICRO",
        "entity": username,
        "calibrated_risk_index": fused_cri,
        "verdict": verdict,
        "primary_vector": top_vector,
        "macro_phase": macro_res,
        "micro_phase": micro_res,
        "is_chained_threat": is_confirmed_threat,
        "recommended_action": "ISOLATE_HOST_AND_REVOKE_TOKENS" if is_confirmed_threat else "ENRICH_AND_MONITOR",
    }

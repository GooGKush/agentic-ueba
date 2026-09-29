# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Deterministic Statistical Hunter Execution Engine for Agentic UEBA.

Executes ad-hoc multi-stage statistical anomaly detection over raw UDM telemetry
(C2 beaconing jitter, Poisson burst dispersion, rare event surges, and admin lateral expansion)
directly via Chronicle OneMCP.
"""

from datetime import datetime, timedelta, timezone
import json
import logging
import math
from typing import Any, Dict, List, Optional, Tuple
from mcp import ClientSession

from src.pipeline_runner import PipelineRunner
from src.config import TenantConfig

logger = logging.getLogger("StatsHunterEngine")


class StatsHunterEngine:
  """Executes ad-hoc raw UDM multi-stage statistical pipelines."""

  SKILL_NAME = "secops-statistical-hunter"

  def __init__(self, tenant_config: Optional[TenantConfig] = None):
    self.runner = PipelineRunner(tenant_config)

  def _iso_window(self, lookback_days: int) -> Tuple[str, str]:
    """Generates strict ISO 8601 UTC start and end timestamps."""
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(days=lookback_days)
    return (
        start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

  async def run_c2_beaconing_jitter(
      self,
      session: ClientSession,
      src_ip: str,
      min_conns: int = 25,
      cv_threshold: float = 0.20,
      lookback_days: int = 7,
  ) -> Dict[str, Any]:
    """Detects robotic C2 beaconing timing regularity via Coefficient of Variation (CV <= 0.20)."""
    start_iso, end_iso = self._iso_window(lookback_days)
    tpl_path = self.runner.find_template(self.SKILL_NAME, "c2_beaconing_jitter_2stage.yl2")

    params = {
        "event_type": "NETWORK_CONNECTION",
        "min_conns": str(min_conns),
        "min_active_hours": "3",
        "prevalence": "5",
        "tier": "STANDARD",
        "bucket_size": "1h",
        "cv": str(cv_threshold),
    }

    rendered = self.runner.render_template(tpl_path, params)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    is_beaconing = False
    top_cv = 1.0
    detected_dst = None

    if rows:
      top_row = rows[0]
      top_cv = float(top_row.get("cv", top_row.get("coefficient_of_variation", 1.0)) or 1.0)
      detected_dst = top_row.get("dst_ip", "UNKNOWN")
      is_beaconing = top_cv <= cv_threshold

    # Invert CV into risk score (lower CV = higher regularity = higher risk)
    risk_score = round(max(0.0, (1.0 - top_cv)) * 100) if is_beaconing else 10

    return {
        "source_ip": src_ip,
        "model": "C2_BEACONING_JITTER",
        "is_beaconing": is_beaconing,
        "coefficient_of_variation": round(top_cv, 3),
        "target_destination": detected_dst,
        "calibrated_risk_index": risk_score,
        "is_outlier": is_beaconing,
        "executed_query": rendered,
    }

  async def run_poisson_burst_clustering(
      self,
      session: ClientSession,
      entity: str,
      event_type: str = "USER_LOGIN",
      lookback_days: int = 7,
  ) -> Dict[str, Any]:
    """Detects intermittent credential spray bursts via Fano Factor dispersion (F = σ² / μ > 4.0)."""
    start_iso, end_iso = self._iso_window(lookback_days)
    tpl_path = self.runner.find_template(self.SKILL_NAME, "poisson_burst_clustering_2stage.yl2")

    params = {
        "event_type": event_type,
        "fano_factor": "4.0",
        "min_fails": "10",
        "min_active_samples": "2",
        "min_mu": "1.0",
        "tier": "STANDARD",
        "entity_field": "target.user.userid",
        "bucket_size": "1h",
        "prevalence": "10",
    }

    rendered = self.runner.render_template(tpl_path, params)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    fano = 1.0
    is_burst = False
    if rows:
      row = rows[0]
      fano = float(row.get("fano_factor", row.get("dispersion", 1.0)) or 1.0)
      is_burst = fano >= 4.0

    cri = self.runner.calculate_cri(fano - 1.0)
    return {
        "entity": entity,
        "model": "POISSON_BURST_CLUSTERING",
        "fano_factor": round(fano, 2),
        "is_burst": is_burst,
        "calibrated_risk_index": cri,
        "is_outlier": is_burst,
        "executed_query": rendered,
    }

  async def run_poisson_rare_surge(
      self,
      session: ClientSession,
      entity: str,
      event_type: str = "PROCESS_LAUNCH",
      lookback_days: int = 7,
  ) -> Dict[str, Any]:
    """Detects acute arrival rarity of sensitive commands/actions on historically quiet baselines."""
    start_iso, end_iso = self._iso_window(lookback_days)
    tpl_path = self.runner.find_template(self.SKILL_NAME, "poisson_rare_surge_2stage.yl2")

    params = {
        "event_type": event_type,
        "entity_field": "principal.user.userid",
        "rare_threshold": "3.5",
        "min_observed": "3",
    }

    rendered = self.runner.render_template(tpl_path, params)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    z_score = 0.0
    if rows:
      z_score = float(rows[0].get("poisson_z", rows[0].get("z_score", 0.0)) or 0.0)

    cri = self.runner.calculate_cri(z_score)
    return {
        "entity": entity,
        "model": "POISSON_RARE_SURGE",
        "poisson_z": round(z_score, 2),
        "calibrated_risk_index": cri,
        "is_outlier": cri >= 46,
        "executed_query": rendered,
    }

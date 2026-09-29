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
        "stats_rows": len(rows),
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
        "top_fano": round(fano, 2),
        "top_z_score": round(fano, 2),
        "is_burst": is_burst,
        "calibrated_risk_index": cri,
        "is_outlier": is_burst,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

  # Alias for backward compatibility
  run_poisson_burst_spray = run_poisson_burst_clustering

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
        "top_z_score": round(z_score, 2),
        "calibrated_risk_index": cri,
        "is_outlier": cri >= 46,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

  async def run_markov_transition_rarity(
      self,
      session: ClientSession,
      host: str,
      event_type: str = "PROCESS_LAUNCH",
      entity_field: str = "principal.hostname",
      bucket_size: str = "1d",
      min_parent_count: int = 5,
      surprisal_threshold: float = 3.5,
      lookback_days: int = 7,
  ) -> Dict[str, Any]:
    """Detects rare, unobserved process parent-child execution transitions via Markov 2-Gram Transition Rarity."""
    start_iso, end_iso = self._iso_window(lookback_days)
    tpl_path = self.runner.find_template(self.SKILL_NAME, "markov_2gram_transition_rarity_2stage.yl2")

    params = {
        "event_type": event_type,
        "entity_field": entity_field,
        "bucket_size": bucket_size,
        "min_parent_count": str(min_parent_count),
        "surprisal_threshold": str(surprisal_threshold),
        "tier": "STANDARD",
    }

    rendered = self.runner.render_template(tpl_path, params)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    threat_score = 0.0
    surprisal = 0.0
    parent_proc = None
    child_proc = None
    if rows:
      top_row = rows[0]
      threat_score = float(top_row.get("markov_threat_score", top_row.get("$markov_threat_score", 0.0)) or 0.0)
      surprisal = float(top_row.get("surprisal_score", top_row.get("$surprisal_score", 0.0)) or 0.0)
      parent_proc = top_row.get("parent", top_row.get("$parent", None))
      child_proc = top_row.get("child", top_row.get("$child", None))

    cri = self.runner.calculate_cri(threat_score)
    is_outlier = cri >= 60 or threat_score >= surprisal_threshold
    return {
        "entity": host,
        "model": "MARKOV_TRANSITION_RARITY",
        "markov_threat_score": round(threat_score, 2),
        "surprisal_score": round(surprisal, 2),
        "parent_process": parent_proc,
        "child_process": child_proc,
        "top_z_score": round(threat_score, 2),
        "calibrated_risk_index": cri,
        "is_outlier": is_outlier,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

  async def run_shannon_character_entropy(
      self,
      session: ClientSession,
      entity: str,
      event_type: str = "PROCESS_LAUNCH",
      entity_field: str = "principal.hostname",
      bucket_size: str = "1d",
      min_length: int = 20,
      entropy_threshold: float = 6.0,
      lookback_days: int = 7,
  ) -> Dict[str, Any]:
    """Detects obfuscated command lines and high-entropy arguments via Shannon Character-Class Entropy."""
    start_iso, end_iso = self._iso_window(lookback_days)
    tpl_path = self.runner.find_template(self.SKILL_NAME, "shannon_entropy_character_2stage.yl2")

    params = {
        "event_type": event_type,
        "entity_field": entity_field,
        "bucket_size": bucket_size,
        "min_length": str(min_length),
        "entropy_threshold": str(entropy_threshold),
        "tier": "STANDARD",
    }

    rendered = self.runner.render_template(tpl_path, params)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    entropy_score = 0.0
    token_cmd = None
    if rows:
      top_row = rows[0]
      entropy_score = float(top_row.get("shannon_entropy_score", top_row.get("$shannon_entropy_score", 0.0)) or 0.0)
      token_cmd = top_row.get("token", top_row.get("$token", None))

    cri = self.runner.calculate_cri(entropy_score)
    is_outlier = cri >= 60 or entropy_score >= entropy_threshold
    return {
        "entity": entity,
        "model": "SHANNON_CHARACTER_ENTROPY",
        "shannon_entropy_score": round(entropy_score, 2),
        "sample_token": token_cmd,
        "top_z_score": round(entropy_score, 2),
        "calibrated_risk_index": cri,
        "is_outlier": is_outlier,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

  async def run_zipfian_process_rarity(
      self,
      session: ClientSession,
      host: str,
      event_type: str = "PROCESS_LAUNCH",
      entity_field: str = "principal.hostname",
      bucket_size: str = "1d",
      max_adopters: int = 2,
      min_count: int = 1,
      zipf_threshold: float = 3.5,
      lookback_days: int = 7,
  ) -> Dict[str, Any]:
    """Detects rare administrative tools in the enterprise Zipfian long tail."""
    start_iso, end_iso = self._iso_window(lookback_days)
    tpl_path = self.runner.find_template(self.SKILL_NAME, "zipfian_process_rarity_2stage.yl2")

    params = {
        "event_type": event_type,
        "entity_field": entity_field,
        "bucket_size": bucket_size,
        "max_adopters": str(max_adopters),
        "min_count": str(min_count),
        "zipf_threshold": str(zipf_threshold),
        "tier": "STANDARD",
    }

    rendered = self.runner.render_template(tpl_path, params)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    zipf_score = 0.0
    rare_binary = None
    if rows:
      top_row = rows[0]
      zipf_score = float(top_row.get("zipf_rarity_score", top_row.get("$zipf_rarity_score", 0.0)) or 0.0)
      rare_binary = top_row.get("binary", top_row.get("$binary", None))

    cri = self.runner.calculate_cri(zipf_score)
    is_outlier = cri >= 60 or zipf_score >= zipf_threshold
    return {
        "entity": host,
        "model": "ZIPFIAN_PROCESS_RARITY",
        "zipf_rarity_score": round(zipf_score, 2),
        "rare_binary": rare_binary,
        "top_z_score": round(zipf_score, 2),
        "calibrated_risk_index": cri,
        "is_outlier": is_outlier,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

  async def run_ewma_burst_velocity(
      self,
      session: ClientSession,
      entity: str,
      event_type: str = "NETWORK_CONNECTION",
      entity_field: str = "principal.ip",
      bucket_size: str = "1h",
      min_active_samples: int = 3,
      min_sd: float = 1.0,
      min_count: int = 5,
      velocity_threshold: float = 3.0,
      lookback_days: int = 7,
  ) -> Dict[str, Any]:
    """Detects acute intraday rate acceleration using Exponentially Weighted Moving Average (EWMA)."""
    start_iso, end_iso = self._iso_window(lookback_days)
    tpl_path = self.runner.find_template(self.SKILL_NAME, "ewma_burst_velocity_2stage.yl2")

    params = {
        "event_type": event_type,
        "entity_field": entity_field,
        "bucket_size": bucket_size,
        "min_active_samples": str(min_active_samples),
        "min_sd": str(min_sd),
        "min_count": str(min_count),
        "velocity_threshold": str(velocity_threshold),
        "tier": "STANDARD",
    }

    rendered = self.runner.render_template(tpl_path, params)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    velocity_score = 0.0
    if rows:
      top_row = rows[0]
      velocity_score = float(top_row.get("ewma_velocity_score", top_row.get("$ewma_velocity_score", 0.0)) or 0.0)

    cri = self.runner.calculate_cri(velocity_score)
    is_outlier = cri >= 60 or velocity_score >= velocity_threshold
    return {
        "entity": entity,
        "model": "EWMA_BURST_VELOCITY",
        "ewma_velocity_score": round(velocity_score, 2),
        "top_z_score": round(velocity_score, 2),
        "calibrated_risk_index": cri,
        "is_outlier": is_outlier,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

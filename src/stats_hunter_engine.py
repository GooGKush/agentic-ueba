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
import re
import sys
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

  def _get_stats_hunter_builder(self) -> Any:
    """Imports multistage_query_builder from secops-statistical-hunter without namespace collision."""
    import importlib.util
    mod_name = "_secops_statistical_hunter_builder"
    if mod_name in sys.modules:
      return sys.modules[mod_name]
    stats_skill = self.runner.skills_root / self.SKILL_NAME
    builder_path = stats_skill / "scripts" / "multistage_query_builder.py"
    spec = importlib.util.spec_from_file_location(mod_name, builder_path)
    if spec is None or spec.loader is None:
      raise ImportError(f"Cannot load multistage_query_builder from {builder_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod

  def _iso_window(self, lookback_days: int, is_entity_graph: bool = False) -> Tuple[str, str]:
    """Generates strict ISO 8601 UTC start and end timestamps (shifts end_dt back 48h for D-2 Entity Graph queries)."""
    end_dt = datetime.now(timezone.utc)
    if is_entity_graph:
      end_dt = end_dt - timedelta(hours=48)
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
    rendered = self.runner.scope_query_to_entity(rendered, src_ip, entity_type="IP")
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    is_beaconing = False
    top_cv = 1.0
    detected_dst = None

    if rows:
      # Filter out multicast, broadcast, and loopback destinations
      valid_rows = [
          r for r in rows
          if not any(
              str(r.get("dst_ip", "")).startswith(p)
              for p in (
                  "224.", "225.", "226.", "227.", "228.", "229.", "230.",
                  "231.", "232.", "233.", "234.", "235.", "236.", "237.",
                  "238.", "239.", "255.", "127.", "0."
              )
          )
      ]
      top_row = valid_rows[0] if valid_rows else rows[0]
      top_cv = float(top_row.get("cv", top_row.get("coefficient_of_variation", 1.0)) or 1.0)
      detected_dst = top_row.get("dst_ip", "UNKNOWN")
      is_beaconing = top_cv <= cv_threshold

    # Invert CV into risk score (lower CV = higher regularity = higher risk)
    risk_score = round(max(0.0, (1.0 - top_cv)) * 100) if is_beaconing else 10

    return {
        "source_ip": src_ip,
        "model": "C2_BEacONING_JITTER" if False else "C2_BEACONING_JITTER",
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
    rendered = self.runner.scope_query_to_entity(rendered, entity, entity_type="USER")
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

  # Aliases for backward compatibility
  run_poisson_burst_spray = run_poisson_burst_clustering
  run_fano_burst_hunting = run_poisson_burst_clustering

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
        "min_baseline_days": "3",
        "max_lambda": "0.5",
        "tier": "STANDARD",
        "poisson_z": "3.5",
        "poisson_z_sq": "12.25",
    }

    rendered = self.runner.render_template(tpl_path, params)
    rendered = self.runner.scope_query_to_entity(rendered, entity, entity_type="USER")
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    z_score = 0.0
    if rows:
      top_row = rows[0]
      raw_pz = top_row.get("poisson_z") or top_row.get("$poisson_z") or top_row.get("z_score") or top_row.get("$z_score")
      if raw_pz is not None:
        z_score = float(raw_pz or 0.0)
      else:
        pz_sq = float(top_row.get("poisson_z_sq") or top_row.get("$poisson_z_sq") or 0.0)
        z_score = math.sqrt(max(0.0, pz_sq))

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

    if entity_field == "principal.hostname" and (":" in host or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)):
      entity_field = "principal.asset.ip"

    params = {
        "event_type": event_type,
        "entity_field": entity_field,
        "bucket_size": bucket_size,
        "min_parent_count": str(min_parent_count),
        "surprisal_threshold": str(surprisal_threshold),
        "tier": "STANDARD",
    }

    rendered = self.runner.render_template(tpl_path, params)
    rendered = self.runner.scope_query_to_entity(rendered, host, entity_type="ASSET")
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

  run_markov_process_transition = run_markov_transition_rarity

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
    rendered = self.runner.scope_query_to_entity(rendered, entity, entity_type="ASSET")
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

  run_shannon_entropy = run_shannon_character_entropy

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

    if entity_field == "principal.hostname" and (":" in host or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)):
      entity_field = "principal.asset.ip"

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
    rendered = self.runner.scope_query_to_entity(rendered, host, entity_type="ASSET")
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

  run_zipf_rarity = run_zipfian_process_rarity

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
    rendered = self.runner.scope_query_to_entity(rendered, entity, entity_type="IP")
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    velocity_score = 0.0
    if rows:
      top_row = rows[0]
      velocity_score = float(
          top_row.get("ewma_velocity_score")
          or top_row.get("$ewma_velocity_score")
          or top_row.get("velocity_score")
          or top_row.get("$velocity_score")
          or 0.0
      )

    cri = self.runner.calculate_cri(velocity_score)
    is_outlier = cri >= 60 or velocity_score >= velocity_threshold
    return {
        "entity": entity,
        "model": "EWMA_BURST_VELOCITY",
        "ewma_velocity_score": round(velocity_score, 2),
        "velocity_score": round(velocity_score, 2),
        "top_z_score": round(velocity_score, 2),
        "calibrated_risk_index": cri,
        "is_outlier": is_outlier,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

  run_ewma_velocity = run_ewma_burst_velocity

  async def run_impossible_travel_velocity(
      self,
      session: ClientSession,
      user_id: str = "*",
      lookback_days: int = 14,
      tier: str = "BALANCED",
  ) -> Dict[str, Any]:
    """Detects impossible travel geographic velocity anomalies (>800 km/h across authentication events)."""
    start_iso, end_iso = self._iso_window(lookback_days)
    builder = self._get_stats_hunter_builder()
    rendered = builder.MultiStageTemplateRouter().build_query(
        archetype="IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
        tier=tier,
    )
    rendered = self.runner.scope_query_to_entity(rendered, user_id, entity_type="USER")
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    max_velocity_kmh = 0.0
    max_distance_km = 0.0
    detected_user = user_id
    if rows:
      top_row = rows[0]
      max_velocity_kmh = float(
          top_row.get("velocity_kmh")
          or top_row.get("$velocity_kmh")
          or top_row.get("max_velocity_kmh")
          or 0.0
      )
      max_distance_km = float(
          top_row.get("distance_km")
          or top_row.get("$distance_km")
          or top_row.get("max_distance_km")
          or 0.0
      )
      detected_user = str(top_row.get("user", top_row.get("entity", user_id)))

    # Normalize velocity above 800 km/h (or great-circle distance above 500 km) into Z-equivalent for CRI
    z_equiv = (
        max(0.0, max_velocity_kmh / 250.0)
        if max_velocity_kmh > 0.0
        else max(0.0, max_distance_km / 250.0)
    )
    cri = self.runner.calculate_cri(z_equiv)
    is_outlier = max_velocity_kmh >= 800.0 or max_distance_km >= 500.0 or cri >= 60
    return {
        "entity": detected_user,
        "model": "IMPOSSIBLE_TRAVEL_GEO_VELOCITY",
        "velocity_kmh": round(max_velocity_kmh, 2),
        "max_velocity_kmh": round(max_velocity_kmh, 2),
        "distance_km": round(max_distance_km, 2),
        "max_distance_km": round(max_distance_km, 2),
        "top_z_score": round(z_equiv, 2),
        "calibrated_risk_index": cri,
        "is_outlier": is_outlier,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

  async def run_producer_consumer_inversion(
      self,
      session: ClientSession,
      hostname: str = "*",
      lookback_days: int = 14,
      tier: str = "BALANCED",
  ) -> Dict[str, Any]:
    """Detects client workstation / endpoint role inversion via Producer-Consumer Ratio (PCR)."""
    start_iso, end_iso = self._iso_window(lookback_days)
    builder = self._get_stats_hunter_builder()
    rendered = builder.MultiStageTemplateRouter().build_query(
        archetype="PRODUCER_CONSUMER_RATIO_INVERSION",
        tier=tier,
    )
    rendered = self.runner.scope_query_to_entity(rendered, hostname, entity_type="ASSET")
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    pcr_score = 0.0
    producer_ratio = 0.0
    detected_host = hostname
    if rows:
      top_row = rows[0]
      producer_ratio = float(
          top_row.get("producer_ratio")
          or top_row.get("$producer_ratio")
          or top_row.get("pcr_ratio")
          or 0.0
      )
      pcr_score = float(
          top_row.get("pcr_z_score")
          or top_row.get("z_score")
          or top_row.get("$z_score")
          or producer_ratio
          or 0.0
      )
      detected_host = str(top_row.get("entity", top_row.get("host", hostname)))

    cri = self.runner.calculate_cri(pcr_score)
    is_outlier = pcr_score >= 3.0 or cri >= 60
    return {
        "entity": detected_host,
        "model": "PRODUCER_CONSUMER_RATIO_INVERSION",
        "pcr_z_score": round(pcr_score, 2),
        "producer_ratio": round(producer_ratio, 3),
        "top_z_score": round(pcr_score, 2),
        "calibrated_risk_index": cri,
        "is_outlier": is_outlier,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }


  async def run_dynamic_archetype_pipeline(
      self,
      session: ClientSession,
      entity: str = "*",
      archetype: str = "ZSCORE_PROCESS_SURGE",
      entity_type: str = "ASSET",
      event_type: Optional[str] = None,
      lookback_days: int = 7,
      tier: str = "BALANCED",
  ) -> Dict[str, Any]:
    """Executes any of the 23 canonical secops-statistical-hunter (v2.8.2) raw UDM multi-stage templates."""
    builder = self._get_stats_hunter_builder()
    router = builder.MultiStageTemplateRouter()
    arch_up = archetype.strip().upper()
    is_ecg = any(
        k in arch_up
        for k in ("DERIVED_CONTEXT", "GLOBAL_THREAT_INTEL", "GLOBAL_CONTEXT", "WHOIS", "ASSET_AGE", "FILE_PREVALENCE", "DOMAIN_PREVALENCE")
    )
    ent_lower = "user" if entity_type.upper() == "USER" else ("ip" if entity_type.upper() == "IP" else "host")
    window_hours = float(max(1, lookback_days) * 24)
    rendered = router.build_query(
        archetype=arch_up,
        tier=tier,
        entity_type=ent_lower,
        event_type=event_type,
        window_hours=window_hours,
    )
    if "DERIVED_CONTEXT" in rendered or "GLOBAL_CONTEXT" in rendered:
      is_ecg = True
    start_iso, end_iso = self._iso_window(lookback_days, is_entity_graph=is_ecg)
    rendered = self.runner.scope_query_to_entity(rendered, entity, entity_type=entity_type)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    primary_score = 0.0
    score_metric = "z_score"
    if rows:
      top_row = rows[0]
      score_keys = list(getattr(builder, "PRIMARY_SCORE_KEYS", ())) + [
          "ewma_velocity_score",
          "velocity_score",
          "markov_threat_score",
          "shannon_entropy_score",
          "zipf_rarity_score",
          "pcr_z_score",
          "producer_ratio",
      ]
      for k in score_keys:
        if k in top_row and top_row[k] is not None:
          score_metric = k
          primary_score = float(top_row[k])
          break
        if f"${k}" in top_row and top_row[f"${k}"] is not None:
          score_metric = k
          primary_score = float(top_row[f"${k}"])
          break

    if score_metric == "cv" and rows:
      z_equiv = max(0.0, (1.0 - primary_score) * 6.0)
    elif score_metric == "diversity_z":
      z_equiv = max(0.0, -primary_score)
    elif score_metric in ("poisson_z_sq", "threat_vector_norm_sq"):
      z_equiv = math.sqrt(max(0.0, primary_score))
    elif score_metric in ("velocity_kmh", "max_velocity_kmh"):
      z_equiv = max(0.0, primary_score / 250.0)
    else:
      z_equiv = max(0.0, primary_score)

    cri = self.runner.calculate_cri(z_equiv) if rows else 14
    return {
        "entity": entity,
        "entity_type": entity_type,
        "model": arch_up,
        "score_metric": score_metric,
        "primary_score": round(primary_score, 3),
        "top_z_score": round(z_equiv, 2),
        "calibrated_risk_index": cri,
        "is_outlier": bool(rows) and (cri >= 60 or z_equiv >= 3.0),
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

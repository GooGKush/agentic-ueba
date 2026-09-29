# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Deterministic Risk Metrics Execution Engine for Agentic UEBA.

Executes 30-day macro-behavioral baselining, decoupled 360° risk radars, and
dual-plane hybrid metric/raw telemetry queries via Chronicle OneMCP without LLM hallucination.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
import logging
import math
from typing import Any, Dict, List, Optional, Tuple
from mcp import ClientSession

from src.pipeline_runner import PipelineRunner
from src.config import TenantConfig

logger = logging.getLogger("RiskMetricsEngine")


class RiskMetricsEngine:
  """Executes pre-computed 30-day UEBA risk metric pipelines."""

  SKILL_NAME = "secops-risk-metrics-multistage"

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

  async def run_360_behavioral_radar(
      self,
      session: ClientSession,
      username: str,
      lookback_days: int = 14,
  ) -> Dict[str, Any]:
    """Profiles user across 5 canonical orthogonal sectors via decoupled micro-queries."""
    start_iso, end_iso = self._iso_window(lookback_days)

    sector_queries = {
        "Auth": f"""stage auth_risk {{
    metadata.event_type = "USER_LOGIN"
    target.user.userid = "{username}"
    $user = target.user.userid
  match:
    $user by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        target.user.userid: "{username}"
    ))
    $std = max(metrics.auth_attempts_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        target.user.userid: "{username}"
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$user = $auth_risk.user

match:
  $user by 1d

outcome:
  $z = max($auth_risk.z)
  $observed = max($auth_risk.obs)

order:
  $z desc""",
        "Cloud": f"""stage cloud_risk {{
    (metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "RESOURCE_DELETION" or metadata.event_type = "RESOURCE_WRITTEN" or metadata.event_type = "RESOURCE_PERMISSIONS_CHANGE")
    principal.user.userid = "{username}"
    $user = principal.user.userid
    $vendor = metadata.vendor_name
    $product = metadata.product_name
  match:
    $user, $vendor, $product by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: "{username}",
        metadata.vendor_name: $vendor,
        metadata.product_name: $product
    ))
    $std = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: "{username}",
        metadata.vendor_name: $vendor,
        metadata.product_name: $product
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$user = $cloud_risk.user

match:
  $user by 1d

outcome:
  $z = max($cloud_risk.z)
  $observed = max($cloud_risk.obs)

order:
  $z desc""",
        "Workspace": f"""stage workspace_risk {{
    metadata.event_type = "USER_RESOURCE_ACCESS"
    principal.user.userid = "{username}"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: "{username}"
    ))
    $std = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: "{username}"
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$user = $workspace_risk.user

match:
  $user by 1d

outcome:
  $z = max($workspace_risk.z)
  $observed = max($workspace_risk.obs)

order:
  $z desc""",
        "Egress": f"""stage egress_risk {{
    metadata.event_type = "NETWORK_CONNECTION"
    principal.user.userid = "{username}"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $obs = sum(network.sent_bytes)
    $avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.user.userid: "{username}"
    ))
    $std = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.user.userid: "{username}"
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$user = $egress_risk.user

match:
  $user by 1d

outcome:
  $z = max($egress_risk.z)
  $observed = max($egress_risk.obs)

order:
  $z desc""",
        "DNS": f"""stage dns_risk {{
    metadata.event_type = "NETWORK_DNS"
    principal.user.userid = "{username}"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.dns_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: "{username}"
    ))
    $std = max(metrics.dns_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: "{username}"
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$user = $dns_risk.user

match:
  $user by 1d

outcome:
  $z = max($dns_risk.z)
  $observed = max($dns_risk.obs)

order:
  $z desc""",
    }

    async def _query_sector(sector_name: str, q_str: str) -> Tuple[str, float, int]:
      try:
        resp = await self.runner.execute_query_via_mcp(session, q_str, start_iso, end_iso)
        rows = self.runner.parse_stats_response(resp)
        if rows:
          row = rows[0]
          z_val = 0.0
          for k in ("z", "z_score", "$z"):
            if k in row and row[k] is not None:
              z_val = float(row[k])
              break
          obs_val = 0
          for k in ("observed", "obs", "$observed", "$obs"):
            if k in row and row[k] is not None:
              obs_val = int(row[k])
              break
          return sector_name, z_val, obs_val
      except Exception as err:
        logger.warning(f"Sector query failed for {sector_name} ({err}); defaulting to 0.0")
      return sector_name, 0.0, 0

    # Execute queries sequentially to preserve single MCP stream stability
    results = []
    for name, q_str in sector_queries.items():
      res = await _query_sector(name, q_str)
      results.append(res)

    z_scores = {name: z for name, z, _ in results}
    observed_counts = {name: obs for name, _, obs in results}

    composite_d = self.runner.compute_euclidean_distance(z_scores)
    cri = self.runner.calculate_cri(composite_d)
    top_sector = max(z_scores.items(), key=lambda x: x[1])[0]

    return {
        "entity": username,
        "composite_d": round(composite_d, 2),
        "calibrated_risk_index": cri,
        "top_sector": top_sector,
        "is_outlier": cri >= 46,
        "sector_z_scores": {k: round(v, 2) for k, v in z_scores.items()},
        "sector_observed_counts": observed_counts,
        "verdict": "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE"),
    }

  async def run_cloud_crud_surge(
      self,
      session: ClientSession,
      username: str,
      lookback_days: int = 14,
  ) -> Dict[str, Any]:
    """Evaluates cloud resource write surges with mandatory companion dimensions."""
    start_iso, end_iso = self._iso_window(lookback_days)
    tpl_path = self.runner.find_template(self.SKILL_NAME, "cloud_repository_scope_dual_branch.yl2")
    rendered = self.runner.render_template(tpl_path, {"sa": username, "target_user": username})

    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)
    top_z = 0.0
    if rows:
      top_z = float(rows[0].get("z_score", rows[0].get("z", 0.0)) or 0.0)

    cri = self.runner.calculate_cri(top_z)
    return {
        "entity": username,
        "metric": "cloud_crud_resource_written",
        "top_z_score": round(top_z, 2),
        "calibrated_risk_index": cri,
        "is_outlier": cri >= 46,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

  async def run_hybrid_enrichment(
      self,
      session: ClientSession,
      username: str,
      macro_metric_avg: str = "metrics.auth_attempts_total(agg: avg, period: 1d, window: 30d)",
      macro_metric_std: str = "metrics.auth_attempts_total(agg: stddev, period: 1d, window: 30d)",
      raw_signature_field: str = "principal.ip",
      lookback_days: int = 14,
  ) -> Dict[str, Any]:
    """Fuses 30-day macro baseline deviation with raw UDM micro-telemetry signatures."""
    start_iso, end_iso = self._iso_window(lookback_days)
    tpl_path = self.runner.find_template(self.SKILL_NAME, "hybrid_metric_raw_enrichment_2stage.yl2")
    
    params = {
        "macro_event_type": "USER_LOGIN",
        "macro_entity_field": "target.user.userid",
        "macro_event_filter": f'target.user.userid = "{username}"',
        "macro_observed_agg": "count(metadata.id)",
        "target_metric_func_avg": macro_metric_avg,
        "target_metric_func_stddev": macro_metric_std,
        "target_metric_func_active_days": "30",
        "raw_event_type": "USER_LOGIN",
        "raw_entity_field": "target.user.userid",
        "raw_event_filter": f'target.user.userid = "{username}"',
        "raw_signature_field": raw_signature_field,
        "anomaly_threshold": "3.0",
        "min_baseline_days": "14",
        "min_raw_events": "5",
        "max_signature_diversity": "3",
    }

    rendered = self.runner.render_template(tpl_path, params)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)
    
    top_z = 0.0
    distinct_sigs = 0
    if rows:
      top_z = float(rows[0].get("z_score", rows[0].get("z", 0.0)) or 0.0)
      distinct_sigs = int(rows[0].get("distinct_signatures", 0) or 0)

    cri = self.runner.calculate_cri(top_z)
    return {
        "entity": username,
        "model": "DUAL_PLANE_HYBRID_ENRICHMENT",
        "macro_z_score": round(top_z, 2),
        "distinct_micro_signatures": distinct_sigs,
        "calibrated_risk_index": cri,
        "is_outlier": cri >= 46,
        "executed_query": rendered,
    }

  async def run_cloud_crud_surge(
      self,
      session: ClientSession,
      username: str,
      lookback_days: int = 14,
  ) -> Dict[str, Any]:
    """Profiles user cloud infrastructure creation, deletion, modification, and permissions changes."""
    start_iso, end_iso = self._iso_window(lookback_days)
    query = f"""stage cloud_risk {{
    (metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "RESOURCE_DELETION" or metadata.event_type = "RESOURCE_WRITTEN" or metadata.event_type = "RESOURCE_PERMISSIONS_CHANGE")
    principal.user.userid = "{username}"
    $user = principal.user.userid
    $vendor = metadata.vendor_name
    $product = metadata.product_name
  match:
    $user, $vendor, $product by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: "{username}",
        metadata.vendor_name: $vendor,
        metadata.product_name: $product
    ))
    $std = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: "{username}",
        metadata.vendor_name: $vendor,
        metadata.product_name: $product
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$user = $cloud_risk.user

match:
  $user by 1d

outcome:
  $top_z = max($cloud_risk.z)
  $observed = max($cloud_risk.obs)

order:
  $top_z desc"""

    resp = await self.runner.execute_query_via_mcp(session, query, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)
    top_z = 0.0
    observed = 0
    if rows:
      top_z = float(rows[0].get("top_z", rows[0].get("z", 0.0)) or 0.0)
      observed = int(rows[0].get("observed", rows[0].get("obs", 0)) or 0)

    cri = self.runner.calculate_cri(top_z)
    return {
        "entity": username,
        "model": "CLOUD_INFRASTRUCTURE_CRUD_SURGE",
        "top_z_score": round(top_z, 2),
        "observed_events": observed,
        "calibrated_risk_index": cri,
        "is_outlier": cri >= 60 or top_z >= 3.0,
        "executed_query": query,
    }

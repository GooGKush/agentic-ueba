# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Deterministic Risk Metrics Execution Engine for Agentic UEBA.

Executes 30-day macro-behavioral baselining, decoupled 6-spoke 360° risk radars,
cross-vector / roll-up sector fusions, and dynamic single-metric pipelines across all
38 Malachite Risk Analytics metrics via Chronicle OneMCP without LLM hallucination.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
import logging
import math
from typing import Any, Dict, List, Optional, Sequence, Tuple
from mcp import ClientSession

from src.pipeline_runner import PipelineRunner
from src.config import TenantConfig

logger = logging.getLogger("RiskMetricsEngine")


class RiskMetricsEngine:
  """Executes pre-computed 30-day UEBA risk metric pipelines across all 38 catalog metrics."""

  SKILL_NAME = "secops-risk-metrics-multistage"

  # Canonical mapping from 360° radar sector names to representative catalog metrics
  USER_SECTOR_METRICS: Dict[str, str] = {
      "Auth": "auth_attempts_fail",
      "Cloud": "resource_creation_total",
      "Workspace": "workspace_total_download_actions",
      "Egress": "network_bytes_outbound",
      "DNS": "dns_queries_fail",
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

  def __init__(self, tenant_config: Optional[TenantConfig] = None):
    self.runner = PipelineRunner(tenant_config)

  def _iso_window(self, lookback_days: int, is_entity_graph: bool = False) -> Tuple[str, str]:
    """Generates strict ISO 8601 UTC start and end timestamps (supports Rule 5 Entity Graph D-2 window)."""
    end_dt = datetime.now(timezone.utc)
    if is_entity_graph:
      # Rule 5: Entity Graph stages require D-2 00:00:00Z start window
      today_midnight = datetime(end_dt.year, end_dt.month, end_dt.day, tzinfo=timezone.utc)
      start_dt = today_midnight - timedelta(days=2)
    else:
      start_dt = end_dt - timedelta(days=lookback_days)
    return (
        start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

  def _resolve_entity_enum(self, entity_type: str) -> Any:
    """Maps string entity_type ('USER', 'ASSET', 'HOST', 'IP') to skill EntityType enum."""
    EntityType, _, _, _ = self.runner.get_validator_enums()
    if str(entity_type).upper() in ("ASSET", "HOST", "IP", "HOSTNAME", "DEVICE"):
      return EntityType.ASSET
    return EntityType.USER

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

  async def run_360_behavioral_radar(
      self,
      session: ClientSession,
      username: str,
      lookback_days: int = 14,
      entity_type: str = "USER",
  ) -> Dict[str, Any]:
    """Profiles user or host across 6 canonical orthogonal sectors via v1.8.0 baseline-aligned micro-queries."""
    start_iso, end_iso = self._iso_window(lookback_days)
    is_host = entity_type.upper() in ("ASSET", "HOST", "IP")
    sector_metric_map = self.ASSET_SECTOR_METRICS if is_host else self.USER_SECTOR_METRICS

    if is_host:
      sector_queries = {
          "Auth": f"""// Sector: Asset Authentication
stage auth_risk {{
    metadata.event_type = "USER_LOGIN"
    not security_result.action = "ALLOW"
    principal.asset.hostname = "{username}"
    $host = principal.asset.hostname
  match:
    $host by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $std = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$host = $auth_risk.host

match:
  $host by 1d

outcome:
  $z = max($auth_risk.z)
  $observed = max($auth_risk.obs)

order:
  $z desc""",
          "Egress": f"""// Sector: Network Outbound Volume
stage egress_risk {{
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.asset.hostname = "{username}"
    $host = principal.asset.hostname
  match:
    $host by 1d
  outcome:
    $obs = sum(network.sent_bytes)
    $avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $std = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$host = $egress_risk.host

match:
  $host by 1d

outcome:
  $z = max($egress_risk.z)
  $observed = max($egress_risk.obs)

order:
  $z desc""",
          "DNS": f"""// Sector: DNS Failures
stage dns_risk {{
    (network.dns.questions.name != "" or network.dns.answers.name != "" or network.dns.id != 0)
    network.dns.response_code != 0
    principal.asset.hostname = "{username}"
    $host = principal.asset.hostname
  match:
    $host by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.dns_queries_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $std = max(metrics.dns_queries_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$host = $dns_risk.host

match:
  $host by 1d

outcome:
  $z = max($dns_risk.z)
  $observed = max($dns_risk.obs)

order:
  $z desc""",
          "Flows": f"""// Sector: Outbound Network Flows
stage flows_risk {{
    network.sent_bytes > 0
    principal.asset.hostname = "{username}"
    $host = principal.asset.hostname
  match:
    $host by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.network_flows_outbound(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $std = max(metrics.network_flows_outbound(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$host = $flows_risk.host

match:
  $host by 1d

outcome:
  $z = max($flows_risk.z)
  $observed = max($flows_risk.obs)

order:
  $z desc""",
          "Alerts": f"""// Sector: Security & EDR Alerts
stage alerts_risk {{
    (metadata.log_type = "CB_EDR" or metadata.log_type = "CS_EDR" or metadata.log_type = "MICROSOFT_GRAPH_ALERT" or metadata.log_type = "SENTINELONE_ALERTS")
    principal.asset.hostname = "{username}"
    security_result.rule_name = $rule_name
    $host = principal.asset.hostname
    $rule_name != ""
  match:
    $host, $rule_name by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.alert_event_name_count(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname,
        security_result.rule_name: security_result.rule_name
    ))
    $std = max(metrics.alert_event_name_count(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname,
        security_result.rule_name: security_result.rule_name
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$host = $alerts_risk.host

match:
  $host by 1d

outcome:
  $z = max($alerts_risk.z)
  $observed = max($alerts_risk.obs)

order:
  $z desc""",
          "Web": f"""// Sector: Web & Proxy Activity
stage web_risk {{
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    principal.asset.hostname = "{username}"
    $host = principal.asset.hostname
  match:
    $host by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.asset.hostname: principal.asset.hostname
    ))
    $std = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.asset.hostname: principal.asset.hostname
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$host = $web_risk.host

match:
  $host by 1d

outcome:
  $z = max($web_risk.z)
  $observed = max($web_risk.obs)

order:
  $z desc""",
      }
    else:
      sector_queries = {
          "Auth": f"""// Sector: IAM & Authentication
stage auth_risk {{
    metadata.event_type = "USER_LOGIN"
    not security_result.action = "ALLOW"
    target.user.userid = "{username}"
    $user = target.user.userid
  match:
    $user by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        target.user.userid: target.user.userid
    ))
    $std = max(metrics.auth_attempts_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        target.user.userid: target.user.userid
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
          "Cloud": f"""// Sector: Cloud Infrastructure CRUD
stage cloud_risk {{
    (metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "USER_RESOURCE_CREATION")
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
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
    ))
    $std = max(metrics.resource_creation_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid,
        metadata.vendor_name: metadata.vendor_name,
        metadata.product_name: metadata.product_name
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
          "Workspace": f"""// Sector: Workspace & Drive Data
stage workspace_risk {{
    metadata.vendor_name = "Google Workspace"
    metadata.product_event_type = "download"
    principal.user.userid = "{username}"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $std = max(metrics.workspace_total_download_actions(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
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
          "Egress": f"""// Sector: Network Egress Volume
stage egress_risk {{
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    principal.user.userid = "{username}"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $obs = sum(network.sent_bytes)
    $avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $std = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.user.userid: principal.user.userid
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
          "DNS": f"""// Sector: DNS Failures
stage dns_risk {{
    (network.dns.questions.name != "" or network.dns.answers.name != "" or network.dns.id != 0)
    network.dns.response_code != 0
    principal.user.userid = "{username}"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.dns_queries_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $std = max(metrics.dns_queries_fail(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
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
          "Web": f"""// Sector: Web & Proxy Activity
stage web_risk {{
    (network.http.method != "" or network.http.user_agent != "" or network.http.response_code != 0 or network.http.referral_url != "")
    principal.user.userid = "{username}"
    $user = principal.user.userid
  match:
    $user by 1d
  outcome:
    $obs = count(metadata.id)
    $avg = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: avg,
        principal.user.userid: principal.user.userid
    ))
    $std = max(metrics.http_queries_total(
        period: 1d, window: 30d, metric: event_count_sum, agg: stddev,
        principal.user.userid: principal.user.userid
    ))
    $z = ($obs - $avg) / if($std > 0, $std, 1.0)
}}

$user = $web_risk.user

match:
  $user by 1d

outcome:
  $z = max($web_risk.z)
  $observed = max($web_risk.obs)

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
              obs_val = int(float(row[k]))
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
    sorted_sectors = sorted(z_scores.items(), key=lambda x: x[1], reverse=True)
    top_sector = sorted_sectors[0][0] if sorted_sectors else "Auth"
    outlier_sectors = [s_name for s_name, z_val in sorted_sectors if abs(z_val) >= 2.0]

    return {
        "entity": username,
        "entity_type": entity_type.upper(),
        "composite_d": round(composite_d, 2),
        "calibrated_risk_index": cri,
        "top_sector": top_sector,
        "outlier_sectors": outlier_sectors,
        "sector_metrics": dict(sector_metric_map),
        "is_outlier": cri >= 46 or len(outlier_sectors) > 0,
        "sector_z_scores": {k: round(v, 2) for k, v in z_scores.items()},
        "sector_observed_counts": observed_counts,
        "verdict": "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE"),
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
  ) -> Dict[str, Any]:
    """Executes generic 3-stage/4-stage Cross-Vector or Roll-Up Sector Fusion for ANY two compatible metrics."""
    start_iso, end_iso = self._iso_window(lookback_days)
    router = self.runner.get_template_router()
    spec_a, spec_b = self.resolve_compatible_fusion_specs(
        fusion_metrics or router.DEFAULT_FUSION_METRICS,
        entity_type=entity_type,
        identifier_field=identifier_field,
    )

    rendered = router.build_sector_fusion_query(
        sector_a=spec_a,
        sector_b=spec_b,
        four_stage=four_stage,
        hypothesis_goal=hypothesis_goal or f"Cross-Vector Fusion ({spec_a.metric} + {spec_b.metric}) for {entity}",
    )
    rendered = self.runner.scope_query_to_entity(rendered, entity)

    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    norm_sq = 0.0
    z_a = 0.0
    z_b = 0.0
    obs_a = 0.0
    obs_b = 0.0
    if rows:
      top_row = rows[0]
      norm_sq = float(
          top_row.get("composite_threat_norm_sq")
          or top_row.get("$composite_threat_norm_sq")
          or top_row.get("fleet_adjusted_threat_norm_sq")
          or 0.0
      )
      z_a = float(
          top_row.get("z_a_gated")
          or top_row.get("z_a")
          or top_row.get("$z_a")
          or top_row.get("sector_a_z")
          or 0.0
      )
      z_b = float(
          top_row.get("z_b_gated")
          or top_row.get("z_b")
          or top_row.get("$z_b")
          or top_row.get("sector_b_z")
          or 0.0
      )
      obs_a = float(top_row.get("a_observed") or top_row.get("$a_observed") or 0.0)
      obs_b = float(top_row.get("b_observed") or top_row.get("$b_observed") or 0.0)
      direct_d = float(top_row.get("composite_threat_score") or top_row.get("$composite_threat_score") or 0.0)
      if norm_sq <= 0.0 and direct_d > 0.0:
        norm_sq = direct_d * direct_d
      elif norm_sq <= 0.0 and (z_a > 0 or z_b > 0):
        norm_sq = (z_a * z_a) + (z_b * z_b)

    composite_d = math.sqrt(max(0.0, norm_sq))
    cri = self.runner.calculate_cri(composite_d)
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
        "z_a": round(z_a, 2),
        "z_b": round(z_b, 2),
        "sector_a_z": round(z_a, 2),
        "sector_b_z": round(z_b, 2),
        "a_observed": obs_a,
        "b_observed": obs_b,
        "composite_d": round(composite_d, 2),
        "composite_threat_score": round(composite_d, 2),
        "top_z_score": round(composite_d, 2),
        "calibrated_risk_index": cri,
        "is_outlier": cri >= 60 or composite_d >= 3.0,
        "stats_rows": len(rows),
        "advisories": list(getattr(router, "last_advisories", [])),
        "executed_query": rendered,
    }

  def _render_rare_destination_ecg_query(
      self,
      target_metric: str = "dns_queries_total",
      host_field: str = "principal.asset.hostname",
      max_fleet_prevalence: int = 3,
      hypothesis_goal: Optional[str] = None,
  ) -> str:
    """Renders the v1.8.1 3-stage rare_destination_ecg_3stage.yl2 pipeline for DNS / HTTP / Outbound Bytes."""
    mc = self.runner.get_malachite_catalog()
    sem = mc.baseline_semantics(target_metric)
    sector_filter = "\n    ".join(sem.observed_filter)
    sector_avg = f"metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: avg, {host_field}: {host_field})"
    sector_std = f"metrics.{target_metric}(period: 1d, window: 30d, metric: {sem.metric_arg}, agg: stddev, {host_field}: {host_field})"

    if "dns" in target_metric:
      contact_sem = mc.baseline_semantics("dns_queries_total")
      contact_filter = "\n    ".join(contact_sem.observed_filter)
      dest_field = "network.dns.questions.name"
      ecg_entity_type = '"DOMAIN_NAME"'
      ecg_key_path = "entity.domain.name"
      ecg_prevalence_path = "entity.domain.prevalence"
    elif "http" in target_metric:
      contact_sem = mc.baseline_semantics("http_queries_total")
      contact_filter = "\n    ".join(contact_sem.observed_filter)
      dest_field = "target.hostname"
      ecg_entity_type = '"DOMAIN_NAME"'
      ecg_key_path = "entity.domain.name"
      ecg_prevalence_path = "entity.domain.prevalence"
    else:
      contact_sem = mc.baseline_semantics("network_bytes_outbound")
      contact_filter = "\n    ".join(contact_sem.observed_filter)
      dest_field = "target.ip"
      ecg_entity_type = '"IP_ADDRESS"'
      ecg_key_path = "entity.artifact.ip"
      ecg_prevalence_path = "entity.artifact.prevalence"

    tpl_path = self.runner.find_template(self.SKILL_NAME, "rare_destination_ecg_3stage.yl2")
    rendered = self.runner.render_template(
        tpl_path,
        {
            "sector_filter": sector_filter,
            "host_field": host_field,
            "sector_observation_agg": sem.observed_agg,
            "sector_metric_func_avg": sector_avg,
            "sector_metric_func_stddev": sector_std,
            "contact_filter": contact_filter,
            "dest_field": dest_field,
            "ecg_entity_type": ecg_entity_type,
            "ecg_key_path": ecg_key_path,
            "ecg_prevalence_path": ecg_prevalence_path,
            "max_fleet_prevalence": str(max_fleet_prevalence),
        },
    )
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
  ) -> str:
    """Renders the v1.8.1 3-stage fusion_rare_destination_3stage.yl2 pipeline."""
    mc = self.runner.get_malachite_catalog()
    sem_a = mc.baseline_semantics(sector_a_metric)
    sem_b = mc.baseline_semantics(sector_b_metric)
    dest_field = "network.dns_domain" if "dns" in sector_b_metric else "target.hostname"
    tpl_path = self.runner.find_template(self.SKILL_NAME, "fusion_rare_destination_3stage.yl2")
    rendered = self.runner.render_template(
        tpl_path,
        {
            "host_field": host_field,
            "sector_a_filter": "\n    ".join(sem_a.observed_filter),
            "sector_a_observation_agg": sem_a.observed_agg,
            "sector_a_metric_func_avg": f"metrics.{sector_a_metric}(period: 1d, window: 30d, metric: {sem_a.metric_arg}, agg: avg, {host_field}: {host_field})",
            "sector_a_metric_func_stddev": f"metrics.{sector_a_metric}(period: 1d, window: 30d, metric: {sem_a.metric_arg}, agg: stddev, {host_field}: {host_field})",
            "sector_b_filter": "\n    ".join(sem_b.observed_filter),
            "dest_field": dest_field,
            "sector_b_observation_agg": sem_b.observed_agg,
            "sector_b_metric_func_avg": f"metrics.{sector_b_metric}(period: 1d, window: 30d, metric: {sem_b.metric_arg}, agg: avg, {host_field}: {host_field}, {dest_field}: {dest_field})",
            "sector_b_metric_func_stddev": f"metrics.{sector_b_metric}(period: 1d, window: 30d, metric: {sem_b.metric_arg}, agg: stddev, {host_field}: {host_field}, {dest_field}: {dest_field})",
            "ecg_entity_type": '"DOMAIN_NAME"',
            "ecg_key_path": "entity.domain.name",
            "ecg_prevalence_path": "entity.domain.prevalence",
            "max_fleet_prevalence": str(max_fleet_prevalence),
        },
    )
    if hypothesis_goal:
      rendered = f"// Goal: {hypothesis_goal}\n" + rendered
    return rendered

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
  ) -> Dict[str, Any]:
    """Dynamically builds and executes ANY 2-stage math model or multi-stage pipeline on ANY catalog metric."""
    if metric_name:
      target_metric = metric_name
    if model:
      model_name = model

    EntityType, PipelineArchitecture, StatisticalModel, _ = self.runner.get_validator_enums()
    mc = self.runner.get_malachite_catalog()
    router = self.runner.get_template_router()
    ent_enum = self._resolve_entity_enum(entity_type)

    model_upper = (model_name or "STANDARD_Z_SCORE").upper()
    if model_upper in ("CUSUM", "LONGITUDINAL_CUSUM"):
      model_upper = "LONGITUDINAL_CUSUM_DRIFT"
    elif model_upper in ("ZSCORE", "Z_SCORE"):
      model_upper = "STANDARD_Z_SCORE"

    # 1. Cross-Vector or Roll-Up Fusion (excluding FUSION_RARE_DESTINATION_3STAGE which uses ECG)
    if "FUSION" in model_upper and "RARE_DESTINATION" not in model_upper:
      metrics_pair = list(fusion_metrics) if fusion_metrics and len(fusion_metrics) >= 2 else [
          target_metric or "workspace_total_download_actions",
          "network_bytes_outbound" if target_metric != "network_bytes_outbound" else "http_queries_total",
      ]
      return await self.run_sector_fusion(
          session=session,
          entity=entity,
          entity_type=entity_type,
          fusion_metrics=metrics_pair,
          four_stage="4STAGE" in model_upper or "MULTI" in model_upper,
          identifier_field=identifier_field,
          lookback_days=lookback_days,
          hypothesis_goal=hypothesis_goal,
      )

    # Validate / fallback target_metric against catalog & entity_type
    if target_metric not in mc.known_metrics():
      target_metric = "workspace_total_download_actions" if ent_enum == EntityType.USER else "http_queries_total"

    # v1.8.1 Derived Prevalence Scoping Rule:
    # HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE is strictly for HTTP request counts (http_queries_total).
    # DNS volume (dns_*) or outbound bytes (network_bytes_*) against rare destinations must route to RARE_DESTINATION_ECG_3STAGE.
    if model_upper == "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE" and not target_metric.startswith("http_"):
      model_upper = "RARE_DESTINATION_ECG_3STAGE"

    # Ensure entity_type is supported for target_metric; adjust if needed
    from scripts.preflight_validator import METRIC_CATALOG
    if ent_enum not in METRIC_CATALOG[target_metric].supported_entity_types:
      ent_enum = METRIC_CATALOG[target_metric].supported_entity_types[0]

    # 2. Multi-Stage Pipeline Architectures vs 2-Stage Statistical Models
    pipeline_map = {
        "MACD_MOMENTUM_VELOCITY": PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
        "MACD_MOMENTUM_VELOCITY_2STAGE": PipelineArchitecture.MACD_MOMENTUM_VELOCITY_2STAGE,
        "CIRCADIAN_VON_MISES": PipelineArchitecture.CIRCADIAN_VON_MISES_2STAGE,
        "CIRCADIAN_VON_MISES_2STAGE": PipelineArchitecture.CIRCADIAN_VON_MISES_2STAGE,
        "PART_OF_THE_WHOLE_MULTILEVEL": PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL,
        "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL": PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
        "DUAL_BASELINE_3STAGE": PipelineArchitecture.DUAL_BASELINE_3STAGE,
        "EMPIRICAL_BAYES_3STAGE": PipelineArchitecture.EMPIRICAL_BAYES_3STAGE,
        "CLOUD_REPOSITORY_SCOPE": PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH,
        "CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH": PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH,
        "HYBRID_METRIC_RAW_ENRICHMENT_2STAGE": PipelineArchitecture.HYBRID_METRIC_RAW_ENRICHMENT_2STAGE,
        "HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE": PipelineArchitecture.HYBRID_METRIC_ENTROPY_CONCENTRATION_2STAGE,
        "HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE": PipelineArchitecture.HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE,
        "HYBRID_METRIC_FLEET_PREVALENCE_2STAGE": PipelineArchitecture.HYBRID_METRIC_FLEET_PREVALENCE_2STAGE,
        "FLEET_PREVALENCE_NORMALIZATION": PipelineArchitecture.HYBRID_METRIC_FLEET_PREVALENCE_2STAGE,
        "HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE": PipelineArchitecture.HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE,
        "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE": PipelineArchitecture.HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE,
        "HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE": PipelineArchitecture.HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE,
        "HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE": PipelineArchitecture.HYBRID_METRIC_DERIVED_ASSET_AGE_2STAGE,
    }

    stat_model_map = {
        "STANDARD_Z_SCORE": StatisticalModel.STANDARD_Z_SCORE,
        "MAD": StatisticalModel.MAD,
        "VARIANCE": StatisticalModel.VARIANCE,
        "POISSON": StatisticalModel.POISSON,
        "COEFFICIENT_OF_VARIATION": StatisticalModel.COEFFICIENT_OF_VARIATION,
        "HOURLY_TEMPORAL_ZSCORE": StatisticalModel.HOURLY_TEMPORAL_ZSCORE,
        "BAYESIAN_GAMMA": StatisticalModel.BAYESIAN_GAMMA,
        "BAYESIAN_BETA_BINOMIAL": StatisticalModel.BAYESIAN_BETA_BINOMIAL,
        "LONGITUDINAL_CUSUM": StatisticalModel.LONGITUDINAL_CUSUM,
        "LONGITUDINAL_CUSUM_DRIFT": StatisticalModel.LONGITUDINAL_CUSUM,
        "TWO_PART_HURDLE": StatisticalModel.TWO_PART_HURDLE,
        "ASYMMETRIC_DIRECTIONAL_Z": StatisticalModel.ASYMMETRIC_DIRECTIONAL_Z,
        "PIECEWISE_CRI": StatisticalModel.PIECEWISE_CRI,
        "FLEET_PREVALENCE_SHIELD": StatisticalModel.FLEET_PREVALENCE_SHIELD,
        "ADAPTIVE_CONTEXT_THRESHOLD": StatisticalModel.ADAPTIVE_CONTEXT_THRESHOLD,
    }

    is_entity_graph = any(
        k in model_upper for k in ("DERIVED_", "WHOIS_", "FLEET_PREVALENCE", "ASSET_AGE", "RARE_DESTINATION")
    )
    start_iso, end_iso = self._iso_window(lookback_days, is_entity_graph=is_entity_graph)

    if model_upper in ("RARE_DESTINATION_ECG_3STAGE", "RARE_DESTINATION_ECG"):
      host_f = identifier_field if identifier_field and "asset" in identifier_field else "principal.asset.hostname"
      rendered = self._render_rare_destination_ecg_query(
          target_metric=target_metric,
          host_field=host_f,
          hypothesis_goal=hypothesis_goal or f"RARE_DESTINATION_ECG_3STAGE on {target_metric} for {entity}",
      )
    elif model_upper in ("FUSION_RARE_DESTINATION_3STAGE", "FUSION_RARE_DESTINATION"):
      host_f = identifier_field if identifier_field and "asset" in identifier_field else "principal.asset.hostname"
      pair = list(fusion_metrics) if fusion_metrics and len(fusion_metrics) >= 2 else [target_metric, "http_queries_total"]
      rendered = self._render_fusion_rare_destination_query(
          sector_a_metric=pair[0],
          sector_b_metric=pair[1],
          host_field=host_f,
          hypothesis_goal=hypothesis_goal or f"FUSION_RARE_DESTINATION_3STAGE ({pair[0]} + {pair[1]}) for {entity}",
      )
    elif model_upper in pipeline_map and not mc.is_composite_only(target_metric):
      pipe_arch = pipeline_map[model_upper]
      rendered = router.build_pipeline_query(
          pipeline_type=pipe_arch,
          target_metric=target_metric,
          entity_type=ent_enum,
          hypothesis_goal=hypothesis_goal or f"{model_upper} on {target_metric} for {entity}",
          target_entity=entity if pipe_arch in (
              PipelineArchitecture.PART_OF_THE_WHOLE_MULTILEVEL,
              PipelineArchitecture.PART_OF_THE_WHOLE_TRIAD_MULTILEVEL,
          ) else None,
          service_account=entity if pipe_arch == PipelineArchitecture.CLOUD_REPOSITORY_SCOPE_DUAL_BRANCH else None,
          target_metrics=list(fusion_metrics) if fusion_metrics else None,
          identifier_field=identifier_field,
      )
    else:
      stat_enum = stat_model_map.get(model_upper, StatisticalModel.LONGITUDINAL_CUSUM)
      rendered = router.build_query(
          target_metric=target_metric,
          entity_type=ent_enum,
          statistical_model=stat_enum,
          hypothesis_goal=hypothesis_goal or f"{stat_enum.value} on {target_metric} for {entity}",
          identifier_field=identifier_field,
      )

    rendered = self.runner.scope_query_to_entity(rendered, entity)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    top_score = 0.0
    observed_val = 0.0
    hist_avg = 0.0
    if rows:
      top_row = rows[0]
      for score_key in (
          "personal_z",
          "cusum_z",
          "z_sector",
          "macd_momentum_score",
          "circadian_threat_score",
          "mad_z_score",
          "z_vs_enterprise",
          "z_vs_team",
          "bayesian_z",
          "hurdle_z",
          "composite_risk",
          "z_score",
          "z",
      ):
        if score_key in top_row and top_row[score_key] is not None:
          top_score = float(top_row[score_key])
          break
      if top_score == 0.0 and "d_sq" in top_row and top_row["d_sq"] is not None:
        top_score = math.sqrt(max(0.0, float(top_row["d_sq"])))
      for obs_key in ("observed", "a_observed", "observed_hour", "observed_val", "obs", "entity_obs"):
        if obs_key in top_row and top_row[obs_key] is not None:
          observed_val = float(top_row[obs_key])
          break
      for avg_key in ("hist_avg", "baseline_avg", "avg_hourly", "historical_avg", "avg", "personal_avg"):
        if avg_key in top_row and top_row[avg_key] is not None:
          hist_avg = float(top_row[avg_key])
          break

    cri = self.runner.calculate_cri(top_score)
    return {
        "entity": entity,
        "entity_type": entity_type,
        "model": model_upper,
        "target_metric": target_metric,
        "top_z_score": round(top_score, 2),
        "observed_value": observed_val,
        "baseline_avg": round(hist_avg, 2),
        "calibrated_risk_index": cri,
        "is_outlier": cri >= 60 or top_score >= 3.0,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

  async def run_circadian_von_mises(
      self,
      session: ClientSession,
      entity: str,
      metric_name: str = "auth_attempts_total",
      event_type: str = "USER_LOGIN",
      dimension_key: str = "target.user.userid",
      lookback_days: int = 14,
  ) -> Dict[str, Any]:
    """Evaluates hourly telemetry against 24-hour circular clock to penalize off-hours deviations."""
    start_iso, end_iso = self._iso_window(lookback_days)
    try:
      mc = self.runner.get_malachite_catalog()
      sem = mc.baseline_semantics(metric_name)
      event_filter_str = "\n    ".join(sem.observed_filter)
      metric_type_val = sem.metric_arg
      obs_agg = sem.observed_agg
    except Exception:
      event_filter_str = f'metadata.event_type = "{event_type}"'
      metric_type_val = "value_sum" if "bytes" in metric_name else "event_count_sum"
      obs_agg = "sum(network.sent_bytes)" if "bytes" in metric_name else "count(metadata.id)"

    tpl_path = self.runner.find_template(self.SKILL_NAME, "circadian_von_mises_2stage.yl2")
    params = {
        "event_filter": event_filter_str,
        "event_type": event_type,
        "entity_field": dimension_key,
        "value_filter": "",
        "observed_aggregation": obs_agg,
        "target_metric_name": metric_name,
        "metric_type_val": metric_type_val,
        "dimension_key": dimension_key,
        "extra_dimensions": "",
    }

    rendered = self.runner.render_template(tpl_path, params)
    rendered = self.runner.scope_query_to_entity(rendered, entity)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    circadian_score = 0.0
    hourly_z = 0.0
    event_hour = 0
    if rows:
      top_row = rows[0]
      circadian_score = float(top_row.get("circadian_threat_score", top_row.get("$circadian_threat_score", 0.0)) or 0.0)
      hourly_z = float(top_row.get("hourly_z", top_row.get("$hourly_z", 0.0)) or 0.0)
      event_hour = int(top_row.get("event_hour", top_row.get("$event_hour", 0)) or 0)

    cri = self.runner.calculate_cri(circadian_score)
    return {
        "entity": entity,
        "model": "CIRCADIAN_VON_MISES",
        "target_metric": metric_name,
        "circadian_threat_score": round(circadian_score, 2),
        "hourly_z": round(hourly_z, 2),
        "event_hour": event_hour,
        "top_z_score": round(circadian_score, 2),
        "calibrated_risk_index": cri,
        "is_outlier": cri >= 60 or circadian_score >= 3.0,
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

  async def run_macd_momentum_velocity(
      self,
      session: ClientSession,
      entity: str,
      metric_name: str = "network_bytes_outbound",
      event_type: str = "NETWORK_CONNECTION",
      dimension_key: str = "principal.user.userid",
      lookback_days: int = 14,
  ) -> Dict[str, Any]:
    """Detects sudden momentum acceleration where short-term surge diverges from slow baseline anchor."""
    start_iso, end_iso = self._iso_window(lookback_days)
    try:
      mc = self.runner.get_malachite_catalog()
      sem = mc.baseline_semantics(metric_name)
      event_filter_str = "\n    ".join(sem.observed_filter)
      metric_type_val = sem.metric_arg
      obs_agg = sem.observed_agg
    except Exception:
      event_filter_str = f'metadata.event_type = "{event_type}"'
      metric_type_val = "value_sum" if "bytes" in metric_name else "event_count_sum"
      obs_agg = "sum(network.sent_bytes)" if "bytes" in metric_name else "count(metadata.id)"

    tpl_path = self.runner.find_template(self.SKILL_NAME, "macd_momentum_velocity_2stage.yl2")
    params = {
        "event_filter": event_filter_str,
        "event_type": event_type,
        "entity_field": dimension_key,
        "value_filter": "",
        "observed_aggregation": obs_agg,
        "target_metric_name": metric_name,
        "metric_type_val": metric_type_val,
        "dimension_key": dimension_key,
        "extra_dimensions": "",
    }

    rendered = self.runner.render_template(tpl_path, params)
    rendered = self.runner.scope_query_to_entity(rendered, entity)
    resp = await self.runner.execute_query_via_mcp(session, rendered, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    macd_score = 0.0
    fast_z = 0.0
    slow_z = 0.0
    if rows:
      top_row = rows[0]
      macd_score = float(top_row.get("macd_momentum_score", top_row.get("$macd_momentum_score", 0.0)) or 0.0)
      fast_z = float(top_row.get("fast_z", top_row.get("$fast_z", 0.0)) or 0.0)
      slow_z = float(top_row.get("slow_z", top_row.get("$slow_z", 0.0)) or 0.0)

    cri = self.runner.calculate_cri(macd_score)
    return {
        "entity": entity,
        "model": "MACD_MOMENTUM_VELOCITY",
        "target_metric": metric_name,
        "macd_momentum_score": round(macd_score, 2),
        "fast_z": round(fast_z, 2),
        "slow_z": round(slow_z, 2),
        "top_z_score": round(macd_score, 2),
        "calibrated_risk_index": cri,
        "is_outlier": cri >= 60 or macd_score >= 3.0,
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
        "macro_event_filter": f'metadata.event_type = "USER_LOGIN"\n    target.user.userid = "{username}"',
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
        "stats_rows": len(rows),
        "executed_query": rendered,
    }

  async def run_cloud_crud_surge(
      self,
      session: ClientSession,
      username: str,
      lookback_days: int = 14,
  ) -> Dict[str, Any]:
    """Profiles user cloud resource activity across all 4 CRUD families (read, write, delete, create).

    Mirrors secops-risk-metrics-multistage v1.8.2: each family's observed count is
    scored against its own resource_*_total baseline, and every metrics.* call
    passes direct UDM field paths (<field>: <field>) on the PRINCIPAL_USER +
    PRODUCT_NAME + VENDOR_NAME dimension set so the query returns the same
    baselines when pasted into the SecOps Search UI with Case Sensitivity Off.
    """
    start_iso, end_iso = self._iso_window(lookback_days)
    dims = (
        "principal.user.userid: principal.user.userid, "
        "metadata.vendor_name: metadata.vendor_name, "
        "metadata.product_name: metadata.product_name"
    )

    def _metric(name: str, agg: str) -> str:
      return f"max(metrics.{name}(period: 1d, window: 30d, metric: event_count_sum, agg: {agg}, {dims}))"

    query = f"""// Sector: Cloud Resource CRUD Surge (read, write, delete, create)
stage cloud_risk {{
    (
        metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS" or
        metadata.event_type = "RESOURCE_WRITTEN" or metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT" or
        metadata.event_type = "RESOURCE_DELETION" or metadata.event_type = "USER_RESOURCE_DELETION" or
        metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "USER_RESOURCE_CREATION"
    )
    principal.user.userid = "{username}"
    $user = principal.user.userid
    $vendor = metadata.vendor_name
    $product = metadata.product_name
  match:
    $user, $vendor, $product by 1d
  outcome:
    // Each count matches its resource_*_total baseline population
    $obs_read = sum(if(metadata.event_type = "RESOURCE_READ" or metadata.event_type = "USER_RESOURCE_ACCESS", 1, 0))
    $obs_write = sum(if(metadata.event_type = "RESOURCE_WRITTEN" or metadata.event_type = "USER_RESOURCE_UPDATE_CONTENT", 1, 0))
    $obs_delete = sum(if(metadata.event_type = "RESOURCE_DELETION" or metadata.event_type = "USER_RESOURCE_DELETION", 1, 0))
    $obs_create = sum(if(metadata.event_type = "RESOURCE_CREATION" or metadata.event_type = "USER_RESOURCE_CREATION", 1, 0))
    $read_avg = {_metric("resource_read_total", "avg")}
    $read_std = {_metric("resource_read_total", "stddev")}
    $write_avg = {_metric("resource_written_total", "avg")}
    $write_std = {_metric("resource_written_total", "stddev")}
    $delete_avg = {_metric("resource_deletion_total", "avg")}
    $delete_std = {_metric("resource_deletion_total", "stddev")}
    $create_avg = {_metric("resource_creation_total", "avg")}
    $create_std = {_metric("resource_creation_total", "stddev")}
    $z_read = ($obs_read - $read_avg) / if($read_std > 0, $read_std, 1.0)
    $z_write = ($obs_write - $write_avg) / if($write_std > 0, $write_std, 1.0)
    $z_delete = ($obs_delete - $delete_avg) / if($delete_std > 0, $delete_std, 1.0)
    $z_create = ($obs_create - $create_avg) / if($create_std > 0, $create_std, 1.0)
}}

$user = $cloud_risk.user

match:
  $user by 1d

// Per-family columns are returned so the peak family's observed count and
// baseline are selected in Python (keeps both stages under the 20-outcome limit).
outcome:
  $z_read = max($cloud_risk.z_read)
  $z_write = max($cloud_risk.z_write)
  $z_delete = max($cloud_risk.z_delete)
  $z_create = max($cloud_risk.z_create)
  $top_z = if(if($z_read > $z_write, $z_read, $z_write) > if($z_delete > $z_create, $z_delete, $z_create), if($z_read > $z_write, $z_read, $z_write), if($z_delete > $z_create, $z_delete, $z_create))
  $obs_read = max($cloud_risk.obs_read)
  $obs_write = max($cloud_risk.obs_write)
  $obs_delete = max($cloud_risk.obs_delete)
  $obs_create = max($cloud_risk.obs_create)
  $read_avg = max($cloud_risk.read_avg)
  $read_std = max($cloud_risk.read_std)
  $write_avg = max($cloud_risk.write_avg)
  $write_std = max($cloud_risk.write_std)
  $delete_avg = max($cloud_risk.delete_avg)
  $delete_std = max($cloud_risk.delete_std)
  $create_avg = max($cloud_risk.create_avg)
  $create_std = max($cloud_risk.create_std)

order:
  $top_z desc"""

    resp = await self.runner.execute_query_via_mcp(session, query, start_iso, end_iso)
    rows = self.runner.parse_stats_response(resp)

    def _f(row: Dict[str, Any], key: str, default: float = 0.0) -> float:
      try:
        val = row.get(key)
        return float(val) if val not in (None, "") else default
      except (TypeError, ValueError):
        return default

    families = ("read", "write", "delete", "create")
    row = rows[0] if rows else {}
    family_z = {fam: round(_f(row, f"z_{fam}"), 2) for fam in families}
    top_family = max(families, key=lambda fam: _f(row, f"z_{fam}", float("-inf")))
    top_z = _f(row, "top_z", family_z[top_family]) if rows else 0.0
    observed = int(_f(row, f"obs_{top_family}")) if rows else 0
    base_avg = _f(row, f"{top_family}_avg") if rows else 0.0
    base_std = (_f(row, f"{top_family}_std", 1.0) or 1.0) if rows else 1.0

    cri = self.runner.calculate_cri(top_z)
    return {
        "entity": username,
        "model": "CLOUD_INFRASTRUCTURE_CRUD_SURGE",
        "family_z_scores": family_z,
        "top_z_score": round(top_z, 2),
        "z_score": round(top_z, 2),
        "observed_events": observed,
        "observed_count": observed,
        "baseline_avg": round(base_avg, 2),
        "baseline_std": round(base_std, 2),
        "calibrated_risk_index": cri,
        "is_outlier": cri >= 60 or top_z >= 3.0,
        "stats_rows": len(rows),
        "executed_query": query,
    }

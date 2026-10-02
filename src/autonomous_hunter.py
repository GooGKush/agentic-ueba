# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Autonomous JIT Threat Hunting Engine for Agentic UEBA.

Connects to Google SecOps OneMCP as an MCP Client, executes multi-stage statistical
and behavioral risk analytics via Gemini 2.5 Pro, and returns structured Clean Hand-Off
payloads along with full 6-pillar forensic reports to SecOps Playbooks and cases.
"""

import src._bootstrap

from datetime import datetime, timedelta, timezone
import json
import logging
import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import google.auth
from google.auth.transport.requests import Request
from google import genai
from google.genai import types
import httpx
from mcp import ClientSession

try:
  from mcp.client.streamable_http import streamable_http_client
except ImportError:
  try:
    from mcp.client.streamable_http import streamablehttp_client as streamable_http_client
  except ImportError:
    from mcp.client.sse import sse_client as streamable_http_client

from src.config import TenantConfig, get_skills_root
from src.dynamic_protocol_adapter import DynamicProtocolAdapter
from src.models import (
    CleanHandOffPayload,
    ForensicsSummary,
    JITHuntRequest,
    JITHuntResponse,
    MetricEvaluation,
    TriageSummary,
)
from src.risk_metrics_engine import RiskMetricsEngine
from src.stats_hunter_engine import StatsHunterEngine
from src.strategy_decider import StrategyDecider
from src.federated_bridge import FederatedBridge
from src.formatters.case_wall_card import CaseWallCardFormatter


logger = logging.getLogger("AutonomousHunter")


class AutonomousHunterEngine:
  """Autonomous threat hunting runtime adapted from DirectMCPEngine."""

  def __init__(self, tenant_config: Optional[TenantConfig] = None):
    self.default_tenant = tenant_config or TenantConfig()
    self.adapter = DynamicProtocolAdapter(get_skills_root())

  @staticmethod
  def sanitize_schema(schema: dict) -> dict:
    """Sanitizes OpenAPI/MCP JSON schemas for Gemini compatibility."""
    ALLOWED_KEYS = {
        "type",
        "format",
        "description",
        "nullable",
        "enum",
        "maxItems",
        "minItems",
        "properties",
        "required",
        "items",
    }
    if not isinstance(schema, dict):
      return schema

    clean = {}
    for k, v in schema.items():
      if k in ALLOWED_KEYS:
        if k == "properties" and isinstance(v, dict):
          clean[k] = {prop: AutonomousHunterEngine.sanitize_schema(val) for prop, val in v.items()}
        elif k == "items" and isinstance(v, dict):
          clean[k] = AutonomousHunterEngine.sanitize_schema(v)
        else:
          clean[k] = v

    if "type" not in clean and "properties" not in clean:
      clean["type"] = "object"
    if "type" in clean and isinstance(clean["type"], list):
      clean["type"] = clean["type"][0]
    return clean

  @staticmethod
  def sanitize_case_comment(comment: str) -> str:
    """Sanitizes and converts Markdown output into Chronicle SOAR Case Wall HTML.

    - Unescapes literal '\\n' and quotes into real newlines and formatting.
    - Strips machine-readable ```json_triage ... ``` code blocks.
    - Converts Markdown headers, tables, lists, inline code, and LaTeX math into
      compact, `safevalues`-compliant semantic HTML for Chronicle SOAR's Case Wall
      (`[innerHTML]="sanitizeContent(commentForClient)"`).
    """
    if not comment:
      return ""
    # Unescape literal backslash escapes if present
    comment = comment.replace("\\n", "\n").replace('\\"', '"').replace("\\'", "'")
    # Strip machine-readable json_triage code block from user-facing case wall comment
    comment = re.sub(r"```(?:json_triage|json)\s*\{.*?\}\s*```\s*", "", comment, flags=re.DOTALL)
    return CaseWallCardFormatter.to_soar_html(comment.strip())

  def generate_behavioral_radar(self, username: str, telemetry_data: Dict[str, float]) -> str:
    """Computes 360-degree behavioral risk metrics and returns raw SVG string."""
    try:
      cx, cy = 250, 250
      scale = 50.0

      auth_z = float(telemetry_data.get("Auth", 0.0))
      cloud_z = float(telemetry_data.get("Cloud", 0.0))
      workspace_z = float(telemetry_data.get("Workspace", 0.0))
      egress_z = float(telemetry_data.get("Egress", 0.0))
      dns_z = float(telemetry_data.get("DNS", 0.0))

      def get_point(z, angle_deg):
        r = min(max(z, 0.0), 4.5) * scale
        angle_rad = math.radians(angle_deg - 90)
        x = cx + r * math.cos(angle_rad)
        y = cy + r * math.sin(angle_rad)
        return x, y

      p_auth = get_point(auth_z, 0)
      p_cloud = get_point(cloud_z, 72)
      p_workspace = get_point(workspace_z, 144)
      p_egress = get_point(egress_z, 216)
      p_dns = get_point(dns_z, 288)

      polygon_points = (
          f"{p_auth[0]},{p_auth[1]} {p_cloud[0]},{p_cloud[1]} "
          f"{p_workspace[0]},{p_workspace[1]} {p_egress[0]},{p_egress[1]} "
          f"{p_dns[0]},{p_dns[1]}"
      )

      def get_ring(z):
        pts = [get_point(z, a) for a in [0, 72, 144, 216, 288]]
        return " ".join([f"{x},{y}" for x, y in pts])

      composite_d = math.sqrt(
          sum(max(0.0, z)**2 for z in [auth_z, cloud_z, workspace_z, egress_z, dns_z])
      )

      svg_output = f"""<svg viewBox="0 0 500 500" width="100%" height="450" xmlns="http://www.w3.org/2000/svg" style="background: #0e1117; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; border-radius: 8px;">
  <defs>
    <radialGradient id="radarGlow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#00e5ff" stop-opacity="0.5"/>
      <stop offset="100%" stop-color="#00b0ff" stop-opacity="0.1"/>
    </radialGradient>
  </defs>
  <text x="250" y="30" text-anchor="middle" fill="#f0f6fc" font-size="15" font-weight="600" letter-spacing="1">360° BEHAVIORAL RISK RADAR — USER: {username.upper()}</text>
  <text x="250" y="48" text-anchor="middle" fill="#8b949e" font-size="11">Composite Threat Distance: D = {composite_d:.2f}σ | Baseline: 30-Day Pre-Computed</text>
  <polygon points="{get_ring(1.0)}" fill="none" stroke="#21262d" stroke-width="1" stroke-dasharray="3 3"/>
  <polygon points="{get_ring(2.0)}" fill="none" stroke="#30363d" stroke-width="1" stroke-dasharray="4 4"/>
  <polygon points="{get_ring(3.0)}" fill="rgba(255, 75, 75, 0.03)" stroke="#ff4b4b" stroke-width="1.5" stroke-dasharray="6 4"/>
  <text x="253" y="98" fill="#ff7b72" font-size="10" font-weight="bold">3.0σ (Anomaly Threshold)</text>
  <line x1="250" y1="250" x2="{get_point(3.0, 0)[0]}" y2="{get_point(3.0, 0)[1]}" stroke="#30363d" stroke-width="1.2"/>
  <line x1="250" y1="250" x2="{get_point(3.0, 72)[0]}" y2="{get_point(3.0, 72)[1]}" stroke="#30363d" stroke-width="1.2"/>
  <line x1="250" y1="250" x2="{get_point(3.0, 144)[0]}" y2="{get_point(3.0, 144)[1]}" stroke="#30363d" stroke-width="1.2"/>
  <line x1="250" y1="250" x2="{get_point(3.0, 216)[0]}" y2="{get_point(3.0, 216)[1]}" stroke="#30363d" stroke-width="1.2"/>
  <line x1="250" y1="250" x2="{get_point(3.0, 288)[0]}" y2="{get_point(3.0, 288)[1]}" stroke="#30363d" stroke-width="1.2"/>
  <text x="250" y="70" text-anchor="middle" fill="#c9d1d9" font-size="11" font-weight="600">🔑 Authentication (Z = {auth_z:+.2f}σ)</text>
  <text x="415" y="195" text-anchor="start" fill="#c9d1d9" font-size="11" font-weight="600">☁️ Cloud CRUD (Z = {cloud_z:+.2f}σ)</text>
  <text x="360" y="395" text-anchor="start" fill="#c9d1d9" font-size="11" font-weight="600">📁 Workspace Exfil (Z = {workspace_z:+.2f}σ)</text>
  <text x="140" y="395" text-anchor="end" fill="#c9d1d9" font-size="11" font-weight="600">🌐 Network Egress (Z = {egress_z:+.2f}σ)</text>
  <text x="85" y="195" text-anchor="end" fill="#c9d1d9" font-size="11" font-weight="600">📡 DNS Queries (Z = {dns_z:+.2f}σ)</text>
  <polygon points="{polygon_points}" fill="url(#radarGlow)" stroke="#00e5ff" stroke-width="2"/>
</svg>""".strip()
      return svg_output
    except Exception as e:
      logger.error(f"Failed generating behavioral radar: {e}")
      return f"ERROR: Could not compute radar metrics: {str(e)}"

  def resolve_skill_selection(self, req: JITHuntRequest) -> str:
    """Selects canonical skill dynamically based on alert physics if 'auto'."""
    if req.skill in ("risk-metrics", "secops-risk-metrics-multistage"):
      return "secops-risk-metrics-multistage"
    if req.skill in ("stats-hunter", "secops-statistical-hunter"):
      return "secops-statistical-hunter"

    # Contextual heuristic based on alert name and description
    context_str = f"{req.alert_name or ''} {req.alert_description or ''}".lower()
    
    # Raw process/command/beaconing indicators route to statistical hunter
    stats_indicators = [
        "powershell", "cmd.exe", "process", "beacon", "jitter", "c2", "burst",
        "spray", "fano", "entropy", "rare binary", "sysmon", "parent"
    ]
    if any(k in context_str for k in stats_indicators):
      return "secops-statistical-hunter"

    # Default to 30-day risk metrics baselining
    return "secops-risk-metrics-multistage"

  async def _execute_secondary_directive(
      self,
      session: ClientSession,
      tenant: TenantConfig,
      req: JITHuntRequest,
      directive: Any,
  ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Executes a Tier 2A or Tier 2B StrategyDirective and returns (result_dict, markdown_card)."""
    sec_query = (directive.directive_query or "").lower().strip()
    target_metric = getattr(directive, "target_metric", None)
    fusion_metrics = getattr(directive, "fusion_metrics", None) or []
    ident_field = getattr(directive, "identifier_field", None)

    if "sector_fusion" in sec_query or "fusion" in sec_query:
      metrics_pair = fusion_metrics if len(fusion_metrics) >= 2 else [
          target_metric or "auth_attempts_total",
          "network_bytes_outbound",
      ]
      sec_res = await RiskMetricsEngine(tenant).run_sector_fusion(
          session=session,
          entity=req.target_entity,
          fusion_metrics=metrics_pair,
          identifier_field=ident_field or "principal.user.userid",
          lookback_days=req.lookback_days,
      )
      sec_cri = sec_res["calibrated_risk_index"]
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Composite Fusion Score ($D$)**",
              "observed": f"`{sec_res['composite_threat_score']:.2f}σ`",
              "threshold": "$\\ge 3.00\\sigma$",
              "assessment": "⚠️ Multi-Sector Kill-Chain Convergence" if sec_outlier else "✅ Uncorrelated Sector Baseline",
          },
          {
              "metric": "**Fused Telemetry Vectors**",
              "observed": f"`{metrics_pair[0]}` + `{metrics_pair[1]}`",
              "threshold": f"Template: `{sec_res.get('template_name', 'dual_sector_fusion_3stage.yl2')}`",
              "assessment": f"Z_A = {sec_res.get('sector_a_z', 0.0):+.2f}σ | Z_B = {sec_res.get('sector_b_z', 0.0):+.2f}σ",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=req.target_entity,
          entity_type=req.entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=float(sec_cri),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=sec_res.get("stats_rows", 0),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "macd" in sec_query or "momentum" in sec_query:
      m_name = target_metric or "network_bytes_outbound"
      sec_res = await RiskMetricsEngine(tenant).run_macd_momentum_velocity(
          session=session,
          entity=req.target_entity,
          metric_name=m_name,
          lookback_days=req.lookback_days,
      )
      sec_cri = sec_res["calibrated_risk_index"]
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": f"**MACD Momentum Score (`{m_name}`)**",
              "observed": f"`{sec_res['macd_momentum_score']:+.2f}σ`",
              "threshold": "$> 3.00\\sigma$",
              "assessment": "⚠️ Acute Regime Acceleration" if sec_outlier else "✅ Stable Velocity Regime",
          },
          {
              "metric": "**Fast Z vs Slow Z Spine**",
              "observed": f"Fast Z = `{sec_res['fast_z']:+.2f}σ` | Slow Z = `{sec_res['slow_z']:+.2f}σ`",
              "threshold": "30-Day Pre-Computed Anchor",
              "assessment": "Dual-Spine Momentum Divergence",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=req.target_entity,
          entity_type=req.entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=float(sec_cri),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=sec_res.get("stats_rows", 0),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "circadian" in sec_query or "von_mises" in sec_query:
      m_name = target_metric or "auth_attempts_total"
      sec_res = await RiskMetricsEngine(tenant).run_circadian_von_mises(
          session=session,
          entity=req.target_entity,
          metric_name=m_name,
          lookback_days=req.lookback_days,
      )
      sec_cri = sec_res["calibrated_risk_index"]
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": f"**Circadian Threat Score (`{m_name}`)**",
              "observed": f"`{sec_res['circadian_threat_score']:.2f}`",
              "threshold": "$\\ge 50.0$",
              "assessment": "⚠️ Off-Hours Diurnal Phase Anomaly" if sec_outlier else "✅ Normal Working Schedule",
          },
          {
              "metric": "**Hourly Z-Score**",
              "observed": f"`{sec_res['hourly_z']:+.2f}σ` (Hour `{sec_res.get('event_hour', 'UTC')}` UTC)",
              "threshold": "$> 2.50\\sigma$",
              "assessment": "Circular von Mises Phase Evaluation",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=req.target_entity,
          entity_type=req.entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=float(sec_cri),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=sec_res.get("stats_rows", 0),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "cloud_crud" in sec_query:
      sec_res = await RiskMetricsEngine(tenant).run_cloud_crud_surge(
          session=session,
          username=req.target_entity,
          lookback_days=req.lookback_days,
      )
      sec_cri = sec_res["calibrated_risk_index"]
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Cloud CRUD Z-Score ($Z$)**",
              "observed": f"`{sec_res['top_z_score']:+.2f}σ`",
              "threshold": "$|Z| \\le 3.0\\sigma$",
              "assessment": "⚠️ IAM / Resource Mutation Surge" if sec_outlier else "✅ Normal Cloud Operations",
          },
          {
              "metric": "**Mutations Observed**",
              "observed": f"`{sec_res.get('observed_events', 0)}` events",
              "threshold": "30-Day Historical Baseline",
              "assessment": "Significant Departure" if sec_outlier else "Baseline",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=req.target_entity,
          entity_type=req.entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=float(sec_cri),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=sec_res.get("stats_rows", 0),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "dynamic_metric" in sec_query or "cusum" in sec_query:
      m_name = target_metric or "workspace_total_download_actions"
      stat_model = getattr(directive, "model_name", None) or ("LONGITUDINAL_CUSUM_DRIFT" if "cusum" in sec_query else "STANDARD_Z_SCORE")
      sec_res = await RiskMetricsEngine(tenant).run_dynamic_metric_pipeline(
          session=session,
          entity=req.target_entity,
          entity_type=req.entity_type,
          target_metric=m_name,
          model_name=stat_model,
          identifier_field=ident_field,
          fusion_metrics=fusion_metrics,
          lookback_days=req.lookback_days,
      )
      sec_cri = sec_res["calibrated_risk_index"]
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": f"**Metric Deviation (`{m_name}`)**",
              "observed": f"`{sec_res['top_z_score']:+.2f}σ`",
              "threshold": "$> 3.00\\sigma$",
              "assessment": "⚠️ Situational Metric Outlier" if sec_outlier else "✅ Within 30-Day Baseline",
          },
          {
              "metric": "**Observed Metric Volume**",
              "observed": f"`{sec_res.get('observed_value', 0.0):.1f}`",
              "threshold": f"Model: `{str(stat_model).upper()}`",
              "assessment": "Pre-Computed Malachite Metric Evaluation",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=req.target_entity,
          entity_type=req.entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=float(sec_cri),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=sec_res.get("stats_rows", 0),
          directive=directive,
          metrics_table_rows=sec_rows,
          second_order_ran=True,
      )
      return sec_res, sec_report

    if "c2_jitter" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_c2_beaconing_jitter(
          session=session,
          src_ip=req.target_entity,
          lookback_days=req.lookback_days,
      )
      sec_cri = sec_res["calibrated_risk_index"]
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Coefficient of Variation ($CV$)**",
              "observed": f"`{sec_res['coefficient_of_variation']:.3f}`",
              "threshold": "$\\le 0.20$",
              "assessment": "⚠️ Low Jitter / Robotic Regularity" if sec_outlier else "✅ Normal Jitter Variance",
          },
          {
              "metric": "**Target Destination**",
              "observed": f"`{sec_res['target_destination']}`",
              "threshold": "N/A",
              "assessment": "Suspected C2 Exfiltration Socket" if sec_outlier else "Benign Traffic",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=req.target_entity,
          entity_type=req.entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=float(sec_cri),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=sec_res.get("stats_rows", 0),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "poisson_burst" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_poisson_burst_spray(
          session=session,
          entity=req.target_entity,
          lookback_days=req.lookback_days,
      )
      sec_cri = sec_res["calibrated_risk_index"]
      sec_outlier = sec_res["is_outlier"]
      fano = float(sec_res.get("top_fano", 1.0))
      sec_rows = [
          {
              "metric": "**Fano Factor ($F = \\sigma^2 / \\mu$)**",
              "observed": f"`{fano:.2f}`",
              "threshold": "$> 4.00$",
              "assessment": "⚠️ Acute Clustered Spray Dispersion" if sec_outlier else "✅ Nominal Poisson Baseline",
          },
          {
              "metric": "**Evaluated Auth Events**",
              "observed": f"`{sec_res.get('stats_rows', 0)}`",
              "threshold": "Baseline",
              "assessment": "Authentication Failure Volatility",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=req.target_entity,
          entity_type=req.entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=float(sec_cri),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=sec_res.get("stats_rows", 0),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "shannon_entropy" in sec_query or "entropy" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_shannon_character_entropy(
          session=session,
          entity=req.target_entity,
          lookback_days=req.lookback_days,
      )
      sec_cri = sec_res["calibrated_risk_index"]
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Shannon Entropy ($H$)**",
              "observed": f"`{sec_res['shannon_entropy_score']:.2f}` bits/char",
              "threshold": "$> 6.00$ bits/char",
              "assessment": "⚠️ Obfuscated / Encoded Command Payload" if sec_outlier else "✅ Standard Text Entropy",
          },
          {
              "metric": "**Sampled Token**",
              "observed": f"`{str(sec_res.get('sample_token') or 'N/A')[:60]}`",
              "threshold": "Plaintext Command Line",
              "assessment": "Process Launch Inspection",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=req.target_entity,
          entity_type=req.entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=float(sec_cri),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=sec_res.get("stats_rows", 0),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "markov" in sec_query or "transition" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_markov_transition_rarity(
          session=session,
          host=req.target_entity,
          lookback_days=req.lookback_days,
      )
      sec_cri = sec_res["calibrated_risk_index"]
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Information Surprisal**",
              "observed": f"`{sec_res['surprisal_score']:.2f}` bits",
              "threshold": "$> 4.00$ bits",
              "assessment": "⚠️ Rare Living-off-the-Land Transition" if sec_outlier else "✅ Standard Process Transition",
          },
          {
              "metric": "**Observed Transition**",
              "observed": f"`{sec_res.get('parent_process', 'UNKNOWN')}` ➔ `{sec_res.get('child_process', 'UNKNOWN')}`",
              "threshold": "$P(\\text{Child}|\\text{Parent}) > 0.05$",
              "assessment": "Parent-Child Process Lineage",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=req.target_entity,
          entity_type=req.entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=float(sec_cri),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=sec_res.get("stats_rows", 0),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "zipf" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_zipfian_process_rarity(
          session=session,
          host=req.target_entity,
          lookback_days=req.lookback_days,
      )
      sec_cri = sec_res["calibrated_risk_index"]
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Zipf Rarity Score**",
              "observed": f"`{sec_res['zipf_rarity_score']:.2f}`",
              "threshold": "$> 3.50$",
              "assessment": "⚠️ Long-Tail Fleet Outlier" if sec_outlier else "✅ Common Fleet Software",
          },
          {
              "metric": "**Top Rare Binary**",
              "observed": f"`{sec_res.get('rare_binary', 'UNKNOWN')}`",
              "threshold": "$\\le 2$ Fleet Hosts",
              "assessment": "Isolated Execution Image",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=req.target_entity,
          entity_type=req.entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=float(sec_cri),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=sec_res.get("stats_rows", 0),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "ewma" in sec_query or "burst_velocity" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_ewma_burst_velocity(
          session=session,
          entity=req.target_entity,
          lookback_days=req.lookback_days,
      )
      sec_cri = sec_res["calibrated_risk_index"]
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**EWMA Velocity Score**",
              "observed": f"`{sec_res['ewma_velocity_score']:+.2f}σ`",
              "threshold": "$> 3.00\\sigma$",
              "assessment": "⚠️ Intraday Kinetic Burst Surge" if sec_outlier else "✅ Nominal Intraday Rate",
          },
          {
              "metric": "**Evaluated Buckets**",
              "observed": f"`{sec_res.get('stats_rows', 0)}`",
              "threshold": "Trailing Hourly Baseline",
              "assessment": "Exponential Smoothing Divergence",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=req.target_entity,
          entity_type=req.entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=float(sec_cri),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=sec_res.get("stats_rows", 0),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    return None, None

  async def execute_jit_hunt(self, req: JITHuntRequest) -> JITHuntResponse:
    """Executes the autonomous JIT investigation end-to-end."""
    # Resolve tenant dynamically
    tenant = TenantConfig(
        project_id=req.project_id or self.default_tenant.project_id,
        customer_id=req.customer_id or self.default_tenant.customer_id,
        region=req.region or self.default_tenant.region,
        mcp_url_override=self.default_tenant.mcp_url_override,
        model=self.default_tenant.model,
        allowed_tools=self.default_tenant.allowed_tools,
    )

    skill_name = self.resolve_skill_selection(req)
    persona = self.adapter.build_jit_persona(
        skill_name=skill_name,
        project_id=tenant.project_id,
        customer_id=tenant.customer_id,
        region=tenant.region,
    )

    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    if gemini_api_key:
      ai_client = genai.Client(
          api_key=gemini_api_key,
          http_options=types.HttpOptions(timeout=180000),
      )
    else:
      ai_client = genai.Client(
          vertexai=True,
          project=tenant.project_id,
          location="us-central1",
          http_options=types.HttpOptions(timeout=180000),
      )

    headers = tenant.get_auth_headers()
    custom_timeout = httpx.Timeout(30.0, read=120.0, write=120.0, pool=120.0)

    async with httpx.AsyncClient(headers=headers, timeout=custom_timeout, follow_redirects=True) as http_client:
      def _create_mcp_context():
        try:
          return streamable_http_client(tenant.mcp_url, headers=headers, timeout=60.0, sse_read_timeout=300.0)
        except TypeError:
          return streamable_http_client(tenant.mcp_url, headers=headers)

      mcp_context = _create_mcp_context()

      async with mcp_context as streams, ClientSession(streams[0], streams[1]) as session:
        await session.initialize()

        query_str = (req.query or "").lower().strip()
        if not query_str:
          decided_skill, decided_query, decided_model = StrategyDecider.decide(
              case_title="",
              alert_name=req.alert_name or "",
              alert_desc=req.alert_description or "",
              entity_type=req.entity_type or "USER",
          )
          logger.info(
              f"No explicit query provided. StrategyDecider selected: query='{decided_query}', skill='{decided_skill}', model='{decided_model}'"
          )
          query_str = decided_query.lower().strip()
          if not req.skill or req.skill == "auto":
            skill_name = decided_skill

        # --- 1. Deterministic Fast-Path: Decoupled 360° Behavioral Risk Radar ---
        if query_str in ("profile_360_risk", "360_risk", "radar_360") or (req.skill == "risk-metrics" and not req.query):
          try:
            if not req.directive:
              req.directive = StrategyDecider.decide_tier1_360(
                  target_entity=req.target_entity,
                  entity_type=req.entity_type,
                  case_id=req.case_id,
                  case_title=req.alert_name or "",
                  case_desc=req.alert_description or "",
                  alerts=req.alerts,
              )

            radar_result = await RiskMetricsEngine(tenant).run_360_behavioral_radar(
                session=session,
                username=req.target_entity,
                lookback_days=req.lookback_days,
                entity_type=req.entity_type,
            )
            radar_svg = self.generate_behavioral_radar(
                req.target_entity,
                radar_result["sector_z_scores"],
            )
            cri = radar_result["calibrated_risk_index"]
            verdict = radar_result["verdict"]
            top_sector = radar_result["top_sector"]

            # --- Tier 2 Secondary Sweep Evaluation & Hypothesis Defense ---
            is_tier1 = not req.directive or getattr(req.directive, "investigation_tier", "TIER_1_BASELINE") == "TIER_1_BASELINE"
            top_z = abs(float(radar_result["sector_z_scores"].get(top_sector, 0.0)))
            alert_corpus = f"{req.alert_name or ''} {req.alert_description or ''}".lower()
            kinetic_trigger = any(
                k in alert_corpus for k in (
                    "beacon", "jitter", "c2", "spray", "brute", "dropper", "exfil",
                    "entropy", "privilege", "lateral", "rat", "drive", "workspace",
                    "download", "upload", "http", "proxy", "dns", "dga", "tunnel",
                )
            )
            needs_secondary = is_tier1 and (
                radar_result["is_outlier"]
                or top_z >= 2.0
                or float(cri) >= 40.0
                or kinetic_trigger
            )

            tier2_directive = None
            alert_list = req.alerts or [{"name": req.alert_name or "", "description": req.alert_description or ""}]
            conn_list = req.connector_events or []

            if needs_secondary:
              try:
                tier2_directive = await StrategyDecider.decide_tier2_deep_dive(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    outlier_vector=top_sector,
                    case_info={"id": req.case_id, "title": req.alert_name or ""},
                    alerts=alert_list,
                    connector_events=conn_list,
                    radar_result=radar_result,
                )
                if req.directive and tier2_directive and tier2_directive.recommended_avenues:
                  req.directive.recommended_avenues = tier2_directive.recommended_avenues
                  req.directive.candidate_hypotheses = tier2_directive.candidate_hypotheses
              except Exception as t2_plan_err:
                logger.warning(f"Tier 2 hypothesis planning encountered non-fatal error: {t2_plan_err}")

            will_run_second_order = bool(
                needs_secondary
                and req.case_id
                and tier2_directive is not None
                and tier2_directive.confidence_score >= StrategyDecider.TIER_2A_AUTO_EXECUTE_THRESHOLD
            )

            sector_metrics_map = radar_result.get("sector_metrics", {})
            sector_rows = [
                {
                    "metric": f"**{s_name} Sector** (`{sector_metrics_map.get(s_name, 'metrics')}`)",
                    "observed": f"Z = {z_val:+.2f} ({radar_result['sector_observed_counts'].get(s_name, 0)} events)",
                    "threshold": "|Z| <= 2.0σ",
                    "assessment": "⚠️ Significant Behavioral Drift" if abs(z_val) > 2.0 else "✅ Nominal Baseline",
                }
                for s_name, z_val in radar_result["sector_z_scores"].items()
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="360_DECOUPLED_RADAR",
                calibrated_risk_index=float(cri),
                is_outlier=radar_result["is_outlier"],
                case_id=req.case_id,
                rows_count=sum(radar_result["sector_observed_counts"].values()),
                directive=req.directive,
                metrics_table_rows=sector_rows,
                soc_guidance=(
                    f"Investigate high-drift sector `{top_sector}` (Composite Euclidean Distance D = {radar_result['composite_d']:.2f}). "
                    "Stage user containment if unauthorized data exfiltration or credential rotation is confirmed."
                    if radar_result["is_outlier"] else
                    "All evaluated behavioral sectors conform to 30-day baseline. No containment needed."
                ),
                primary_vector=top_sector,
                second_order_ran=will_run_second_order,
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True

            triage = TriageSummary(
                calibrated_risk_index=float(cri),
                verdict=verdict,
                is_outlier=radar_result["is_outlier"],
                primary_vector=f"{top_sector}_behavioral_drift",
                common_vector=CaseWallCardFormatter.normalize_common_vector(raw_vector=top_sector),
                second_order_ran=will_run_second_order,
                top_z_score=float(radar_result["sector_z_scores"].get(top_sector, 0.0)),
                radar_dimensions=radar_result["sector_z_scores"],
                recommended_action="QUARANTINE" if cri >= 80 else ("INVESTIGATE" if cri >= 60 else "MONITOR"),
                entities_to_quarantine=[req.target_entity] if radar_result["is_outlier"] else [],
                mitre_tactics=["TA0001", "TA0006"] if radar_result["is_outlier"] else [],
            )

            # --- Confidence-Gated Tier 2A Auto-Execution & Bounded Tier 2B Epistemic Pivot ---
            if needs_secondary and req.case_id and tier2_directive is not None:
              try:
                executed_signatures = set()
                empty_families = set()
                secondary_hunts_run = 0

                if tier2_directive.confidence_score >= StrategyDecider.TIER_2A_AUTO_EXECUTE_THRESHOLD:
                  logger.info(
                      f"Tier 2A Confidence Gate PASSED (score={tier2_directive.confidence_score:.2f} >= "
                      f"{StrategyDecider.TIER_2A_AUTO_EXECUTE_THRESHOLD:.2f}, model={tier2_directive.model_name}, "
                      f"metric={tier2_directive.target_metric}). Auto-executing secondary hunt for '{req.target_entity}'..."
                  )
                  sig_2a = StrategyDecider.build_signature(
                      tier2_directive.model_name,
                      tier2_directive.target_metric,
                      tier2_directive.fusion_metrics,
                      req.target_entity,
                  )
                  executed_signatures.add(sig_2a)
                  sec_res, sec_report = await self._execute_secondary_directive(
                      session=session,
                      tenant=tenant,
                      req=req,
                      directive=tier2_directive,
                  )
                  secondary_hunts_run += 1

                  if sec_res is not None and int(sec_res.get("stats_rows", 0)) == 0:
                    empty_families.add(StrategyDecider.family_for_query(tier2_directive.directive_query))

                  if sec_report and req.post_to_case_wall:
                    await session.call_tool(
                        "create_case_comment",
                        {
                            "projectId": tenant.project_id,
                            "customerId": tenant.customer_id,
                            "region": tenant.region,
                            "caseId": str(req.case_id),
                            "comment": self.sanitize_case_comment(sec_report),
                        },
                    )
                    markdown_report = f"{markdown_report}\n\n---\n\n{sec_report}"
                    sec_cri = float(sec_res.get("calibrated_risk_index", 0.0)) if sec_res else 0.0
                    sec_outlier = bool(sec_res.get("is_outlier", False)) if sec_res else False
                    cri = max(cri, sec_cri)
                    if sec_outlier:
                      triage.is_outlier = True
                      triage.calibrated_risk_index = float(cri)
                      triage.verdict = "CRITICAL_OUTLIER" if cri >= 80 else "HIGH_OUTLIER"
                      triage.primary_vector = f"tier2a_{tier2_directive.model_name.lower()}"

                  # Evaluate Bounded Tier 2B Epistemic Pivot (Refutation Pivot or Multi-Sector Fusion Pivot)
                  if sec_res is not None and secondary_hunts_run < StrategyDecider.MAX_SECONDARY_HUNTS:
                    pivot_directive = StrategyDecider.decide_tier2_pivot(
                        target_entity=req.target_entity,
                        entity_type=req.entity_type,
                        radar_result=radar_result,
                        tier2a_directive=tier2_directive,
                        tier2a_result=sec_res,
                        alerts=alert_list,
                        connector_events=conn_list,
                        executed_signatures=executed_signatures,
                        empty_families=empty_families,
                        secondary_hunts_run=secondary_hunts_run,
                    )
                    if (
                        pivot_directive is not None
                        and pivot_directive.confidence_score >= StrategyDecider.TIER_2B_PIVOT_AUTO_EXECUTE_THRESHOLD
                    ):
                      logger.info(
                          f"Tier 2B Epistemic Pivot Gate PASSED (score={pivot_directive.confidence_score:.2f} >= "
                          f"{StrategyDecider.TIER_2B_PIVOT_AUTO_EXECUTE_THRESHOLD:.2f}, model={pivot_directive.model_name}). "
                          f"Auto-executing bounded pivot (2/{StrategyDecider.MAX_SECONDARY_HUNTS}) for '{req.target_entity}'..."
                      )
                      sig_2b = StrategyDecider.build_signature(
                          pivot_directive.model_name,
                          pivot_directive.target_metric,
                          pivot_directive.fusion_metrics,
                          req.target_entity,
                      )
                      executed_signatures.add(sig_2b)
                      piv_res, piv_report = await self._execute_secondary_directive(
                          session=session,
                          tenant=tenant,
                          req=req,
                          directive=pivot_directive,
                      )
                      secondary_hunts_run += 1
                      if piv_report and req.post_to_case_wall:
                        await session.call_tool(
                            "create_case_comment",
                            {
                                "projectId": tenant.project_id,
                                "customerId": tenant.customer_id,
                                "region": tenant.region,
                                "caseId": str(req.case_id),
                                "comment": self.sanitize_case_comment(piv_report),
                            },
                        )
                        markdown_report = f"{markdown_report}\n\n---\n\n{piv_report}"
                        piv_cri = float(piv_res.get("calibrated_risk_index", 0.0)) if piv_res else 0.0
                        piv_outlier = bool(piv_res.get("is_outlier", False)) if piv_res else False
                        cri = max(cri, piv_cri)
                        if piv_outlier:
                          triage.is_outlier = True
                          triage.calibrated_risk_index = float(cri)
                          triage.verdict = "CRITICAL_OUTLIER" if cri >= 80 else "HIGH_OUTLIER"
                          triage.primary_vector = f"tier2b_{pivot_directive.model_name.lower()}"

                  if secondary_hunts_run > 0:
                    triage.second_order_ran = True
                    triage.common_vector = CaseWallCardFormatter.normalize_common_vector(
                        raw_vector=top_sector,
                        model_name=triage.primary_vector,
                    )
                    triage.tags = CaseWallCardFormatter.build_case_tags(
                        calibrated_risk_index=triage.calibrated_risk_index,
                        primary_vector=top_sector,
                        model_name=triage.primary_vector,
                        second_order_ran=True,
                        is_outlier=triage.is_outlier,
                    )
                else:
                  logger.info(
                      f"Tier 2A Confidence Gate HELD (score={tier2_directive.confidence_score:.2f} < "
                      f"{StrategyDecider.TIER_2A_AUTO_EXECUTE_THRESHOLD:.2f}). Defended hypothesis surfaced on Case Wall without auto-execution."
                  )
              except Exception as sec_err:
                logger.warning(f"Tier 2 secondary sweep encountered non-fatal error: {sec_err}")
            clean_hand_off = CleanHandOffPayload(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                primary_model="secops-risk-metrics-multistage",
                outlier_topology=f"{top_sector.upper()}_DRIFT",
                mitre_tactics_mapped=triage.mitre_tactics,
                recommended_swarm_playbook="DECOUPLED_RADAR_INVESTIGATION",
                escalation_action=triage.recommended_action,
            )
            forensics = ForensicsSummary(
                executed_query="360° Decoupled Sector Micro-Queries (Auth, Cloud, Workspace, Egress, DNS, Web)",
                markdown_report=markdown_report,
                radar_svg=radar_svg,
            )
            return JITHuntResponse(
                status="SUCCESS",
                triage=triage,
                clean_hand_off=clean_hand_off,
                forensics=forensics,
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic 360 radar fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        # --- 2. Deterministic Fast-Path: C2 Beaconing Jitter ---
        elif "c2_jitter" in query_str or "beaconing" in query_str:
          try:
            jitter_result = await StatsHunterEngine(tenant).run_c2_beaconing_jitter(
                session=session,
                src_ip=req.target_entity,
                lookback_days=req.lookback_days,
            )
            cri = jitter_result["calibrated_risk_index"]
            verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
            rows_count = jitter_result.get("stats_rows", 0)
            jitter_rows = [
                {
                    "metric": "**Coefficient of Variation ($CV$)**",
                    "observed": f"`{jitter_result['coefficient_of_variation']:.3f}`",
                    "threshold": "$\\le 0.300$",
                    "assessment": "⚠️ Low Jitter / Periodic Beaconing" if jitter_result["is_outlier"] else "✅ High Jitter (Stochastic / Irregular)",
                },
                {
                    "metric": "**Top Target Destination**",
                    "observed": f"`{jitter_result.get('target_destination', 'UNKNOWN')}`",
                    "threshold": "External IP",
                    "assessment": "Primary Egress Communication Endpoint",
                },
                {
                    "metric": "**Sampled Outbound Flows**",
                    "observed": f"`{rows_count}` connections",
                    "threshold": "$\\ge 20$ connections",
                    "assessment": "Sufficient Statistical Power" if rows_count >= 20 else "Limited Sample Size",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="C2_BEACONING_JITTER",
                calibrated_risk_index=float(cri),
                is_outlier=jitter_result["is_outlier"],
                case_id=req.case_id,
                rows_count=rows_count,
                directive=req.directive,
                metrics_table_rows=jitter_rows,
                soc_guidance=(
                    f"Outbound network traffic to `{jitter_result.get('target_destination')}` exhibits rigid periodicity ($CV = {jitter_result['coefficient_of_variation']:.3f}$). "
                    "Host quarantine and perimeter IP block recommended."
                    if jitter_result["is_outlier"] else
                    f"Outbound connection intervals exhibit high timing jitter ($CV = {jitter_result['coefficient_of_variation']:.3f}$), typical of normal cloud applications and distributed polling. No beaconing detected."
                ),
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True
            return JITHuntResponse(
                status="SUCCESS",
                triage=TriageSummary(
                    calibrated_risk_index=float(cri),
                    verdict=verdict,
                    is_outlier=jitter_result["is_outlier"],
                    primary_vector="c2_timing_regularity",
                    top_z_score=float(jitter_result.get("top_z_score", 0.0)),
                    recommended_action="ISOLATE_HOST" if cri >= 80 else "MONITOR",
                    entities_to_quarantine=[req.target_entity] if jitter_result["is_outlier"] else [],
                    mitre_tactics=["TA0011"] if jitter_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-statistical-hunter",
                    outlier_topology="C2_REGULARITY",
                    mitre_tactics_mapped=["TA0011"] if jitter_result["is_outlier"] else [],
                    recommended_swarm_playbook="C2_CONTAINMENT",
                    escalation_action="ISOLATE_HOST" if cri >= 80 else "MONITOR",
                ),
                forensics=ForensicsSummary(
                    executed_query=jitter_result["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic C2 jitter fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        # --- 3. Deterministic Fast-Path: Poisson Burst Spray ---
        elif "poisson_burst" in query_str or "spray" in query_str:
          try:
            spray_result = await StatsHunterEngine(tenant).run_poisson_burst_spray(
                session=session,
                entity=req.target_entity,
                lookback_days=req.lookback_days,
            )
            cri = spray_result["calibrated_risk_index"]
            verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
            fano = float(spray_result.get("top_fano", 1.0))
            spray_rows = [
                {
                    "metric": "**Fano Factor ($F = \\sigma^2 / \\mu$)**",
                    "observed": f"`{fano:.2f}`",
                    "threshold": "$> 4.00$",
                    "assessment": "⚠️ Severe Overdispersion (Clustered Spray)" if spray_result["is_outlier"] else "✅ Poisson Dispersion (Nominal Rate)",
                },
                {
                    "metric": "**Evaluated Auth Events**",
                    "observed": f"`{spray_result.get('stats_rows', 0)}` events",
                    "threshold": "$\\ge 10$ events",
                    "assessment": "Observed Sample Window",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="POISSON_BURST_CLUSTERING",
                calibrated_risk_index=float(cri),
                is_outlier=spray_result["is_outlier"],
                case_id=req.case_id,
                rows_count=spray_result.get("stats_rows", 0),
                directive=req.directive,
                metrics_table_rows=spray_rows,
                soc_guidance=(
                    f"Detected automated credential spray bursts ($Fano = {fano:.2f}$). Lock account credentials and invalidate active OAuth/SAML tokens."
                    if spray_result["is_outlier"] else
                    f"Authentication failures show no statistical clustering ($Fano = {fano:.2f}$), consistent with random user typing mistakes."
                ),
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True
            return JITHuntResponse(
                status="SUCCESS",
                triage=TriageSummary(
                    calibrated_risk_index=float(cri),
                    verdict=verdict,
                    is_outlier=spray_result["is_outlier"],
                    primary_vector="poisson_burst_clustering",
                    top_z_score=float(spray_result.get("top_fano", 0.0)),
                    recommended_action="LOCK_ACCOUNT" if cri >= 80 else "MONITOR",
                    entities_to_quarantine=[req.target_entity] if spray_result["is_outlier"] else [],
                    mitre_tactics=["TA0006"] if spray_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-statistical-hunter",
                    outlier_topology="POISSON_BURST",
                    mitre_tactics_mapped=["TA0006"] if spray_result["is_outlier"] else [],
                    recommended_swarm_playbook="CREDENTIAL_SPRAY_REMEDIATION",
                    escalation_action="LOCK_ACCOUNT" if cri >= 80 else "MONITOR",
                ),
                forensics=ForensicsSummary(
                    executed_query=spray_result["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic Poisson burst fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        # --- 4. Deterministic Fast-Path: Cloud Infrastructure CRUD Surge ---
        elif "cloud_crud" in query_str or "cloud_surge" in query_str:
          try:
            cloud_result = await RiskMetricsEngine(tenant).run_cloud_crud_surge(
                session=session,
                username=req.target_entity,
                lookback_days=req.lookback_days,
            )
            cri = cloud_result["calibrated_risk_index"]
            verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
            top_z = float(cloud_result.get("top_z_score", 0.0))
            cloud_rows = [
                {
                    "metric": "**Cloud Mutation Z-Score**",
                    "observed": f"`{top_z:+.2f}σ`",
                    "threshold": "$> 3.00\\sigma$",
                    "assessment": "⚠️ Significant Administrative Mutation" if cloud_result["is_outlier"] else "✅ Within Baseline Volatility",
                },
                {
                    "metric": "**Observed Cloud Modifications**",
                    "observed": f"`{cloud_result.get('observed_events', 0)}` mutations",
                    "threshold": "Historical 30-Day Mean",
                    "assessment": "Cloud Resource Write Events",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="CLOUD_CRUD_SURGE",
                calibrated_risk_index=float(cri),
                is_outlier=cloud_result["is_outlier"],
                case_id=req.case_id,
                rows_count=cloud_result.get("observed_events", 0),
                directive=req.directive,
                metrics_table_rows=cloud_rows,
                soc_guidance=(
                    f"Abnormal cloud infrastructure creation/permission spike ($Z = {top_z:+.2f}\\sigma$). Audit IAM changes and newly deployed cloud workloads."
                    if cloud_result["is_outlier"] else
                    f"Cloud resource management operations ($Z = {top_z:+.2f}\\sigma$) match expected deployment baselines."
                ),
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True
            return JITHuntResponse(
                status="SUCCESS",
                triage=TriageSummary(
                    calibrated_risk_index=float(cri),
                    verdict=verdict,
                    is_outlier=cloud_result["is_outlier"],
                    primary_vector="cloud_crud_surge",
                    top_z_score=float(cloud_result.get("top_z_score", 0.0)),
                    recommended_action="REVOKE_IAM_ROLES" if cri >= 80 else "MONITOR",
                    entities_to_quarantine=[req.target_entity] if cloud_result["is_outlier"] else [],
                    mitre_tactics=["TA0003", "TA0004"] if cloud_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-risk-metrics-multistage",
                    outlier_topology="CLOUD_CRUD_SURGE",
                    mitre_tactics_mapped=["TA0003", "TA0004"] if cloud_result["is_outlier"] else [],
                    recommended_swarm_playbook="IAM_ABUSE_INVESTIGATION",
                    escalation_action="REVOKE_IAM_ROLES" if cri >= 80 else "MONITOR",
                ),
                forensics=ForensicsSummary(
                    executed_query=cloud_result["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic Cloud CRUD fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        # --- 5. Deterministic Fast-Path: Circadian von Mises Temporal Anomaly ---
        elif "circadian" in query_str or "von_mises" in query_str:
          try:
            m_name = getattr(req.directive, "target_metric", None) or "auth_attempts_total"
            circ_result = await RiskMetricsEngine(tenant).run_circadian_von_mises(
                session=session,
                entity=req.target_entity,
                metric_name=m_name,
                lookback_days=req.lookback_days,
            )
            cri = circ_result["calibrated_risk_index"]
            verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
            hourly_z = float(circ_result.get("hourly_z", 0.0))
            circ_rows = [
                {
                    "metric": "**Circadian Threat Score**",
                    "observed": f"`{circ_result.get('circadian_threat_score', 0)}`",
                    "threshold": "$\\ge 50$",
                    "assessment": "⚠️ Off-Hours / Temporal Outlier" if circ_result["is_outlier"] else "✅ Active Working Hours",
                },
                {
                    "metric": "**Hourly Z-Score**",
                    "observed": f"`{hourly_z:+.2f}σ`",
                    "threshold": "$> 2.50\\sigma$",
                    "assessment": f"Event Hour: {circ_result.get('event_hour', 'UTC')} UTC",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="CIRCADIAN_VON_MISES",
                calibrated_risk_index=float(cri),
                is_outlier=circ_result["is_outlier"],
                case_id=req.case_id,
                rows_count=1,
                directive=req.directive,
                metrics_table_rows=circ_rows,
                soc_guidance=(
                    f"Activity occurred at a statistically rare circadian angle for this identity ($Z = {hourly_z:+.2f}\\sigma$). Verify user physical travel or remote session legitimacy."
                    if circ_result["is_outlier"] else
                    f"Activity timing is consistent with user normal diurnal schedule ($Z = {hourly_z:+.2f}\\sigma$)."
                ),
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True
            return JITHuntResponse(
                status="SUCCESS",
                triage=TriageSummary(
                    calibrated_risk_index=float(cri),
                    verdict=verdict,
                    is_outlier=circ_result["is_outlier"],
                    primary_vector="circadian_temporal_anomaly",
                    top_z_score=float(circ_result.get("top_z_score", 0.0)),
                    recommended_action="FORCE_MFA_CHALLENGE" if cri >= 80 else "MONITOR",
                    entities_to_quarantine=[req.target_entity] if circ_result["is_outlier"] else [],
                    mitre_tactics=["TA0001"] if circ_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-risk-metrics-multistage",
                    outlier_topology="CIRCADIAN_TEMPORAL_DEPARTURE",
                    mitre_tactics_mapped=["TA0001"] if circ_result["is_outlier"] else [],
                    recommended_swarm_playbook="OFF_HOURS_ACCESS_CONTAINMENT",
                    escalation_action="FORCE_MFA_CHALLENGE" if cri >= 80 else "MONITOR",
                ),
                forensics=ForensicsSummary(
                    executed_query=circ_result["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic Circadian fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        # --- 6. Deterministic Fast-Path: MACD Momentum Velocity ---
        elif "macd" in query_str or "momentum" in query_str:
          try:
            m_name = getattr(req.directive, "target_metric", None) or "network_bytes_outbound"
            macd_result = await RiskMetricsEngine(tenant).run_macd_momentum_velocity(
                session=session,
                entity=req.target_entity,
                metric_name=m_name,
                lookback_days=req.lookback_days,
            )
            cri = macd_result["calibrated_risk_index"]
            verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
            macd_rows = [
                {
                    "metric": f"**MACD Momentum Score (`{m_name}`)**",
                    "observed": f"`{macd_result['macd_momentum_score']:+.2f}σ`",
                    "threshold": "$> 3.00\\sigma$",
                    "assessment": "⚠️ Acute Regime Acceleration" if macd_result["is_outlier"] else "✅ Stable Velocity Regime",
                },
                {
                    "metric": "**Fast Z vs Slow Z Spine**",
                    "observed": f"Fast Z = `{macd_result['fast_z']:+.2f}σ` | Slow Z = `{macd_result['slow_z']:+.2f}σ`",
                    "threshold": "30-Day Pre-Computed Anchor",
                    "assessment": "Dual-Spine Momentum Divergence",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="MACD_MOMENTUM_VELOCITY",
                calibrated_risk_index=float(cri),
                is_outlier=macd_result["is_outlier"],
                case_id=req.case_id,
                rows_count=macd_result.get("stats_rows", 0),
                directive=req.directive,
                metrics_table_rows=macd_rows,
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True
            return JITHuntResponse(
                status="SUCCESS",
                triage=TriageSummary(
                    calibrated_risk_index=float(cri),
                    verdict=verdict,
                    is_outlier=macd_result["is_outlier"],
                    primary_vector="macd_momentum_acceleration",
                    top_z_score=float(macd_result.get("top_z_score", 0.0)),
                    recommended_action="THROTTLE_EGRESS" if cri >= 80 else "MONITOR",
                    entities_to_quarantine=[req.target_entity] if macd_result["is_outlier"] else [],
                    mitre_tactics=["TA0010"] if macd_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-risk-metrics-multistage",
                    outlier_topology="MACD_MOMENTUM_DIVERGENCE",
                    mitre_tactics_mapped=["TA0010"] if macd_result["is_outlier"] else [],
                    recommended_swarm_playbook="EXFILTRATION_MOMENTUM_CONTAINMENT",
                    escalation_action="THROTTLE_EGRESS" if cri >= 80 else "MONITOR",
                ),
                forensics=ForensicsSummary(
                    executed_query=macd_result["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic MACD fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        # --- 7. Deterministic Fast-Path: Shannon Character Entropy ---
        elif "shannon" in query_str or "entropy" in query_str:
          try:
            shannon_result = await StatsHunterEngine(tenant).run_shannon_character_entropy(
                session=session,
                entity=req.target_entity,
                lookback_days=req.lookback_days,
            )
            cri = shannon_result["calibrated_risk_index"]
            verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
            sample_tok = shannon_result.get("sample_token") or "N/A"
            shannon_rows = [
                {
                    "metric": "**Shannon Entropy ($H$)**",
                    "observed": f"`{shannon_result['shannon_entropy_score']:.2f}` bits/char",
                    "threshold": "> 6.00 bits/char",
                    "assessment": "⚠️ Obfuscated / Encrypted Command Payload" if shannon_result["is_outlier"] else "✅ Standard Text Entropy",
                },
                {
                    "metric": "**Sampled Execution Token**",
                    "observed": f"`{sample_tok[:60]}`",
                    "threshold": "Plaintext Command Line",
                    "assessment": "Command Line Argument Inspection",
                },
                {
                    "metric": "**Sampled Executions**",
                    "observed": f"`{shannon_result.get('stats_rows', 0)}` records",
                    "threshold": "$\\ge 1$ required",
                    "assessment": "Process Launch Telemetry",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="SHANNON_CHARACTER_ENTROPY",
                calibrated_risk_index=float(cri),
                is_outlier=shannon_result["is_outlier"],
                case_id=req.case_id,
                rows_count=shannon_result.get("stats_rows", 0),
                directive=req.directive,
                metrics_table_rows=shannon_rows,
                soc_guidance=(
                    f"Command line on `{req.target_entity}` exhibits high Shannon character-class entropy ($H = {shannon_result['shannon_entropy_score']:.2f}$ bits/char), indicating Base64/XOR obfuscated scripts. "
                    "Terminate process and extract decoded command buffers."
                    if shannon_result["is_outlier"] else
                    f"Command line entropy on `{req.target_entity}` is within expected readable parameter distributions."
                ),
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True
            return JITHuntResponse(
                status="SUCCESS",
                triage=TriageSummary(
                    calibrated_risk_index=float(cri),
                    verdict=verdict,
                    is_outlier=shannon_result["is_outlier"],
                    primary_vector="command_line_obfuscation_entropy",
                    top_z_score=float(shannon_result.get("top_z_score", 0.0)),
                    recommended_action="TERMINATE_PROCESS" if cri >= 80 else "MONITOR",
                    entities_to_quarantine=[req.target_entity] if shannon_result["is_outlier"] else [],
                    mitre_tactics=["TA0005"] if shannon_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-statistical-hunter",
                    outlier_topology="SHANNON_CHARACTER_ENTROPY",
                    mitre_tactics_mapped=["TA0005"] if shannon_result["is_outlier"] else [],
                    recommended_swarm_playbook="OBFUSCATED_COMMAND_REMEDIATION",
                    escalation_action="TERMINATE_PROCESS" if cri >= 80 else "MONITOR",
                ),
                forensics=ForensicsSummary(
                    executed_query=shannon_result["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic Shannon entropy fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        # --- 8. Deterministic Fast-Path: Markov 2-Gram Transition Rarity ---
        elif "markov" in query_str or "transition" in query_str:
          try:
            markov_result = await StatsHunterEngine(tenant).run_markov_transition_rarity(
                session=session,
                host=req.target_entity,
                lookback_days=req.lookback_days,
            )
            cri = markov_result["calibrated_risk_index"]
            verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
            p_proc = markov_result.get("parent_process") or "UNKNOWN"
            c_proc = markov_result.get("child_process") or "UNKNOWN"
            markov_rows = [
                {
                    "metric": "**Information Surprisal**",
                    "observed": f"`{markov_result['surprisal_score']:.2f}` bits",
                    "threshold": "> 4.00 bits",
                    "assessment": "⚠️ Rare Living-off-the-Land Transition" if markov_result["is_outlier"] else "✅ Standard Process Transition",
                },
                {
                    "metric": "**Observed Transition**",
                    "observed": f"`{p_proc}` ➔ `{c_proc}`",
                    "threshold": "P(Child|Parent) > 0.05",
                    "assessment": "Parent-Child Process Lineage",
                },
                {
                    "metric": "**Sampled Executions**",
                    "observed": f"`{markov_result.get('stats_rows', 0)}` records",
                    "threshold": "$\\ge 1$ required",
                    "assessment": "Process Lineage Telemetry",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="MARKOV_TRANSITION_RARITY",
                calibrated_risk_index=float(cri),
                is_outlier=markov_result["is_outlier"],
                case_id=req.case_id,
                rows_count=markov_result.get("stats_rows", 0),
                directive=req.directive,
                metrics_table_rows=markov_rows,
                soc_guidance=(
                    f"Process lineage `{p_proc}` ➔ `{c_proc}` exhibits extreme surprisal ({markov_result['surprisal_score']:.2f} bits) characteristic of Living-off-the-Land execution. "
                    "Isolate host and investigate command line arguments."
                    if markov_result["is_outlier"] else
                    f"Process execution transitions on `{req.target_entity}` conform to standard enterprise operational tooling."
                ),
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True
            return JITHuntResponse(
                status="SUCCESS",
                triage=TriageSummary(
                    calibrated_risk_index=float(cri),
                    verdict=verdict,
                    is_outlier=markov_result["is_outlier"],
                    primary_vector="markov_process_transition_rarity",
                    top_z_score=float(markov_result.get("top_z_score", 0.0)),
                    recommended_action="ISOLATE_HOST" if cri >= 80 else "MONITOR",
                    entities_to_quarantine=[req.target_entity] if markov_result["is_outlier"] else [],
                    mitre_tactics=["TA0002", "TA0005"] if markov_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-statistical-hunter",
                    outlier_topology="MARKOV_TRANSITION_RARITY",
                    mitre_tactics_mapped=["TA0002", "TA0005"] if markov_result["is_outlier"] else [],
                    recommended_swarm_playbook="LIVING_OFF_THE_LAND_CONTAINMENT",
                    escalation_action="ISOLATE_HOST" if cri >= 80 else "MONITOR",
                ),
                forensics=ForensicsSummary(
                    executed_query=markov_result["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic Markov transition fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        # --- 9. Deterministic Fast-Path: Zipfian Process Rarity ---
        elif "zipf" in query_str or "zipfian" in query_str:
          try:
            zipf_result = await StatsHunterEngine(tenant).run_zipfian_process_rarity(
                session=session,
                host=req.target_entity,
                lookback_days=req.lookback_days,
            )
            cri = zipf_result["calibrated_risk_index"]
            verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
            rare_bin = zipf_result.get("rare_binary") or "UNKNOWN"
            zipf_rows = [
                {
                    "metric": "**Zipf Rarity Score**",
                    "observed": f"`{zipf_result['zipf_rarity_score']:.2f}`",
                    "threshold": "> 3.50",
                    "assessment": "⚠️ Long-Tail Fleet Outlier" if zipf_result["is_outlier"] else "✅ Common Fleet Software",
                },
                {
                    "metric": "**Top Rare Binary**",
                    "observed": f"`{rare_bin}`",
                    "threshold": "<= 2 Fleet Hosts",
                    "assessment": "Isolated Execution Image",
                },
                {
                    "metric": "**Sampled Process Executions**",
                    "observed": f"`{zipf_result.get('stats_rows', 0)}` records",
                    "threshold": "$\\ge 1$ required",
                    "assessment": "Process Launch Telemetry",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="ZIPFIAN_PROCESS_RARITY",
                calibrated_risk_index=float(cri),
                is_outlier=zipf_result["is_outlier"],
                case_id=req.case_id,
                rows_count=zipf_result.get("stats_rows", 0),
                directive=req.directive,
                metrics_table_rows=zipf_rows,
                soc_guidance=(
                    f"Host `{req.target_entity}` executed rare binary `{rare_bin}` sitting in the extreme asymptotic fleet tail (Zipf Score = {zipf_result['zipf_rarity_score']:.2f}). "
                    "Isolate host, terminate binary process, and inspect persistence entries."
                    if zipf_result["is_outlier"] else
                    f"Process execution telemetry on `{req.target_entity}` conforms to common enterprise software distributions."
                ),
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True
            return JITHuntResponse(
                status="SUCCESS",
                triage=TriageSummary(
                    calibrated_risk_index=float(cri),
                    verdict=verdict,
                    is_outlier=zipf_result["is_outlier"],
                    primary_vector="zipfian_rare_tool_execution",
                    top_z_score=float(zipf_result.get("top_z_score", 0.0)),
                    recommended_action="ISOLATE_HOST" if cri >= 80 else "MONITOR",
                    entities_to_quarantine=[req.target_entity] if zipf_result["is_outlier"] else [],
                    mitre_tactics=["TA0002"] if zipf_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-statistical-hunter",
                    outlier_topology="ZIPFIAN_PROCESS_RARITY",
                    mitre_tactics_mapped=["TA0002"] if zipf_result["is_outlier"] else [],
                    recommended_swarm_playbook="RARE_ADMIN_TOOL_REMEDIATION",
                    escalation_action="ISOLATE_HOST" if cri >= 80 else "MONITOR",
                ),
                forensics=ForensicsSummary(
                    executed_query=zipf_result["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic Zipfian fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        # --- 10. Deterministic Fast-Path: EWMA Burst Velocity ---
        elif "ewma" in query_str or "burst_velocity" in query_str:
          try:
            ewma_result = await StatsHunterEngine(tenant).run_ewma_burst_velocity(
                session=session,
                entity=req.target_entity,
                lookback_days=req.lookback_days,
            )
            cri = ewma_result["calibrated_risk_index"]
            verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
            markdown_report = (
                f"# EWMA Burst Velocity Analysis: {req.target_entity}\n\n"
                f"**Calibrated Risk Index (CRI)**: {cri}/100 ({verdict})\n"
                f"**EWMA Velocity Score**: {ewma_result['ewma_velocity_score']}σ\n"
                f"**Is Outlier**: {ewma_result['is_outlier']}\n\n"
                f"## Forensic Details\n"
                f"- Evaluated intraday exponential smoothing divergence to capture acute kinetic rate surges.\n"
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True
            return JITHuntResponse(
                status="SUCCESS",
                triage=TriageSummary(
                    calibrated_risk_index=float(cri),
                    verdict=verdict,
                    is_outlier=ewma_result["is_outlier"],
                    primary_vector="ewma_kinetic_burst_velocity",
                    top_z_score=float(ewma_result.get("top_z_score", 0.0)),
                    recommended_action="RATE_LIMIT_ENTITY" if cri >= 80 else "MONITOR",
                    entities_to_quarantine=[req.target_entity] if ewma_result["is_outlier"] else [],
                    mitre_tactics=["TA0010"] if ewma_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-statistical-hunter",
                    outlier_topology="EWMA_BURST_VELOCITY",
                    mitre_tactics_mapped=["TA0010"] if ewma_result["is_outlier"] else [],
                    recommended_swarm_playbook="KINETIC_BURST_CONTAINMENT",
                    escalation_action="RATE_LIMIT_ENTITY" if cri >= 80 else "MONITOR",
                ),
                forensics=ForensicsSummary(
                    executed_query=ewma_result["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic EWMA fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        # --- 11. Deterministic Fast-Path: Cross-Vector / Roll-Up Sector Fusion ---
        elif "sector_fusion" in query_str or "fusion" in query_str:
          try:
            f_metrics = getattr(req.directive, "fusion_metrics", None) or [
                getattr(req.directive, "target_metric", None) or "auth_attempts_total",
                "network_bytes_outbound",
            ]
            ident_f = getattr(req.directive, "identifier_field", None) or "principal.user.userid"
            fus_res = await RiskMetricsEngine(tenant).run_sector_fusion(
                session=session,
                entity=req.target_entity,
                fusion_metrics=f_metrics,
                identifier_field=ident_f,
                lookback_days=req.lookback_days,
            )
            cri = fus_res["calibrated_risk_index"]
            verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
            fus_rows = [
                {
                    "metric": "**Composite Fusion Score ($D$)**",
                    "observed": f"`{fus_res['composite_threat_score']:.2f}σ`",
                    "threshold": "$\\ge 3.00\\sigma$",
                    "assessment": "⚠️ Multi-Sector Kill-Chain Convergence" if fus_res["is_outlier"] else "✅ Uncorrelated Sector Baseline",
                },
                {
                    "metric": "**Fused Telemetry Vectors**",
                    "observed": f"`{f_metrics[0]}` + `{f_metrics[1]}`",
                    "threshold": f"Template: `{fus_res.get('template_name', 'dual_sector_fusion_3stage.yl2')}`",
                    "assessment": f"Z_A = {fus_res.get('sector_a_z', 0.0):+.2f}σ | Z_B = {fus_res.get('sector_b_z', 0.0):+.2f}σ",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name=fus_res.get("model", "DUAL_SECTOR_FUSION_3STAGE"),
                calibrated_risk_index=float(cri),
                is_outlier=fus_res["is_outlier"],
                case_id=req.case_id,
                rows_count=fus_res.get("stats_rows", 0),
                directive=req.directive,
                metrics_table_rows=fus_rows,
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True
            return JITHuntResponse(
                status="SUCCESS",
                triage=TriageSummary(
                    calibrated_risk_index=float(cri),
                    verdict=verdict,
                    is_outlier=fus_res["is_outlier"],
                    primary_vector="multi_sector_fusion_convergence",
                    top_z_score=float(fus_res.get("top_z_score", 0.0)),
                    recommended_action="QUARANTINE" if cri >= 80 else "MONITOR",
                    entities_to_quarantine=[req.target_entity] if fus_res["is_outlier"] else [],
                    mitre_tactics=["TA0001", "TA0010"] if fus_res["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-risk-metrics-multistage",
                    outlier_topology="MULTI_SECTOR_FUSION",
                    mitre_tactics_mapped=["TA0001", "TA0010"] if fus_res["is_outlier"] else [],
                    recommended_swarm_playbook="KILL_CHAIN_CONVERGENCE_CONTAINMENT",
                    escalation_action="QUARANTINE" if cri >= 80 else "MONITOR",
                ),
                forensics=ForensicsSummary(
                    executed_query=fus_res["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic Sector Fusion fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        # --- 12. Deterministic Fast-Path: Dynamic Situational Metric / CUSUM Drift ---
        elif "dynamic_metric" in query_str or "cusum" in query_str:
          try:
            m_name = getattr(req.directive, "target_metric", None) or "workspace_total_download_actions"
            stat_model = "cusum" if "cusum" in query_str else "zscore"
            dyn_res = await RiskMetricsEngine(tenant).run_dynamic_metric_pipeline(
                session=session,
                entity=req.target_entity,
                metric_name=m_name,
                model=stat_model,
                lookback_days=req.lookback_days,
            )
            cri = dyn_res["calibrated_risk_index"]
            verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
            dyn_rows = [
                {
                    "metric": f"**Metric Deviation (`{m_name}`)**",
                    "observed": f"`{dyn_res['top_z_score']:+.2f}σ`",
                    "threshold": "$> 3.00\\sigma$",
                    "assessment": "⚠️ Situational Metric Outlier" if dyn_res["is_outlier"] else "✅ Within 30-Day Baseline",
                },
                {
                    "metric": "**Observed Metric Volume**",
                    "observed": f"`{dyn_res.get('observed_value', 0.0):.1f}`",
                    "threshold": f"Model: `{stat_model.upper()}`",
                    "assessment": "Pre-Computed Malachite Metric Evaluation",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name=dyn_res.get("model", "DYNAMIC_METRIC_BASELINE"),
                calibrated_risk_index=float(cri),
                is_outlier=dyn_res["is_outlier"],
                case_id=req.case_id,
                rows_count=dyn_res.get("stats_rows", 0),
                directive=req.directive,
                metrics_table_rows=dyn_rows,
            )
            case_wall_updated = False
            if req.case_id and req.post_to_case_wall:
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": self.sanitize_case_comment(markdown_report),
                  },
              )
              case_wall_updated = True
            return JITHuntResponse(
                status="SUCCESS",
                triage=TriageSummary(
                    calibrated_risk_index=float(cri),
                    verdict=verdict,
                    is_outlier=dyn_res["is_outlier"],
                    primary_vector=f"dynamic_metric_{m_name}",
                    top_z_score=float(dyn_res.get("top_z_score", 0.0)),
                    recommended_action="INVESTIGATE" if cri >= 60 else "MONITOR",
                    entities_to_quarantine=[req.target_entity] if dyn_res["is_outlier"] else [],
                    mitre_tactics=["TA0009", "TA0010"] if dyn_res["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-risk-metrics-multistage",
                    outlier_topology=f"DYNAMIC_METRIC_{m_name.upper()}",
                    mitre_tactics_mapped=["TA0009", "TA0010"] if dyn_res["is_outlier"] else [],
                    recommended_swarm_playbook="SITUATIONAL_METRIC_INVESTIGATION",
                    escalation_action="INVESTIGATE" if cri >= 60 else "MONITOR",
                ),
                forensics=ForensicsSummary(
                    executed_query=dyn_res["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic Dynamic Metric fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
            )

        mcp_tools = await session.list_tools()

        # Build Gemini functions filtered by allowed_tools
        gemini_functions = []
        for tool in mcp_tools.tools:
          if tenant.allowed_tools and tool.name not in tenant.allowed_tools:
            continue
          raw_schema = getattr(tool, "inputSchema", getattr(tool, "input_schema", {}))
          if hasattr(raw_schema, "model_dump"):
            raw_schema = raw_schema.model_dump()
          elif hasattr(raw_schema, "dict"):
            raw_schema = raw_schema.dict()
          clean_schema = self.sanitize_schema(raw_schema)
          
          gemini_functions.append(
              types.FunctionDeclaration(
                  name=tool.name,
                  description=tool.description or "",
                  parameters=clean_schema,
              )
          )

        # Register local behavioral radar tool
        gemini_functions.append(
            types.FunctionDeclaration(
                name="generate_behavioral_radar",
                description="Generates a 360-degree behavioral risk pentagon radar SVG chart for a user based on 5 Z-scores.",
                parameters={
                    "type": "object",
                    "properties": {
                        "username": {"type": "string"},
                        "telemetry_data": {
                            "type": "object",
                            "properties": {
                                "Auth": {"type": "number"},
                                "Cloud": {"type": "number"},
                                "Workspace": {"type": "number"},
                                "Egress": {"type": "number"},
                                "DNS": {"type": "number"},
                            },
                            "required": ["Auth", "Cloud", "Workspace", "Egress", "DNS"],
                        },
                    },
                    "required": ["username", "telemetry_data"],
                },
            )
        )

        candidate_models = [tenant.model]
        for fallback in getattr(tenant, "fallback_models", ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-pro"]):
          if fallback not in candidate_models:
            candidate_models.append(fallback)

        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=req.lookback_days)
        start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        prompt_lines = [
            f"EXECUTE AUTONOMOUS JIT THREAT INVESTIGATION:",
            f"- Target Entity: {req.target_entity} (Type: {req.entity_type})",
            f"- Investigation Horizon: {start_iso} to {end_iso}",
        ]
        if req.query:
          prompt_lines.append(f"- Playbook Investigative Directive: \"{req.query}\"")
        if req.case_id:
          prompt_lines.append(f"- Chronicle SOAR Case ID: {req.case_id}")
        if req.alert_id:
          prompt_lines.append(f"- Chronicle SOAR Alert ID: {req.alert_id}")
        if req.alert_name:
          prompt_lines.append(f"- Triggering Alert Name: {req.alert_name}")
        if req.alert_description:
          prompt_lines.append(f"- Triggering Alert Details: {req.alert_description}")

        prompt_lines.extend([
            "",
            "AUTONOMOUS INVESTIGATION MANDATE:",
            "1. Formulate the primary threat hypothesis based on the alert telemetry and directive.",
            "2. Execute ONE 1-shot compiler probe (`udm_search(..., maxEvents=1)`).",
            "3. Immediately execute the candidate multi-stage YARA-L query via `udm_search`.",
            "4. If 5 risk sectors are calculated, call `generate_behavioral_radar`.",
        ])
        if req.case_id and req.post_to_case_wall:
          prompt_lines.append(
              f"5. Post ONLY your human-readable 6-pillar forensic report (DO NOT include the ```json_triage``` code block in the comment) to the case wall by calling `create_case_comment(caseId='{req.case_id}', comment=...)`."
          )
        prompt_lines.extend([
            "6. Conclude your final response with a ```json_triage ... ``` block containing structured CRI and verdict, followed by the complete 6-pillar forensic report.",
        ])

        initial_prompt = "\n".join(prompt_lines)
        react_success = False
        final_response = None

        for model_candidate in candidate_models:
          try:
            logger.info(f"Initiating autonomous ReAct investigation with candidate model: {model_candidate}")
            chat = ai_client.aio.chats.create(
                model=model_candidate,
                config=types.GenerateContentConfig(
                    temperature=0.0,
                    tools=[types.Tool(function_declarations=gemini_functions)],
                    system_instruction=persona,
                ),
            )
            response = await chat.send_message(initial_prompt)

            max_steps = 10
            executed_query = ""
            case_wall_updated = False
            radar_svg = None

            while response.function_calls and max_steps > 0:
              max_steps -= 1
              tool_call = response.function_calls[0]
              tool_name = tool_call.name
              tool_args = dict(tool_call.args)

              logger.info(f"JIT Tool Call [{max_steps} remaining]: {tool_name}")

              # Automatically inject tenant parameters for OneMCP tools if omitted
              if tool_name in ("udm_search", "create_case_comment", "list_cases", "list_case_alerts", "get_case", "get_case_alert"):
                tool_args.setdefault("projectId", tenant.project_id)
                tool_args.setdefault("customerId", tenant.customer_id)
                tool_args.setdefault("region", tenant.region)

              if tool_name == "udm_search":
                q_text = tool_args.get("query", "")
                if "stage" in q_text:
                  executed_query = q_text
                res = await session.call_tool("udm_search", tool_args)
                output_str = res.content[0].text if res.content else "{}"

              elif tool_name == "generate_behavioral_radar":
                radar_svg = self.generate_behavioral_radar(
                    tool_args.get("username", req.target_entity),
                    tool_args.get("telemetry_data", {}),
                )
                output_str = json.dumps({"status": "SUCCESS", "svg_length": len(radar_svg)})

              elif tool_name == "create_case_comment":
                raw_c = tool_args.get("comment", "")
                tool_args["comment"] = self.sanitize_case_comment(raw_c)
                res = await session.call_tool("create_case_comment", tool_args)
                case_wall_updated = True
                output_str = res.content[0].text if res.content else '{"status": "SUCCESS"}'

              else:
                res = await session.call_tool(tool_name, tool_args)
                output_str = res.content[0].text if res.content else "{}"

              response = await chat.send_message(
                  types.Part.from_function_response(
                      name=tool_name,
                      response={"result": output_str},
                  )
              )

            final_text = response.text or ""
            if req.case_id and req.post_to_case_wall and not case_wall_updated:
              logger.info(
                  f"ReAct agent did not explicitly call create_case_comment; automatically posting report to Case {req.case_id} wall."
              )
              clean_comment = self.sanitize_case_comment(final_text)
              await session.call_tool(
                  "create_case_comment",
                  {
                      "projectId": tenant.project_id,
                      "customerId": tenant.customer_id,
                      "region": tenant.region,
                      "caseId": str(req.case_id),
                      "comment": clean_comment,
                  },
              )
              case_wall_updated = True

            final_response = self._build_hunt_response(
                final_text=final_text,
                executed_query=executed_query,
                radar_svg=radar_svg,
                case_wall_updated=case_wall_updated,
                req=req,
                skill_name=skill_name,
            )
            react_success = True
            logger.info(f"Autonomous ReAct hunt completed successfully with model: {model_candidate}")
            break

          except Exception as model_err:
            err_str = str(model_err).lower()
            logger.warning(
                f"Candidate model '{model_candidate}' failed during autonomous investigation: {model_err}"
            )
            if "429" in err_str or "resource_exhausted" in err_str or "quota" in err_str or "overloaded" in err_str or "503" in err_str:
              continue
            else:
              continue

        if react_success and final_response is not None:
          return final_response

        # --- Emergency Deterministic Fallback if all LLMs are throttled ---
        logger.error(
            "All candidate LLM models failed or were throttled. Falling back to deterministic baseline engine."
        )
        if req.entity_type in ("USER", "USER_ID", "EMAIL"):
          radar_result = await RiskMetricsEngine(tenant).run_360_behavioral_radar(
              session=session,
              username=req.target_entity,
              lookback_days=req.lookback_days,
          )
          radar_svg = self.generate_behavioral_radar(
              req.target_entity,
              radar_result["sector_z_scores"],
          )
          cri = radar_result["calibrated_risk_index"]
          verdict = radar_result["verdict"]
          top_sector = radar_result["top_sector"]

          report_lines = [
              f"# 360° Decoupled Behavioral Risk Radar (Deterministic Fallback): {req.target_entity}",
              "> [!WARNING] Gemini LLM quota was temporarily exhausted; automatically triaged via 30-day precomputed metrics.",
              f"**Calibrated Risk Index (CRI)**: {cri}/100 ({verdict})",
              f"**Top Risk Sector**: {top_sector} (Composite Distance D: {radar_result['composite_d']})",
              "",
              "## Forensic Sector Analysis",
          ]
          for s_name, z_val in radar_result["sector_z_scores"].items():
            obs = radar_result["sector_observed_counts"].get(s_name, 0)
            report_lines.append(f"- **{s_name}**: Z-score = {z_val:+.2f} (Observed: {obs})")

          markdown_report = "\n".join(report_lines)
          case_wall_updated = False
          if req.case_id and req.post_to_case_wall:
            await session.call_tool(
                "create_case_comment",
                {
                    "projectId": tenant.project_id,
                    "customerId": tenant.customer_id,
                    "region": tenant.region,
                    "caseId": str(req.case_id),
                    "comment": self.sanitize_case_comment(markdown_report),
                },
            )
            case_wall_updated = True

          return JITHuntResponse(
              status="SUCCESS",
              triage=TriageSummary(
                  calibrated_risk_index=float(cri),
                  verdict=verdict,
                  is_outlier=radar_result["is_outlier"],
                  primary_vector=f"{top_sector}_behavioral_drift",
                  top_z_score=float(radar_result["sector_z_scores"].get(top_sector, 0.0)),
                  radar_dimensions=radar_result["sector_z_scores"],
                  recommended_action="QUARANTINE" if cri >= 80 else ("INVESTIGATE" if cri >= 60 else "MONITOR"),
                  entities_to_quarantine=[req.target_entity] if radar_result["is_outlier"] else [],
                  mitre_tactics=["TA0001", "TA0006"] if radar_result["is_outlier"] else [],
              ),
              clean_hand_off=CleanHandOffPayload(
                  target_entity=req.target_entity,
                  entity_type=req.entity_type,
                  evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                  primary_model="secops-risk-metrics-multistage",
                  outlier_topology=f"{top_sector.upper()}_DRIFT",
                  mitre_tactics_mapped=["TA0001", "TA0006"] if radar_result["is_outlier"] else [],
                  recommended_swarm_playbook="DECOUPLED_RADAR_INVESTIGATION",
                  escalation_action="QUARANTINE" if cri >= 80 else ("INVESTIGATE" if cri >= 60 else "MONITOR"),
              ),
              forensics=ForensicsSummary(
                  executed_query="360° Decoupled Sector Micro-Queries (Auth, Cloud, Workspace, Egress, DNS)",
                  markdown_report=markdown_report,
                  radar_svg=radar_svg,
              ),
              case_wall_updated=case_wall_updated,
          )
        else:
          jitter_result = await StatsHunterEngine(tenant).run_c2_beaconing_jitter(
              session=session,
              src_ip=req.target_entity,
              lookback_days=req.lookback_days,
          )
          cri = jitter_result["calibrated_risk_index"]
          verdict = "CRITICAL_OUTLIER" if cri >= 80 else ("HIGH_OUTLIER" if cri >= 60 else "NOMINAL_BASELINE")
          markdown_report = (
              f"# C2 Beaconing Jitter Analysis (Deterministic Fallback): {req.target_entity}\n\n"
              f"> [!WARNING] Gemini LLM quota was temporarily exhausted; automatically triaged via statistical hunting.\n"
              f"**CRI**: {cri}/100\n**Is Outlier**: {jitter_result['is_outlier']}"
          )
          case_wall_updated = False
          if req.case_id and req.post_to_case_wall:
            await session.call_tool(
                "create_case_comment",
                {
                    "projectId": tenant.project_id,
                    "customerId": tenant.customer_id,
                    "region": tenant.region,
                    "caseId": str(req.case_id),
                    "comment": self.sanitize_case_comment(markdown_report),
                },
            )
            case_wall_updated = True
          return JITHuntResponse(
              status="SUCCESS",
              triage=TriageSummary(
                  calibrated_risk_index=float(cri),
                  verdict=verdict,
                  is_outlier=jitter_result["is_outlier"],
                  primary_vector="c2_timing_regularity",
                  top_z_score=float(jitter_result.get("top_z_score", 0.0)),
                  recommended_action="ISOLATE_HOST" if cri >= 80 else "MONITOR",
                  entities_to_quarantine=[req.target_entity] if jitter_result["is_outlier"] else [],
                  mitre_tactics=["TA0011"] if jitter_result["is_outlier"] else [],
              ),
              clean_hand_off=CleanHandOffPayload(
                  target_entity=req.target_entity,
                  entity_type=req.entity_type,
                  evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                  primary_model="secops-statistical-hunter",
                  outlier_topology="C2_REGULARITY",
                  mitre_tactics_mapped=["TA0011"] if jitter_result["is_outlier"] else [],
                  recommended_swarm_playbook="C2_CONTAINMENT",
                  escalation_action="ISOLATE_HOST" if cri >= 80 else "MONITOR",
              ),
              forensics=ForensicsSummary(
                  executed_query=jitter_result["executed_query"],
                  markdown_report=markdown_report,
              ),
              case_wall_updated=case_wall_updated,
          )

  def _build_hunt_response(
      self,
      final_text: str,
      executed_query: str,
      radar_svg: Optional[str],
      case_wall_updated: bool,
      req: JITHuntRequest,
      skill_name: str,
  ) -> JITHuntResponse:
    """Extracts structured triage JSON and packages final response."""
    # Attempt to extract json_triage code block
    triage_data = {}
    json_match = re.search(r"```(?:json_triage|json)\s*(\{.*?\})\s*```", final_text, re.DOTALL)
    if json_match:
      try:
        triage_data = json.loads(json_match.group(1))
      except Exception:
        pass

    cri = float(triage_data.get("calibrated_risk_index", 0.0))
    if not cri and "cri" in triage_data:
      cri = float(triage_data["cri"])

    verdict = triage_data.get("verdict", "NOMINAL_BASELINE")
    if cri >= 80:
      verdict = "CRITICAL_OUTLIER"
    elif cri >= 60:
      verdict = "HIGH_OUTLIER"
    elif cri >= 46:
      verdict = "MEDIUM_OUTLIER"

    is_outlier = cri >= 46
    top_z = float(triage_data.get("top_z_score", 0.0))
    primary_vector = triage_data.get("primary_vector", "multi_sector")
    radar_dims = triage_data.get("radar_dimensions", {})
    recommended_action = triage_data.get("recommended_action", "MONITOR")
    entities_to_quarantine = triage_data.get("entities_to_quarantine", [])
    if not entities_to_quarantine and is_outlier:
      entities_to_quarantine = [req.target_entity]
    mitre_tactics = triage_data.get("mitre_tactics", [])

    triage_summary = TriageSummary(
        calibrated_risk_index=cri,
        verdict=verdict,
        is_outlier=is_outlier,
        primary_vector=primary_vector,
        top_z_score=top_z,
        radar_dimensions=radar_dims,
        recommended_action=recommended_action,
        entities_to_quarantine=entities_to_quarantine,
        mitre_tactics=mitre_tactics,
    )

    clean_hand_off = CleanHandOffPayload(
        target_entity=req.target_entity,
        entity_type=req.entity_type,
        evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        primary_model=skill_name,
        outlier_topology=primary_vector.upper(),
        mitre_tactics_mapped=mitre_tactics,
        recommended_swarm_playbook=triage_data.get("swarm_playbook", "DEFAULT_INVESTIGATION"),
        escalation_action=recommended_action,
    )

    forensics = ForensicsSummary(
        executed_query=executed_query,
        markdown_report=final_text,
        radar_svg=radar_svg,
    )

    return JITHuntResponse(
        status="SUCCESS",
        triage=triage_summary,
        clean_hand_off=clean_hand_off,
        forensics=forensics,
        case_wall_updated=case_wall_updated,
    )

  async def scan_and_triage_cases(
      self,
      limit: int = 5,
      tenant_override: Optional[TenantConfig] = None,
  ) -> List[Dict[str, Any]]:
    """Watchdog Mode: Queries open SecOps cases, inspects alerts, and runs targeted hunts."""
    tenant = tenant_override or self.default_tenant
    headers = tenant.get_auth_headers()
    custom_timeout = httpx.Timeout(30.0, read=120.0, write=120.0, pool=120.0)
    results = []

    async with httpx.AsyncClient(headers=headers, timeout=custom_timeout, follow_redirects=True) as http_client:
      def _create_mcp_context():
        try:
          return streamable_http_client(tenant.mcp_url, headers=headers, timeout=60.0, sse_read_timeout=300.0)
        except TypeError:
          return streamable_http_client(tenant.mcp_url, headers=headers)

      mcp_context = _create_mcp_context()

      async with mcp_context as streams, ClientSession(streams[0], streams[1]) as session:
        await session.initialize()
        
        # 1. Query open cases
        list_cases_res = await session.call_tool(
            "list_cases",
            {
                "projectId": tenant.project_id,
                "customerId": tenant.customer_id,
                "region": tenant.region,
                "filter": "Status='OPENED'",
                "pageSize": limit,
            },
        )
        raw_cases = json.loads(list_cases_res.content[0].text) if list_cases_res.content else {}
        cases = raw_cases.get("cases", [])[:limit]
        logger.info(f"Watchdog discovered {len(cases)} open cases for triage.")

        def _get_cid(c: Dict[str, Any]) -> str:
          return str(c.get("id") or (c.get("name", "").split("/")[-1] if "/" in str(c.get("name", "")) else ""))

        # 2. Iterate each case and extract entities
        for case in cases:
          case_id = _get_cid(case)
          if not case_id:
            continue

          case_title = case.get("displayName") or case.get("title", "Untitled Case")
          case_desc = case.get("description", "")

          try:
            # Query alerts in this case
            alerts_res = await session.call_tool(
                "list_case_alerts",
                {
                    "projectId": tenant.project_id,
                    "customerId": tenant.customer_id,
                    "region": tenant.region,
                    "caseId": case_id,
                },
            )
            raw_alerts = json.loads(alerts_res.content[0].text) if alerts_res.content else {}
            alerts = raw_alerts.get("caseAlerts", raw_alerts.get("alerts", []))

            target_entity = None
            entity_type = "USER"
            alert_name = case_title

            if alerts:
              for alert in alerts:
                alert_name = alert.get("displayName") or alert.get("name", case_title)
                alert_desc = alert.get("description", case_desc)
                alert_name_str = str(alert.get("name", ""))
                alert_numeric_id = alert_name_str.split("/")[-1] if "/" in alert_name_str else str(alert.get("id", ""))

                entities = alert.get("entities", [])
                if not entities and alert_numeric_id:
                  try:
                    ent_res = await session.call_tool(
                        "list_involved_entities",
                        {
                            "projectId": tenant.project_id,
                            "customerId": tenant.customer_id,
                            "region": tenant.region,
                            "caseId": case_id,
                            "caseAlertId": alert_numeric_id,
                        },
                    )
                    if ent_res.content:
                      ent_json = json.loads(ent_res.content[0].text)
                      entities = ent_json.get("involvedEntities", [])
                  except Exception as ent_err:
                    logger.debug(f"Could not fetch involved entities for alert {alert_numeric_id}: {ent_err}")

                for ent in entities:
                  e_type = str(ent.get("type") or ent.get("entityType", "")).upper()
                  ident = ent.get("identifier") or ent.get("OriginalIdentifier")
                  if not ident:
                    continue
                  if e_type in ("USER", "USER_ID", "EMAIL"):
                    target_entity = ident.lower()
                    entity_type = "USER"
                    break
                  elif e_type in ("HOSTNAME", "ASSET"):
                    target_entity = ident.lower()
                    entity_type = "ASSET"
                    break
                  elif e_type in ("IP", "IP_ADDRESS"):
                    target_entity = ident
                    entity_type = "IP"
                    break
                if target_entity:
                  break

            # Fallback to case-level entities if alert entities empty
            if not target_entity:
              for ent in case.get("entities", []):
                target_entity = ent.get("identifier")
                break

            if not target_entity:
              logger.warning(f"Case {case_id} had no extractable entities; skipping.")
              continue

            logger.info(f"Watchdog dispatching JIT hunt for Case {case_id} -> {target_entity}")
            req = JITHuntRequest(
                target_entity=target_entity,
                entity_type=entity_type,
                case_id=case_id,
                alert_name=alert_name,
                alert_description=case_desc,
                skill="auto",
                post_to_case_wall=True,
            )

            hunt_resp = await self.execute_jit_hunt(req)
            results.append({
                "case_id": case_id,
                "entity": target_entity,
                "cri": hunt_resp.triage.calibrated_risk_index,
                "verdict": hunt_resp.triage.verdict,
                "vector": hunt_resp.triage.primary_vector,
                "case_wall_updated": hunt_resp.case_wall_updated,
            })
          except Exception as e:
            logger.error(f"Failed scanning Case {case_id}: {e}")

    return results

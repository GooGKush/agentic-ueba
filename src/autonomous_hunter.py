# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Autonomous JIT Threat Hunting Engine for Agentic UEBA.

Connects to Google SecOps OneMCP as an MCP Client, executes multi-stage statistical
and behavioral risk analytics via Gemini 2.5 Pro, and returns structured Clean Hand-Off
payloads along with full 6-pillar forensic reports to SecOps Playbooks and cases.

Verdicts, recommended actions, CRI bands, write-back gates, retired models and
Mode A / Entity Graph windows come from the remediated UEBA harness via
`src.harness_truth`. Recommended actions are recommendations only: this engine
never executes containment.
"""

import src._bootstrap

from datetime import datetime, timedelta, timezone
import json
import logging
import math
import os
import re
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

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

from src import harness_truth
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

# secops-statistical-hunter model the hunter runs for hour-of-day / circadian intents.
HOUR_OF_DAY_PROFILE = "HOUR_OF_DAY_PROFILE"
HOUR_OF_DAY_QUERY = "hour_of_day_profile"

# Active models this hunter can execute in place of a retired one, mapped to the dispatch query
# of the path that runs them. A retired model is routed to one of these only when the skill's
# own retirement message (harness_truth.retirement_message) names it as the replacement.
_REPLACEMENT_QUERIES: Dict[str, str] = {
    HOUR_OF_DAY_PROFILE: HOUR_OF_DAY_QUERY,
    "STANDARD_Z_SCORE": "dynamic_metric",
    "DUAL_SECTOR_FUSION_3STAGE": "sector_fusion",
}

# Entity-level containment recommendation for paths without a narrower domain action.
GENERIC_CONTAINMENT_ACTION = "QUARANTINE"

# The harness's response kinds (CONTAIN / INVESTIGATE / MONITOR); a domain action that is one of
# these is not a containment action.
_HARNESS_RESPONSE_KINDS = frozenset(kind for kind, _ in harness_truth.BAND_RESPONSES.values())


class TriageDecision(NamedTuple):
  """Harness verdict and recommended action for one CRI value."""

  cri: Optional[int]  # harness-coerced CRI (0..100); None when missing or invalid
  verdict: str  # harness_truth.verdict_for
  action: str  # harness_truth.recommended_action (domain containment only at Critical)
  contain: bool  # True only when the harness recommends a containment action

  @property
  def cri_value(self) -> float:
    """CRI for the numeric TriageSummary / card schema; 0.0 when not evaluated (verdict NOT_EVALUATED)."""
    return float(self.cri) if self.cri is not None else 0.0


def decide(cri: Any, containment_action: str) -> TriageDecision:
  """Verdict and recommended action for `cri`, from the harness bands (missing CRI never escalates)."""
  value = harness_truth.coerce_cri(cri)
  action = harness_truth.recommended_action(value, containment_action=containment_action)
  band_kind = harness_truth.BAND_RESPONSES[harness_truth.cri_band(value)[0]][0]
  contain = band_kind == "CONTAIN" and action not in _HARNESS_RESPONSE_KINDS
  return TriageDecision(value, harness_truth.verdict_for(value), action, contain)


def _alertable(cri: Any) -> bool:
  """True when the harness recommends more than monitoring (Medium band and above)."""
  return harness_truth.recommended_action(cri) != "MONITOR"


def _max_cri(*values: Any) -> Optional[int]:
  """Highest evaluated CRI among `values`; None when none of them was evaluated."""
  evaluated = [c for c in (harness_truth.coerce_cri(v) for v in values) if c is not None]
  return max(evaluated) if evaluated else None


def _soc_guidance(decision: TriageDecision, finding: str = "") -> str:
  """Case Wall guidance: the finding, the harness band verdict and action, and the recommendation-only note."""
  _, label, emoji = harness_truth.cri_band(decision.cri)
  lead = f"{finding.strip()} " if finding and finding.strip() else ""
  return (
      f"{lead}{emoji} {label} (CRI {harness_truth.format_cri(decision.cri)}, verdict `{decision.verdict}`): "
      f"recommended action `{decision.action}`. {harness_truth.action_guidance(decision.cri)}"
  )


def _report_footer(decision: TriageDecision) -> str:
  """Markdown footer stating the harness verdict and the recommendation-only action."""
  return (
      f"**Harness Verdict**: `{decision.verdict}` (CRI {harness_truth.format_cri(decision.cri)}) | "
      f"**Recommended Action**: `{decision.action}`\n\n> {harness_truth.action_guidance(decision.cri)}"
  )


def _name_tokens(name: Any) -> List[str]:
  """`name` plus its whitespace/comma separated tokens (model names, archetypes, queries)."""
  raw = str(getattr(name, "value", name) or "").strip()
  if not raw:
    return []
  return [raw] + [t for t in re.split(r"[\s,;]+", raw) if t and t != raw]


def retirement_route(*names: Any) -> Tuple[Optional[str], Optional[str]]:
  """(skill retirement message, runnable replacement) for the first retired name among `names`.

  The replacement is the first model of `_REPLACEMENT_QUERIES` that the skill's own retirement
  message names and that is itself active, or None when this hunter has no path for it.
  """
  for name in names:
    for token in _name_tokens(name):
      message = harness_truth.retirement_message(token)
      if message:
        named = sorted(
            (message.find(model), model)
            for model in _REPLACEMENT_QUERIES
            if model in message and not harness_truth.is_retired(model)
        )
        return message, (named[0][1] if named else None)
  return None, None


def _is_hour_of_day_query(query: str) -> bool:
  return any(k in query for k in (HOUR_OF_DAY_QUERY, "hour_of_day", "circadian", "von_mises"))


def _macro_evaluated_day(result: Dict[str, Any]) -> str:
  """Scored UTC day of a macro (metrics.*) result: the engine's evaluated day, else the Mode A day."""
  return str(result.get("evaluated_day") or harness_truth.mode_a_day().isoformat())


def _secondary_sweep_z_gate() -> float:
  """Top-sector |Z| that warrants a Tier 2 sweep: the harness HIGH_RECALL anomaly threshold."""
  _, thresholds = harness_truth.constants().resolve_sensitivity_thresholds("HIGH_RECALL")
  return float(thresholds["anomaly_threshold"])


def _sector_assessment(sector: str, z_val: Any, variance_masked: set, dormant: set) -> str:
  """Per-sector radar assessment from the sector's harness CRI band."""
  sector_cri = harness_truth.calculate_cri(z_val)
  _, label, emoji = harness_truth.cri_band(sector_cri)
  banded = f"{emoji} {label} (CRI {harness_truth.format_cri(sector_cri)})"
  if _alertable(sector_cri):
    return banded
  if sector in variance_masked:
    return "🔎 Sub-Threshold Drift (Variance-Masked)"
  if sector in dormant:
    return "🔎 Dormant Baseline Awakening"
  return banded


def _finite_float(value: Any, default: float = 0.0) -> float:
  try:
    parsed = float(value)
  except (TypeError, ValueError):
    return default
  return parsed if math.isfinite(parsed) else default


# Engine results carry None (or NaN) for a CRI or a model metric that was not evaluated (e.g. a micro helper
# without enough evidence, or a template model with zero rows). Those values render as the harness N/A, never
# through float() or a format spec.


def _na() -> str:
  """The harness rendering of a value that was not evaluated ("N/A")."""
  return harness_truth.format_cri(None)


def _num_or_none(value: Any) -> Optional[float]:
  """A finite float, or None when the value is missing, not evaluated or not numeric."""
  if value is None or isinstance(value, bool):
    return None
  parsed = _finite_float(value, default=math.nan)
  return None if math.isnan(parsed) else parsed


def _fmt(value: Any, spec: str, unit: str = "") -> str:
  """`value` formatted with `spec` plus `unit`, or N/A when it was not evaluated."""
  num = _num_or_none(value)
  return _na() if num is None else f"{format(num, spec)}{unit}"


def _show(value: Any, unit: str = "") -> str:
  """`value` as reported plus `unit`, or N/A when it is missing or not a finite number."""
  if value is None or (isinstance(value, str) and not value.strip()):
    return _na()
  if isinstance(value, float) and not math.isfinite(value):
    return _na()
  return f"{value}{unit}"


_TEX_SIGMA = "\\sigma"  # KaTeX sigma unit for _math_value


def _math_value(symbol: str, value: Any, spec: str, unit: str = "") -> str:
  """`$symbol = value unit$` (KaTeX), or plain `symbol = N/A` when the value was not evaluated."""
  num = _num_or_none(value)
  return f"{symbol} = {_na()}" if num is None else f"${symbol} = {format(num, spec)}{unit}$"


def _rows(result: Dict[str, Any]) -> int:
  """Evaluated row count of an engine result (0 when missing)."""
  return int(_finite_float(result.get("stats_rows")))


def _finite_dims(scores: Dict[str, Any]) -> Dict[str, float]:
  """Radar dimensions that were evaluated (sectors without a finite score are left out)."""
  return {name: num for name, num in ((k, _num_or_none(v)) for k, v in (scores or {}).items()) if num is not None}


def _hod_score(result: Dict[str, Any]) -> Optional[float]:
  """HOUR_OF_DAY_PROFILE's native score (primary_score), else its Z-equivalent; None when not evaluated."""
  score = _num_or_none(result.get("primary_score"))
  return score if score is not None else _num_or_none(result.get("top_z_score"))


def _not_evaluated_finding(result: Dict[str, Any], what: str) -> Optional[str]:
  """Finding for a hunt the engine reported as not evaluated (insufficient evidence), else None."""
  reason = result.get("not_evaluated_reason")
  return f"{what} was not evaluated ({reason})." if reason else None


def _apply_escalation(triage: TriageSummary, decision: TriageDecision, entity: str, primary_vector: str) -> None:
  """Raises a Tier 1 triage to a confirmed Tier 2 outlier at the harness verdict and action for its CRI."""
  triage.is_outlier = True
  triage.calibrated_risk_index = decision.cri_value
  triage.verdict = decision.verdict
  triage.recommended_action = decision.action
  triage.entities_to_quarantine = [entity] if decision.contain else []
  triage.primary_vector = primary_vector


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
    # Strip any accidental BigQuery backend attribution before rendering
    comment = DynamicProtocolAdapter.sanitize_bq_backend_references(comment)
    # Unescape literal backslash escapes if present
    comment = comment.replace("\\n", "\n").replace('\\"', '"').replace("\\'", "'")
    # Strip machine-readable json_triage code block from user-facing case wall comment
    comment = re.sub(r"```(?:json_triage|json)\s*\{.*?\}\s*```\s*", "", comment, flags=re.DOTALL)
    return CaseWallCardFormatter.to_soar_html(comment.strip())

  def generate_behavioral_radar(
      self,
      username: str,
      telemetry_data: Dict[str, float],
      entity_type: str = "USER",
  ) -> str:
    """Computes 6-spoke hexagonal 360-degree behavioral risk metrics and returns raw SVG string."""
    try:
      cx, cy = 250, 250
      scale = 50.0
      is_host = (
          str(entity_type).upper() in ("ASSET", "HOST", "IP")
          or (("Flows" in telemetry_data or "Alerts" in telemetry_data) and "Workspace" not in telemetry_data)
      )

      def get_point(z, angle_deg):
        r = min(max(z, 0.0), 4.5) * scale
        angle_rad = math.radians(angle_deg - 90)
        x = cx + r * math.cos(angle_rad)
        y = cy + r * math.sin(angle_rad)
        return x, y

      angles = [0, 60, 120, 180, 240, 300]
      # A sector score that was not evaluated (None / NaN) is drawn at the centre and labelled N/A.
      if is_host:
        spokes = [
            ("🔑 Host Auth", telemetry_data.get("Auth", 0.0)),
            ("🌐 Network Egress", telemetry_data.get("Egress", 0.0)),
            ("📡 DNS Queries", telemetry_data.get("DNS", 0.0)),
            ("🔀 Outbound Flows", telemetry_data.get("Flows", 0.0)),
            ("🚨 Security Alerts", telemetry_data.get("Alerts", 0.0)),
            ("🕸️ Web & Proxy", telemetry_data.get("Web", 0.0)),
        ]
        entity_badge = "ASSET"
      else:
        spokes = [
            ("🔑 Authentication", telemetry_data.get("Auth", 0.0)),
            ("☁️ Cloud CRUD", telemetry_data.get("Cloud", 0.0)),
            ("📁 Workspace Exfil", telemetry_data.get("Workspace", 0.0)),
            ("🌐 Network Egress", telemetry_data.get("Egress", 0.0)),
            ("📡 DNS Queries", telemetry_data.get("DNS", 0.0)),
            ("🕸️ Web & Proxy", telemetry_data.get("Web", 0.0)),
        ]
        entity_badge = "USER"
      labels = [_fmt(z_val, "+.2f", "σ") for _, z_val in spokes]
      spokes = [(name, _finite_float(z_val)) for name, z_val in spokes]

      spoke_points = [get_point(z_val, ang) for (_, z_val), ang in zip(spokes, angles)]
      polygon_points = " ".join(f"{x},{y}" for x, y in spoke_points)

      def get_ring(z):
        pts = [get_point(z, a) for a in angles]
        return " ".join([f"{x},{y}" for x, y in pts])

      composite_d = math.sqrt(sum(max(0.0, z_val) ** 2 for _, z_val in spokes))

      svg_output = f"""<svg viewBox="0 0 500 500" width="100%" height="450" xmlns="http://www.w3.org/2000/svg" style="background: #0e1117; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; border-radius: 8px;">
  <defs>
    <radialGradient id="radarGlow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#00e5ff" stop-opacity="0.5"/>
      <stop offset="100%" stop-color="#00b0ff" stop-opacity="0.1"/>
    </radialGradient>
  </defs>
  <text x="250" y="30" text-anchor="middle" fill="#f0f6fc" font-size="15" font-weight="600" letter-spacing="1">360° BEHAVIORAL RISK RADAR — {entity_badge}: {username.upper()}</text>
  <text x="250" y="48" text-anchor="middle" fill="#8b949e" font-size="11">Composite Threat Distance: D = {composite_d:.2f}σ | Baseline: 30-Day Pre-Computed (6-Spoke Hex)</text>
  <polygon points="{get_ring(1.0)}" fill="none" stroke="#21262d" stroke-width="1" stroke-dasharray="3 3"/>
  <polygon points="{get_ring(2.0)}" fill="none" stroke="#30363d" stroke-width="1" stroke-dasharray="4 4"/>
  <polygon points="{get_ring(3.0)}" fill="rgba(255, 75, 75, 0.03)" stroke="#ff4b4b" stroke-width="1.5" stroke-dasharray="6 4"/>
  <text x="253" y="98" fill="#ff7b72" font-size="10" font-weight="bold">3.0σ (Anomaly Threshold)</text>
  <line x1="250" y1="250" x2="{get_point(3.0, 0)[0]}" y2="{get_point(3.0, 0)[1]}" stroke="#30363d" stroke-width="1.2"/>
  <line x1="250" y1="250" x2="{get_point(3.0, 60)[0]}" y2="{get_point(3.0, 60)[1]}" stroke="#30363d" stroke-width="1.2"/>
  <line x1="250" y1="250" x2="{get_point(3.0, 120)[0]}" y2="{get_point(3.0, 120)[1]}" stroke="#30363d" stroke-width="1.2"/>
  <line x1="250" y1="250" x2="{get_point(3.0, 180)[0]}" y2="{get_point(3.0, 180)[1]}" stroke="#30363d" stroke-width="1.2"/>
  <line x1="250" y1="250" x2="{get_point(3.0, 240)[0]}" y2="{get_point(3.0, 240)[1]}" stroke="#30363d" stroke-width="1.2"/>
  <line x1="250" y1="250" x2="{get_point(3.0, 300)[0]}" y2="{get_point(3.0, 300)[1]}" stroke="#30363d" stroke-width="1.2"/>
  <text x="250" y="70" text-anchor="middle" fill="#c9d1d9" font-size="11" font-weight="600">{spokes[0][0]} (Z = {labels[0]})</text>
  <text x="395" y="165" text-anchor="start" fill="#c9d1d9" font-size="11" font-weight="600">{spokes[1][0]} (Z = {labels[1]})</text>
  <text x="395" y="340" text-anchor="start" fill="#c9d1d9" font-size="11" font-weight="600">{spokes[2][0]} (Z = {labels[2]})</text>
  <text x="250" y="425" text-anchor="middle" fill="#c9d1d9" font-size="11" font-weight="600">{spokes[3][0]} (Z = {labels[3]})</text>
  <text x="105" y="340" text-anchor="end" fill="#c9d1d9" font-size="11" font-weight="600">{spokes[4][0]} (Z = {labels[4]})</text>
  <text x="105" y="165" text-anchor="end" fill="#c9d1d9" font-size="11" font-weight="600">{spokes[5][0]} (Z = {labels[5]})</text>
  <polygon points="{polygon_points}" fill="url(#radarGlow)" stroke="#00e5ff" stroke-width="2"/>
</svg>""".strip()
      return svg_output
    except Exception as e:
      logger.error(f"Failed generating behavioral radar: {e}")
      return f"ERROR: Could not compute radar metrics: {str(e)}"

  def get_hybrid_function_declarations(self) -> List[types.FunctionDeclaration]:
    """Returns Gemini FunctionDeclarations for the 3 composable Python Hybrid Engine tools."""
    return [
        types.FunctionDeclaration(
            name="compile_hunt_pipeline",
            description=(
                "Compiles a deterministic, AST-validated multi-stage YARA-L 2.0 hunt pipeline, "
                "Pre-Flight Hunting Specification card, and 1-shot schema validation probe query "
                "from parameterized UEBA metrics, statistical models, and architectures."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "statistical_model": {
                        "type": "string",
                        "description": "Statistical model identifier (e.g. 'STANDARD_Z_SCORE', 'MAD', 'LONGITUDINAL_CUSUM', 'POISSON', 'TWO_PART_HURDLE').",
                    },
                    "metrics": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of 30-day Risk Analytics metric names from the Malachite catalog.",
                    },
                    "architecture": {
                        "type": "string",
                        "description": "Pipeline architecture ('single_metric', 'fusion', 'triad', 'rollup', 'peer_cohort', '360_radar', 'hybrid_enrichment', etc.).",
                    },
                    "plane": {
                        "type": "string",
                        "description": "Execution plane: 'MACRO_METRICS', 'HYBRID_GRAPH', 'MICRO_RAW_UDM', or 'DUAL_PLANE'.",
                    },
                    "entity_type": {
                        "type": "string",
                        "description": "Target entity type: 'USER', 'ASSET', 'RESOURCE', 'LOG_TYPE', or 'EMAIL'.",
                    },
                    "entity_value": {
                        "type": "string",
                        "description": "Optional specific entity identifier (username, hostname, service account) or 'fleet'.",
                    },
                    "custom_filter": {
                        "type": "string",
                        "description": "Optional additional UDM filter predicate to inject into Stage 1.",
                    },
                    "mode": {
                        "type": "string",
                        "description": "Execution mode: 'A' (today UTC acute triage), 'B' (multi-day timeline), or 'C' (per-day sharded baseline).",
                    },
                    "window_days": {
                        "type": "integer",
                        "description": "Search window duration in days (default 1 for Mode A, 7 or 14 for Mode B/C).",
                    },
                    "sensitivity": {
                        "type": "string",
                        "description": "Anomaly threshold sensitivity tier: 'HIGH', 'BALANCED', or 'LOW'.",
                    },
                },
                "required": ["statistical_model", "metrics"],
            },
        ),
        types.FunctionDeclaration(
            name="dispatch_hybrid_handoff",
            description=(
                "Constructs and dispatches a federated handoff payload (secops-threat-hunt-handoff-v1) "
                "to secops-statistical-hunter for Turn 1 non-metrics demarcation or Phase 2 Macro-to-Micro "
                "raw UDM enrichment."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "intent": {
                        "type": "string",
                        "description": "Handoff intent (e.g. 'C2_BEACONING_JITTER', 'DIVERSITY_DEFICIT', 'ELEPHANT_FLOW_CONCENTRATION', 'TWO_PART_HURDLE', 'FLEET_PREVALENCE_NORMALIZATION').",
                    },
                    "entity_type": {
                        "type": "string",
                        "description": "Target entity type ('HOSTNAME', 'USER', 'IP', 'ASSET').",
                    },
                    "entity_value": {
                        "type": "string",
                        "description": "Target entity identifier.",
                    },
                    "lookback": {
                        "type": "string",
                        "description": "Search window lookback (e.g. '24h', '7d', '14d').",
                    },
                    "sensitivity": {
                        "type": "string",
                        "description": "Sensitivity tier ('HIGH', 'BALANCED', 'LOW').",
                    },
                },
                "required": ["intent"],
            },
        ),
        types.FunctionDeclaration(
            name="render_forensic_dossier",
            description=(
                "Formats post-execution Chronicle udm_search stats rows (or empty rows for Clean Hunt) "
                "into the canonical 6-Section CommonMark Forensic Triage Dossier with Calibrated Risk Index (CRI)."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "rows": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of aggregated outlier row dictionaries returned by udm_search.",
                    },
                    "executed_query": {
                        "type": "string",
                        "description": "The exact multi-stage YARA-L 2.0 query that was executed via udm_search.",
                    },
                    "statistical_model": {
                        "type": "string",
                        "description": "Statistical model used in the hunt.",
                    },
                    "metric_name": {
                        "type": "string",
                        "description": "Primary Risk Analytics metric evaluated.",
                    },
                    "entity_type": {
                        "type": "string",
                        "description": "Entity type ('USER', 'ASSET', 'RESOURCE').",
                    },
                    "mode": {
                        "type": "string",
                        "description": "Execution mode ('A', 'B', or 'C').",
                    },
                    "window_days": {
                        "type": "integer",
                        "description": "Window duration in days.",
                    },
                },
                "required": ["rows", "executed_query"],
            },
        ),
    ]

  def resolve_skill_selection(self, req: JITHuntRequest) -> str:
    """Selects canonical skill dynamically based on alert physics if 'auto'."""
    if req.skill in ("bilateral", "both", "bilateral-ueba"):
      return "bilateral"
    if req.skill in ("risk-metrics", "secops-risk-metrics-multistage"):
      return "secops-risk-metrics-multistage"
    if req.skill in ("stats-hunter", "secops-statistical-hunter"):
      return "secops-statistical-hunter"

    # Contextual heuristic based on alert name, description, and query directive
    context_str = f"{req.alert_name or ''} {req.alert_description or ''} {req.query or ''}".lower()

    # Open-ended exploit / CTI / Shadow AI / Bilateral UEBA indicators
    bilateral_indicators = [
        "http2shell", "web-to-shell", "web to shell", "webshell", "exploit chain",
        "bilateral", "shadow ai", "agentic ai",
    ]
    if any(k in context_str for k in bilateral_indicators):
      return "bilateral"
    
    # Raw process/command/beaconing indicators route to statistical hunter
    stats_indicators = [
        "powershell", "cmd.exe", "process", "beacon", "jitter", "c2", "burst",
        "spray", "fano", "entropy", "rare binary", "sysmon", "parent"
    ]
    if any(k in context_str for k in stats_indicators):
      return "secops-statistical-hunter"

    # Default to 30-day risk metrics baselining
    return "secops-risk-metrics-multistage"

  @staticmethod
  def _annotate_directive_post_data(directive: Any, sec_res: Dict[str, Any]) -> None:
    """Attaches post-execution outcome classification and MITRE ATT&CK progression to directive."""
    if not directive or not isinstance(sec_res, dict):
      return
    rows = _rows(sec_res)
    is_outlier = bool(sec_res.get("is_outlier", False))
    if rows == 0 or not is_outlier:
      outcome_class = "CLEAN_OR_SUBTHRESHOLD"
    elif rows >= 10:
      outcome_class = "FLEET_WAVE"
    else:
      outcome_class = "ACUTE_OUTLIER"
    try:
      directive.post_data_outcome_class = outcome_class
      if getattr(directive, "target_metric", None) and not getattr(directive, "killchain_progression", None):
        from src.pipeline_runner import PipelineRunner
        fmt_cls = PipelineRunner().get_triage_formatter()
        if fmt_cls:
          directive.killchain_progression = fmt_cls.get_mitre_progression(directive.target_metric)
    except Exception:
      pass

  async def _execute_secondary_directive(
      self,
      session: ClientSession,
      tenant: TenantConfig,
      req: JITHuntRequest,
      directive: Any,
  ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Executes a Tier 2A or Tier 2B StrategyDirective and returns (result_dict, markdown_card).

    A directive naming a retired model runs the replacement that the skill's own retirement
    message names (when this hunter has a path for it) and is skipped otherwise. Each card's
    guidance carries the harness verdict and recommended action for the result's CRI.
    """
    retired_note, replacement = retirement_route(getattr(directive, "model_name", None), directive.directive_query)
    route_note = ""
    if retired_note:
      if replacement is None:
        logger.warning(f"Skipping retired secondary directive (no runnable replacement): {retired_note}")
        return None, None
      logger.info(f"Routing retired secondary directive to the skill-named replacement {replacement}: {retired_note}")
      directive.model_name = replacement
      directive.directive_query = _REPLACEMENT_QUERIES[replacement]
      route_note = f"Requested model retired by the harness: {retired_note} Executed `{replacement}` instead."
    sec_query = (directive.directive_query or "").lower().strip()
    target_metric = getattr(directive, "target_metric", None)
    fusion_metrics = getattr(directive, "fusion_metrics", None) or []
    ident_field = getattr(directive, "identifier_field", None)
    exec_entity = getattr(directive, "target_entity", None) or req.target_entity
    exec_entity_type = getattr(directive, "entity_type", None) or req.entity_type

    if "killchain_archetype" in sec_query or "killchain" in sec_query:
      archetype_name = getattr(directive, "killchain_archetype", None) or directive.model_name
      sec_res = await RiskMetricsEngine(tenant).run_killchain_archetype(
          session=session,
          entity=exec_entity,
          archetype=archetype_name,
          entity_type=exec_entity_type,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), GENERIC_CONTAINMENT_ACTION)
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": f"**MITRE Kill-Chain Archetype (`{sec_res.get('archetype') or archetype_name}`)**",
              "observed": f"`{_fmt(sec_res.get('composite_threat_score'), '.2f', 'σ')}`",
              "threshold": "$\\ge 3.00\\sigma$",
              "assessment": "⚠️ Multi-Stage Kill-Chain Progression" if sec_outlier else "✅ Uncorrelated Kill-Chain Stages",
          },
          {
              "metric": "**Correlated Telemetry Vectors**",
              "observed": " + ".join(f"`{m}`" for m in sec_res.get("fusion_metrics", [])),
              "threshold": f"Template: `{sec_res.get('template_name', 'dual_sector_fusion_3stage.yl2')}`",
              "assessment": "Cross-Tactic Behavioral Convergence",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "workspace_triad" in sec_query:
      sec_res = await RiskMetricsEngine(tenant).run_workspace_triad(
          session=session,
          entity=exec_entity,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), GENERIC_CONTAINMENT_ACTION)
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Workspace Triad Composite ($Z_{triad}$)**",
              "observed": f"`{_fmt(sec_res.get('composite_z_score'), '+.2f', 'σ')}`",
              "threshold": "$\\ge 3.00\\sigma$",
              "assessment": "⚠️ Coordinated Insider Triad Outlier" if sec_outlier else "✅ Within Peer Cohort Triad",
          },
          {
              "metric": "**Evaluated Workspace Vectors**",
              "observed": "`downloads` + `changes` + `emails`",
              "threshold": "Template: `part_of_the_whole_triad_3stage.yl2`",
              "assessment": f"Observed Volume = `{_fmt(sec_res.get('observed_value'), '.1f')}`",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "cloud_repo_scope" in sec_query:
      mode = getattr(directive, "outcome_mode", None) or "total"
      sec_res = await RiskMetricsEngine(tenant).run_cloud_repository_scope(
          session=session,
          entity=exec_entity,
          outcome_mode=mode,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "REVOKE_IAM_ROLES")
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": f"**Cloud Repository Scope (`mode={mode}`)**",
              "observed": f"`{_fmt(sec_res.get('top_z_score'), '+.2f', 'σ')}` (Fold = `{_fmt(sec_res.get('fold_change'), '.2f', 'x')}`)",
              "threshold": "$\\ge 3.00\\sigma$",
              "assessment": "⚠️ Out-of-Scope Repository Enumeration" if sec_outlier else "✅ Nominal Cloud Scope",
          },
          {
              "metric": "**Evaluated Metric Family**",
              "observed": f"`{sec_res.get('metric', 'resource_read_total')}`",
              "threshold": f"Observed: `{_fmt(sec_res.get('observed_events'), '.1f')}`",
              "assessment": "Cloud Resource Read / Permission Scope",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "failure_ratio_surge" in sec_query:
      fail_m = target_metric or "http_queries_fail"
      sec_res = await RiskMetricsEngine(tenant).run_failure_ratio_surge(
          session=session,
          entity=exec_entity,
          fail_metric=fail_m,
          entity_type=exec_entity_type,
          identifier_field=ident_field,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), GENERIC_CONTAINMENT_ACTION)
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": f"**Failure Ratio Surge (`{fail_m}`)**",
              "observed": f"`{_fmt(sec_res.get('top_z_score'), '+.2f', 'σ')}` (Fail Ratio = `{_fmt(sec_res.get('failure_ratio'), '.2%')}`)",
              "threshold": "$\\ge 3.00\\sigma$",
              "assessment": "⚠️ Acute Error / Access Denied Surge" if sec_outlier else "✅ Nominal Error Ratio",
          },
          {
              "metric": "**Paired Total Metric**",
              "observed": f"`{sec_res.get('total_metric', 'http_queries_total')}`",
              "threshold": "Template: `failure_ratio_surge_3stage.yl2`",
              "assessment": "3-Stage Ratio Baseline Evaluation",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "alert_surge" in sec_query:
      sec_res = await RiskMetricsEngine(tenant).run_alert_surge(
          session=session,
          entity=exec_entity,
          entity_type=exec_entity_type,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), GENERIC_CONTAINMENT_ACTION)
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Security Alert Surge (`alert_event_name_count`)**",
              "observed": f"`{_fmt(sec_res.get('top_z_score'), '+.2f', 'σ')}` (`{_fmt(sec_res.get('observed_alerts'), '.0f')}` alerts)",
              "threshold": "$\\ge 3.00\\sigma$",
              "assessment": "⚠️ Multi-Rule Alert Accumulation" if sec_outlier else "✅ Baseline Alert Volume",
          },
          {
              "metric": "**Attribution Scope**",
              "observed": f"`{exec_entity_type}` (`{exec_entity}`)",
              "threshold": "30-Day Pre-Computed Alert Baseline",
              "assessment": "Host/User Alert Density",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "sector_fusion" in sec_query or "fusion" in sec_query:
      metrics_pair = fusion_metrics if len(fusion_metrics) >= 2 else [
          target_metric or "auth_attempts_total",
          "network_bytes_outbound",
      ]
      sec_res = await RiskMetricsEngine(tenant).run_sector_fusion(
          session=session,
          entity=exec_entity,
          fusion_metrics=metrics_pair,
          identifier_field=ident_field or "principal.user.userid",
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), GENERIC_CONTAINMENT_ACTION)
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Composite Fusion Score ($D$)**",
              "observed": f"`{_fmt(sec_res.get('composite_threat_score'), '.2f', 'σ')}`",
              "threshold": "$\\ge 3.00\\sigma$",
              "assessment": "⚠️ Multi-Sector Kill-Chain Convergence" if sec_outlier else "✅ Uncorrelated Sector Baseline",
          },
          {
              "metric": "**Fused Telemetry Vectors**",
              "observed": f"`{metrics_pair[0]}` + `{metrics_pair[1]}`",
              "threshold": f"Template: `{sec_res.get('template_name', 'dual_sector_fusion_3stage.yl2')}`",
              "assessment": f"Z_A = {_fmt(sec_res.get('sector_a_z'), '+.2f', 'σ')} | Z_B = {_fmt(sec_res.get('sector_b_z'), '+.2f', 'σ')}",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "macd" in sec_query or "momentum" in sec_query:
      m_name = target_metric or "network_bytes_outbound"
      sec_res = await RiskMetricsEngine(tenant).run_macd_momentum_velocity(
          session=session,
          entity=exec_entity,
          metric_name=m_name,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "THROTTLE_EGRESS")
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": f"**MACD Momentum Score (`{m_name}`)**",
              "observed": f"`{_fmt(sec_res.get('macd_momentum_score'), '+.2f', 'σ')}`",
              "threshold": "$> 3.00\\sigma$",
              "assessment": "⚠️ Acute Regime Acceleration" if sec_outlier else "✅ Stable Velocity Regime",
          },
          {
              "metric": "**Fast Z vs Slow Z Spine**",
              "observed": f"Fast Z = `{_fmt(sec_res.get('fast_z'), '+.2f', 'σ')}` | Slow Z = `{_fmt(sec_res.get('slow_z'), '+.2f', 'σ')}`",
              "threshold": "30-Day Pre-Computed Anchor",
              "assessment": "Dual-Spine Momentum Divergence",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if _is_hour_of_day_query(sec_query):
      sec_res = await StatsHunterEngine(tenant).run_dynamic_archetype_pipeline(
          session=session,
          entity=exec_entity,
          archetype=HOUR_OF_DAY_PROFILE,
          entity_type=exec_entity_type,
          event_type="USER_LOGIN",
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "FORCE_MFA_CHALLENGE")
      sec_outlier = bool(sec_res.get("is_outlier", False))
      hod_score = _hod_score(sec_res)
      sec_rows = [
          {
              "metric": f"**Hour-of-Day Profile Score (`{sec_res.get('score_metric') or 'hod_z_score'}`)**",
              "observed": f"`{_fmt(hod_score, '+.2f')}`",
              "threshold": f"$\\ge {harness_truth.constants().DEFAULT_ANOMALY_THRESHOLD:.2f}$",
              "assessment": "⚠️ Out-of-Profile Hour-of-Day Activity" if sec_outlier else "✅ Within Learned 24-Bin Profile",
          },
          {
              "metric": "**Evaluated Hour Buckets**",
              "observed": f"`{_rows(sec_res)}`",
              "threshold": "Learned 24-Bin UTC Hour-of-Day Profile",
              "assessment": f"`secops-statistical-hunter` `{HOUR_OF_DAY_PROFILE}`",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "cloud_crud" in sec_query:
      sec_res = await RiskMetricsEngine(tenant).run_cloud_crud_surge(
          session=session,
          username=exec_entity,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "REVOKE_IAM_ROLES")
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Cloud CRUD Z-Score ($Z$)**",
              "observed": f"`{_fmt(sec_res.get('top_z_score'), '+.2f', 'σ')}`",
              "threshold": "$|Z| \\le 3.0\\sigma$",
              "assessment": "⚠️ IAM / Resource Mutation Surge" if sec_outlier else "✅ Normal Cloud Operations",
          },
          {
              "metric": "**Mutations Observed**",
              "observed": f"`{_show(sec_res.get('observed_events', 0))}` events",
              "threshold": "30-Day Historical Baseline",
              "assessment": "Significant Departure" if sec_outlier else "Baseline",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "dynamic_metric" in sec_query or "cusum" in sec_query or "quantile" in sec_query or "tukey" in sec_query or "bowley" in sec_query:
      m_name = target_metric or "workspace_total_download_actions"
      default_stat_model = (
          "QUANTILE_IQR_SKEW"
          if any(k in sec_query for k in ("quantile", "tukey", "bowley"))
          else ("LONGITUDINAL_CUSUM_DRIFT" if "cusum" in sec_query else "STANDARD_Z_SCORE")
      )
      stat_model = getattr(directive, "model_name", None) or default_stat_model
      sec_res = await RiskMetricsEngine(tenant).run_dynamic_metric_pipeline(
          session=session,
          entity=exec_entity,
          entity_type=exec_entity_type,
          target_metric=m_name,
          model_name=stat_model,
          identifier_field=ident_field,
          fusion_metrics=fusion_metrics,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "INVESTIGATE")
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": f"**Metric Deviation (`{m_name}`)**",
              "observed": f"`{_fmt(sec_res.get('top_z_score'), '+.2f', 'σ')}`",
              "threshold": "$> 3.00\\sigma$",
              "assessment": "⚠️ Situational Metric Outlier" if sec_outlier else "✅ Within 30-Day Baseline",
          },
          {
              "metric": "**Observed Metric Volume**",
              "observed": f"`{_fmt(sec_res.get('observed_value'), '.1f')}`",
              "threshold": f"Model: `{str(stat_model).upper()}`",
              "assessment": "Pre-Computed Malachite Metric Evaluation",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
          second_order_ran=True,
      )
      return sec_res, sec_report

    if "c2_jitter" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_c2_beaconing_jitter(
          session=session,
          src_ip=exec_entity,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "ISOLATE_HOST")
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Coefficient of Variation ($CV$)**",
              "observed": f"`{_fmt(sec_res.get('coefficient_of_variation'), '.3f')}`",
              "threshold": "$\\le 0.20$",
              "assessment": "⚠️ Low Jitter / Robotic Regularity" if sec_outlier else "✅ Normal Jitter Variance",
          },
          {
              "metric": "**Target Destination**",
              "observed": f"`{_show(sec_res.get('target_destination'))}`",
              "threshold": "N/A",
              "assessment": "Suspected C2 Exfiltration Socket" if sec_outlier else "Benign Traffic",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "poisson_burst" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_poisson_burst_spray(
          session=session,
          entity=exec_entity,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "LOCK_ACCOUNT")
      sec_outlier = sec_res["is_outlier"]
      fano = _num_or_none(sec_res.get("top_fano"))
      sec_rows = [
          {
              "metric": "**Fano Factor ($F = \\sigma^2 / \\mu$)**",
              "observed": f"`{_fmt(fano, '.2f')}`",
              "threshold": "$> 4.00$",
              "assessment": "⚠️ Acute Clustered Spray Dispersion" if sec_outlier else "✅ Nominal Poisson Baseline",
          },
          {
              "metric": "**Evaluated Auth Events**",
              "observed": f"`{_rows(sec_res)}`",
              "threshold": "Baseline",
              "assessment": "Authentication Failure Volatility",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "shannon_entropy" in sec_query or "entropy" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_shannon_character_entropy(
          session=session,
          entity=exec_entity,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "TERMINATE_PROCESS")
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Shannon Entropy ($H$)**",
              "observed": f"`{_fmt(sec_res.get('shannon_entropy_score'), '.2f')}` bits/char",
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
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "markov" in sec_query or "transition" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_markov_transition_rarity(
          session=session,
          host=exec_entity,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "ISOLATE_HOST")
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Information Surprisal**",
              "observed": f"`{_fmt(sec_res.get('surprisal_score'), '.2f')}` bits",
              "threshold": "$> 4.00$ bits",
              "assessment": "⚠️ Rare Living-off-the-Land Transition" if sec_outlier else "✅ Standard Process Transition",
          },
          {
              "metric": "**Observed Transition**",
              "observed": f"`{sec_res.get('parent_process') or 'UNKNOWN'}` ➔ `{sec_res.get('child_process') or 'UNKNOWN'}`",
              "threshold": "$P(\\text{Child}|\\text{Parent}) > 0.05$",
              "assessment": "Parent-Child Process Lineage",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "zipf" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_zipfian_process_rarity(
          session=session,
          host=exec_entity,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "ISOLATE_HOST")
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Zipf Rarity Score**",
              "observed": f"`{_fmt(sec_res.get('zipf_rarity_score'), '.2f')}`",
              "threshold": "$> 3.50$",
              "assessment": "⚠️ Long-Tail Fleet Outlier" if sec_outlier else "✅ Common Fleet Software",
          },
          {
              "metric": "**Top Rare Binary**",
              "observed": f"`{sec_res.get('rare_binary') or 'UNKNOWN'}`",
              "threshold": "$\\le 2$ Fleet Hosts",
              "assessment": "Isolated Execution Image",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "ewma" in sec_query or "burst_velocity" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_ewma_burst_velocity(
          session=session,
          entity=exec_entity,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "RATE_LIMIT_ENTITY")
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**EWMA Velocity Score**",
              "observed": f"`{_fmt(sec_res.get('ewma_velocity_score'), '+.2f', 'σ')}`",
              "threshold": "$> 3.00\\sigma$",
              "assessment": "⚠️ Intraday Kinetic Burst Surge" if sec_outlier else "✅ Nominal Intraday Rate",
          },
          {
              "metric": "**Evaluated Buckets**",
              "observed": f"`{_rows(sec_res)}`",
              "threshold": "Trailing Hourly Baseline",
              "assessment": "Exponential Smoothing Divergence",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "producer_consumer" in sec_query or "ratio_inversion" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_producer_consumer_inversion(
          session=session,
          hostname=exec_entity,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), "ISOLATE_HOST")
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Producer-Consumer Ratio Z ($Z_{PCR}$)**",
              "observed": f"`{_fmt(sec_res.get('pcr_z_score'), '+.2f', 'σ')}` (Ratio = `{_fmt(sec_res.get('producer_ratio'), '.3f')}`)",
              "threshold": "$\\ge 3.00\\sigma$",
              "assessment": "⚠️ Endpoint Producer Role Inversion" if sec_outlier else "✅ Standard Consumer Ratio",
          },
          {
              "metric": "**Evaluated Buckets**",
              "observed": f"`{_rows(sec_res)}`",
              "threshold": "Directional Byte Asymmetry",
              "assessment": "Outbound vs Inbound Byte Ratio",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    if "poisson_rare" in sec_query or "rare_surge" in sec_query:
      sec_res = await StatsHunterEngine(tenant).run_poisson_rare_surge(
          session=session,
          entity=exec_entity,
          lookback_days=req.lookback_days,
      )
      self._annotate_directive_post_data(directive, sec_res)
      sec_decision = decide(sec_res.get("calibrated_risk_index"), GENERIC_CONTAINMENT_ACTION)
      sec_outlier = sec_res["is_outlier"]
      sec_rows = [
          {
              "metric": "**Poisson Arrival Rarity ($Z_{poisson}$)**",
              "observed": f"`{_fmt(sec_res.get('poisson_z'), '+.2f', 'σ')}`",
              "threshold": "$\\ge 3.50\\sigma$",
              "assessment": "⚠️ Rare Command Arrival Surge" if sec_outlier else "✅ Nominal Arrival Rate",
          },
          {
              "metric": "**Evaluated Buckets**",
              "observed": f"`{_rows(sec_res)}`",
              "threshold": "Quiet Historical Baseline",
              "assessment": "Discrete Poisson Rarity",
          },
      ]
      sec_report = CaseWallCardFormatter.format_card(
          target_entity=exec_entity,
          entity_type=exec_entity_type,
          model_name=directive.model_name,
          calibrated_risk_index=sec_decision.cri_value,
          soc_guidance=_soc_guidance(sec_decision, route_note),
          is_outlier=sec_outlier,
          case_id=req.case_id,
          rows_count=_rows(sec_res),
          directive=directive,
          metrics_table_rows=sec_rows,
      )
      return sec_res, sec_report

    return None, None

  def _get_genai_client(
      self, tenant: TenantConfig, model_name: Optional[str] = None
  ) -> genai.Client:
    """Initializes a Google GenAI client with dynamic per-model Vertex location routing."""
    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    if gemini_api_key:
      return genai.Client(
          api_key=gemini_api_key,
          http_options=types.HttpOptions(timeout=180000),
      )
    resolved_location = tenant.resolve_vertex_location(model_name)
    return genai.Client(
        vertexai=True,
        project=tenant.project_id,
        location=resolved_location,
        http_options=types.HttpOptions(timeout=180000),
    )

  async def execute_jit_hunt(self, req: JITHuntRequest) -> JITHuntResponse:
    """Executes the autonomous JIT investigation end-to-end."""
    # Resolve tenant dynamically
    tenant = TenantConfig(
        project_id=req.project_id or self.default_tenant.project_id,
        customer_id=req.customer_id or self.default_tenant.customer_id,
        region=req.region or self.default_tenant.region,
        mcp_url_override=self.default_tenant.mcp_url_override,
        model=self.default_tenant.model,
        fallback_models=self.default_tenant.fallback_models,
        vertex_location=self.default_tenant.vertex_location,
        allowed_tools=self.default_tenant.allowed_tools,
        fleet_360_enabled=self.default_tenant.fleet_360_enabled,
        fleet_360_ingest_events=self.default_tenant.fleet_360_ingest_events,
        fleet_360_spike_threshold_z=self.default_tenant.fleet_360_spike_threshold_z,
        fleet_360_spoke_inclusion_z=self.default_tenant.fleet_360_spoke_inclusion_z,
    )

    skill_name = self.resolve_skill_selection(req)
    if skill_name == "bilateral":
      persona = self.adapter.build_bilateral_jit_persona(
          project_id=tenant.project_id,
          customer_id=tenant.customer_id,
          region=tenant.region,
      )
    else:
      persona = self.adapter.build_jit_persona(
          skill_name=skill_name,
          project_id=tenant.project_id,
          customer_id=tenant.customer_id,
          region=tenant.region,
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

        if str(req.entity_type or "USER").upper() in ("USER", "USER_ID", "EMAIL") and RiskMetricsEngine.extract_email_local_part(req.target_entity):
          req.target_entity = await RiskMetricsEngine(tenant).resolve_user_identifier(
              session=session,
              username=req.target_entity,
              lookback_days=req.lookback_days,
          )

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

        # Retired models never run: route to the replacement the skill's retirement message names,
        # or leave the query to the ReAct loop (which is told the model is retired).
        retired_note, replacement = retirement_route(query_str)
        route_note = ""
        if retired_note:
          logger.warning(f"Requested hunt model is retired by the harness: {retired_note}")
          if replacement:
            route_note = f"Requested model retired by the harness: {retired_note} Executed `{replacement}` instead."
            query_str = _REPLACEMENT_QUERIES[replacement]

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
                entity_type=req.entity_type,
            )
            radar_decision = decide(radar_result.get("calibrated_risk_index"), GENERIC_CONTAINMENT_ACTION)
            cri = radar_decision.cri
            top_sector = radar_result["top_sector"]
            evaluated_day = _macro_evaluated_day(radar_result)

            alert_list = req.alerts or [{"name": req.alert_name or "", "description": req.alert_description or ""}]
            conn_list = req.connector_events or []
            try:
              radar_insights = StrategyDecider.analyze_360_insights(
                  radar_result=radar_result,
                  ctx={
                      "case_title": req.alert_name or "",
                      "case_description": req.alert_description or "",
                      "alerts": [a.get("name") or a.get("displayName", "") for a in alert_list],
                      "primary_entity": req.target_entity,
                  },
                  entity_type=req.entity_type,
              )
            except Exception as insights_err:
              # Insights are advisory (e.g. a radar without a CRI); never let them bypass the fast path.
              logger.warning(f"360 radar insights unavailable ({insights_err}); continuing without them.")
              radar_insights = {}
            if req.directive:
              req.directive.radar_insights = radar_insights

            # --- Tier 2 Secondary Sweep Evaluation & Hypothesis Defense ---
            is_tier1 = not req.directive or getattr(req.directive, "investigation_tier", "TIER_1_BASELINE") == "TIER_1_BASELINE"
            top_z = abs(_finite_float(radar_result["sector_z_scores"].get(top_sector)))
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
                or bool(radar_insights.get("secondary_warranted", False))
                or top_z >= _secondary_sweep_z_gate()
                or _alertable(cri)
                or kinetic_trigger
            )

            tier2_directive = None
            focus_sector = radar_insights.get("recommended_focus_sector") or top_sector

            if needs_secondary:
              try:
                tier2_directive = await StrategyDecider.decide_tier2_deep_dive(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    outlier_vector=focus_sector,
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
            vm_sectors = set(radar_insights.get("variance_masked_sectors", []) or [])
            da_sectors = set(radar_insights.get("dormant_awakening_sectors", []) or [])
            band_floors = "/".join(str(low) for low, *_ in harness_truth.cri_bands()[1:])
            sector_rows = [
                {
                    "metric": f"**{s_name} Sector** (`{sector_metrics_map.get(s_name, 'metrics')}`)",
                    "observed": f"Z = {_fmt(z_val, '+.2f')} ({_show(radar_result['sector_observed_counts'].get(s_name, 0))} events)",
                    "threshold": f"Sector CRI bands {band_floors}",
                    "assessment": _sector_assessment(s_name, z_val, vm_sectors, da_sectors),
                }
                for s_name, z_val in radar_result["sector_z_scores"].items()
            ]
            radar_finding = (
                f"Highest-drift sector `{top_sector}` (Composite Euclidean Distance D = {_fmt(radar_result.get('composite_d'), '.2f')})."
                if radar_result["is_outlier"] else
                "All evaluated behavioral sectors conform to the 30-day baseline."
            )
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="360_DECOUPLED_RADAR",
                calibrated_risk_index=radar_decision.cri_value,
                is_outlier=radar_result["is_outlier"],
                case_id=req.case_id,
                evaluated_window=f"UTC day {evaluated_day}",
                rows_count=sum(int(_finite_float(v)) for v in radar_result["sector_observed_counts"].values()),
                directive=req.directive,
                metrics_table_rows=sector_rows,
                soc_guidance=_soc_guidance(radar_decision, radar_finding),
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
              spike_z_gate = float(getattr(tenant, "fleet_360_spike_threshold_z", 3.0))
              # UDM write-back of the finding requires the harness write-back CRI as well as the D gate.
              if (
                  _finite_float(radar_result.get("composite_d")) >= spike_z_gate
                  and cri is not None
                  and cri >= harness_truth.writeback_cri_threshold()
                  and bool(getattr(tenant, "fleet_360_enabled", False))
                  and bool(getattr(tenant, "fleet_360_ingest_events", True))
              ):
                try:
                  rm_eng = RiskMetricsEngine(tenant)
                  now_dt = datetime.now(timezone.utc)
                  eval_day = evaluated_day
                  sec_map = {
                      s: {
                          "z": _finite_float(z_v),
                          "obs": _finite_float(radar_result.get("sector_observed_counts", {}).get(s, 0)),
                          "avg": _finite_float(radar_result.get("sector_baseline_avg", {}).get(s, 0.0)),
                          "std": _finite_float(radar_result.get("sector_baseline_std", {}).get(s, 0.0)),
                      }
                      for s, z_v in radar_result.get("sector_z_scores", {}).items()
                  }
                  udm_ev = rm_eng.build_360_outlier_udm_event(
                      entity_id=str(radar_result.get("entity") or req.target_entity),
                      entity_type=req.entity_type,
                      sectors=sec_map,
                      composite_d=_finite_float(radar_result.get("composite_d")),
                      composite_cri=cri,
                      campaign_id=f"case-360-{req.case_id}-{eval_day}",
                      run_timestamp_iso=now_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      evaluated_day=eval_day,
                      spike_threshold_z=spike_z_gate,
                  )
                  rm_eng.ingest_udm_events([udm_ev])
                except Exception as ingest_err:
                  logger.warning(f"Case 360 UDM event ingestion skipped for case {req.case_id}: {ingest_err}")

            triage = TriageSummary(
                calibrated_risk_index=radar_decision.cri_value,
                verdict=radar_decision.verdict,
                is_outlier=radar_result["is_outlier"],
                primary_vector=f"{top_sector}_behavioral_drift",
                common_vector=CaseWallCardFormatter.normalize_common_vector(raw_vector=top_sector),
                second_order_ran=will_run_second_order,
                top_z_score=_num_or_none(radar_result["sector_z_scores"].get(top_sector)),
                radar_dimensions=_finite_dims(radar_result["sector_z_scores"]),
                recommended_action=radar_decision.action,
                entities_to_quarantine=[req.target_entity] if radar_decision.contain else [],
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

                  if sec_res is not None and _rows(sec_res) == 0:
                    empty_families.add(StrategyDecider.family_for_query(tier2_directive.directive_query))

                  if sec_report:
                    if req.post_to_case_wall:
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
                  if sec_res is not None:
                    cri = _max_cri(cri, sec_res.get("calibrated_risk_index"))
                    if bool(sec_res.get("is_outlier", False)):
                      _apply_escalation(
                          triage,
                          decide(cri, GENERIC_CONTAINMENT_ACTION),
                          req.target_entity,
                          f"tier2a_{tier2_directive.model_name.lower()}",
                      )

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
                      if piv_report:
                        if req.post_to_case_wall:
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
                      if piv_res is not None:
                        cri = _max_cri(cri, piv_res.get("calibrated_risk_index"))
                        if bool(piv_res.get("is_outlier", False)):
                          _apply_escalation(
                              triage,
                              decide(cri, GENERIC_CONTAINMENT_ACTION),
                              req.target_entity,
                              f"tier2b_{pivot_directive.model_name.lower()}",
                          )

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
                evaluated_window=evaluated_day,
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
            decision = decide(jitter_result.get("calibrated_risk_index"), "ISOLATE_HOST")
            rows_count = _rows(jitter_result)
            jitter_rows = [
                {
                    "metric": "**Coefficient of Variation ($CV$)**",
                    "observed": f"`{_fmt(jitter_result.get('coefficient_of_variation'), '.3f')}`",
                    "threshold": "$\\le 0.300$",
                    "assessment": "⚠️ Low Jitter / Periodic Beaconing" if jitter_result["is_outlier"] else "✅ High Jitter (Stochastic / Irregular)",
                },
                {
                    "metric": "**Top Target Destination**",
                    "observed": f"`{jitter_result.get('target_destination') or 'UNKNOWN'}`",
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
                calibrated_risk_index=decision.cri_value,
                is_outlier=jitter_result["is_outlier"],
                case_id=req.case_id,
                rows_count=rows_count,
                directive=req.directive,
                metrics_table_rows=jitter_rows,
                soc_guidance=_soc_guidance(decision, (
                    _not_evaluated_finding(jitter_result, "Beaconing regularity")
                    or (
                        f"Outbound network traffic to `{jitter_result.get('target_destination') or 'UNKNOWN'}` exhibits rigid periodicity ({_math_value('CV', jitter_result.get('coefficient_of_variation'), '.3f')})."
                        if jitter_result["is_outlier"] else
                        f"Outbound connection intervals exhibit high timing jitter ({_math_value('CV', jitter_result.get('coefficient_of_variation'), '.3f')}), typical of normal cloud applications and distributed polling. No beaconing detected."
                    )
                )),
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=jitter_result["is_outlier"],
                    primary_vector="c2_timing_regularity",
                    top_z_score=_num_or_none(jitter_result.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
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
                    escalation_action=decision.action,
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
            decision = decide(spray_result.get("calibrated_risk_index"), "LOCK_ACCOUNT")
            fano = _num_or_none(spray_result.get("top_fano"))
            spray_rows = [
                {
                    "metric": "**Fano Factor ($F = \\sigma^2 / \\mu$)**",
                    "observed": f"`{_fmt(fano, '.2f')}`",
                    "threshold": "$> 4.00$",
                    "assessment": "⚠️ Severe Overdispersion (Clustered Spray)" if spray_result["is_outlier"] else "✅ Poisson Dispersion (Nominal Rate)",
                },
                {
                    "metric": "**Evaluated Auth Events**",
                    "observed": f"`{_rows(spray_result)}` events",
                    "threshold": "$\\ge 10$ events",
                    "assessment": "Observed Sample Window",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="POISSON_BURST_CLUSTERING",
                calibrated_risk_index=decision.cri_value,
                is_outlier=spray_result["is_outlier"],
                case_id=req.case_id,
                rows_count=_rows(spray_result),
                directive=req.directive,
                metrics_table_rows=spray_rows,
                soc_guidance=_soc_guidance(decision, (
                    f"Detected automated credential spray bursts ({_math_value('Fano', fano, '.2f')})."
                    if spray_result["is_outlier"] else
                    f"Authentication failures show no statistical clustering ({_math_value('Fano', fano, '.2f')}), consistent with random user typing mistakes."
                )),
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=spray_result["is_outlier"],
                    primary_vector="poisson_burst_clustering",
                    top_z_score=_num_or_none(spray_result.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
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
                    escalation_action=decision.action,
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
            decision = decide(cloud_result.get("calibrated_risk_index"), "REVOKE_IAM_ROLES")
            top_z = _num_or_none(cloud_result.get("top_z_score"))
            cloud_rows = [
                {
                    "metric": "**Cloud Mutation Z-Score**",
                    "observed": f"`{_fmt(top_z, '+.2f', 'σ')}`",
                    "threshold": "$> 3.00\\sigma$",
                    "assessment": "⚠️ Significant Administrative Mutation" if cloud_result["is_outlier"] else "✅ Within Baseline Volatility",
                },
                {
                    "metric": "**Observed Cloud Modifications**",
                    "observed": f"`{_show(cloud_result.get('observed_events', 0))}` mutations",
                    "threshold": "Historical 30-Day Mean",
                    "assessment": "Cloud Resource Write Events",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="CLOUD_CRUD_SURGE",
                calibrated_risk_index=decision.cri_value,
                is_outlier=cloud_result["is_outlier"],
                case_id=req.case_id,
                rows_count=int(_finite_float(cloud_result.get("observed_events"))),
                directive=req.directive,
                metrics_table_rows=cloud_rows,
                soc_guidance=_soc_guidance(decision, (
                    f"Abnormal cloud infrastructure creation/permission spike ({_math_value('Z', top_z, '+.2f', _TEX_SIGMA)}). Audit IAM changes and newly deployed cloud workloads."
                    if cloud_result["is_outlier"] else
                    f"Cloud resource management operations ({_math_value('Z', top_z, '+.2f', _TEX_SIGMA)}) match expected deployment baselines."
                )),
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=cloud_result["is_outlier"],
                    primary_vector="cloud_crud_surge",
                    top_z_score=_num_or_none(cloud_result.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
                    mitre_tactics=["TA0003", "TA0004"] if cloud_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=_macro_evaluated_day(cloud_result),
                    primary_model="secops-risk-metrics-multistage",
                    outlier_topology="CLOUD_CRUD_SURGE",
                    mitre_tactics_mapped=["TA0003", "TA0004"] if cloud_result["is_outlier"] else [],
                    recommended_swarm_playbook="IAM_ABUSE_INVESTIGATION",
                    escalation_action=decision.action,
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

        # --- 5. Deterministic Fast-Path: Hour-of-Day Profile (secops-statistical-hunter) ---
        # Off-hours / circadian intents run HOUR_OF_DAY_PROFILE, the model the skills name as the
        # replacement for the retired CIRCADIAN_VON_MISES / HOURLY_TEMPORAL_ZSCORE / geo-velocity paths.
        elif _is_hour_of_day_query(query_str):
          try:
            hod_result = await StatsHunterEngine(tenant).run_dynamic_archetype_pipeline(
                session=session,
                entity=req.target_entity,
                archetype=HOUR_OF_DAY_PROFILE,
                entity_type=req.entity_type,
                event_type="USER_LOGIN",
                lookback_days=req.lookback_days,
            )
            decision = decide(hod_result.get("calibrated_risk_index"), "FORCE_MFA_CHALLENGE")
            hod_outlier = bool(hod_result.get("is_outlier", False))
            hod_score = _hod_score(hod_result)
            rows_count = _rows(hod_result)
            hod_rows = [
                {
                    "metric": f"**Hour-of-Day Profile Score (`{hod_result.get('score_metric') or 'hod_z_score'}`)**",
                    "observed": f"`{_fmt(hod_score, '+.2f')}`",
                    "threshold": f"$\\ge {harness_truth.constants().DEFAULT_ANOMALY_THRESHOLD:.2f}$",
                    "assessment": "⚠️ Out-of-Profile Hour-of-Day Activity" if hod_outlier else "✅ Within Learned 24-Bin Profile",
                },
                {
                    "metric": "**Evaluated Hour Buckets**",
                    "observed": f"`{rows_count}` rows",
                    "threshold": "Learned 24-Bin UTC Hour-of-Day Profile",
                    "assessment": f"`secops-statistical-hunter` `{HOUR_OF_DAY_PROFILE}`",
                },
            ]
            hod_finding = (
                f"Login activity for `{req.target_entity}` fell outside its learned 24-bin hour-of-day profile (score = {_fmt(hod_score, '+.2f')})."
                if hod_outlier else
                f"Login timing for `{req.target_entity}` is consistent with its learned 24-bin hour-of-day profile."
            )
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name=HOUR_OF_DAY_PROFILE,
                calibrated_risk_index=decision.cri_value,
                is_outlier=hod_outlier,
                case_id=req.case_id,
                rows_count=rows_count,
                directive=req.directive,
                metrics_table_rows=hod_rows,
                soc_guidance=_soc_guidance(decision, f"{route_note} {hod_finding}"),
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=hod_outlier,
                    primary_vector="hour_of_day_login_anomaly",
                    top_z_score=_num_or_none(hod_result.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
                    mitre_tactics=["TA0001"] if hod_outlier else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-statistical-hunter",
                    outlier_topology="HOUR_OF_DAY_PROFILE_DEPARTURE",
                    mitre_tactics_mapped=["TA0001"] if hod_outlier else [],
                    recommended_swarm_playbook="OFF_HOURS_ACCESS_CONTAINMENT",
                    escalation_action=decision.action,
                ),
                forensics=ForensicsSummary(
                    executed_query=hod_result.get("executed_query", ""),
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic Hour-of-Day Profile fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
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
            decision = decide(macd_result.get("calibrated_risk_index"), "THROTTLE_EGRESS")
            macd_rows = [
                {
                    "metric": f"**MACD Momentum Score (`{m_name}`)**",
                    "observed": f"`{_fmt(macd_result.get('macd_momentum_score'), '+.2f', 'σ')}`",
                    "threshold": "$> 3.00\\sigma$",
                    "assessment": "⚠️ Acute Regime Acceleration" if macd_result["is_outlier"] else "✅ Stable Velocity Regime",
                },
                {
                    "metric": "**Fast Z vs Slow Z Spine**",
                    "observed": f"Fast Z = `{_fmt(macd_result.get('fast_z'), '+.2f', 'σ')}` | Slow Z = `{_fmt(macd_result.get('slow_z'), '+.2f', 'σ')}`",
                    "threshold": "30-Day Pre-Computed Anchor",
                    "assessment": "Dual-Spine Momentum Divergence",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="MACD_MOMENTUM_VELOCITY",
                calibrated_risk_index=decision.cri_value,
                is_outlier=macd_result["is_outlier"],
                case_id=req.case_id,
                rows_count=_rows(macd_result),
                directive=req.directive,
                metrics_table_rows=macd_rows,
                soc_guidance=_soc_guidance(decision),
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=macd_result["is_outlier"],
                    primary_vector="macd_momentum_acceleration",
                    top_z_score=_num_or_none(macd_result.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
                    mitre_tactics=["TA0010"] if macd_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=_macro_evaluated_day(macd_result),
                    primary_model="secops-risk-metrics-multistage",
                    outlier_topology="MACD_MOMENTUM_DIVERGENCE",
                    mitre_tactics_mapped=["TA0010"] if macd_result["is_outlier"] else [],
                    recommended_swarm_playbook="EXFILTRATION_MOMENTUM_CONTAINMENT",
                    escalation_action=decision.action,
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
            decision = decide(shannon_result.get("calibrated_risk_index"), "TERMINATE_PROCESS")
            sample_tok = shannon_result.get("sample_token") or "N/A"
            shannon_rows = [
                {
                    "metric": "**Shannon Entropy ($H$)**",
                    "observed": f"`{_fmt(shannon_result.get('shannon_entropy_score'), '.2f')}` bits/char",
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
                    "observed": f"`{_rows(shannon_result)}` records",
                    "threshold": "$\\ge 1$ required",
                    "assessment": "Process Launch Telemetry",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="SHANNON_CHARACTER_ENTROPY",
                calibrated_risk_index=decision.cri_value,
                is_outlier=shannon_result["is_outlier"],
                case_id=req.case_id,
                rows_count=_rows(shannon_result),
                directive=req.directive,
                metrics_table_rows=shannon_rows,
                soc_guidance=_soc_guidance(decision, (
                    _not_evaluated_finding(shannon_result, "Command-line entropy")
                    or (
                        f"Command line on `{req.target_entity}` exhibits high Shannon character-class entropy ({_math_value('H', shannon_result.get('shannon_entropy_score'), '.2f')} bits/char), indicating Base64/XOR obfuscated scripts. "
                        "Extract and review the decoded command buffers."
                        if shannon_result["is_outlier"] else
                        f"Command line entropy on `{req.target_entity}` is within expected readable parameter distributions."
                    )
                )),
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=shannon_result["is_outlier"],
                    primary_vector="command_line_obfuscation_entropy",
                    top_z_score=_num_or_none(shannon_result.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
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
                    escalation_action=decision.action,
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
            decision = decide(markov_result.get("calibrated_risk_index"), "ISOLATE_HOST")
            p_proc = markov_result.get("parent_process") or "UNKNOWN"
            c_proc = markov_result.get("child_process") or "UNKNOWN"
            markov_rows = [
                {
                    "metric": "**Information Surprisal**",
                    "observed": f"`{_fmt(markov_result.get('surprisal_score'), '.2f')}` bits",
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
                    "observed": f"`{_rows(markov_result)}` records",
                    "threshold": "$\\ge 1$ required",
                    "assessment": "Process Lineage Telemetry",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="MARKOV_TRANSITION_RARITY",
                calibrated_risk_index=decision.cri_value,
                is_outlier=markov_result["is_outlier"],
                case_id=req.case_id,
                rows_count=_rows(markov_result),
                directive=req.directive,
                metrics_table_rows=markov_rows,
                soc_guidance=_soc_guidance(decision, (
                    f"Process lineage `{p_proc}` ➔ `{c_proc}` exhibits extreme surprisal ({_fmt(markov_result.get('surprisal_score'), '.2f', ' bits')}) characteristic of Living-off-the-Land execution. "
                    "Investigate the command line arguments."
                    if markov_result["is_outlier"] else
                    f"Process execution transitions on `{req.target_entity}` conform to standard enterprise operational tooling."
                )),
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=markov_result["is_outlier"],
                    primary_vector="markov_process_transition_rarity",
                    top_z_score=_num_or_none(markov_result.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
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
                    escalation_action=decision.action,
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
            decision = decide(zipf_result.get("calibrated_risk_index"), "ISOLATE_HOST")
            rare_bin = zipf_result.get("rare_binary") or "UNKNOWN"
            zipf_rows = [
                {
                    "metric": "**Zipf Rarity Score**",
                    "observed": f"`{_fmt(zipf_result.get('zipf_rarity_score'), '.2f')}`",
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
                    "observed": f"`{_rows(zipf_result)}` records",
                    "threshold": "$\\ge 1$ required",
                    "assessment": "Process Launch Telemetry",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name="ZIPFIAN_PROCESS_RARITY",
                calibrated_risk_index=decision.cri_value,
                is_outlier=zipf_result["is_outlier"],
                case_id=req.case_id,
                rows_count=_rows(zipf_result),
                directive=req.directive,
                metrics_table_rows=zipf_rows,
                soc_guidance=_soc_guidance(decision, (
                    f"Host `{req.target_entity}` executed rare binary `{rare_bin}` sitting in the extreme asymptotic fleet tail (Zipf Score = {_fmt(zipf_result.get('zipf_rarity_score'), '.2f')}). "
                    "Inspect persistence entries for the binary."
                    if zipf_result["is_outlier"] else
                    f"Process execution telemetry on `{req.target_entity}` conforms to common enterprise software distributions."
                )),
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=zipf_result["is_outlier"],
                    primary_vector="zipfian_rare_tool_execution",
                    top_z_score=_num_or_none(zipf_result.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
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
                    escalation_action=decision.action,
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
            decision = decide(ewma_result.get("calibrated_risk_index"), "RATE_LIMIT_ENTITY")
            markdown_report = (
                f"# EWMA Burst Velocity Analysis: {req.target_entity}\n\n"
                f"**Calibrated Risk Index (CRI)**: {harness_truth.format_cri(decision.cri)}/100 ({decision.verdict})\n"
                f"**EWMA Velocity Score**: {_show(ewma_result.get('ewma_velocity_score'), 'σ')}\n"
                f"**Is Outlier**: {ewma_result['is_outlier']}\n\n"
                f"## Forensic Details\n"
                f"- Evaluated intraday exponential smoothing divergence to capture acute kinetic rate surges.\n\n"
                f"{_report_footer(decision)}\n"
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=ewma_result["is_outlier"],
                    primary_vector="ewma_kinetic_burst_velocity",
                    top_z_score=_num_or_none(ewma_result.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
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
                    escalation_action=decision.action,
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

        # --- 10C. Deterministic Fast-Path: Producer-Consumer Byte Ratio Inversion ---
        elif "producer_consumer" in query_str or "ratio_inversion" in query_str:
          try:
            pc_result = await StatsHunterEngine(tenant).run_producer_consumer_inversion(
                session=session,
                hostname=req.target_entity,
                lookback_days=req.lookback_days,
            )
            decision = decide(pc_result.get("calibrated_risk_index"), "ISOLATE_HOST")
            markdown_report = (
                f"# Producer-Consumer Byte Ratio Inversion Analysis: {req.target_entity}\n\n"
                f"**Calibrated Risk Index (CRI)**: {harness_truth.format_cri(decision.cri)}/100 ({decision.verdict})\n"
                f"**Producer Ratio**: {_show(pc_result.get('producer_ratio'))} (Z-Score: {_show(pc_result.get('top_z_score'), 'σ')})\n"
                f"**Is Outlier**: {pc_result['is_outlier']}\n\n"
                f"## Forensic Details\n"
                f"- Evaluated directional byte asymmetry (`sent / (sent + recv)`) and outbound byte baseline departure.\n\n"
                f"{_report_footer(decision)}\n"
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=pc_result["is_outlier"],
                    primary_vector="producer_consumer_ratio_inversion",
                    top_z_score=_num_or_none(pc_result.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
                    mitre_tactics=["TA0009", "TA0010"] if pc_result["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    primary_model="secops-statistical-hunter",
                    outlier_topology="PRODUCER_CONSUMER_RATIO_INVERSION",
                    mitre_tactics_mapped=["TA0009", "TA0010"] if pc_result["is_outlier"] else [],
                    recommended_swarm_playbook="DATA_STAGING_EXFIL_CONTAINMENT",
                    escalation_action=decision.action,
                ),
                forensics=ForensicsSummary(
                    executed_query=pc_result["executed_query"],
                    markdown_report=markdown_report,
                ),
                case_wall_updated=case_wall_updated,
            )
          except Exception as fast_path_err:
            logger.warning(
                f"Deterministic Producer-Consumer fast-path bypassed due to error ({fast_path_err}); falling back to autonomous ReAct."
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
            decision = decide(fus_res.get("calibrated_risk_index"), "QUARANTINE")
            fus_rows = [
                {
                    "metric": "**Composite Fusion Score ($D$)**",
                    "observed": f"`{_fmt(fus_res.get('composite_threat_score'), '.2f', 'σ')}`",
                    "threshold": "$\\ge 3.00\\sigma$",
                    "assessment": "⚠️ Multi-Sector Kill-Chain Convergence" if fus_res["is_outlier"] else "✅ Uncorrelated Sector Baseline",
                },
                {
                    "metric": "**Fused Telemetry Vectors**",
                    "observed": f"`{f_metrics[0]}` + `{f_metrics[1]}`",
                    "threshold": f"Template: `{fus_res.get('template_name', 'dual_sector_fusion_3stage.yl2')}`",
                    "assessment": f"Z_A = {_fmt(fus_res.get('sector_a_z'), '+.2f', 'σ')} | Z_B = {_fmt(fus_res.get('sector_b_z'), '+.2f', 'σ')}",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name=fus_res.get("model", "DUAL_SECTOR_FUSION_3STAGE"),
                calibrated_risk_index=decision.cri_value,
                is_outlier=fus_res["is_outlier"],
                case_id=req.case_id,
                rows_count=_rows(fus_res),
                directive=req.directive,
                metrics_table_rows=fus_rows,
                soc_guidance=_soc_guidance(decision, route_note),
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=fus_res["is_outlier"],
                    primary_vector="multi_sector_fusion_convergence",
                    top_z_score=_num_or_none(fus_res.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
                    mitre_tactics=["TA0001", "TA0010"] if fus_res["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=_macro_evaluated_day(fus_res),
                    primary_model="secops-risk-metrics-multistage",
                    outlier_topology="MULTI_SECTOR_FUSION",
                    mitre_tactics_mapped=["TA0001", "TA0010"] if fus_res["is_outlier"] else [],
                    recommended_swarm_playbook="KILL_CHAIN_CONVERGENCE_CONTAINMENT",
                    escalation_action=decision.action,
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

        # --- 12. Deterministic Fast-Path: Dynamic Situational Metric / CUSUM Drift / Quantile IQR Skew ---
        elif "dynamic_metric" in query_str or "cusum" in query_str or "quantile" in query_str or "tukey" in query_str or "bowley" in query_str:
          try:
            m_name = getattr(req.directive, "target_metric", None) or "workspace_total_download_actions"
            stat_model = (
                "QUANTILE_IQR_SKEW"
                if any(k in query_str for k in ("quantile", "tukey", "bowley"))
                else ("cusum" if "cusum" in query_str else "zscore")
            )
            dyn_res = await RiskMetricsEngine(tenant).run_dynamic_metric_pipeline(
                session=session,
                entity=req.target_entity,
                metric_name=m_name,
                model=stat_model,
                lookback_days=req.lookback_days,
            )
            decision = decide(dyn_res.get("calibrated_risk_index"), "INVESTIGATE")
            dyn_rows = [
                {
                    "metric": f"**Metric Deviation (`{m_name}`)**",
                    "observed": f"`{_fmt(dyn_res.get('top_z_score'), '+.2f', 'σ')}`",
                    "threshold": "$> 3.00\\sigma$",
                    "assessment": "⚠️ Situational Metric Outlier" if dyn_res["is_outlier"] else "✅ Within 30-Day Baseline",
                },
                {
                    "metric": "**Observed Metric Volume**",
                    "observed": f"`{_fmt(dyn_res.get('observed_value'), '.1f')}`",
                    "threshold": f"Model: `{stat_model.upper()}`",
                    "assessment": "Pre-Computed Malachite Metric Evaluation",
                },
            ]
            markdown_report = CaseWallCardFormatter.format_card(
                target_entity=req.target_entity,
                entity_type=req.entity_type,
                model_name=dyn_res.get("model", "DYNAMIC_METRIC_BASELINE"),
                calibrated_risk_index=decision.cri_value,
                is_outlier=dyn_res["is_outlier"],
                case_id=req.case_id,
                rows_count=_rows(dyn_res),
                directive=req.directive,
                metrics_table_rows=dyn_rows,
                soc_guidance=_soc_guidance(decision, route_note),
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
                    calibrated_risk_index=decision.cri_value,
                    verdict=decision.verdict,
                    is_outlier=dyn_res["is_outlier"],
                    primary_vector=f"dynamic_metric_{m_name}",
                    top_z_score=_num_or_none(dyn_res.get("top_z_score")),
                    recommended_action=decision.action,
                    entities_to_quarantine=[req.target_entity] if decision.contain else [],
                    mitre_tactics=["TA0009", "TA0010"] if dyn_res["is_outlier"] else [],
                ),
                clean_hand_off=CleanHandOffPayload(
                    target_entity=req.target_entity,
                    entity_type=req.entity_type,
                    evaluated_window=_macro_evaluated_day(dyn_res),
                    primary_model="secops-risk-metrics-multistage",
                    outlier_topology=f"DYNAMIC_METRIC_{m_name.upper()}",
                    mitre_tactics_mapped=["TA0009", "TA0010"] if dyn_res["is_outlier"] else [],
                    recommended_swarm_playbook="SITUATIONAL_METRIC_INVESTIGATION",
                    escalation_action=decision.action,
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

        # Register local behavioral radar tool and Python Hybrid Engine tools
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
        if os.environ.get("SECOPS_DISABLE_HYBRID_TOOLS") != "1":
          gemini_functions.extend(self.get_hybrid_function_declarations())

        candidate_models = [tenant.model]
        for fallback in getattr(tenant, "fallback_models", ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-pro"]):
          if fallback not in candidate_models:
            candidate_models.append(fallback)

        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=req.lookback_days)
        start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        mode_a_start, mode_a_end = harness_truth.mode_a_window()
        ecg_start, ecg_end = harness_truth.ecg_window()

        prompt_lines = [
            f"EXECUTE AUTONOMOUS JIT THREAT INVESTIGATION:",
            f"- Target Entity: {req.target_entity} (Type: {req.entity_type})",
            f"- Investigation Horizon: {start_iso} to {end_iso}",
            f"- Mode A Scored Day (30d metrics.* baselines): startTime={mode_a_start}, endTime={mode_a_end} (last complete UTC day)",
            f"- Entity Graph Joins (Mode A): startTime={ecg_start}, endTime={ecg_end}; pin every event stage with "
            f"`{harness_truth.event_day_pin()}`",
        ]
        if retired_note:
          prompt_lines.append(f"- Retired Model Requested: {retired_note}")
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
            f"7. {harness_truth.RECOMMENDATION_NOTE} Report containment only as a recommended action; never execute it.",
        ])

        initial_prompt = "\n".join(prompt_lines)
        react_success = False
        final_response = None

        for model_candidate in candidate_models:
          try:
            resolved_loc = tenant.resolve_vertex_location(model_candidate)
            logger.info(
                f"Initiating autonomous ReAct investigation with candidate model: {model_candidate} (location={resolved_loc})"
            )
            ai_client = self._get_genai_client(tenant, model_candidate)
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

              elif tool_name in ("compile_hunt_pipeline", "dispatch_hybrid_handoff", "render_forensic_dossier"):
                try:
                  from src.pipeline_runner import PipelineRunner
                  he_mod = PipelineRunner(tenant).get_hybrid_engine()
                  fn = getattr(he_mod, tool_name)
                  res_dict = fn(**tool_args)
                  if tool_name == "compile_hunt_pipeline" and isinstance(res_dict, dict) and res_dict.get("compiled_query"):
                    executed_query = executed_query or str(res_dict["compiled_query"])
                  output_str = json.dumps(res_dict, default=str)
                except Exception as he_err:
                  output_str = json.dumps({"status": "ERROR", "error": str(he_err)})

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
            # Build the harness-derived response first so an automatic Case Wall post carries the
            # harness verdict, recommended action and recommendation-only note.
            final_response = self._build_hunt_response(
                final_text=final_text,
                executed_query=executed_query,
                radar_svg=radar_svg,
                case_wall_updated=case_wall_updated,
                req=req,
                skill_name=skill_name,
            )
            if req.case_id and req.post_to_case_wall and not case_wall_updated:
              logger.info(
                  f"ReAct agent did not explicitly call create_case_comment; automatically posting report to Case {req.case_id} wall."
              )
              clean_comment = self.sanitize_case_comment(final_response.forensics.markdown_report)
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
              final_response.case_wall_updated = True
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
          decision = decide(radar_result.get("calibrated_risk_index"), GENERIC_CONTAINMENT_ACTION)
          top_sector = radar_result["top_sector"]

          report_lines = [
              f"# 360° Decoupled Behavioral Risk Radar (Deterministic Fallback): {req.target_entity}",
              "> [!WARNING] Gemini LLM quota was temporarily exhausted; automatically triaged via 30-day precomputed metrics.",
              f"**Calibrated Risk Index (CRI)**: {harness_truth.format_cri(decision.cri)}/100 ({decision.verdict})",
              f"**Top Risk Sector**: {top_sector} (Composite Distance D: {_show(radar_result.get('composite_d'))})",
              "",
              "## Forensic Sector Analysis",
          ]
          for s_name, z_val in radar_result["sector_z_scores"].items():
            obs = radar_result["sector_observed_counts"].get(s_name, 0)
            report_lines.append(f"- **{s_name}**: Z-score = {_fmt(z_val, '+.2f')} (Observed: {_show(obs)})")
          report_lines.extend(["", _report_footer(decision)])

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
                  calibrated_risk_index=decision.cri_value,
                  verdict=decision.verdict,
                  is_outlier=radar_result["is_outlier"],
                  primary_vector=f"{top_sector}_behavioral_drift",
                  top_z_score=_num_or_none(radar_result["sector_z_scores"].get(top_sector)),
                  radar_dimensions=_finite_dims(radar_result["sector_z_scores"]),
                  recommended_action=decision.action,
                  entities_to_quarantine=[req.target_entity] if decision.contain else [],
                  mitre_tactics=["TA0001", "TA0006"] if radar_result["is_outlier"] else [],
              ),
              clean_hand_off=CleanHandOffPayload(
                  target_entity=req.target_entity,
                  entity_type=req.entity_type,
                  evaluated_window=_macro_evaluated_day(radar_result),
                  primary_model="secops-risk-metrics-multistage",
                  outlier_topology=f"{top_sector.upper()}_DRIFT",
                  mitre_tactics_mapped=["TA0001", "TA0006"] if radar_result["is_outlier"] else [],
                  recommended_swarm_playbook="DECOUPLED_RADAR_INVESTIGATION",
                  escalation_action=decision.action,
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
          decision = decide(jitter_result.get("calibrated_risk_index"), "ISOLATE_HOST")
          markdown_report = (
              f"# C2 Beaconing Jitter Analysis (Deterministic Fallback): {req.target_entity}\n\n"
              f"> [!WARNING] Gemini LLM quota was temporarily exhausted; automatically triaged via statistical hunting.\n"
              f"**CRI**: {harness_truth.format_cri(decision.cri)}/100\n**Is Outlier**: {jitter_result['is_outlier']}\n\n"
              f"{_report_footer(decision)}"
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
                  calibrated_risk_index=decision.cri_value,
                  verdict=decision.verdict,
                  is_outlier=jitter_result["is_outlier"],
                  primary_vector="c2_timing_regularity",
                  top_z_score=_num_or_none(jitter_result.get("top_z_score")),
                  recommended_action=decision.action,
                  entities_to_quarantine=[req.target_entity] if decision.contain else [],
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
                  escalation_action=decision.action,
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
    """Extracts structured triage JSON and packages final response.

    The CRI is taken from the json_triage block (missing or invalid CRI is NOT_EVALUATED and never
    escalates); the verdict and recommended action come from the harness bands, never from the
    LLM's own verdict string. The LLM's action is kept only as the domain containment action that
    the harness recommends at the Critical band.
    """
    final_text = DynamicProtocolAdapter.sanitize_bq_backend_references(final_text)
    # Attempt to extract json_triage code block
    triage_data = {}
    json_match = re.search(r"```(?:json_triage|json)\s*(\{.*?\})\s*```", final_text, re.DOTALL)
    if json_match:
      try:
        triage_data = json.loads(json_match.group(1))
      except Exception:
        pass
    if not isinstance(triage_data, dict):
      triage_data = {}

    cri = harness_truth.coerce_cri(triage_data.get("calibrated_risk_index"))
    if not cri and "cri" in triage_data:
      alt_cri = harness_truth.coerce_cri(triage_data.get("cri"))
      if alt_cri is not None:
        cri = alt_cri

    llm_action = str(triage_data.get("recommended_action") or "").strip().upper()
    containment = llm_action if llm_action and llm_action not in _HARNESS_RESPONSE_KINDS else GENERIC_CONTAINMENT_ACTION
    decision = decide(cri, containment)

    is_outlier = _alertable(decision.cri)
    top_z = _finite_float(triage_data.get("top_z_score"))
    primary_vector = triage_data.get("primary_vector", "multi_sector")
    radar_dims = triage_data.get("radar_dimensions", {})
    entities_to_quarantine = triage_data.get("entities_to_quarantine") or []
    if not isinstance(entities_to_quarantine, list):
      entities_to_quarantine = []
    if decision.contain:
      entities_to_quarantine = entities_to_quarantine or [req.target_entity]
    else:
      entities_to_quarantine = []
    mitre_tactics = triage_data.get("mitre_tactics", [])

    triage_summary = TriageSummary(
        calibrated_risk_index=decision.cri_value,
        verdict=decision.verdict,
        is_outlier=is_outlier,
        primary_vector=primary_vector,
        top_z_score=top_z,
        radar_dimensions=radar_dims,
        recommended_action=decision.action,
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
        escalation_action=decision.action,
    )

    forensics = ForensicsSummary(
        executed_query=executed_query,
        markdown_report=f"{final_text.rstrip()}\n\n---\n\n{_report_footer(decision)}",
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

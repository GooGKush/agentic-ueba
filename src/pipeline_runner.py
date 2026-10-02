# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Universal Template Pipeline Runner for SecOps Threat Hunting.

Loads canonical .yl2 templates dynamically from secops-risk-metrics-multistage
and secops-statistical-hunter, renders placeholders deterministically, executes
queries via Chronicle OneMCP, and evaluates exact statistical metrics in pure Python.
"""

from datetime import datetime, timedelta, timezone
import json
import logging
import math
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx
from mcp import ClientSession

from src.config import TenantConfig, get_skills_root

logger = logging.getLogger("PipelineRunner")


class PipelineRunner:
  """Renders and executes multi-stage YARA-L 2.0 query templates."""

  def __init__(self, tenant_config: Optional[TenantConfig] = None):
    self.tenant = tenant_config or TenantConfig()
    self.skills_root = get_skills_root()

  def find_template(self, skill_name: str, template_name: str) -> Path:
    """Locates a .yl2 template file within the canonical skill directory."""
    skill_dir = self.skills_root / skill_name
    candidates = [
        skill_dir / "templates" / "pipelines" / template_name,
        skill_dir / "templates" / "pipelines" / f"{template_name}.yl2",
        skill_dir / "templates" / template_name,
        skill_dir / "templates" / f"{template_name}.yl2",
    ]
    for c in candidates:
      if c.is_file():
        return c
    raise FileNotFoundError(
        f"Template '{template_name}' not found under {skill_dir}/templates/"
    )

  def render_template(self, template_path: Path, params: Dict[str, Any]) -> str:
    """Renders a .yl2 template by substituting {{placeholder}} variables."""
    raw_text = template_path.read_text(encoding="utf-8")
    merged_params = dict(params)
    # v1.8.1 Entity Graph freshness filter: auto-populate {{today_date}} (YYYY-MM-DD in UTC)
    if "{{today_date}}" in raw_text and "today_date" not in merged_params:
      from datetime import datetime, timezone
      merged_params["today_date"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if "{{today_start_epoch}}" in raw_text and "today_start_epoch" not in merged_params:
      from datetime import datetime, timezone
      now_utc = datetime.now(timezone.utc)
      midnight_utc = datetime(now_utc.year, now_utc.month, now_utc.day, tzinfo=timezone.utc)
      merged_params["today_start_epoch"] = int(midnight_utc.timestamp())

    rendered = raw_text
    for key, val in merged_params.items():
      placeholder = f"{{{{{key}}}}}"
      rendered = rendered.replace(placeholder, str(val))

    # Safety check for unrendered placeholders
    unrendered = re.findall(r"\{\{([a-zA-Z0-9_]+)\}\}", rendered)
    if unrendered:
      logger.warning(
          f"Template {template_path.name} contains unrendered placeholders: {set(unrendered)}"
      )

    return rendered

  def _ensure_skill_path(self) -> Path:
    """Ensures secops-risk-metrics-multistage is importable and returns its path."""
    import sys
    metrics_skill = self.skills_root / "secops-risk-metrics-multistage"
    if metrics_skill.is_dir() and str(metrics_skill) not in sys.path:
      sys.path.insert(0, str(metrics_skill))
    return metrics_skill

  def get_malachite_catalog(self) -> Any:
    """Returns the compiler-grounded malachite_catalog module from secops-risk-metrics-multistage."""
    self._ensure_skill_path()
    from scripts import malachite_catalog
    return malachite_catalog

  def get_template_router(self) -> Any:
    """Returns an initialized MultiStageTemplateRouter instance from secops-risk-metrics-multistage."""
    metrics_skill = self._ensure_skill_path()
    from scripts.template_router import MultiStageTemplateRouter
    return MultiStageTemplateRouter(template_dir=metrics_skill / "templates")

  def get_validator_enums(self) -> Tuple[Any, Any, Any, Any]:
    """Returns (EntityType, PipelineArchitecture, StatisticalModel, PreFlightValidator)."""
    self._ensure_skill_path()
    from scripts.preflight_validator import (
        EntityType,
        PipelineArchitecture,
        StatisticalModel,
        PreFlightValidator,
    )
    return EntityType, PipelineArchitecture, StatisticalModel, PreFlightValidator

  @staticmethod
  def scope_query_to_entity(query: str, target_entity: Optional[str]) -> str:
    """Scopes non-fleet Stage 1 / Sector stages to a specific target entity if provided."""
    if not target_entity or target_entity.lower() in ("fleet", "unknown", "unknown_entity", "target_entity", "*"):
      return query

    def _scope_stage(match: re.Match) -> str:
      stage_name = match.group(1)
      stage_body = match.group(2)
      # Preserve fleet-wide normalization and Entity Graph stages intact
      if any(w in stage_name.lower() for w in ("fleet", "enterprise", "cohort", "peer", "global", "rare_dest", "graph")):
        return match.group(0)
      scoped_body = re.sub(
          r'(\$(?:entity|user|host|asset)\s*)!=\s*""',
          f'\\1= "{target_entity}"',
          stage_body,
      )
      return f"stage {stage_name} {{{scoped_body}}}"

    return re.sub(r"stage\s+([a-zA-Z0-9_]+)\s*\{(.*?)\}", _scope_stage, query, flags=re.DOTALL)

  def validate_ast(self, query: str) -> List[str]:
    """Validates YARA-L 2.0 query against Malachite AST grammar & metric invariants."""
    try:
      self._ensure_skill_path()
      from scripts.preflight_validator import MalachiteASTValidator
      return MalachiteASTValidator.validate_query(query)
    except Exception as e:
      logger.debug(f"Malachite AST validator unavailable: {e}")
      return []

  @staticmethod
  def calculate_cri(z_score: float) -> int:
    """Computes Calibrated Risk Index (CRI) [0–100] via sigmoid normalization.
    
    Formula: CRI(Z) = round(100 / (1 + exp(-0.6 * (Z - 3.0))))
    """
    try:
      clamped_z = min(max(z_score, -5.0), 15.0)
      return round(100.0 / (1.0 + math.exp(-0.6 * (clamped_z - 3.0))))
    except Exception:
      return 0

  @staticmethod
  def compute_euclidean_distance(z_scores: Dict[str, float]) -> float:
    """Computes composite Euclidean threat distance D across orthogonal sectors.
    
    Formula: D = sqrt(sum max(0, Z_i)^2)
    """
    return math.sqrt(sum(max(0.0, float(z))**2 for z in z_scores.values()))

  @staticmethod
  def parse_stats_response(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalizes Chronicle UDM stats response into a list of row dicts.
    
    Handles both Chronicle Protobuf StatsData columnar format and row-based lists.
    """
    raw_stats = resp.get("stats")
    if not raw_stats:
      return []

    if isinstance(raw_stats, list):
      return raw_stats

    if isinstance(raw_stats, dict):
      results = raw_stats.get("results", [])
      if not results:
        return []

      col_data: Dict[str, List[Any]] = {}
      max_rows = 0
      for col_entry in results:
        col_name = col_entry.get("column", "").lstrip("$")
        vals = []
        for cell in col_entry.get("values", []):
          val_obj = cell.get("value", {}) if isinstance(cell, dict) else {}
          for k in ("doubleVal", "int64Val", "stringVal", "boolVal", "uint64Val"):
            if k in val_obj and val_obj[k] is not None:
              vals.append(val_obj[k])
              break
          else:
            vals.append(None)
        col_data[col_name] = vals
        if len(vals) > max_rows:
          max_rows = len(vals)

      rows = []
      for i in range(max_rows):
        row = {}
        for col_name, vals in col_data.items():
          row[col_name] = vals[i] if i < len(vals) else None
        rows.append(row)
      return rows

    return []

  async def execute_query_via_mcp(
      self,
      session: ClientSession,
      query: str,
      start_iso: str,
      end_iso: str,
  ) -> Dict[str, Any]:
    """Executes a multi-stage YARA-L search query against Chronicle OneMCP."""
    tool_args = {
        "query": query,
        "startTime": start_iso,
        "endTime": end_iso,
        "projectId": self.tenant.project_id,
        "customerId": self.tenant.customer_id,
        "region": self.tenant.region,
    }
    # Preflight Malachite AST validation check
    ast_errors = self.validate_ast(query)
    crit_errors = [e for e in ast_errors if not e.startswith("MISSING_GOAL_HEADER")]
    if crit_errors:
      logger.warning(f"Malachite AST preflight invariant warnings: {crit_errors}")

    logger.info(f"Executing query over OneMCP: {query[:120]}...")
    res = await session.call_tool("udm_search", tool_args)
    if not res.content:
      return {"stats": [], "events": []}

    raw_text = res.content[0].text if hasattr(res.content[0], "text") else ""
    if not raw_text or not raw_text.strip():
      return {"stats": [], "events": []}

    try:
      return json.loads(raw_text)
    except Exception as e:
      logger.warning(f"udm_search returned non-JSON text ({e}): {raw_text[:160]}")
      return {"raw_text": raw_text, "stats": [], "events": []}

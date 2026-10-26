# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Universal Template Pipeline Runner for SecOps Threat Hunting.

Loads canonical .yl2 templates dynamically from secops-risk-metrics-multistage
and secops-statistical-hunter, renders placeholders deterministically, executes
queries via Chronicle OneMCP, and evaluates exact statistical metrics in pure Python.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import functools
import json
import logging
import math
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
import weakref

import httpx
from mcp import ClientSession

from src.config import TenantConfig, get_skills_root
from src.query_integrity_gate import (
    ChronicleBackendQueryError,
    QueryIntegrityGate,
    QueryValidationError,
)

logger = logging.getLogger("PipelineRunner")


class PipelineRunner:
  """Renders and executes multi-stage YARA-L 2.0 query templates."""

  # Root significance gate values passed into secops-risk-metrics-multistage templates and router
  # (skill v1.8.6+ ships each model's gate as a root `condition:`). They mirror this system's own
  # outlier rules so the query never drops an entity the engine would flag:
  #   sigma scores >= 3.0 (ARCHITECTURE.md Statistical Gate, CRI >= 46/50), fusion D >= 3.0
  #   (run_sector_fusion `composite_d >= 3.0`, so D^2 >= 9.0; the skill default is 12.25),
  #   fold change >= 2.0 and MAD modified Z >= 3.5 (skill defaults).
  GATE_DEFAULTS: Dict[str, Any] = {
      "anomaly_threshold": 3.0,
      "fold_change_threshold": 2.0,
      "fusion_threshold_sq": 9.0,
      "robust_threshold": 3.5,
  }

  _SHARED_IO_POOL: Optional[ThreadPoolExecutor] = None
  _LOOP_SEARCH_SEMAPHORES: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, Tuple[int, asyncio.Semaphore]]" = (
      weakref.WeakKeyDictionary()
  )

  def __init__(self, tenant_config: Optional[TenantConfig] = None):
    self.tenant = tenant_config or TenantConfig()
    self.skills_root = get_skills_root()
    self.max_concurrent_udm_searches = max(
        1, int(getattr(self.tenant, "max_concurrent_udm_searches", 6))
    )
    self.blocking_io_workers = max(
        1, int(getattr(self.tenant, "blocking_io_workers", 4))
    )

  @classmethod
  def get_io_thread_pool(cls, max_workers: int = 4) -> ThreadPoolExecutor:
    """Returns the shared background ThreadPoolExecutor for synchronous blocking I/O and CPU tasks."""
    if cls._SHARED_IO_POOL is None:
      cls._SHARED_IO_POOL = ThreadPoolExecutor(
          max_workers=max(2, max_workers),
          thread_name_prefix="secops-ueba-io",
      )
    return cls._SHARED_IO_POOL

  async def run_in_io_thread(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Offloads a synchronous blocking function (e.g. urllib ImportEvents, ADC auth, AST parse) to a worker thread."""
    loop = asyncio.get_running_loop()
    pool = self.get_io_thread_pool(self.blocking_io_workers)
    bound = functools.partial(func, *args, **kwargs)
    return await loop.run_in_executor(pool, bound)

  def _get_udm_search_semaphore(self) -> asyncio.Semaphore:
    """Returns a per-event-loop semaphore governing concurrent Chronicle `udm_search` calls."""
    loop = asyncio.get_running_loop()
    entry = self._LOOP_SEARCH_SEMAPHORES.get(loop)
    if entry is None or entry[0] != self.max_concurrent_udm_searches:
      sem = asyncio.Semaphore(self.max_concurrent_udm_searches)
      self._LOOP_SEARCH_SEMAPHORES[loop] = (self.max_concurrent_udm_searches, sem)
      return sem
    return entry[1]

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
    # Skill v1.8.6 root significance gate: auto-populate the gate placeholders with this system's
    # outlier rules unless the caller passes its own value.
    for gate_key, gate_val in self.GATE_DEFAULTS.items():
      if f"{{{{{gate_key}}}}}" in raw_text and gate_key not in merged_params:
        merged_params[gate_key] = gate_val
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

  def get_killchain_archetypes(self) -> Tuple[Any, Dict[Any, Dict[str, Any]]]:
    """Returns (KillChainArchetype, KILLCHAIN_CATALOG) from secops-risk-metrics-multistage v1.9.1+."""
    self._ensure_skill_path()
    from scripts.preflight_validator import KillChainArchetype
    from scripts.template_router import MultiStageTemplateRouter
    return KillChainArchetype, MultiStageTemplateRouter.KILLCHAIN_CATALOG

  def get_chained_hunt_router(self) -> Any:
    """Returns the ChainedHuntRouter class from secops-risk-metrics-multistage v1.9.1+."""
    self._ensure_skill_path()
    from scripts.template_router import ChainedHuntRouter
    return ChainedHuntRouter

  def get_triage_formatter(self) -> Any:
    """Returns the CommonMarkTriageFormatter class from secops-risk-metrics-multistage v1.9.1+."""
    self._ensure_skill_path()
    from scripts.triage_formatter import CommonMarkTriageFormatter
    return CommonMarkTriageFormatter

  def get_hybrid_engine(self) -> Any:
    """Returns the unified Python Hybrid Engine module (scripts.ueba_hybrid_engine) from secops-risk-metrics-multistage v2.0.0+."""
    self._ensure_skill_path()
    from scripts import ueba_hybrid_engine
    return ueba_hybrid_engine

  @staticmethod
  def scope_query_to_entity(
      query: str,
      target_entity: Optional[str],
      entity_type: Optional[str] = None,
  ) -> str:
    """Scopes non-fleet Stage 1 / Sector stages to a specific target entity if provided."""
    if not target_entity or target_entity.lower() in ("fleet", "unknown", "unknown_entity", "target_entity", "*"):
      return query

    ent_upper = (entity_type or "").upper()

    def _scope_stage(match: re.Match) -> str:
      stage_name = match.group(1)
      stage_body = match.group(2)
      # Preserve fleet-wide normalization and Entity Graph stages intact
      if any(w in stage_name.lower() for w in ("fleet", "enterprise", "cohort", "peer", "global", "rare_dest", "graph")):
        return match.group(0)
      # If both $user and $host appear in the same stage (e.g. user-attributed alert surge),
      # only bind the variable matching entity_type (or $user by default).
      has_user = bool(re.search(r'\$user\s*!=\s*""', stage_body))
      has_host = bool(re.search(r'\$(?:host|asset)\s*!=\s*""', stage_body))
      if has_user and has_host:
        if ent_upper in ("ASSET", "HOST", "IP", "HOSTNAME", "DEVICE"):
          target_pattern = r'(\$(?:host|asset)\s*)!=\s*""'
        else:
          target_pattern = r'(\$user\s*)!=\s*""'
        scoped_body = re.sub(target_pattern, f'\\1= "{target_entity}"', stage_body, count=1)
      else:
        scoped_body = re.sub(
            r'(\$(?:entity|user|host|asset|sa|src_ip)\s*)!=\s*""',
            f'\\1= "{target_entity}"',
            stage_body,
            count=1,
        )
        # Fallback for raw UDM stages without a `!= ""` guard (e.g. c2_beaconing_jitter_2stage.yl2
        # or `$e.principal.asset.hostname = $host` / `$e.principal.user.userid != ""`).
        if scoped_body == stage_body and (
            "metadata.event_type" in stage_body or "$e." in stage_body
        ):
          scoped_body = re.sub(
              r'((?:\$[a-zA-Z0-9_]+\.)?(?:principal|target|src)\.(?:asset\.)?(?:hostname|ip|user\.userid)\s*=\s*(\$(?:entity|user|host|asset|sa|src_ip))\b)',
              f'\\1\n    \\2 = "{target_entity}"',
              stage_body,
              count=1,
          )
          if scoped_body == stage_body:
            scoped_body = re.sub(
                r'((\$(?:entity|user|host|asset|sa|src_ip))\s*=\s*(?:\$[a-zA-Z0-9_]+\.)?(?:principal|target|src)\.(?:asset\.)?(?:hostname|ip|user\.userid)\b)',
                f'\\1\n    \\2 = "{target_entity}"',
                stage_body,
                count=1,
            )
          if scoped_body == stage_body:
            scoped_body = re.sub(
                r'((?:\$[a-zA-Z0-9_]+\.)?(?:principal|target|src)\.(?:asset\.)?(?:hostname|ip|user\.userid)\s*)!=\s*""',
                f'\\1= "{target_entity}"',
                stage_body,
                count=1,
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
          for k in ("doubleVal", "int64Val", "stringVal", "boolVal", "uint64Val", "timestampVal"):
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
      expected_entity: Optional[str] = None,
      expected_preflight_query: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Executes a multi-stage YARA-L search query against Chronicle OneMCP."""
    # Pre-dispatch QueryIntegrityGate check (no silent query mutation)
    QueryIntegrityGate.verify_pre_dispatch(
        query,
        expected_entity=expected_entity,
        expected_preflight_query=expected_preflight_query,
        ast_validator_fn=self.validate_ast,
        raise_on_error=True,
    )

    tool_args = {
        "query": query,
        "startTime": start_iso,
        "endTime": end_iso,
        "projectId": self.tenant.project_id,
        "customerId": self.tenant.customer_id,
        "region": self.tenant.region,
    }

    query_preview = " ".join(query[:120].split())
    logger.info(f"Executing query over OneMCP: {query_preview}...")

    max_attempts = 2
    search_sem = self._get_udm_search_semaphore()
    async with search_sem:
      for attempt in range(max_attempts):
        res = await session.call_tool("udm_search", tool_args)
        if not res.content:
          return {"stats": [], "events": []}

        raw_text = res.content[0].text if hasattr(res.content[0], "text") else ""
        if not raw_text or not raw_text.strip():
          return {"stats": [], "events": []}

        is_error_flag = bool(getattr(res, "isError", False))
        try:
          parsed = json.loads(raw_text)
        except Exception as e:
          logger.warning(f"udm_search returned non-JSON text ({e}): {raw_text[:160]}")
          parsed = {"raw_text": raw_text, "stats": [], "events": []}

        try:
          QueryIntegrityGate.verify_backend_response(
              query,
              parsed,
              raw_text=raw_text,
              is_error_flag=is_error_flag,
              raise_on_error=True,
          )
          return parsed
        except ChronicleBackendQueryError:
          if attempt + 1 >= max_attempts:
            raise
          logger.warning(
              f"Retrying udm_search after ChronicleBackendQueryError (attempt {attempt + 1}/{max_attempts})"
          )

    return {"stats": [], "events": []}

  async def materialize_bridge_data_table(
      self,
      session: ClientSession,
      table_name: str,
      rows: List[Dict[str, Any]],
      columns: Optional[List[str]] = None,
      description: str = "Agentic UEBA Hunt Bridge Table",
  ) -> Dict[str, Any]:
    """Creates/updates a Chronicle Data Table (`%<table_name>`) for stateful multi-query bridging."""
    clean_name = table_name.lstrip("%").strip()
    if not columns:
      if rows:
        columns = list(rows[0].keys())
      else:
        columns = ["entity", "risk_tier", "cri_score", "primary_vector"]

    col_info = [
        {"columnIndex": idx, "originalColumn": col, "columnType": "STRING"}
        for idx, col in enumerate(columns)
    ]
    create_args = {
        "name": clean_name,
        "description": description,
        "columnInfo": col_info,
        "projectId": self.tenant.project_id,
        "customerId": self.tenant.customer_id,
        "region": self.tenant.region,
    }
    created = False
    try:
      await session.call_tool("create_data_table", create_args)
      created = True
    except Exception as e:
      logger.debug(f"create_data_table '{clean_name}' skipped/existing: {e}")

    formatted_rows = [
        {"values": [str(r.get(col, "")) for col in columns]}
        for r in rows
    ]
    added_count = 0
    if formatted_rows:
      add_args = {
          "tableName": clean_name,
          "rows": formatted_rows,
          "projectId": self.tenant.project_id,
          "customerId": self.tenant.customer_id,
          "region": self.tenant.region,
      }
      await session.call_tool("add_rows_to_data_table", add_args)
      added_count = len(formatted_rows)

    return {
        "table_name": clean_name,
        "columns": columns,
        "created": created,
        "rows_added": added_count,
    }

  async def fetch_data_table_rows(
      self,
      session: ClientSession,
      table_name: str,
  ) -> List[Dict[str, Any]]:
    """Lists rows from a Chronicle Data Table (`%<table_name>`) via OneMCP."""
    clean_name = table_name.lstrip("%").strip()
    list_args = {
        "tableName": clean_name,
        "projectId": self.tenant.project_id,
        "customerId": self.tenant.customer_id,
        "region": self.tenant.region,
    }
    res = await session.call_tool("list_data_table_rows", list_args)
    if not res or not getattr(res, "content", None):
      return []
    raw_text = res.content[0].text if hasattr(res.content[0], "text") else ""
    if not raw_text or not raw_text.strip():
      return []
    try:
      data = json.loads(raw_text)
      if isinstance(data, list):
        return data
      if isinstance(data, dict):
        return data.get("dataTableRows", data.get("rows", []))
    except Exception as e:
      logger.warning(f"list_data_table_rows returned non-JSON ({e}): {raw_text[:160]}")
    return []

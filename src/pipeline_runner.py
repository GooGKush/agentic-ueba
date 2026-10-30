# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Universal Template Pipeline Runner for SecOps Threat Hunting.

Loads canonical .yl2 templates dynamically from secops-risk-metrics-multistage
and secops-statistical-hunter, renders placeholders deterministically, executes
queries via Chronicle OneMCP, and evaluates exact statistical metrics in pure Python.

Harness truth (CRI, gate thresholds, retired models, Mode A day) is read at runtime
through src.harness_truth, and queries are validated by the skills' own validators.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, time, timezone
import functools
import importlib
import importlib.util
import json
import logging
import math
from pathlib import Path
import re
import sys
import threading
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Tuple
import weakref

import httpx
from mcp import ClientSession

from src import harness_truth as ht
from src.config import TenantConfig, get_skills_root
from src.query_integrity_gate import (
    ChronicleBackendQueryError,
    QueryIntegrityGate,
    QueryValidationError,
)

logger = logging.getLogger("PipelineRunner")

# Any {{...}} template slot (YARA-L itself never uses double braces).
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([^{}\n]*?)\s*\}\}")

# Serializes by-path loading of skill scripts across worker threads.
_SCRIPT_LOAD_LOCK = threading.Lock()


class _HarnessGateDefaults:
  """Gate defaults resolved from the canonical harness constants on every access.

  A fresh dict is returned each time, so callers cannot mutate the shared truth.
  """

  def __get__(self, instance: Any, owner: Any) -> Dict[str, Any]:
    c = ht.constants()
    return {
        "anomaly_threshold": c.DEFAULT_ANOMALY_THRESHOLD,
        "fold_change_threshold": c.DEFAULT_FOLD_CHANGE_THRESHOLD,
        "fusion_threshold_sq": c.RADAR_FUSION_DISTANCE_THRESHOLD ** 2,
        "robust_threshold": c.DEFAULT_ROBUST_THRESHOLD,
        "tukey_excess_threshold": c.DEFAULT_TUKEY_EXCESS_THRESHOLD,
        "min_baseline_days": c.DEFAULT_MIN_BASELINE_DAYS,
    }


class PipelineRunner:
  """Renders and executes multi-stage YARA-L 2.0 query templates."""

  # Root significance and maturity gates filled into templates that carry them (skill v1.8.6+ ships each
  # model's gate as a root `condition:`), read from ueba_constants via harness_truth:
  #   anomaly / fold-change / robust (MAD) / Tukey-excess thresholds: the skill defaults (3.0, 2.0, 3.5, 1.0);
  #   fusion: D >= RADAR_FUSION_DISTANCE_THRESHOLD (3.0), i.e. D^2 >= 9.0, so the query never drops an entity
  #   agentic_ueba's composite-D rule would flag (the skill's default fusion gate is the stricter 12.25);
  #   min_baseline_days: the 7-active-day maturity gate (DEFAULT_MIN_BASELINE_DAYS).
  GATE_DEFAULTS = _HarnessGateDefaults()

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

  @staticmethod
  def _template_retirement_message(template_name: str) -> Optional[str]:
    """The skill's retirement message for a template name (with or without its `_<N>stage` suffix)."""
    stem = Path(str(template_name)).name
    message = ht.retirement_message(stem)
    if message is None:
      base = re.sub(r"_\d+stage(?:\.yl2)?$", "", stem, flags=re.IGNORECASE)
      if base != stem:
        message = ht.retirement_message(base)
    return message

  def find_template(self, skill_name: str, template_name: str) -> Path:
    """Locates a .yl2 template file within the canonical skill directory.

    Retired templates are refused with the skill's own retirement message (ValueError).
    """
    retired = self._template_retirement_message(template_name)
    if retired:
      raise ValueError(retired)
    skill_dir = self.skills_root / skill_name
    candidates = [
        skill_dir / "templates" / "pipelines" / template_name,
        skill_dir / "templates" / "pipelines" / f"{template_name}.yl2",
        # Canonical decoupled 360 radar sector queries (secops-risk-metrics-multistage).
        skill_dir / "templates" / "radar_360" / template_name,
        skill_dir / "templates" / "radar_360" / f"{template_name}.yl2",
        skill_dir / "templates" / template_name,
        skill_dir / "templates" / f"{template_name}.yl2",
    ]
    for c in candidates:
      if c.is_file():
        return c
    raise FileNotFoundError(
        f"Template '{template_name}' not found under {skill_dir}/templates/"
    )

  @staticmethod
  def unrendered_placeholders(text: str) -> List[str]:
    """Names of the {{...}} slots still present in `text` (comments included)."""
    return sorted({m.group(1) for m in _PLACEHOLDER_RE.finditer(text or "")})

  @classmethod
  def assert_fully_rendered(cls, text: str, source: str = "query") -> str:
    """Returns `text`, or raises QueryValidationError if any {{...}} slot is unrendered."""
    missing = cls.unrendered_placeholders(text)
    if missing:
      raise QueryValidationError(
          [f"UNRESOLVED_TEMPLATE_PLACEHOLDERS: {source} left {missing} unrendered"], query=text
      )
    return text

  def render_template(self, template_path: Path, params: Dict[str, Any]) -> str:
    """Renders a .yl2 template by substituting {{placeholder}} slots.

    Slots the caller does not pass are filled from harness truth when they are gates (GATE_DEFAULTS) or
    Mode A date slots (the last complete UTC day D). A None value is not a value. Any slot left
    unrendered raises QueryValidationError: an unrendered {{...}} never reaches Chronicle.
    """
    raw_text = template_path.read_text(encoding="utf-8")
    values: Dict[str, Any] = {k: v for k, v in params.items() if v is not None}
    for gate_key, gate_val in self.GATE_DEFAULTS.items():
      values.setdefault(gate_key, gate_val)
    scored_day = ht.mode_a_day()
    values.setdefault("today_date", scored_day.isoformat())
    values.setdefault(
        "today_start_epoch", int(datetime.combine(scored_day, time.min, tzinfo=timezone.utc).timestamp())
    )

    def _fill(match: re.Match) -> str:
      key = match.group(1)
      return str(values[key]) if key in values else match.group(0)

    rendered = raw_text
    for _ in range(5):  # values may themselves carry slots filled by other values
      updated = _PLACEHOLDER_RE.sub(_fill, rendered)
      if updated == rendered:
        break
      rendered = updated
    return self.assert_fully_rendered(rendered, source=template_path.name)

  def _ensure_skill_path(self) -> Path:
    """Ensures secops-risk-metrics-multistage is importable and returns its path."""
    metrics_skill = self.skills_root / ht.RISK_METRICS_SKILL
    if metrics_skill.is_dir() and str(metrics_skill) not in sys.path:
      sys.path.insert(0, str(metrics_skill))
    return metrics_skill

  def _import_risk_metrics_script(self, name: str) -> ModuleType:
    """Imports secops-risk-metrics-multistage/scripts/<name>.py as `scripts.<name>`.

    Risk-metrics scripts import each other as the `scripts` package; the resolved file is checked so
    another skill's scripts directory can never stand in for it.
    """
    metrics_skill = self._ensure_skill_path()
    module = importlib.import_module(f"scripts.{name}")
    expected = (metrics_skill / "scripts" / f"{name}.py").resolve()
    if Path(module.__file__).resolve() != expected:
      raise ImportError(
          f"'scripts.{name}' resolved to {module.__file__}, not {expected}; another skill's scripts "
          f"directory is ahead of {ht.RISK_METRICS_SKILL} on sys.path."
      )
    return module

  # The stats-hunter query builder shares harness_truth's private module name (one load per process).
  _STATS_HUNTER_MODULE_NAMES: Dict[str, str] = {"multistage_query_builder": "_harness_sh_query_builder"}

  def get_stats_hunter_script(self, name: str) -> ModuleType:
    """Loads secops-statistical-hunter/scripts/<name>.py by file path under a private module name.

    The stats-hunter skill root is never put on sys.path, so its `scripts` directory cannot collide with
    the risk-metrics `scripts` package. Its builder imports the shared ueba_constants as
    `scripts.ueba_constants` (byte-identical in both skills), so the risk-metrics root is made importable
    first.
    """
    module_name = self._STATS_HUNTER_MODULE_NAMES.get(name, f"_harness_sh_{name}")
    with _SCRIPT_LOAD_LOCK:
      cached = sys.modules.get(module_name)
      if cached is not None:
        return cached
      self._ensure_skill_path()
      path = self.skills_root / ht.STATS_HUNTER_SKILL / "scripts" / f"{name}.py"
      if not path.is_file():
        raise FileNotFoundError(f"Harness source not found: {path}")
      spec = importlib.util.spec_from_file_location(module_name, path)
      if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
      module = importlib.util.module_from_spec(spec)
      sys.modules[module_name] = module
      try:
        spec.loader.exec_module(module)
      except Exception:
        sys.modules.pop(module_name, None)
        raise
      return module

  def get_stats_hunter_builder(self) -> ModuleType:
    """secops-statistical-hunter scripts/multistage_query_builder.py (router, validators, sensitivity map)."""
    return self.get_stats_hunter_script("multistage_query_builder")

  def get_micro_python_helpers(self) -> ModuleType:
    """secops-statistical-hunter scripts/micro_python_helpers.py (vetted D6 EWMA, Shannon, C2 jitter helpers)."""
    return self.get_stats_hunter_script("micro_python_helpers")

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

  def validate_ast(self, query: str, skill: Optional[str] = None) -> List[str]:
    """Validates a YARA-L 2.0 query with the skills' own validators (never re-implemented here).

    Every query:
      * secops-risk-metrics-multistage scripts/submission_tests.py: check_stage_references,
        check_root_match_stage_prefix, check_outcome_conditionals_and_divisions, check_ecg_invariants, and
        the verified-live if() branch rule (iter_if_calls + if_branch_has_compound_arithmetic) on both the
        then and the else branch;
      * secops-risk-metrics-multistage preflight MalachiteASTValidator (bare sqrt, if() then branch, outcome
        and source limits, metric calls).
    skill="secops-statistical-hunter" (raw UDM micro-plane queries) additionally runs
    multistage_query_builder.validate_multistage_syntax (incl. <= 20 variables per outcome block, root
    included) and check_scope_exclusions. skill="secops-risk-metrics-multistage" additionally runs
    submission_tests.check_Stage_1_zero_filters.

    Returns the validators' findings verbatim, de-duplicated in order. Fails closed: a validator that
    cannot load or crashes yields an AST_VALIDATOR_UNAVAILABLE error, never an empty list.
    """
    if skill not in (None, ht.STATS_HUNTER_SKILL, ht.RISK_METRICS_SKILL):
      raise ValueError(f"validate_ast: unknown skill {skill!r}")
    findings: List[str] = []
    try:
      submission = self._import_risk_metrics_script("submission_tests")
      preflight = self._import_risk_metrics_script("preflight_validator")
      for check in (
          submission.check_stage_references,
          submission.check_root_match_stage_prefix,
          submission.check_outcome_conditionals_and_divisions,
          submission.check_ecg_invariants,
      ):
        findings.extend(check(query))
      for call_text, args in submission.iter_if_calls(query):
        for label, branch in zip(("then", "else"), args[1:3]):
          if submission.if_branch_has_compound_arithmetic(branch):
            findings.append(
                f"Illegal 'if(...)' expression in query: compound arithmetic in '{label}' clause: {call_text}"
            )
      findings.extend(preflight.MalachiteASTValidator.validate_query(query))
      if skill == ht.RISK_METRICS_SKILL:
        findings.extend(submission.check_Stage_1_zero_filters(query))
      elif skill == ht.STATS_HUNTER_SKILL:
        builder = self.get_stats_hunter_builder()
        findings.extend(builder.check_scope_exclusions(query))
        findings.extend(builder.validate_multistage_syntax(query))
    except Exception as e:  # fail closed: an unvalidated query must not dispatch
      logger.error(f"Skill query validator unavailable: {type(e).__name__}: {e}")
      return [f"AST_VALIDATOR_UNAVAILABLE: {type(e).__name__}: {e}"]
    return list(dict.fromkeys(findings))

  @staticmethod
  def calculate_cri(z_score: Any) -> Optional[int]:
    """Calibrated Risk Index [0-100] for a Z / Z-equivalent score: the harness CRI (harness_truth).

    CRI(Z) = round(100 / (1 + exp(-0.6 * (Z - 3.0)))) for Z > 0, 0 for Z <= 0, and None (N/A) when the
    score is missing or not finite.
    """
    return ht.calculate_cri(z_score)

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

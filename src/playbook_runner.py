# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Markdown Playbook Parser, Scheduler Support, and UDM Event Builder.

Allows Agentic UEBA to read multi-stage YARA-L 2.0 hunting playbooks directly from
GitHub Markdown URLs (blob, raw, or repo directory) or local files, validate each
query against the Malachite AST validator, execute periodic searches via Chronicle
OneMCP, chain upstream candidate entities into seeded follow-up queries, and ingest
confirmed matches as native UDM GENERIC_EVENT records via Chronicle ImportEvents.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import logging
import math
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import httpx

from src.config import TenantConfig
from src.pipeline_runner import PipelineRunner
from src.risk_metrics_engine import RiskMetricsEngine

logger = logging.getLogger("PlaybookRunner")


class PlaybookQuerySpec:
  """Parsed specification for a single multi-stage YARA-L 2.0 query inside a Markdown playbook."""

  def __init__(
      self,
      query_id: str,
      index: int,
      section: str,
      goal: str,
      statistical_model: str,
      raw_query: str,
      plane: str,
      default_lookback_days: int,
      is_seeded: bool,
      entity_type_hint: str,
      ast_errors: List[str],
  ):
    self.query_id = query_id
    self.index = index
    self.section = section
    self.goal = goal
    self.statistical_model = statistical_model
    self.raw_query = raw_query
    self.plane = plane
    self.default_lookback_days = default_lookback_days
    self.is_seeded = is_seeded
    self.entity_type_hint = entity_type_hint
    self.ast_errors = ast_errors

  def to_dict(self, include_query: bool = False) -> Dict[str, Any]:
    data = {
        "query_id": self.query_id,
        "index": self.index,
        "section": self.section,
        "goal": self.goal,
        "statistical_model": self.statistical_model,
        "plane": self.plane,
        "default_lookback_days": self.default_lookback_days,
        "is_seeded": self.is_seeded,
        "entity_type_hint": self.entity_type_hint,
        "ast_valid": len(self.ast_errors) == 0,
        "ast_errors": self.ast_errors,
    }
    if include_query:
      data["query"] = self.raw_query
    return data


class PlaybookRunner:
  """Loads, validates, executes, and ingests UDM findings from Markdown hunting playbooks."""

  PLAYBOOK_EVENT_METADATA: Dict[str, str] = {
      "product_name": "SecOps Risk Metrics Hunter",
      "vendor_name": "Google SecOps",
      "event_type": "GENERIC_EVENT",
      "product_event_type": "PLAYBOOK_BEHAVIORAL_HUNT_MATCH",
  }

  # Example placeholder IPs used in documentation for chained follow-up queries
  SEED_PLACEHOLDER_IPS = ("10.0.0.50", "192.168.1.100")

  def __init__(
      self,
      tenant_config: Optional[TenantConfig] = None,
      risk_engine: Optional[RiskMetricsEngine] = None,
  ):
    self.tenant = tenant_config or TenantConfig()
    self.risk_engine = risk_engine or RiskMetricsEngine(self.tenant)
    self.runner: PipelineRunner = self.risk_engine.runner
    self._cache: Dict[str, Dict[str, Any]] = {}

  @staticmethod
  def derive_playbook_id(source: str) -> str:
    """Derives a clean, URL-safe playbook_id from a GitHub URL or file path."""
    cleaned = source.strip().rstrip("/")
    if cleaned.startswith(("http://", "https://")):
      parsed = urlparse(cleaned)
      parts = [p for p in parsed.path.split("/") if p]
      if parts:
        last = parts[-1]
        if last.lower().endswith(".md"):
          last = last[:-3]
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", last).strip("-").lower()
        if slug:
          return slug
    else:
      p = Path(cleaned.replace("file://", ""))
      stem = p.stem
      slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", stem).strip("-").lower()
      if slug:
        return slug
    digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:8]
    return f"playbook-{digest}"

  @staticmethod
  def normalize_playbook_source(source: str) -> str:
    """Normalizes a GitHub blob URL into a raw.githubusercontent.com URL or resolves local paths.

    Examples:
      https://github.com/GooGKush/docs/blob/main/php2shell-ueba-hunting.md
      -> https://raw.githubusercontent.com/GooGKush/docs/main/php2shell-ueba-hunting.md
    """
    raw = source.strip()
    if raw.startswith("file://"):
      return raw[len("file://") :]

    # Match https://github.com/<owner>/<repo>/blob/<branch>/<path>
    blob_match = re.match(
        r"^https?://github\.com/([^/]+)/([^/]+)/(?:blob|raw)/([^/]+)/(.+)$",
        raw,
    )
    if blob_match:
      owner, repo, ref, file_path = blob_match.groups()
      return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{file_path}"

    return raw

  @classmethod
  async def discover_repo_markdown_urls(
      cls,
      repo_url: str,
      http_client: Optional[httpx.AsyncClient] = None,
  ) -> List[str]:
    """Resolves all hunting Markdown files in a GitHub repository root or tree URL."""
    raw = repo_url.strip().rstrip("/")
    tree_match = re.match(
        r"^https?://github\.com/([^/]+)/([^/]+)(?:/tree/([^/]+)(?:/(.*))?)?$",
        raw,
    )
    if not tree_match:
      return [cls.normalize_playbook_source(raw)]

    owner, repo, ref, subpath = tree_match.groups()
    subpath = (subpath or "").strip("/")
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
    if subpath:
      api_url = f"{api_url}/{subpath}"
    params = {"ref": ref} if ref else {}

    close_client = False
    if http_client is None:
      http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
      close_client = True

    try:
      resp = await http_client.get(
          api_url,
          params=params,
          headers={"Accept": "application/vnd.github.v3+json"},
      )
      resp.raise_for_status()
      items = resp.json()
      if not isinstance(items, list):
        return [cls.normalize_playbook_source(raw)]

      excluded = {"readme.md", "license.md", "contributing.md", "changelog.md"}
      discovered: List[str] = []
      for item in items:
        if not isinstance(item, dict):
          continue
        name = str(item.get("name", ""))
        if (
            item.get("type") == "file"
            and name.lower().endswith(".md")
            and name.lower() not in excluded
        ):
          dl_url = item.get("download_url") or item.get("html_url")
          if dl_url:
            discovered.append(cls.normalize_playbook_source(str(dl_url)))
      return discovered
    finally:
      if close_client:
        await http_client.aclose()

  async def fetch_markdown(
      self,
      source: str,
      http_client: Optional[httpx.AsyncClient] = None,
  ) -> Tuple[str, str, str]:
    """Fetches Markdown content from a local path or URL with ETag/SHA256 caching.

    Returns:
      (markdown_text, normalized_source, content_sha256)
    """
    norm_source = self.normalize_playbook_source(source)

    # Local file path handling
    if not norm_source.startswith(("http://", "https://")):
      path = Path(norm_source).expanduser()
      if not path.is_file():
        raise FileNotFoundError(f"Playbook Markdown file not found: {path}")
      content = path.read_text(encoding="utf-8")
      sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
      return content, str(path.resolve()), sha

    cached = self._cache.get(norm_source, {})
    req_headers: Dict[str, str] = {"Accept": "text/plain, text/markdown, */*"}
    if cached.get("etag"):
      req_headers["If-None-Match"] = str(cached["etag"])

    close_client = False
    if http_client is None:
      http_client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
      close_client = True

    try:
      resp = await http_client.get(norm_source, headers=req_headers)
      if resp.status_code == 304 and cached.get("content"):
        return (
            str(cached["content"]),
            norm_source,
            str(cached["sha256"]),
        )
      resp.raise_for_status()
      content = resp.text
      sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
      self._cache[norm_source] = {
          "content": content,
          "sha256": sha,
          "etag": resp.headers.get("ETag"),
          "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
      }
      return content, norm_source, sha
    except Exception as fetch_err:
      if cached.get("content"):
        logger.warning(
            f"Transient error fetching {norm_source} ({fetch_err}); using cached version "
            f"(sha256={str(cached.get('sha256'))[:12]})."
        )
        return (
            str(cached["content"]),
            norm_source,
            str(cached["sha256"]),
        )
      raise
    finally:
      if close_client:
        await http_client.aclose()

  @staticmethod
  def _infer_entity_type_hint(query: str) -> str:
    """Infers whether the primary entity in Stage 1 is USER, IP, or ASSET."""
    first_stage_match = re.search(r"stage\s+[a-zA-Z0-9_]+\s*\{(.*?)\}", query, re.DOTALL)
    stage_body = first_stage_match.group(1) if first_stage_match else query

    if re.search(r"(?:principal|target|src)\.user\.userid\s*=\s*\$(?:entity|user)", stage_body) or re.search(
        r"\$(?:entity|user)\s*=\s*(?:principal|target|src)\.user\.userid", stage_body
    ):
      return "USER"
    if re.search(r"(?:principal|target|src)\.(?:asset\.)?ip\s*=\s*\$(?:entity|ip|client_ip|target_ip)", stage_body) or re.search(
        r"\$(?:entity|ip|client_ip|target_ip)\s*=\s*(?:principal|target|src)\.(?:asset\.)?ip", stage_body
    ):
      return "IP"
    return "ASSET"

  @staticmethod
  def _infer_lookback_days(query: str, goal: str, model: str) -> int:
    """Infers the optimal lookback window in days for a multi-stage query."""
    if "metrics." in query:
      # 30-day rolling metrics require a 35-day window to populate all 30 historical buckets
      return 35

    combined = f"{goal} {model} {query}".lower()
    if any(k in combined for k in ("5m", "bailout", "fano", "burst", "1h")):
      if "by 1d" not in query:
        return 1
    if any(k in combined for k in ("zipf", "markov", "hurdle", "mad", "poisson_rare", "beta_binomial", "by 1d")):
      return 7
    return 1

  @classmethod
  def _is_seeded_query(cls, query: str) -> bool:
    """Returns True if the query contains documentation example seed IPs or a seed replacement marker."""
    if any(ip in query for ip in cls.SEED_PLACEHOLDER_IPS):
      return True
    if re.search(r"//\s*Replace with candidate", query, re.IGNORECASE):
      return True
    return False

  def parse_markdown_playbook(self, markdown_text: str) -> List[PlaybookQuerySpec]:
    """Extracts and validates all multi-stage YARA-L 2.0 queries from a Markdown document."""
    lines = markdown_text.splitlines()
    current_heading = "Playbook Query"
    fence_open = False
    fence_lang = ""
    fence_lines: List[str] = []
    heading_at_fence_start = current_heading

    raw_blocks: List[Tuple[str, str]] = []
    for line in lines:
      stripped = line.strip()
      if not fence_open:
        heading_match = re.match(r"^(#{1,4})\s+(.+)$", stripped)
        if heading_match:
          current_heading = heading_match.group(2).strip()
        fence_start = re.match(r"^```([a-zA-Z0-9_-]*)\s*$", stripped)
        if fence_start:
          fence_open = True
          fence_lang = fence_start.group(1).lower()
          fence_lines = []
          heading_at_fence_start = current_heading
      else:
        if stripped == "```":
          block_text = "\n".join(fence_lines).strip()
          if fence_lang in ("yara", "yaral", "yl2", ""):
            if re.search(r"^\s*stage\s+[a-zA-Z0-9_]+\s*\{", block_text, re.MULTILINE):
              raw_blocks.append((heading_at_fence_start, block_text))
          fence_open = False
          fence_lang = ""
          fence_lines = []
        else:
          fence_lines.append(line)

    specs: List[PlaybookQuerySpec] = []
    for idx, (section, query_text) in enumerate(raw_blocks, 1):
      goal_match = re.search(r"//\s*Goal:\s*(.+)", query_text)
      model_match = re.search(
          r"//\s*(?:Statistical Model|ARCHITECTURE):\s*(.+)", query_text
      )
      goal = goal_match.group(1).strip() if goal_match else section
      model = (
          model_match.group(1).strip()
          if model_match
          else ("MACRO_30D_METRICS" if "metrics." in query_text else "RAW_STATISTICAL_HUNTER")
      )
      plane = "MACRO_METRICS" if "metrics." in query_text else "RAW_TELEMETRY"
      lookback_days = self._infer_lookback_days(query_text, goal, model)
      is_seeded = self._is_seeded_query(query_text)
      entity_type_hint = self._infer_entity_type_hint(query_text)

      slug_source = re.sub(r"[^a-zA-Z0-9]+", "_", section or goal).strip("_").lower()
      slug_short = "_".join(slug_source.split("_")[:6]) or f"hunt_{idx}"
      query_id = f"q{idx:02d}_{slug_short}"

      ast_errors = self.runner.validate_ast(query_text)
      specs.append(
          PlaybookQuerySpec(
              query_id=query_id,
              index=idx,
              section=section,
              goal=goal,
              statistical_model=model,
              raw_query=query_text,
              plane=plane,
              default_lookback_days=lookback_days,
              is_seeded=is_seeded,
              entity_type_hint=entity_type_hint,
              ast_errors=ast_errors,
          )
      )

    return specs

  @classmethod
  def prepare_seeded_query(
      cls,
      query_text: str,
      candidate_entities: Sequence[str],
      unscope_to_fleet: bool = False,
  ) -> Optional[str]:
    """Substitutes upstream candidate IPs/hosts into a seeded query or unscopes it to fleetwide.

    Returns:
      Modified query string ready for execution, or None if the query should be skipped
      because no upstream candidate entities were found and `unscope_to_fleet` is False.
    """
    clean_candidates = []
    for c in candidate_entities:
      val = str(c).strip()
      if val and val not in clean_candidates and not any(ch in val for ch in ('"', "\\", "\n")):
        clean_candidates.append(val)

    seed_pattern = re.compile(
        r"^[ \t]*\((?:[a-zA-Z0-9_$.]+\s*=\s*\"(?:10\.0\.0\.50|192\.168\.1\.100)\"(?:\s+or\s+)?)+[ \t]*\)[ \t]*\r?\n?",
        re.MULTILINE,
    )

    if clean_candidates:
      # Extract field name used in the placeholder expression (e.g. principal.asset.ip)
      field_match = re.search(
          r"\(([a-zA-Z0-9_$.]+)\s*=\s*\"10\.0\.0\.50\"",
          query_text,
      )
      field_name = field_match.group(1) if field_match else "principal.asset.ip"
      or_clauses = " or ".join(f'{field_name} = "{ip}"' for ip in clean_candidates[:25])
      replacement_line = f"    ({or_clauses})\n"
      if seed_pattern.search(query_text):
        return seed_pattern.sub(replacement_line, query_text, count=1)

    if unscope_to_fleet:
      # Remove placeholder filter line so the query evaluates across the entire fleet
      return seed_pattern.sub("", query_text)

    return None

  @staticmethod
  def extract_row_entity(
      row: Dict[str, Any],
      default_entity_type: str = "ASSET",
  ) -> Tuple[str, str]:
    """Extracts (entity_id, entity_type) from a parsed Chronicle stats row."""
    # Priority order for primary entity identification
    if row.get("user"):
      return str(row["user"]), "USER"
    if row.get("target_ip"):
      return str(row["target_ip"]), "IP"
    if row.get("host"):
      return str(row["host"]), "ASSET"
    if row.get("entity"):
      val = str(row["entity"])
      # Check if val is an IPv4/IPv6 literal
      try:
        ipaddress.ip_address(val)
        return val, "IP"
      except ValueError:
        return val, default_entity_type
    if row.get("client_ip"):
      return str(row["client_ip"]), "IP"

    for k, v in row.items():
      if v is not None and str(v).strip():
        return str(v).strip(), default_entity_type
    return "unknown_entity", default_entity_type

  @staticmethod
  def extract_row_effective_z(row: Dict[str, Any]) -> Tuple[float, str]:
    """Extracts (effective_z_score, score_field_name) from a parsed Chronicle stats row.

    Maps model-specific statistical outputs (Z-score, Modified Z, Hurdle score,
    Markov surprisal, Zipf rarity, Fano factor, squared Z norms, Beta-Binomial rate,
    or causal sequence matches) onto a unified positive sigma scale for CRI scoring.
    """
    direct_z_fields = (
        "z_score",
        "personal_z",
        "m_z_score",
        "hurdle_threat_score",
        "markov_threat_score",
        "zipf_rarity_score",
        "recon_score",
        "fail_z",
        "intensity_z",
        "surprisal_score",
        "fano_factor",
    )
    for field in direct_z_fields:
      val = row.get(field)
      if val is not None:
        try:
          fval = float(val)
          if not math.isnan(fval):
            return fval, field
        except (ValueError, TypeError):
          pass

    squared_z_fields = ("composite_threat_norm_sq", "poisson_z_sq")
    for field in squared_z_fields:
      val = row.get(field)
      if val is not None:
        try:
          fval = max(0.0, float(val))
          return math.sqrt(fval), field
        except (ValueError, TypeError):
          pass

    if row.get("regularized_failure_prob") is not None:
      try:
        prob = float(row["regularized_failure_prob"])
        # Map regularized failure rate [0.40 .. 1.0] onto sigma [3.5 .. 8.0]
        eff_z = 3.5 + max(0.0, (prob - 0.40)) * 7.5
        return round(eff_z, 2), "regularized_failure_prob"
      except (ValueError, TypeError):
        pass

    if row.get("carrier_events") is not None or row.get("bailout_events") is not None:
      # Two-stage causal sequence bridge match that passed root `condition:`
      return 4.5, "causal_sequence_match"

    return 3.5, "condition_gate_match"

  def build_playbook_match_udm_event(
      self,
      playbook_id: str,
      playbook_source: str,
      playbook_sha256: str,
      spec: PlaybookQuerySpec,
      row: Dict[str, Any],
      run_timestamp_iso: str,
      evaluated_day: str,
  ) -> Dict[str, Any]:
    """Builds a Chronicle ImportEvents-compliant UDM GENERIC_EVENT for a matched row."""
    entity_id, entity_type = self.extract_row_entity(row, spec.entity_type_hint)
    effective_z, score_field = self.extract_row_effective_z(row)
    raw_cri = self.runner.calculate_cri(effective_z)
    # Any row passing a playbook query's root `condition:` is a confirmed outlier (>= 50 CRI)
    cri_score = max(50, raw_cri)
    severity = self.risk_engine.derive_cri_severity(cri_score)

    if entity_type == "USER":
      principal: Dict[str, Any] = {"user": {"userid": entity_id}}
    elif entity_type == "IP":
      principal = {"ip": [entity_id], "asset": {"ip": [entity_id]}}
    else:
      principal = {"hostname": entity_id, "asset": {"hostname": entity_id}}

    labels = [
        {"key": "Risk Source", "value": "Autonomous Markdown Playbook Hunter"},
        {"key": "Playbook ID", "value": playbook_id},
        {"key": "Playbook Source", "value": playbook_source},
        {"key": "Playbook SHA256", "value": playbook_sha256[:16]},
        {"key": "Query ID", "value": spec.query_id},
        {"key": "Query Section", "value": spec.section},
        {"key": "Goal", "value": spec.goal},
        {"key": "Statistical Model", "value": spec.statistical_model},
        {"key": "Plane", "value": spec.plane},
        {"key": "Evaluated Window", "value": evaluated_day},
        {"key": "Target Entity", "value": entity_id},
        {"key": "Entity Type", "value": entity_type},
        {"key": "Score Metric", "value": score_field},
        {"key": "Effective Z-Score", "value": f"+{effective_z:.2f}σ"},
        {"key": "CRI Score", "value": str(cri_score)},
        {"key": "Severity Tier", "value": severity},
    ]

    # Attach all returned query outcome columns as structured labels
    for col_key, col_val in sorted(row.items()):
      if col_val is None:
        continue
      if isinstance(col_val, (list, dict)):
        val_str = json.dumps(col_val)[:256]
      elif isinstance(col_val, float):
        val_str = f"{col_val:.4f}".rstrip("0").rstrip(".")
      else:
        val_str = str(col_val)[:256]
      labels.append({"key": f"col.{col_key}", "value": val_str})

    summary_text = (
        f"[{playbook_id}/{spec.query_id}] {spec.goal} — "
        f"{entity_type} {entity_id} matched ({score_field}={effective_z:.2f}, CRI={cri_score}/100)"
    )

    return {
        "metadata": {
            "event_timestamp": run_timestamp_iso,
            "ingested_timestamp": run_timestamp_iso,
            "product_name": self.PLAYBOOK_EVENT_METADATA["product_name"],
            "vendor_name": self.PLAYBOOK_EVENT_METADATA["vendor_name"],
            "event_type": self.PLAYBOOK_EVENT_METADATA["event_type"],
            "product_event_type": self.PLAYBOOK_EVENT_METADATA["product_event_type"],
            "description": summary_text,
        },
        "observer": {
            "hostname": "secops-agentic-playbook-hunter",
            "application": "Google SecOps Autonomous Playbook Runner",
        },
        "principal": principal,
        "target": {
            "resource": {
                "name": self.PLAYBOOK_EVENT_METADATA["product_event_type"],
                "attribute": {"labels": labels},
            }
        },
        "security_result": [
            {
                "rule_name": f"{playbook_id}:{spec.query_id}",
                "rule_type": "PLAYBOOK_MULTISTAGE_YARAL",
                "threat_name": spec.section,
                "threat_status": "ACTIVE",
                "severity": severity,
                "risk_score": cri_score,
                "confidence_score": round(effective_z, 2),
                "summary": summary_text,
                "description": spec.goal,
            }
        ],
    }

  async def execute_playbook(
      self,
      session: Any,
      source: str,
      playbook_id: Optional[str] = None,
      ingest_events: bool = True,
      unscope_seeded_to_fleet: bool = False,
      inter_query_delay_sec: float = 1.0,
      lookback_days_override: Optional[int] = None,
      now_utc: Optional[datetime] = None,
      should_emit_fn: Optional[Callable[[str, str, str, str, float], bool]] = None,
      record_emit_fn: Optional[Callable[[str, str, str, str, float, int], None]] = None,
      http_client: Optional[httpx.AsyncClient] = None,
  ) -> Dict[str, Any]:
    """Fetches, parses, validates, and executes all multi-stage queries in a Markdown playbook."""
    stamp_dt = now_utc or datetime.now(timezone.utc)
    run_timestamp_iso = stamp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    bucket_date = stamp_dt.strftime("%Y-%m-%d")

    pb_id = playbook_id or self.derive_playbook_id(source)
    md_text, norm_source, content_sha = await self.fetch_markdown(
        source, http_client=http_client
    )
    specs = self.parse_markdown_playbook(md_text)

    query_reports: List[Dict[str, Any]] = []
    udm_events_to_ingest: List[Dict[str, Any]] = []
    previous_candidates: List[str] = []

    total_matches = 0
    total_emitted = 0
    total_suppressed = 0
    queries_executed = 0
    queries_skipped = 0

    for idx, spec in enumerate(specs):
      if spec.ast_errors:
        logger.warning(
            f"Playbook '{pb_id}' query '{spec.query_id}' skipped due to AST validation errors: {spec.ast_errors}"
        )
        queries_skipped += 1
        query_reports.append({
            "query_id": spec.query_id,
            "section": spec.section,
            "goal": spec.goal,
            "status": "SKIPPED_AST_INVALID",
            "ast_errors": spec.ast_errors,
            "matches_found": 0,
        })
        previous_candidates = []
        continue

      query_to_run = spec.raw_query
      if spec.is_seeded:
        prepared = self.prepare_seeded_query(
            spec.raw_query,
            candidate_entities=previous_candidates,
            unscope_to_fleet=unscope_seeded_to_fleet,
        )
        if prepared is None:
          queries_skipped += 1
          query_reports.append({
              "query_id": spec.query_id,
              "section": spec.section,
              "goal": spec.goal,
              "status": "SKIPPED_NO_UPSTREAM_CANDIDATES",
              "matches_found": 0,
          })
          previous_candidates = []
          continue
        query_to_run = prepared

      if queries_executed > 0 and inter_query_delay_sec > 0:
        await asyncio.sleep(inter_query_delay_sec)

      lb_days = (
          int(lookback_days_override)
          if lookback_days_override is not None
          else spec.default_lookback_days
      )
      start_dt = stamp_dt - timedelta(days=max(1, lb_days))
      start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

      try:
        raw_resp = await self.runner.execute_query_via_mcp(
            session=session,
            query=query_to_run,
            start_iso=start_iso,
            end_iso=run_timestamp_iso,
        )
        queries_executed += 1
        rows = self.runner.parse_stats_response(raw_resp)
      except Exception as q_err:
        logger.error(f"Playbook '{pb_id}' query '{spec.query_id}' execution failed: {q_err}")
        query_reports.append({
            "query_id": spec.query_id,
            "section": spec.section,
            "goal": spec.goal,
            "status": "ERROR",
            "error": str(q_err),
            "matches_found": 0,
        })
        previous_candidates = []
        continue

      current_candidates: List[str] = []
      matched_entities: List[Dict[str, Any]] = []
      emitted_for_query = 0
      suppressed_for_query = 0

      for row in rows:
        entity_id, entity_type = self.extract_row_entity(row, spec.entity_type_hint)
        effective_z, score_field = self.extract_row_effective_z(row)
        if entity_id and entity_id != "unknown_entity":
          current_candidates.append(entity_id)

        total_matches += 1
        if should_emit_fn is not None:
          if not should_emit_fn(bucket_date, pb_id, spec.query_id, entity_id, effective_z):
            total_suppressed += 1
            suppressed_for_query += 1
            continue

        udm_event = self.build_playbook_match_udm_event(
            playbook_id=pb_id,
            playbook_source=norm_source,
            playbook_sha256=content_sha,
            spec=spec,
            row=row,
            run_timestamp_iso=run_timestamp_iso,
            evaluated_day=bucket_date,
        )
        udm_events_to_ingest.append(udm_event)
        cri_score = udm_event["security_result"][0]["risk_score"]
        total_emitted += 1
        emitted_for_query += 1

        if record_emit_fn is not None:
          record_emit_fn(bucket_date, pb_id, spec.query_id, entity_id, effective_z, cri_score)

        matched_entities.append({
            "entity": entity_id,
            "entity_type": entity_type,
            "score_field": score_field,
            "effective_z": round(effective_z, 2),
            "cri_score": cri_score,
        })

      previous_candidates = current_candidates
      query_reports.append({
          "query_id": spec.query_id,
          "section": spec.section,
          "goal": spec.goal,
          "statistical_model": spec.statistical_model,
          "plane": spec.plane,
          "lookback_days": lb_days,
          "status": "SUCCESS",
          "matches_found": len(rows),
          "matches_emitted": emitted_for_query,
          "matches_suppressed_dedup": suppressed_for_query,
          "matched_entities": matched_entities[:25],
      })

    ingestion_result: Dict[str, Any] = {
        "status": "SKIPPED" if not ingest_events else "NO_EVENTS",
        "events_ingested": 0,
        "batches": 0,
    }
    if ingest_events and udm_events_to_ingest:
      try:
        ingestion_result = self.risk_engine.ingest_udm_events(udm_events_to_ingest)
      except Exception as ing_err:
        logger.error(f"Playbook '{pb_id}' UDM ingestion failed: {ing_err}")
        ingestion_result = {
            "status": "ERROR",
            "error": str(ing_err),
            "events_ingested": 0,
            "batches": 0,
        }

    return {
        "status": "SUCCESS",
        "playbook_id": pb_id,
        "source": source,
        "normalized_source": norm_source,
        "content_sha256": content_sha,
        "timestamp": run_timestamp_iso,
        "evaluated_day": bucket_date,
        "queries_discovered": len(specs),
        "queries_executed": queries_executed,
        "queries_skipped": queries_skipped,
        "total_matches_found": total_matches,
        "total_matches_emitted": total_emitted,
        "total_matches_suppressed_dedup": total_suppressed,
        "total_udm_events_generated": len(udm_events_to_ingest),
        "ingestion": ingestion_result,
        "queries": query_reports,
    }

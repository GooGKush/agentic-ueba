# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Markdown Playbook Parser, Scheduler Support, and UDM Event Builder.

Allows Agentic UEBA to read multi-stage YARA-L 2.0 hunting playbooks directly from
GitHub Markdown URLs (blob, raw, or repo directory) or local files, validate each
query against the Malachite AST validator, execute periodic searches via Chronicle
OneMCP, chain upstream candidate entities into seeded follow-up queries, and ingest
confirmed matches as native UDM GENERIC_EVENT records via Chronicle ImportEvents.

Scoring, gating and time windows follow the remediated UEBA harness at runtime
(`src.harness_truth`): native model scores map onto the Z-equivalent scale through the
skills' score-semantics registry, CRI comes from the canonical formula, verdicts and
recommended actions from the CRI bands, UDM write-back requires
`writeback_cri_threshold()`, Wave 3 loopback convergence requires
`loopback_thresholds()`, and every query runs on the Mode A / Entity Graph / raw-baseline
windows (`mode_a_window`, `ecg_window`, `raw_baseline_window`) for the last complete UTC day D,
with its event-day pins and first-scored dates set to D at execution (`event_day_pin`).
"""

import asyncio
from datetime import date, datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import logging
import math
from pathlib import Path
import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
import uuid

import httpx

from src import harness_truth
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
      is_capstone: bool = False,
      is_udm_gated: bool = False,
      execution_wave: Optional[int] = None,
  ):
    self.query_id = query_id
    self.index = index
    self.section = section
    self.goal = goal
    self.statistical_model = statistical_model
    self.raw_query = raw_query
    self.plane = plane
    self.default_lookback_days = lookback_days if (lookback_days := default_lookback_days) else 1
    self.is_seeded = is_seeded
    self.is_capstone = is_capstone
    self.is_udm_gated = is_udm_gated
    self.execution_wave = (
        int(execution_wave)
        if execution_wave is not None
        else (2 if is_udm_gated else (3 if is_capstone else 1))
    )
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
        "is_capstone": self.is_capstone,
        "is_udm_gated": self.is_udm_gated,
        "execution_wave": self.execution_wave,
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

  # Example placeholder IPs and user/SA entities used in documentation for Option 2 chained follow-up queries
  SEED_PLACEHOLDER_IPS = ("10.0.0.50", "192.168.1.100")
  SEED_PLACEHOLDER_VALUES = (
      "10.0.0.50",
      "192.168.1.100",
      "user@example.com",
      "admin@example.com",
      "sa-app@proj.iam.gserviceaccount.com",
      "sa-worker@proj.iam.gserviceaccount.com",
  )

  # Strict Telemetry Physics Guardrail: raw UDM statistical hunts are bounded by the harness micro
  # Mode B cap (harness_truth.mode_caps()["mode_b_micro_days"]); see max_raw_telemetry_lookback_days().
  _METRICS_CALL_RE = re.compile(r"^[ \t]*(?!//).*?\bmetrics\.[a-zA-Z0-9_]+\s*\(", re.MULTILINE)

  # Entity Graph joins (same detection as the risk-metrics hybrid engine) and the raw-baseline
  # scoring gate used by MAD / quantile pipelines that need a wide raw window.
  _ECG_JOIN_RE = re.compile(r"\bgraph\.(?:entity|metadata|relations)\b")
  _SCORING_WINDOW_RE = re.compile(r"\$in_scoring_window\b")
  # timestamp.get_date() of the event time (optional event variable and time-zone argument).
  _EVENT_DATE_CALL = (
      r'timestamp\.get_date\(\s*(?:\$[A-Za-z_]\w*\.)?metadata\.event_timestamp\.seconds\s*(?:,\s*"[^"\n]*"\s*)?\)'
  )
  # Event-day pin `... = "YYYY-MM-DD"` and the first-scored date of a `$in_scoring_window` gate
  # (`$in_scoring_window = max(if(... >= "YYYY-MM-DD", 1, 0))` or its `{{first_scored_date}}` slot).
  _EVENT_DATE_PIN_RE = re.compile(rf'({_EVENT_DATE_CALL}\s*=\s*)"\d{{4}}-\d{{2}}-\d{{2}}"')
  _FIRST_SCORED_DATE_RE = re.compile(
      rf'(\$in_scoring_window\s*=[^\n]*?{_EVENT_DATE_CALL}\s*>=\s*)"\d{{4}}-\d{{2}}-\d{{2}}"'
  )
  _FIRST_SCORED_SLOT_RE = re.compile(r"\{\{\s*first_scored_date\s*\}\}")
  _LOOPBACK_EVENT_LITERAL = '"PLAYBOOK_BEHAVIORAL_HUNT_MATCH"'
  _EVENT_VARIABLE_RE = re.compile(
      r"\$([A-Za-z_]\w*)\.(?:metadata|principal|target|src|network|security_result|about|intermediary|observer|extensions)\."
  )

  # Domain containment recommended at Critical CRI (harness_truth.recommended_action), by entity type.
  # Recommendations only: agentic_ueba never executes containment.
  CONTAINMENT_ACTION_BY_ENTITY_TYPE: Dict[str, str] = {
      "USER": "LOCK_ACCOUNT",
      "IP": "THROTTLE_EGRESS",
      "ASSET": "ISOLATE_HOST",
  }

  # Wave 3 capstone row columns carrying the loopback evidence (distinct scenario hits and sum Z^2).
  LOOPBACK_DISTINCT_HIT_COLUMNS: Tuple[str, ...] = (
      "distinct_scenarios_matched",
      "distinct_queries",
      "distinct_queries_matched",
      "distinct_hits",
      "distinct_scenarios",
  )
  LOOPBACK_SUM_Z_SQ_COLUMNS: Tuple[str, ...] = (
      "capstone_threat_norm_sq",
      "composite_threat_norm_sq",
      "sum_z_sq",
  )
  # Score-semantics registry key used to map an in-memory convergence sum Z^2 onto the Z-equivalent scale.
  CONVERGENCE_SCORE_KEY = "composite_threat_norm_sq"

  # Default UDM Loopback indexing wait budget (45 attempts * 30s = 22.5 minutes) to accommodate
  # Chronicle SIEM UDM indexing latency (typically 2-20 minutes for ImportEvents).
  DEFAULT_UDM_VALIDATION_MAX_ATTEMPTS = 45
  DEFAULT_UDM_VALIDATION_POLL_SEC = 30.0

  @classmethod
  def _has_metrics_call(cls, query: str) -> bool:
    """Returns True only if the query invokes a pre-computed `metrics.<fn>(...)` expression outside comments."""
    return bool(cls._METRICS_CALL_RE.search(query))

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

    if re.search(
        r"(?:principal|target|src)\.user\.userid\s*=\s*\$[a-zA-Z0-9_]+", stage_body
    ) or re.search(
        r"\$[a-zA-Z0-9_]+\s*=\s*(?:principal|target|src)\.user\.userid", stage_body
    ):
      return "USER"
    if re.search(
        r"(?:principal|target|src)\.(?:asset\.)?ip\s*=\s*\$[a-zA-Z0-9_]+", stage_body
    ) or re.search(
        r"\$[a-zA-Z0-9_]+\s*=\s*(?:principal|target|src)\.(?:asset\.)?ip", stage_body
    ):
      return "IP"
    return "ASSET"

  @classmethod
  def _infer_lookback_days(cls, query: str, goal: str, model: str) -> int:
    """Infers the optimal lookback window in days for a multi-stage query."""
    if cls._has_metrics_call(query):
      # 30-day rolling metrics require a 35-day window to populate all 30 historical buckets
      return 35

    combined = f"{goal} {model} {query}".lower()
    if any(k in combined for k in ("5m", "bailout", "fano", "burst", "1h")):
      if "by 1d" not in query:
        return 1
    if "playbook_behavioral_hunt_match" in combined:
      return 7
    if any(
        k in combined
        for k in (
            "zipf",
            "markov",
            "hurdle",
            "mad",
            "quantile",
            "tukey",
            "bowley",
            "iqr",
            "poisson_rare",
            "beta_binomial",
            "by 1d",
        )
    ):
      return 7
    return 1

  @classmethod
  def max_raw_telemetry_lookback_days(cls) -> int:
    """Telemetry Physics Guardrail ceiling for raw UDM hunts: the harness micro Mode B cap."""
    return int(harness_truth.mode_caps()["mode_b_micro_days"])

  @classmethod
  def resolve_effective_lookback_days(
      cls, spec: PlaybookQuerySpec, lookback_days_override: Optional[int] = None
  ) -> int:
    """Resolves lookback days for a playbook query while enforcing the Telemetry Physics Guardrail.

    Raw UDM statistical hunter queries (`RAW_TELEMETRY`) are clamped to the harness micro Mode B cap
    (`max_raw_telemetry_lookback_days()`) even when a wider `lookback_days_override` (e.g., 30d/35d) is
    passed, preventing 1M row scan cap timeouts.
    """
    lb = (
        int(lookback_days_override)
        if lookback_days_override is not None
        else spec.default_lookback_days
    )
    lb = max(1, lb)
    raw_cap = cls.max_raw_telemetry_lookback_days()
    if spec.plane == "RAW_TELEMETRY" and lb > raw_cap:
      logger.info(
          f"Telemetry Physics Guardrail: clamping RAW_TELEMETRY query '{spec.query_id}' "
          f"lookback from {lb}d to {raw_cap}d."
      )
      return raw_cap
    return lb

  @staticmethod
  def _strip_yaral_comments(query: str) -> str:
    no_block = re.sub(r"/\*.*?\*/", "", query, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", no_block)

  @staticmethod
  def _utc_midnight(day: date) -> str:
    return f"{day.isoformat()}T00:00:00Z"

  @classmethod
  def resolve_query_window(
      cls,
      spec: PlaybookQuerySpec,
      evaluated_day: date,
      now_utc: Optional[datetime] = None,
      lookback_days_override: Optional[int] = None,
  ) -> Dict[str, Any]:
    """Resolves the `[start, end)` search window of a playbook query for scored UTC day D.

    D is the last complete UTC day (`harness_truth.mode_a_day`). Windows:
    * UDM loopback queries (Stage B and Capstone): `[D, now + 2m)`, covering the scored day and the
      PLAYBOOK_BEHAVIORAL_HUNT_MATCH events written during this run (scoped by run ID).
    * `metrics.*` queries: Mode A `harness_truth.mode_a_window(D)`; with an explicit lookback override,
      a Mode B fixed-baseline timeline ending at D, capped by `mode_caps()["mode_b_macro_days"]`.
    * `metrics.*` queries gated by `$in_scoring_window` (raw MAD / quantile baselines): the raw 30-day
      baseline window `harness_truth.raw_baseline_window(D)`, as the risk-metrics hybrid engine.
    * Entity Graph joins: `harness_truth.ecg_window(D)` with raw-event stages pinned to D
      (`pin_event_stages=True`, see `pin_query_to_scored_day`).
    * Raw telemetry: complete UTC days ending at D (`resolve_effective_lookback_days`).
    """
    day_start, day_end = harness_truth.mode_a_window(evaluated_day)
    end_date = evaluated_day + timedelta(days=1)

    def _window(mode: str, start: str, end: str, pin_event_stages: bool = False) -> Dict[str, Any]:
      start_date = datetime.strptime(start[:10], "%Y-%m-%d").date()
      return {
          "mode": mode,
          "start": start,
          "end": end,
          "scored_day": evaluated_day.isoformat(),
          "lookback_days": max(1, (end_date - start_date).days),
          "pin_event_stages": pin_event_stages,
      }

    if spec.is_capstone:
      now = max(datetime.now(timezone.utc), now_utc or datetime.now(timezone.utc))
      loopback_end = (now + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
      return _window("LOOPBACK_RUN_SCOPED", day_start, loopback_end)

    code = cls._strip_yaral_comments(spec.raw_query)
    has_ecg = bool(cls._ECG_JOIN_RE.search(code))
    caps = harness_truth.mode_caps()

    if spec.plane == "MACRO_METRICS":
      if cls._SCORING_WINDOW_RE.search(code):
        raw_start, raw_end = harness_truth.raw_baseline_window(evaluated_day)
        return _window("RAW_BASELINE_SCORING_WINDOW", raw_start, raw_end)
      if has_ecg:
        ecg_start, ecg_end = harness_truth.ecg_window(evaluated_day)
        return _window("ECG_MODE_A", ecg_start, ecg_end, pin_event_stages=True)
      scored_days = 1
      if lookback_days_override is not None and int(lookback_days_override) > 1:
        scored_days = min(int(lookback_days_override), int(caps["mode_b_macro_days"]))
      if scored_days <= 1:
        return _window("MODE_A", day_start, day_end)
      start = cls._utc_midnight(evaluated_day - timedelta(days=scored_days - 1))
      return _window("MODE_B", start, day_end)

    lb_days = cls.resolve_effective_lookback_days(spec, lookback_days_override)
    if has_ecg and lb_days <= 1:
      ecg_start, ecg_end = harness_truth.ecg_window(evaluated_day)
      return _window("ECG_MODE_A", ecg_start, ecg_end, pin_event_stages=True)
    start = cls._utc_midnight(evaluated_day - timedelta(days=lb_days - 1))
    if has_ecg:
      start = min(start, harness_truth.ecg_window(evaluated_day)[0])
    return _window("MODE_A" if lb_days <= 1 else "RAW_LOOKBACK", start, day_end)

  @staticmethod
  def _named_stage_body_spans(query: str) -> List[Tuple[str, int, int]]:
    """`(stage_name, body_start, body_end)` for each named stage, by brace depth (comments/strings skipped)."""
    spans: List[Tuple[str, int, int]] = []
    for m in re.finditer(r"(?m)^[ \t]*stage\s+([A-Za-z0-9_]+)\s*\{", query):
      depth, i, n = 1, m.end(), len(query)
      quote: Optional[str] = None
      while i < n and depth:
        ch = query[i]
        if quote:
          if ch == quote and query[i - 1] != "\\":
            quote = None
        elif ch in "\"`":
          quote = ch
        elif query.startswith("//", i):
          nl = query.find("\n", i)
          i = n if nl < 0 else nl
          continue
        elif query.startswith("/*", i):
          close = query.find("*/", i + 2)
          i = n if close < 0 else close + 2
          continue
        elif ch == "{":
          depth += 1
        elif ch == "}":
          depth -= 1
        i += 1
      if depth == 0:
        spans.append((m.group(1), m.end(), i - 1))
    return spans

  @classmethod
  def pin_event_stages_to_day(cls, query_text: str, day: date) -> str:
    """Pins each raw-event named stage of an Entity Graph query to scored day D.

    Uses `harness_truth.event_day_pin(D)`. Graph stages and stages derived from other stages are left
    alone; an existing `timestamp.get_date(...) = "YYYY-MM-DD"` pin is re-dated to D (as the
    risk-metrics hybrid engine does) instead of being duplicated. A pin that only appears in a comment
    is not a pin.
    """
    pin = harness_truth.event_day_pin(day)
    spans = cls._named_stage_body_spans(query_text)
    names = [name for name, _, _ in spans]
    insertions: List[Tuple[int, int, str]] = []
    for name, body_start, body_end in spans:
      body = query_text[body_start:body_end]
      body_code = cls._strip_yaral_comments(body)
      event_part = re.split(r"\b(?:match|outcome|condition|order)\s*:", body_code, maxsplit=1)[0]
      if re.search(r"\bgraph\.", event_part):
        continue
      if any(re.search(r"\$" + re.escape(other) + r"\.", event_part) for other in names if other != name):
        continue
      if cls._EVENT_DATE_PIN_RE.search(body_code):
        insertions.append((body_start, body_end, cls._EVENT_DATE_PIN_RE.sub(rf'\g<1>"{day.isoformat()}"', body)))
        continue
      event_vars = sorted(set(cls._EVENT_VARIABLE_RE.findall(event_part)))
      predicates = (
          [pin.replace("metadata.event_timestamp", f"${var}.metadata.event_timestamp", 1) for var in event_vars]
          if event_vars
          else [pin]
      )
      insertions.append((body_start, body_start, "".join(f"\n    {p}" for p in predicates)))
    pinned = query_text
    for start, end, text in sorted(insertions, reverse=True):
      pinned = pinned[:start] + text + pinned[end:]
    return pinned

  @classmethod
  def pin_query_to_scored_day(cls, query_text: str, day: date, pin_event_stages: bool = False) -> str:
    """Execution-time dates for scored day D; the parsed runbook text itself is never modified.

    Regenerated runbooks carry concrete example dates. Before dispatch:
    * `{{first_scored_date}}` and the first-scored date of a `$in_scoring_window` gate become D (Mode A
      scores only D);
    * every existing event-day pin `timestamp.get_date(metadata.event_timestamp.seconds) = "YYYY-MM-DD"`
      is re-dated to D, except in loopback stages: PLAYBOOK_BEHAVIORAL_HUNT_MATCH events carry the
      run timestamp, not D;
    * with `pin_event_stages` (Entity Graph joins), `harness_truth.event_day_pin(D)` is added to each
      raw-event stage that has no pin (`pin_event_stages_to_day`).
    Idempotent: a second pass changes nothing and a stage never carries two pins.
    """
    day_str = day.isoformat()
    pinned = cls._FIRST_SCORED_SLOT_RE.sub(day_str, query_text)
    pinned = cls._FIRST_SCORED_DATE_RE.sub(rf'\g<1>"{day_str}"', pinned)
    loopback_spans = [
        (start, end)
        for _, start, end in cls._named_stage_body_spans(pinned)
        if cls._LOOPBACK_EVENT_LITERAL in cls._strip_yaral_comments(pinned[start:end])
    ]

    def _redate(match: "re.Match[str]") -> str:
      if any(start <= match.start() < end for start, end in loopback_spans):
        return match.group(0)
      return f'{match.group(1)}"{day_str}"'

    pinned = cls._EVENT_DATE_PIN_RE.sub(_redate, pinned)
    if pin_event_stages:
      pinned = cls.pin_event_stages_to_day(pinned, day)
    return pinned

  @classmethod
  def _is_seeded_query(cls, query: str) -> bool:
    """Returns True if the query contains Option 2 upstream candidate seed markers or placeholder entities."""
    if any(val in query for val in cls.SEED_PLACEHOLDER_VALUES):
      return True
    if re.search(
        r"/\*\s*UPSTREAM_CANDIDATE_(?:IPS|USERS|ENTITIES|HOSTS|SAS)\s*\*/",
        query,
        re.IGNORECASE,
    ):
      return True
    if re.search(r"//\s*Replace with candidate", query, re.IGNORECASE):
      return True
    return False

  @classmethod
  def _is_capstone_query(cls, query: str, section: str = "", goal: str = "") -> bool:
    """Returns True if the query aggregates UDM loopback PLAYBOOK_BEHAVIORAL_HUNT_MATCH events."""
    if cls._has_metrics_call(query):
      return False
    if re.search(r'^[ \t]*(?!//).*?"PLAYBOOK_BEHAVIORAL_HUNT_MATCH"', query, re.MULTILINE):
      return True
    combined = f"{section} {goal}".lower()
    return "capstone" in combined and "convergence" in combined and "loopback" in combined

  @staticmethod
  def _is_stage_b_loopback_query(spec: PlaybookQuerySpec) -> bool:
    """Returns True if `spec` is an inline Stage B UDM-Loopback query (Wave 2) rather than a final Capstone rollup (Wave 3)."""
    if not spec.is_capstone:
      return False
    header_blob = f"{spec.query_id} {spec.section} {spec.goal}".lower()
    if "capstone" in header_blob:
      return False
    return bool(
        re.search(
            r"(?:query_[1-9][0-9]*[ab]\b|stage1_upstream_)",
            spec.raw_query,
            re.IGNORECASE,
        )
    )

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
          if fence_lang in ("yara", "yaral", "yara-l", "yl2", ""):
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
      is_capstone = self._is_capstone_query(query_text, section, goal)
      has_metrics = self._has_metrics_call(query_text)
      model = (
          model_match.group(1).strip()
          if model_match
          else (
              "CAPSTONE_UDM_LOOPBACK_CONVERGENCE"
              if is_capstone
              else ("MACRO_30D_METRICS" if has_metrics else "RAW_STATISTICAL_HUNTER")
          )
      )
      plane = (
          "UDM_LOOPBACK_CONVERGENCE"
          if is_capstone
          else ("MACRO_METRICS" if has_metrics else "RAW_TELEMETRY")
      )
      lookback_days = self._infer_lookback_days(query_text, goal, model)
      is_seeded = self._is_seeded_query(query_text)
      entity_type_hint = self._infer_entity_type_hint(query_text)

      slug_source = re.sub(r"[^a-zA-Z0-9]+", "_", section or goal).strip("_").lower()
      slug_short = "_".join(slug_source.split("_")[:6]) or f"hunt_{idx}"
      query_id = f"q{idx:02d}_{slug_short}"

      ast_errors = self.runner.validate_ast(query_text)
      header_blob = f"{query_id} {section} {goal}".lower()
      is_udm_gated = bool(
          is_capstone
          and "capstone" not in header_blob
          and re.search(
              r"(?:query_[1-9][0-9]*[ab]\b|stage1_upstream_)",
              query_text,
              re.IGNORECASE,
          )
      )
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
              is_capstone=is_capstone,
              is_udm_gated=is_udm_gated,
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
    """Substitutes upstream candidate IPs/users/hosts into a seeded query or unscopes it to fleetwide.

    Supports Option 2 Upstream Candidate Seeding (`/* UPSTREAM_CANDIDATE_IPS */`,
    `/* UPSTREAM_CANDIDATE_USERS */`, `/* UPSTREAM_CANDIDATE_ENTITIES */`) across IP, user,
    and service-account placeholder expressions.

    Returns:
      Modified query string ready for execution, or None if the query should be skipped
      because no upstream candidate entities were found and `unscope_to_fleet` is False.
    """
    clean_candidates = []
    for c in candidate_entities:
      val = str(c).strip()
      if val and val not in clean_candidates and not any(ch in val for ch in ('"', "\\", "\n")):
        clean_candidates.append(val)

    placeholder_alts = "|".join(re.escape(v) for v in cls.SEED_PLACEHOLDER_VALUES)
    seed_pattern = re.compile(
        r"(?:^[ \t]*/\*\s*UPSTREAM_CANDIDATE_[A-Z_]+\s*\*/[ \t]*\r?\n)?"
        rf"^[ \t]*\((?:[a-zA-Z0-9_$.]+\s*=\s*\"(?:{placeholder_alts})\"(?:\s+or\s+)?)+[ \t]*\)[ \t]*\r?\n?",
        re.MULTILINE,
    )
    marker_only_pattern = re.compile(
        r"^[ \t]*/\*\s*UPSTREAM_CANDIDATE_([A-Z_]+)\s*\*/[ \t]*\r?\n?",
        re.MULTILINE,
    )

    if clean_candidates:
      # Extract field name used in the placeholder expression (e.g. principal.asset.ip or principal.user.userid)
      field_match = re.search(
          rf"\(([a-zA-Z0-9_$.]+)\s*=\s*\"(?:{placeholder_alts})\"",
          query_text,
      )
      if field_match:
        field_name = field_match.group(1)
      else:
        marker_match = marker_only_pattern.search(query_text)
        marker_kind = marker_match.group(1).upper() if marker_match else "IPS"
        if marker_kind in ("USERS", "SAS"):
          field_name = "principal.user.userid"
        elif marker_kind == "HOSTS":
          field_name = "principal.hostname"
        else:
          field_name = "principal.asset.ip" if "metrics." in query_text else "principal.ip"

      or_clauses = " or ".join(f'{field_name} = "{ent}"' for ent in clean_candidates[:25])
      replacement_line = f"    ({or_clauses})\n"
      if seed_pattern.search(query_text):
        return seed_pattern.sub(replacement_line, query_text, count=1)
      if marker_only_pattern.search(query_text):
        return marker_only_pattern.sub(replacement_line, query_text, count=1)

    if unscope_to_fleet:
      # Remove placeholder filter line and marker comment so the query evaluates across the entire fleet
      unscoped = seed_pattern.sub("", query_text)
      return marker_only_pattern.sub("", unscoped)

    return None

  @staticmethod
  def generate_run_id(playbook_id: str, stamp_dt: Optional[datetime] = None) -> str:
    """Generates a unique correlation identifier (`run_id`) for a single playbook execution."""
    dt = stamp_dt or datetime.now(timezone.utc)
    ts_str = dt.strftime("%Y%m%dT%H%M%SZ")
    short_uid = uuid.uuid4().hex[:8]
    safe_pb = re.sub(r"[^a-zA-Z0-9_-]+", "-", playbook_id).strip("-")[:32] or "playbook"
    return f"run_{safe_pb}_{ts_str}_{short_uid}"

  @classmethod
  def prepare_capstone_query(
      cls,
      query_text: str,
      run_id: str,
      scope_to_run_id: bool = True,
      playbook_id: Optional[str] = None,
  ) -> str:
    """Aligns a Capstone UDM Loopback query with the current execution's `run_id` and `playbook_id`.

    - Always substitutes explicit `{{RUN_ID}}` or `RUN_ID_PLACEHOLDER` tokens if present.
    - When `playbook_id` is provided, injects `re.regex(security_result.rule_name, `^<playbook_id>:`)`
      into Stage 1 so concurrent or historical runs of other playbooks never pollute this stream.
    - When `scope_to_run_id=True` (default), injects `metadata.product_log_id = "<run_id>"` into
      Stage 1 so the Capstone query strictly evaluates UDM loopback events emitted during
      the current playbook run.
    """
    safe_run_id = re.sub(r'["\\\n\r]', "", str(run_id).strip())
    safe_pb_id = re.sub(r'["\\\n\r`]', "", str(playbook_id or "").strip())
    updated = query_text.replace("{{RUN_ID}}", safe_run_id).replace(
        "RUN_ID_PLACEHOLDER", safe_run_id
    )

    target_line = 'metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"'
    injections: List[str] = []
    if (
        scope_to_run_id
        and safe_run_id
        and f'metadata.product_log_id = "{safe_run_id}"' not in updated
    ):
      injections.append(f'    metadata.product_log_id = "{safe_run_id}"')

    if safe_pb_id:
      escaped_pb = re.escape(safe_pb_id)
      pb_rule_filter = f"re.regex(security_result.rule_name, `^{escaped_pb}:`)"
      if pb_rule_filter not in updated and f'"{safe_pb_id}:' not in updated:
        injections.append(f"    {pb_rule_filter}")

    if injections and target_line in updated:
      joined_injections = "\n".join(injections)
      updated = updated.replace(
          target_line,
          f"{target_line}\n{joined_injections}",
          1,
      )
    return updated

  @classmethod
  def build_udm_run_validation_query(
      cls, run_id: str, playbook_id: Optional[str] = None
  ) -> str:
    """Builds a lightweight UDM query to validate how many events for `run_id` are indexed."""
    safe_run_id = re.sub(r'["\\\n\r]', "", str(run_id).strip())
    safe_pb_id = re.sub(r'["\\\n\r`]', "", str(playbook_id or "").strip())
    pb_line = ""
    if safe_pb_id:
      pb_line = f"re.regex(security_result.rule_name, `^{re.escape(safe_pb_id)}:`)\n"
    return (
        'metadata.event_type = "GENERIC_EVENT"\n'
        f'metadata.product_event_type = "{cls.PLAYBOOK_EVENT_METADATA["product_event_type"]}"\n'
        f'metadata.product_log_id = "{safe_run_id}"\n'
        f"{pb_line}"
        "$run_id = metadata.product_log_id\n"
        "match:\n"
        "  $run_id\n"
        "outcome:\n"
        "  $indexed_events = count(metadata.id)\n"
    )

  async def verify_udm_run_indexed(
      self,
      session: Any,
      run_id: str,
      expected_events: int,
      start_iso: str,
      end_iso: str,
      max_attempts: int = DEFAULT_UDM_VALIDATION_MAX_ATTEMPTS,
      poll_interval_sec: float = DEFAULT_UDM_VALIDATION_POLL_SEC,
      playbook_id: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Polls Chronicle UDM search to verify that all `expected_events` for `run_id` are indexed.

    Because Chronicle ImportEvents is asynchronous (typically taking 2-20 minutes for UDM
    indexing), this barrier polls until `indexed_events >= expected_events` so a downstream
    Capstone query never starts prematurely on a partially indexed batch (e.g. 300 of 3,000 events).
    """
    if expected_events <= 0:
      return {
          "status": "NO_UPSTREAM_EVENTS",
          "run_id": run_id,
          "expected_events": 0,
          "indexed_events": 0,
          "verified": True,
          "attempts": 0,
          "elapsed_sec": 0.0,
      }

    validation_query = self.build_udm_run_validation_query(run_id, playbook_id=playbook_id)
    attempts = 0
    indexed_events = 0
    last_error: Optional[str] = None
    t0 = time.monotonic()
    eff_max_attempts = max(1, int(max_attempts))

    for attempt in range(1, eff_max_attempts + 1):
      attempts = attempt
      try:
        raw_resp = await self.runner.execute_query_via_mcp(
            session=session,
            query=validation_query,
            start_iso=start_iso,
            end_iso=end_iso,
        )
        rows = self.runner.parse_stats_response(raw_resp)
        if rows:
          raw_count = rows[0].get("indexed_events", 0)
          try:
            indexed_events = int(float(raw_count))
          except (ValueError, TypeError):
            indexed_events = len(rows)
        else:
          indexed_events = 0
      except Exception as val_err:
        last_error = str(val_err)
        logger.warning(
            f"UDM indexing validation probe attempt {attempt}/{eff_max_attempts} "
            f"for run_id='{run_id}' failed: {val_err}"
        )

      if indexed_events >= expected_events:
        elapsed = round(time.monotonic() - t0, 3)
        return {
            "status": "VERIFIED",
            "run_id": run_id,
            "expected_events": expected_events,
            "indexed_events": indexed_events,
            "verified": True,
            "attempts": attempts,
            "elapsed_sec": elapsed,
        }

      if attempt < eff_max_attempts and poll_interval_sec > 0:
        await asyncio.sleep(poll_interval_sec)

    elapsed = round(time.monotonic() - t0, 3)
    result: Dict[str, Any] = {
        "status": "PARTIAL_TIMEOUT" if indexed_events > 0 else "INDEX_LAG_TIMEOUT",
        "run_id": run_id,
        "expected_events": expected_events,
        "indexed_events": indexed_events,
        "verified": False,
        "attempts": attempts,
        "elapsed_sec": elapsed,
    }
    if last_error:
      result["last_error"] = last_error
    return result

  @staticmethod
  def extract_row_entity(
      row: Dict[str, Any],
      default_entity_type: str = "ASSET",
  ) -> Tuple[str, str]:
    """Extracts (entity_id, entity_type) from a parsed Chronicle stats row."""
    # Priority order for primary entity identification
    if row.get("user"):
      return str(row["user"]), "USER"
    if row.get("sa"):
      return str(row["sa"]), "USER"
    if row.get("target_ip"):
      return str(row["target_ip"]), "IP"
    if row.get("host"):
      return str(row["host"]), ("USER" if default_entity_type == "USER" else "ASSET")
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

    Picks the row's primary model output (Z-score, Modified Z, Piecewise Unified score,
    Hurdle score, Markov surprisal, Zipf rarity, Fano factor, CUSUM drift, Shannon entropy,
    Bayesian anomaly score, Delta-Z, squared Z norms, Beta-Binomial rate, Jitter CV,
    or causal sequence matches) and maps it onto the harness Z-equivalent scale (model
    threshold -> 3.0, true sigma unchanged) with the skills' score-semantics registry
    (`scripts/ueba_constants.score_to_z_equivalent`), so CRI and loopback sum Z^2 are calibrated.
    """
    semantics = harness_truth.constants()
    direct_z_fields = (
        "unified_threat_score",
        "piecewise_threat_score",
        "capstone_threat_score",
        "composite_threat_score",
        "z_score",
        "personal_z",
        "m_z_score",
        "modified_z",
        "tukey_fence_ratio",
        "flow_tail_burst_ratio",
        "tail_to_median_ratio",
        "fused_threat_score",
        "threat_score",
        "composite_risk",
        "hurdle_threat_score",
        "markov_threat_score",
        "zipf_rarity_score",
        "cusum_drift_score",
        "cusum_drift",
        "shannon_entropy_score",
        "ewma_velocity_score",
        "velocity_score",
        "pcr_z_score",
        "macd_momentum_score",
        "circadian_threat_score",
        "hourly_z",
        "shielded_z",
        "sensitivity_excess",
        "upper_tail_z",
        "diversity_ratio",
        "anomaly_score",
        "delta_z",
        "recon_score",
        "fail_z",
        "intensity_z",
        "surprisal_score",
        "fano_factor",
        "tail_heaviness",
        "tail_ratio",
        "bowley_skew",
        "qcd",
        "tail_lag_spread",
        "surge_ratio",
    )
    for field in direct_z_fields:
      val = row.get(field)
      if val is not None:
        z_equiv = semantics.score_to_z_equivalent(field, val)
        if z_equiv is not None:
          return z_equiv, field

    squared_z_fields = (
        "capstone_threat_norm_sq",
        "composite_threat_norm_sq",
        "threat_vector_norm_sq",
        "d_vs_fleet_sq",
        "poisson_z_sq",
    )
    # Bounded failure probability and inter-arrival jitter CV (inverted) close the scored columns.
    for field in squared_z_fields + ("regularized_failure_prob", "cv"):
      val = row.get(field)
      if val is not None:
        z_equiv = semantics.score_to_z_equivalent(field, val)
        if z_equiv is not None:
          return z_equiv, field

    if row.get("carrier_events") is not None or row.get("bailout_events") is not None:
      # Two-stage causal sequence bridge match that passed root `condition:`
      return 4.5, "causal_sequence_match"

    return 3.5, "condition_gate_match"

  @staticmethod
  def _finite_float(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
      return None
    try:
      fval = float(value)
    except (ValueError, TypeError):
      return None
    return fval if math.isfinite(fval) else None

  @classmethod
  def is_final_capstone(cls, spec: PlaybookQuerySpec) -> bool:
    """True for a Wave 3 Capstone rollup (a capstone that is not an inline Stage B loopback query)."""
    return spec.is_capstone and not cls._is_stage_b_loopback_query(spec)

  @classmethod
  def score_row(cls, row: Dict[str, Any], spec: PlaybookQuerySpec) -> Dict[str, Any]:
    """Entity, Z-equivalent score and canonical CRI for one returned row.

    Wave 3 Capstone rows are scored on the loopback sum Z^2 they were gated on; every
    other row on its primary model output (`extract_row_effective_z`).
    """
    entity_id, entity_type = cls.extract_row_entity(row, spec.entity_type_hint)
    effective_z: Optional[float] = None
    score_field = ""
    if cls.is_final_capstone(spec):
      for col in cls.LOOPBACK_SUM_Z_SQ_COLUMNS:
        if row.get(col) is not None:
          effective_z = harness_truth.constants().score_to_z_equivalent(col, row[col])
          if effective_z is not None:
            score_field = col
            break
    if effective_z is None:
      effective_z, score_field = cls.extract_row_effective_z(row)
    return {
        "entity": entity_id,
        "entity_type": entity_type,
        "effective_z": effective_z,
        "score_field": score_field,
        "native_score": row.get(score_field),
        "cri": harness_truth.calculate_cri(effective_z),
    }

  @classmethod
  def evaluate_loopback_gate(cls, row: Dict[str, Any]) -> Dict[str, Any]:
    """Harness loopback gate for a Wave 3 Capstone row.

    Fires only on >= LOOPBACK_MIN_DISTINCT_HITS distinct hits and sum Z^2 >=
    LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD (`harness_truth.loopback_thresholds()`), whatever gate the
    playbook query itself used. Rows without both evidence columns fail closed.
    """
    min_hits, sum_z_sq_threshold = harness_truth.loopback_thresholds()
    distinct_hits = next(
        (v for v in (cls._finite_float(row.get(c)) for c in cls.LOOPBACK_DISTINCT_HIT_COLUMNS) if v is not None),
        None,
    )
    sum_z_sq = next(
        (v for v in (cls._finite_float(row.get(c)) for c in cls.LOOPBACK_SUM_Z_SQ_COLUMNS) if v is not None),
        None,
    )
    if distinct_hits is None or sum_z_sq is None:
      reason = "MISSING_LOOPBACK_EVIDENCE"
    elif distinct_hits < min_hits:
      reason = "BELOW_MIN_DISTINCT_HITS"
    elif sum_z_sq < sum_z_sq_threshold:
      reason = "BELOW_SUM_Z_SQ_THRESHOLD"
    else:
      reason = "FIRED"
    return {
        "fired": reason == "FIRED",
        "reason": reason,
        "distinct_hits": distinct_hits,
        "sum_z_sq": sum_z_sq,
        "min_distinct_hits": min_hits,
        "sum_z_sq_threshold": sum_z_sq_threshold,
    }

  @classmethod
  def assess_cri(cls, cri: Any, entity_type: str) -> Dict[str, Any]:
    """Band, UDM severity, verdict and recommended action for a CRI (all from harness_truth)."""
    band_code, band_label, _ = harness_truth.cri_band(cri)
    return {
        "band": band_label,
        "severity": "UNKNOWN_SEVERITY" if band_code == "N/A" else band_code,
        "verdict": harness_truth.verdict_for(cri),
        "recommended_action": harness_truth.recommended_action(
            cri, containment_action=cls.CONTAINMENT_ACTION_BY_ENTITY_TYPE.get(entity_type, "ISOLATE_HOST")
        ),
        "action_guidance": harness_truth.action_guidance(cri),
    }

  def build_playbook_match_udm_event(
      self,
      playbook_id: str,
      playbook_source: str,
      playbook_sha256: str,
      spec: PlaybookQuerySpec,
      row: Dict[str, Any],
      run_timestamp_iso: str,
      evaluated_day: str,
      run_id: Optional[str] = None,
      query_window: Optional[Dict[str, Any]] = None,
  ) -> Dict[str, Any]:
    """Builds a Chronicle ImportEvents-compliant UDM GENERIC_EVENT for a matched row.

    CRI is the canonical harness CRI of the row's Z-equivalent score (no floor); severity, verdict and
    recommended action come from its band. Callers gate write-back on
    `harness_truth.writeback_cri_threshold()`.
    """
    eff_run_id = run_id or f"run_{playbook_id}_{evaluated_day}"
    scored = self.score_row(row, spec)
    entity_id, entity_type = scored["entity"], scored["entity_type"]
    effective_z, score_field = scored["effective_z"], scored["score_field"]
    cri_score = scored["cri"] if scored["cri"] is not None else 0
    assessment = self.assess_cri(cri_score, entity_type)
    severity = assessment["severity"]
    semantics = harness_truth.constants()
    native_score = scored["native_score"]

    if entity_type == "USER":
      principal: Dict[str, Any] = {"user": {"userid": entity_id}}
    elif entity_type == "IP":
      principal = {"ip": [entity_id], "asset": {"ip": [entity_id]}}
    else:
      principal = {"hostname": entity_id, "asset": {"hostname": entity_id}}

    labels = [
        {"key": "Risk Source", "value": "Autonomous Markdown Playbook Hunter"},
        {"key": "Run ID", "value": eff_run_id},
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
        {
            "key": "Native Score",
            "value": semantics.format_score_with_unit(score_field, native_score) if native_score is not None else "N/A",
        },
        {"key": "Effective Z-Score", "value": semantics.format_score_with_unit(score_field, effective_z)},
        {"key": "CRI Score", "value": str(cri_score)},
        {"key": "CRI Band", "value": assessment["band"]},
        {"key": "Severity Tier", "value": severity},
        {"key": "Verdict", "value": assessment["verdict"]},
        {"key": "Recommended Action", "value": assessment["recommended_action"]},
        {"key": "Action Guidance", "value": assessment["action_guidance"]},
    ]
    if query_window:
      labels.append({"key": "Query Window", "value": f"{query_window.get('start')} -> {query_window.get('end')}"})

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
            "product_log_id": eff_run_id,
            "product_name": self.PLAYBOOK_EVENT_METADATA["product_name"],
            "vendor_name": self.PLAYBOOK_EVENT_METADATA["vendor_name"],
            "event_type": self.PLAYBOOK_EVENT_METADATA["event_type"],
            "product_event_type": self.PLAYBOOK_EVENT_METADATA["product_event_type"],
            "description": summary_text,
            "ingestion_labels": [
                {"key": "run_id", "value": eff_run_id},
                {"key": "playbook_id", "value": playbook_id},
                {"key": "query_id", "value": spec.query_id},
            ],
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
                "detection_fields": [
                    {"key": "run_id", "value": eff_run_id},
                    {"key": "playbook_id", "value": playbook_id},
                    {"key": "query_id", "value": spec.query_id},
                ],
            }
        ],
    }

  def converge_playbook_entities(
      self,
      playbook_id: str,
      playbook_source: str,
      playbook_sha256: str,
      entity_hits: Dict[str, List[Dict[str, Any]]],
      run_timestamp_iso: str,
      evaluated_day: str,
      run_id: Optional[str] = None,
  ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Synthesizes Cross-Query Entity Convergence across all matched queries in a playbook run.

    An entity converges only when it matches >= LOOPBACK_MIN_DISTINCT_HITS distinct queries with
    sum(z_i^2) >= LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD (`harness_truth.loopback_thresholds()`, read
    on every call). The sum Z^2 maps onto the Z-equivalent scale through the harness score-semantics
    registry; its canonical CRI must clear `harness_truth.writeback_cri_threshold()` for the
    consolidated UDM convergence event to be written back.
    """
    eff_run_id = run_id or f"run_{playbook_id}_{evaluated_day}"
    converged_summaries: List[Dict[str, Any]] = []
    convergence_udm_events: List[Dict[str, Any]] = []
    min_distinct_hits, sum_z_sq_threshold = harness_truth.loopback_thresholds()
    writeback_threshold = harness_truth.writeback_cri_threshold()
    semantics = harness_truth.constants()

    for entity_id, hits in sorted(entity_hits.items()):
      if not entity_id or entity_id == "unknown_entity":
        continue
      # Deduplicate by query_id, keeping max effective_z per query_id
      by_query: Dict[str, Dict[str, Any]] = {}
      for hit in hits:
        qid = hit["query_id"]
        if qid not in by_query or hit["effective_z"] > by_query[qid]["effective_z"]:
          by_query[qid] = hit

      if len(by_query) < min_distinct_hits:
        continue

      distinct_hits = list(by_query.values())
      entity_type = distinct_hits[0]["entity_type"]
      norm_sq = sum(h["effective_z"] ** 2 for h in distinct_hits)
      if norm_sq < sum_z_sq_threshold:
        continue
      combined_norm = math.sqrt(norm_sq)
      combined_z = semantics.score_to_z_equivalent(self.CONVERGENCE_SCORE_KEY, norm_sq)
      cri_score = harness_truth.calculate_cri(combined_z)
      if cri_score is None or cri_score < writeback_threshold:
        continue
      assessment = self.assess_cri(cri_score, entity_type)
      severity = assessment["severity"]
      contributing_queries = sorted(by_query.keys())
      contributing_sections = sorted({h["section"] for h in distinct_hits if h.get("section")})

      summary_entry = {
          "entity": entity_id,
          "entity_type": entity_type,
          "run_id": eff_run_id,
          "distinct_queries_matched": len(distinct_hits),
          "contributing_queries": contributing_queries,
          "contributing_sections": contributing_sections,
          "combined_effective_z": round(combined_z, 2),
          "combined_l2_norm": round(combined_norm, 2),
          "combined_norm_sq": round(norm_sq, 2),
          "cri_score": cri_score,
          "severity": severity,
          "verdict": assessment["verdict"],
          "recommended_action": assessment["recommended_action"],
          "loopback_thresholds": {
              "min_distinct_hits": min_distinct_hits,
              "sum_z_sq_threshold": sum_z_sq_threshold,
          },
      }
      converged_summaries.append(summary_entry)

      if entity_type == "USER":
        principal: Dict[str, Any] = {"user": {"userid": entity_id}}
      elif entity_type == "IP":
        principal = {"ip": [entity_id], "asset": {"ip": [entity_id]}}
      else:
        principal = {"hostname": entity_id, "asset": {"hostname": entity_id}}

      labels = [
          {"key": "Risk Source", "value": "Autonomous Markdown Playbook Hunter"},
          {"key": "Run ID", "value": eff_run_id},
          {"key": "Playbook ID", "value": playbook_id},
          {"key": "Playbook Source", "value": playbook_source},
          {"key": "Playbook SHA256", "value": playbook_sha256[:16]},
          {"key": "Query ID", "value": "capstone_cross_query_convergence"},
          {"key": "Statistical Model", "value": "Multi-Stage Cross-Query Euclidean L2 Convergence"},
          {"key": "Plane", "value": "UDM_LOOPBACK_CONVERGENCE"},
          {"key": "Evaluated Window", "value": evaluated_day},
          {"key": "Target Entity", "value": entity_id},
          {"key": "Entity Type", "value": entity_type},
          {"key": "Distinct Queries Matched", "value": str(len(distinct_hits))},
          {"key": "Contributing Queries", "value": ",".join(contributing_queries)[:256]},
          {"key": "Sum Z^2", "value": f"{norm_sq:.2f}"},
          {"key": "Combined L2 Norm", "value": f"{combined_norm:.2f}"},
          {"key": "Effective Z-Score", "value": f"{combined_z:.2f}"},
          {"key": "CRI Score", "value": str(cri_score)},
          {"key": "CRI Band", "value": assessment["band"]},
          {"key": "Severity Tier", "value": severity},
          {"key": "Verdict", "value": assessment["verdict"]},
          {"key": "Recommended Action", "value": assessment["recommended_action"]},
          {"key": "Action Guidance", "value": assessment["action_guidance"]},
      ]

      summary_text = (
          f"[{playbook_id}/capstone_cross_query_convergence] Cross-Query Entity Convergence — "
          f"{entity_type} {entity_id} matched {len(distinct_hits)} distinct queries "
          f"({','.join(contributing_queries)}) with sum Z^2={norm_sq:.2f} "
          f"(L2 norm {combined_norm:.2f}), CRI={cri_score}/100"
      )

      convergence_udm_events.append({
          "metadata": {
              "event_timestamp": run_timestamp_iso,
              "ingested_timestamp": run_timestamp_iso,
              "product_log_id": eff_run_id,
              "product_name": self.PLAYBOOK_EVENT_METADATA["product_name"],
              "vendor_name": self.PLAYBOOK_EVENT_METADATA["vendor_name"],
              "event_type": self.PLAYBOOK_EVENT_METADATA["event_type"],
              "product_event_type": self.PLAYBOOK_EVENT_METADATA["product_event_type"],
              "description": summary_text,
              "ingestion_labels": [
                  {"key": "run_id", "value": eff_run_id},
                  {"key": "playbook_id", "value": playbook_id},
                  {"key": "query_id", "value": "capstone_cross_query_convergence"},
              ],
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
                  "rule_name": f"{playbook_id}:capstone_cross_query_convergence",
                  "rule_type": "PLAYBOOK_CAPSTONE_CONVERGENCE",
                  "threat_name": "Multi-Scenario Playbook Entity Convergence",
                  "threat_status": "ACTIVE",
                  "severity": severity,
                  "risk_score": cri_score,
                  "confidence_score": round(combined_z, 2),
                  "summary": summary_text,
                  "description": (
                      f"Entity {entity_id} triggered {len(distinct_hits)} distinct behavioral "
                      f"queries in playbook {playbook_id}: {', '.join(contributing_queries)}"
                  ),
                  "detection_fields": [
                      {"key": "run_id", "value": eff_run_id},
                      {"key": "playbook_id", "value": playbook_id},
                      {"key": "query_id", "value": "capstone_cross_query_convergence"},
                  ],
              }
          ],
      })

    return converged_summaries, convergence_udm_events

  async def execute_playbook(
      self,
      session: Any,
      source: str,
      playbook_id: Optional[str] = None,
      run_id: Optional[str] = None,
      ingest_events: bool = True,
      unscope_seeded_to_fleet: bool = False,
      scope_capstone_to_run_id: bool = True,
      validate_udm_before_capstone: bool = True,
      require_complete_udm_sync: bool = True,
      udm_validation_max_attempts: Optional[int] = None,
      udm_validation_poll_sec: Optional[float] = None,
      query_concurrency: Optional[int] = None,
      inter_query_delay_sec: float = 1.0,
      lookback_days_override: Optional[int] = None,
      now_utc: Optional[datetime] = None,
      should_emit_fn: Optional[Callable[[str, str, str, str, float], bool]] = None,
      record_emit_fn: Optional[Callable[[str, str, str, str, float, int], None]] = None,
      http_client: Optional[httpx.AsyncClient] = None,
  ) -> Dict[str, Any]:
    """Fetches, parses, validates, and executes all multi-stage queries in a Markdown playbook.

    Every query runs on the harness window for the last complete UTC day D
    (`resolve_query_window`) with its dates set to D (`pin_query_to_scored_day`); D is the run's
    `evaluated_day` and intra-day dedup bucket.
    """
    stamp_dt = now_utc or datetime.now(timezone.utc)
    run_timestamp_iso = stamp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    evaluated_day = harness_truth.mode_a_day(stamp_dt)
    bucket_date = evaluated_day.isoformat()
    writeback_threshold = harness_truth.writeback_cri_threshold()
    loopback_min_hits, loopback_sum_z_sq = harness_truth.loopback_thresholds()

    pb_id = playbook_id or self.derive_playbook_id(source)
    eff_run_id = run_id or self.generate_run_id(pb_id, stamp_dt)
    eff_val_max_attempts = (
        int(udm_validation_max_attempts)
        if udm_validation_max_attempts is not None
        else int(
            getattr(
                self.tenant,
                "udm_validation_max_attempts",
                self.DEFAULT_UDM_VALIDATION_MAX_ATTEMPTS,
            )
        )
    )
    eff_val_poll_sec = (
        float(udm_validation_poll_sec)
        if udm_validation_poll_sec is not None
        else float(
            getattr(
                self.tenant,
                "udm_validation_poll_sec",
                self.DEFAULT_UDM_VALIDATION_POLL_SEC,
            )
        )
    )
    eff_query_concurrency = max(
        1,
        int(
            query_concurrency
            if query_concurrency is not None
            else getattr(self.tenant, "playbook_query_concurrency", 3)
        ),
    )
    md_text, norm_source, content_sha = await self.fetch_markdown(
        source, http_client=http_client
    )
    specs = await self.runner.run_in_io_thread(self.parse_markdown_playbook, md_text)
    has_capstone = any(s.is_capstone for s in specs)
    spec_order_map = {s.query_id: s.index for s in specs}

    # Schedule execution in 3 waves when inline UDM-Loopback Stage B queries (e.g. 2B, 4B) exist:
    # Wave 1: Independent/seeded upstream queries (`not s.is_capstone`)
    # Wave 2: Inline Stage B UDM-Loopback queries (`_is_stage_b_loopback_query(s)`)
    # Wave 3: Final Capstone rollup queries (`s.is_capstone and not _is_stage_b_loopback_query(s)`)
    if any(self._is_stage_b_loopback_query(s) for s in specs):
      wave1_specs = [s for s in specs if not s.is_capstone]
      wave2_specs = [s for s in specs if s.is_capstone and self._is_stage_b_loopback_query(s)]
      wave3_specs = [s for s in specs if s.is_capstone and not self._is_stage_b_loopback_query(s)]
      specs = wave1_specs + wave2_specs + wave3_specs

    query_reports: List[Dict[str, Any]] = []
    udm_events_to_ingest: List[Dict[str, Any]] = []
    entity_query_hits: Dict[str, List[Dict[str, Any]]] = {}
    previous_candidates: List[str] = []

    total_matches = 0
    total_emitted = 0
    total_suppressed = 0
    total_below_writeback = 0
    total_below_loopback = 0
    total_udm_generated = 0
    upstream_udm_generated = 0
    flushed_upstream_udm = 0
    wave2_flushed = False
    wave3_flushed = False
    queries_executed = 0
    queries_skipped = 0
    accumulated_ingested = 0
    accumulated_batches = 0
    ingestion_error: Optional[str] = None
    last_udm_sync_validation: Optional[Dict[str, Any]] = None

    async def _flush_pending_udm_events() -> None:
      nonlocal accumulated_ingested, accumulated_batches, ingestion_error, flushed_upstream_udm
      flushed_upstream_udm = upstream_udm_generated
      if not ingest_events or not udm_events_to_ingest:
        return
      pending = list(udm_events_to_ingest)
      udm_events_to_ingest.clear()
      try:
        res = await self.runner.run_in_io_thread(
            self.risk_engine.ingest_udm_events, pending
        )
        accumulated_ingested += int(res.get("events_ingested", len(pending)))
        accumulated_batches += int(res.get("batches", 1))
      except Exception as ing_err:
        logger.error(f"Playbook '{pb_id}' UDM ingestion failed: {ing_err}")
        ingestion_error = str(ing_err)

    def _process_query_rows(
        spec: PlaybookQuerySpec,
        window: Dict[str, Any],
        rows: List[Dict[str, Any]],
        capstone_sync_validation: Optional[Dict[str, Any]] = None,
    ) -> None:
      nonlocal previous_candidates, total_matches, total_emitted, total_suppressed
      nonlocal total_udm_generated, upstream_udm_generated, total_below_writeback, total_below_loopback
      current_candidates: List[str] = []
      matched_entities: List[Dict[str, Any]] = []
      emitted_for_query = 0
      suppressed_for_query = 0
      below_writeback_for_query = 0
      below_loopback_for_query = 0
      is_final_capstone = self.is_final_capstone(spec)

      for row in rows:
        scored = self.score_row(row, spec)
        entity_id, entity_type = scored["entity"], scored["entity_type"]
        effective_z, score_field = scored["effective_z"], scored["score_field"]
        cri_score = scored["cri"]
        # UDM write-back requires the harness CRI threshold; only qualifying findings feed convergence.
        writeback_eligible = cri_score is not None and cri_score >= writeback_threshold
        if entity_id and entity_id != "unknown_entity":
          current_candidates.append(entity_id)
          if not is_final_capstone and writeback_eligible:
            entity_query_hits.setdefault(entity_id, []).append({
                "query_id": spec.query_id,
                "section": spec.section,
                "goal": spec.goal,
                "entity_type": entity_type,
                "effective_z": effective_z,
                "score_field": score_field,
            })

        total_matches += 1
        # Wave 3 Capstone rows fire only on the harness loopback gate, whatever the query's own gate.
        if is_final_capstone and not self.evaluate_loopback_gate(row)["fired"]:
          total_below_loopback += 1
          below_loopback_for_query += 1
          continue
        if not writeback_eligible:
          total_below_writeback += 1
          below_writeback_for_query += 1
          continue
        # When a playbook has a downstream `run_id`-scoped Capstone query, never suppress
        # upstream events via intra-day deduplication so the current `run_id` batch is complete.
        bypass_intraday_dedup = has_capstone and scope_capstone_to_run_id and not is_final_capstone
        if should_emit_fn is not None and not bypass_intraday_dedup:
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
            run_id=eff_run_id,
            query_window=window,
        )
        udm_events_to_ingest.append(udm_event)
        total_udm_generated += 1
        if not is_final_capstone:
          upstream_udm_generated += 1
        cri_score = udm_event["security_result"][0]["risk_score"]
        total_emitted += 1
        emitted_for_query += 1

        if record_emit_fn is not None:
          record_emit_fn(bucket_date, pb_id, spec.query_id, entity_id, effective_z, cri_score)

        assessment = self.assess_cri(cri_score, entity_type)
        matched_entities.append({
            "entity": entity_id,
            "entity_type": entity_type,
            "score_field": score_field,
            "effective_z": round(effective_z, 2),
            "cri_score": cri_score,
            "verdict": assessment["verdict"],
            "recommended_action": assessment["recommended_action"],
        })

      previous_candidates = current_candidates
      q_report: Dict[str, Any] = {
          "query_id": spec.query_id,
          "section": spec.section,
          "goal": spec.goal,
          "statistical_model": spec.statistical_model,
          "plane": spec.plane,
          "is_capstone": spec.is_capstone,
          "lookback_days": window["lookback_days"],
          "window": {"start": window["start"], "end": window["end"], "mode": window["mode"]},
          "status": "SUCCESS",
          "matches_found": len(rows),
          "matches_emitted": emitted_for_query,
          "matches_suppressed_dedup": suppressed_for_query,
          "matches_below_writeback_cri": below_writeback_for_query,
          "matched_entities": matched_entities[:25],
      }
      if is_final_capstone:
        q_report["matches_below_loopback_gate"] = below_loopback_for_query
        q_report["loopback_gate"] = {
            "min_distinct_hits": loopback_min_hits,
            "sum_z_sq_threshold": loopback_sum_z_sq,
        }
      if capstone_sync_validation is not None:
        q_report["udm_sync_validation"] = capstone_sync_validation
      query_reports.append(q_report)

    query_sem = asyncio.Semaphore(eff_query_concurrency)
    idx = 0
    num_specs = len(specs)

    while idx < num_specs:
      spec = specs[idx]

      # Fast-gather wave of consecutive independent upstream queries when query_concurrency > 1
      if (
          eff_query_concurrency > 1
          and not spec.ast_errors
          and not spec.is_seeded
          and not spec.is_capstone
      ):
        wave_specs: List[PlaybookQuerySpec] = []
        while (
            idx < num_specs
            and not specs[idx].ast_errors
            and not specs[idx].is_seeded
            and not specs[idx].is_capstone
        ):
          wave_specs.append(specs[idx])
          idx += 1

        if len(wave_specs) > 1:
          async def _run_wave_item(
              w_idx: int, w_spec: PlaybookQuerySpec
          ) -> Tuple[PlaybookQuerySpec, Dict[str, Any], Optional[List[Dict[str, Any]]], Optional[str]]:
            w_window = self.resolve_query_window(w_spec, evaluated_day, stamp_dt, lookback_days_override)
            w_query = self.pin_query_to_scored_day(w_spec.raw_query, evaluated_day, w_window["pin_event_stages"])
            async with query_sem:
              if w_idx > 0 and inter_query_delay_sec > 0:
                await asyncio.sleep(inter_query_delay_sec)
              try:
                resp = await self.runner.execute_query_via_mcp(
                    session=session,
                    query=w_query,
                    start_iso=w_window["start"],
                    end_iso=w_window["end"],
                )
                return w_spec, w_window, self.runner.parse_stats_response(resp), None
              except Exception as w_err:
                return w_spec, w_window, None, str(w_err)

          wave_outcomes = await asyncio.gather(
              *(_run_wave_item(w_i, w_s) for w_i, w_s in enumerate(wave_specs))
          )
          for w_spec, w_window, w_rows, w_err in wave_outcomes:
            if w_err is not None or w_rows is None:
              logger.error(f"Playbook '{pb_id}' query '{w_spec.query_id}' execution failed: {w_err}")
              query_reports.append({
                  "query_id": w_spec.query_id,
                  "section": w_spec.section,
                  "goal": w_spec.goal,
                  "status": "ERROR",
                  "error": w_err or "Unknown error",
                  "matches_found": 0,
                  "window": {"start": w_window["start"], "end": w_window["end"], "mode": w_window["mode"]},
              })
              previous_candidates = []
            else:
              queries_executed += 1
              _process_query_rows(w_spec, w_window, w_rows)
          continue
        else:
          # Single query in wave: rewind idx by 1 and fall through to standard sequential path
          idx -= 1

      spec = specs[idx]
      idx += 1

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

      window = self.resolve_query_window(spec, evaluated_day, stamp_dt, lookback_days_override)
      start_iso, window_end_iso = window["start"], window["end"]

      # Option 3: If this query is a Capstone UDM Loopback query (`PLAYBOOK_BEHAVIORAL_HUNT_MATCH`),
      # flush all upstream playbook match UDM events AND verify they are indexed in Chronicle UDM
      # before running the Capstone query.
      capstone_sync_validation: Optional[Dict[str, Any]] = None
      if spec.is_capstone:
        is_stage_b_loopback = self._is_stage_b_loopback_query(spec)
        if is_stage_b_loopback and not wave2_flushed:
          wave2_flushed = True
          if udm_events_to_ingest:
            await _flush_pending_udm_events()
          else:
            flushed_upstream_udm = upstream_udm_generated
        elif not is_stage_b_loopback and not wave3_flushed:
          wave3_flushed = True
          if udm_events_to_ingest:
            await _flush_pending_udm_events()
          else:
            flushed_upstream_udm = upstream_udm_generated

        expected_for_wave = flushed_upstream_udm
        if validate_udm_before_capstone:
          if not ingest_events:
            capstone_sync_validation = {
                "status": "INGESTION_DISABLED",
                "run_id": eff_run_id,
                "expected_events": expected_for_wave,
                "indexed_events": 0,
                "verified": False,
                "attempts": 0,
                "elapsed_sec": 0.0,
            }
          elif (
              last_udm_sync_validation is not None
              and last_udm_sync_validation.get("verified") is True
              and last_udm_sync_validation.get("expected_events") == expected_for_wave
          ):
            capstone_sync_validation = dict(last_udm_sync_validation)
          else:
            capstone_sync_validation = await self.verify_udm_run_indexed(
                session=session,
                run_id=eff_run_id,
                expected_events=expected_for_wave,
                start_iso=start_iso,
                end_iso=window_end_iso,
                max_attempts=eff_val_max_attempts,
                poll_interval_sec=eff_val_poll_sec,
                playbook_id=pb_id,
            )
          last_udm_sync_validation = capstone_sync_validation

          if require_complete_udm_sync:
            if scope_capstone_to_run_id and expected_for_wave <= 0:
              queries_skipped += 1
              query_reports.append({
                  "query_id": spec.query_id,
                  "section": spec.section,
                  "goal": spec.goal,
                  "plane": spec.plane,
                  "is_capstone": True,
                  "status": "SKIPPED_NO_UPSTREAM_UDM_EVENTS",
                  "matches_found": 0,
                  "udm_sync_validation": capstone_sync_validation,
              })
              previous_candidates = []
              continue
            if not capstone_sync_validation.get("verified", False):
              logger.warning(
                  f"Playbook '{pb_id}' Capstone query '{spec.query_id}' blocked: UDM sync incomplete "
                  f"(indexed={capstone_sync_validation.get('indexed_events')}/"
                  f"expected={capstone_sync_validation.get('expected_events')}, "
                  f"status={capstone_sync_validation.get('status')})."
              )
              queries_skipped += 1
              query_reports.append({
                  "query_id": spec.query_id,
                  "section": spec.section,
                  "goal": spec.goal,
                  "plane": spec.plane,
                  "is_capstone": True,
                  "status": "SKIPPED_INCOMPLETE_UDM_SYNC",
                  "matches_found": 0,
                  "udm_sync_validation": capstone_sync_validation,
              })
              previous_candidates = []
              continue

      query_to_run = spec.raw_query
      if spec.is_capstone:
        query_to_run = self.prepare_capstone_query(
            query_to_run,
            run_id=eff_run_id,
            scope_to_run_id=scope_capstone_to_run_id,
            playbook_id=pb_id,
        )
      if spec.is_seeded:
        prepared = self.prepare_seeded_query(
            query_to_run,
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
      query_to_run = self.pin_query_to_scored_day(query_to_run, evaluated_day, window["pin_event_stages"])

      if queries_executed > 0 and inter_query_delay_sec > 0:
        await asyncio.sleep(inter_query_delay_sec)

      try:
        async with query_sem:
          raw_resp = await self.runner.execute_query_via_mcp(
              session=session,
              query=query_to_run,
              start_iso=start_iso,
              end_iso=window_end_iso,
          )
        queries_executed += 1
        rows = self.runner.parse_stats_response(raw_resp)
      except Exception as q_err:
        logger.error(f"Playbook '{pb_id}' query '{spec.query_id}' execution failed: {q_err}")
        err_report: Dict[str, Any] = {
            "query_id": spec.query_id,
            "section": spec.section,
            "goal": spec.goal,
            "status": "ERROR",
            "error": str(q_err),
            "matches_found": 0,
            "window": {"start": start_iso, "end": window_end_iso, "mode": window["mode"]},
        }
        if capstone_sync_validation is not None:
          err_report["udm_sync_validation"] = capstone_sync_validation
        query_reports.append(err_report)
        previous_candidates = []
        continue

      _process_query_rows(spec, window, rows, capstone_sync_validation)

    converged_entities, convergence_events = self.converge_playbook_entities(
        playbook_id=pb_id,
        playbook_source=norm_source,
        playbook_sha256=content_sha,
        entity_hits=entity_query_hits,
        run_timestamp_iso=run_timestamp_iso,
        evaluated_day=bucket_date,
        run_id=eff_run_id,
    )
    for conv_summary, conv_event in zip(converged_entities, convergence_events):
      ent_id = conv_summary["entity"]
      comb_z = conv_summary["combined_effective_z"]
      cri_val = conv_summary["cri_score"]
      if should_emit_fn is not None:
        if not should_emit_fn(
            bucket_date, pb_id, "capstone_cross_query_convergence", ent_id, comb_z
        ):
          continue
      udm_events_to_ingest.append(conv_event)
      total_udm_generated += 1
      if record_emit_fn is not None:
        record_emit_fn(
            bucket_date, pb_id, "capstone_cross_query_convergence", ent_id, comb_z, cri_val
        )

    await _flush_pending_udm_events()
    query_reports.sort(key=lambda r: spec_order_map.get(r.get("query_id", ""), 9999))

    if not ingest_events:
      ingestion_result: Dict[str, Any] = {
          "status": "SKIPPED",
          "events_ingested": 0,
          "batches": 0,
      }
    elif ingestion_error is not None:
      ingestion_result = {
          "status": "ERROR",
          "error": ingestion_error,
          "events_ingested": accumulated_ingested,
          "batches": accumulated_batches,
      }
    elif accumulated_ingested == 0:
      ingestion_result = {
          "status": "NO_EVENTS",
          "events_ingested": 0,
          "batches": 0,
      }
    else:
      ingestion_result = {
          "status": "SUCCESS",
          "events_ingested": accumulated_ingested,
          "batches": accumulated_batches,
      }

    return {
        "status": "SUCCESS",
        "playbook_id": pb_id,
        "run_id": eff_run_id,
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
        "total_matches_below_writeback_cri": total_below_writeback,
        "total_capstone_rows_below_loopback_gate": total_below_loopback,
        "total_udm_events_generated": total_udm_generated,
        "writeback_cri_threshold": writeback_threshold,
        "loopback_thresholds": {
            "min_distinct_hits": loopback_min_hits,
            "sum_z_sq_threshold": loopback_sum_z_sq,
        },
        "udm_sync_validation": last_udm_sync_validation,
        "converged_entities": converged_entities,
        "ingestion": ingestion_result,
        "queries": query_reports,
    }

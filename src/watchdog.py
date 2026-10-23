# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Autonomous Watchdog Daemon for Continuous SecOps Threat Hunting.

Runs a continuous background monitoring loop that:
1. Polls open Chronicle SOAR cases within a sliding time horizon.
2. Deduplicates against previously analyzed cases via persistent sliding-window state.
3. Automatically determines the optimal threat hunting strategy.
4. Enqueues hunt requests to a bounded producer-consumer queue drained by a parallel worker pool.
5. Executes multi-stage YARA-L behavioral/statistical hunts against Chronicle OneMCP.
6. Injects 6-pillar forensic reports directly into the case wall via create_case_comment.
"""

import asyncio
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import httpx
from mcp import ClientSession

try:
  from mcp.client.streamable_http import streamable_http_client
except ImportError:
  try:
    from mcp.client.streamable_http import streamablehttp_client as streamable_http_client
  except ImportError:
    from mcp.client.sse import sse_client as streamable_http_client

from src.config import TenantConfig
from src.models import JITHuntRequest, JITHuntResponse
from src.playbook_runner import PlaybookRunner
from src.risk_metrics_engine import RiskMetricsEngine
from src.strategy_decider import StrategyDecider

logger = logging.getLogger("WatchdogDaemon")


def _unwrap_exception(e: BaseException) -> str:
  """Recursively formats ExceptionGroup sub-exceptions for clear diagnostic logging."""
  if hasattr(e, "exceptions") and e.exceptions:
    sub_msgs = [_unwrap_exception(sub) for sub in e.exceptions]
    return f"{type(e).__name__}: {e} [Sub-exceptions: {'; '.join(sub_msgs)}]"
  return f"{type(e).__name__}: {e}"


def _extract_entity_from_connector_events(events: List[Dict[str, Any]]) -> Optional[Tuple[str, str]]:
  """Extracts target entity and type (USER, ASSET, IP) from raw connector events / UDM data."""
  for ev in events:
    # 1. Inspect eventJsonData -> rawEvent
    raw_data = ev.get("eventJsonData", {}).get("rawEvent") or "{}"
    try:
      parsed_raw = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
    except Exception:
      parsed_raw = {}

    fields = parsed_raw.get("_rawDataFields", {}) if isinstance(parsed_raw, dict) else {}

    # Check principal user
    user = (fields.get("event_principal_user_userid") or 
            fields.get("event_principal_user_email_addresses_1") or
            fields.get("event_target_user_userid"))
    if user:
      return str(user).lower(), "USER"

    # Check principal hostname
    host = (fields.get("event_principal_hostname") or 
            fields.get("event_principal_asset_hostname"))
    if host:
      return str(host).lower(), "ASSET"

    # Check principal asset IP
    ip = (fields.get("event_principal_asset_ip_1") or 
          fields.get("event_principal_ip_1") or 
          fields.get("event_principal_ip"))
    if ip:
      return str(ip), "IP"

    # Check target hostname / IP
    target_host = fields.get("event_target_hostname") or fields.get("event_target_asset_hostname")
    if target_host:
      return str(target_host).lower(), "ASSET"
    target_ip = (fields.get("event_target_asset_ip_1") or 
                 fields.get("event_target_ip_1") or 
                 fields.get("event_target_ip"))
    if target_ip:
      return str(target_ip), "IP"

    # Direct nested UDM structure in parsed_raw
    if isinstance(parsed_raw, dict):
      udm_event = parsed_raw.get("event", {})
      if isinstance(udm_event, dict):
        princ = udm_event.get("principal", {})
        if isinstance(princ, dict):
          p_user = princ.get("user", {}).get("userid")
          if p_user:
            return str(p_user).lower(), "USER"
          p_host = princ.get("hostname") or (princ.get("asset", {}).get("hostname") if isinstance(princ.get("asset"), dict) else None)
          if p_host:
            return str(p_host).lower(), "ASSET"
          p_ip = (princ.get("asset", {}).get("ip") if isinstance(princ.get("asset"), dict) else None) or princ.get("ip")
          if p_ip:
            val = p_ip[0] if isinstance(p_ip, list) and p_ip else p_ip
            return str(val), "IP"
        targ = udm_event.get("target", {})
        if isinstance(targ, dict):
          t_host = targ.get("hostname") or (targ.get("asset", {}).get("hostname") if isinstance(targ.get("asset"), dict) else None)
          if t_host:
            return str(t_host).lower(), "ASSET"
          t_ip = (targ.get("asset", {}).get("ip") if isinstance(targ.get("asset"), dict) else None) or targ.get("ip")
          if t_ip:
            val = t_ip[0] if isinstance(t_ip, list) and t_ip else t_ip
            return str(val), "IP"

    # 2. Inspect mappedEventJson
    mapped_raw = ev.get("mappedEventJson") or "{}"
    try:
      parsed_mapped = json.loads(mapped_raw) if isinstance(mapped_raw, str) else mapped_raw
    except Exception:
      parsed_mapped = {}

    if isinstance(parsed_mapped, dict):
      m_fields = parsed_mapped.get("_fields", {})
      m_ip = m_fields.get("SourceAddress") or m_fields.get("DestinationAddress")
      if m_ip:
        return str(m_ip), "IP"
      m_host = m_fields.get("SourceHostName") or m_fields.get("DestinationHostName")
      if m_host:
        return str(m_host).lower(), "ASSET"
      m_user = m_fields.get("SourceUserName") or m_fields.get("DestinationUserName")
      if m_user:
        return str(m_user).lower(), "USER"

  return None


class WatchdogState:
  """Persistent state tracking for processed cases and intra-day 360 radar emissions."""

  def __init__(self, state_file: Optional[Path] = None, max_state_size: int = 2000, max_results: int = 1000):
    self.state_file = state_file or Path("data/watchdog_state.json")
    self.max_state_size = max_state_size
    self.max_results = max_results
    self.seen_case_ids: OrderedDict[str, None] = OrderedDict()
    self.last_scan_time: Optional[str] = None
    self.triaged_count: int = 0
    self.recent_results: List[Dict[str, Any]] = []
    self.fleet_360_emissions: Dict[str, Dict[str, Any]] = {}
    self.last_fleet_360_sweep_time: Optional[str] = None
    self.fleet_360_sweeps: List[Dict[str, Any]] = []
    self.playbooks: Dict[str, Dict[str, Any]] = {}
    self.playbook_emissions: Dict[str, Dict[str, Any]] = {}
    self.playbook_runs: List[Dict[str, Any]] = []
    self.load()

  def load(self) -> None:
    if self.state_file.is_file():
      try:
        data = json.loads(self.state_file.read_text(encoding="utf-8"))
        raw_seen = data.get("seen_case_ids", [])
        self.seen_case_ids = OrderedDict(
            (str(cid), None) for cid in raw_seen[-self.max_state_size:]
        )
        self.last_scan_time = data.get("last_scan_time")
        self.triaged_count = int(data.get("triaged_count", len(self.seen_case_ids)))
        self.recent_results = data.get("recent_results", [])
        raw_emissions = data.get("fleet_360_emissions", {})
        if isinstance(raw_emissions, dict):
          self.fleet_360_emissions = raw_emissions
        self.last_fleet_360_sweep_time = data.get("last_fleet_360_sweep_time")
        raw_sweeps = data.get("fleet_360_sweeps", [])
        if isinstance(raw_sweeps, list):
          self.fleet_360_sweeps = raw_sweeps[-50:]
        raw_playbooks = data.get("playbooks", {})
        if isinstance(raw_playbooks, dict):
          self.playbooks = raw_playbooks
        raw_pb_emissions = data.get("playbook_emissions", {})
        if isinstance(raw_pb_emissions, dict):
          self.playbook_emissions = raw_pb_emissions
        raw_pb_runs = data.get("playbook_runs", [])
        if isinstance(raw_pb_runs, list):
          self.playbook_runs = raw_pb_runs[-50:]
        logger.info(f"Loaded watchdog state with {len(self.seen_case_ids)} seen cases.")
      except Exception as e:
        logger.warning(f"Failed loading watchdog state file: {e}")

  def save(self) -> None:
    try:
      self.state_file.parent.mkdir(parents=True, exist_ok=True)
      payload = {
          "seen_case_ids": list(self.seen_case_ids.keys()),
          "last_scan_time": self.last_scan_time,
          "triaged_count": self.triaged_count,
          "recent_results": self.recent_results[-self.max_results:],
          "fleet_360_emissions": self.fleet_360_emissions,
          "last_fleet_360_sweep_time": self.last_fleet_360_sweep_time,
          "fleet_360_sweeps": self.fleet_360_sweeps[-50:],
          "playbooks": self.playbooks,
          "playbook_emissions": self.playbook_emissions,
          "playbook_runs": self.playbook_runs[-50:],
      }
      # Atomic file replacement prevents corrupted state writes during process interruption
      tmp_file = self.state_file.with_suffix(".tmp")
      tmp_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
      tmp_file.replace(self.state_file)
    except Exception as e:
      logger.error(f"Failed persisting watchdog state: {e}")

  def record_case(self, case_id: str, summary: Optional[Dict[str, Any]] = None) -> None:
    cid = str(case_id)
    if cid in self.seen_case_ids:
      self.seen_case_ids.move_to_end(cid)
    else:
      self.seen_case_ids[cid] = None
      self.triaged_count += 1
      # Enforce sliding-window FIFO ring-buffer capacity
      while len(self.seen_case_ids) > self.max_state_size:
        self.seen_case_ids.popitem(last=False)

    if summary is not None:
      self.recent_results.append(summary)
      if len(self.recent_results) > self.max_results:
        self.recent_results = self.recent_results[-self.max_results:]
    self.save()

  def is_seen(self, case_id: str) -> bool:
    return str(case_id) in self.seen_case_ids

  def should_emit_fleet_360(
      self,
      bucket_date: str,
      entity_type: str,
      entity_id: str,
      breached_sectors: List[str],
      composite_d: float,
      min_delta_d: float = 2.0,
  ) -> bool:
    """Intra-day deduplication check for 4-hour Mode A fleet 360 radar sweeps.

    Returns True if:
    - Entity has not been emitted yet on `bucket_date`, OR
    - At least one sector in `breached_sectors` was not previously breached on `bucket_date`, OR
    - The Euclidean composite distance D escalated by >= `min_delta_d` (+2.0 sigma).
    """
    key = f"{bucket_date}:{entity_type.upper()}:{entity_id.lower()}"
    prev = self.fleet_360_emissions.get(key)
    if not prev:
      return True
    prev_sectors = set(prev.get("breached_sectors", []))
    if any(sec not in prev_sectors for sec in breached_sectors):
      return True
    prev_d = float(prev.get("composite_d", 0.0))
    if (float(composite_d) - prev_d) >= min_delta_d:
      return True
    return False

  def record_fleet_360_emission(
      self,
      bucket_date: str,
      entity_type: str,
      entity_id: str,
      breached_sectors: List[str],
      composite_d: float,
      composite_cri: int,
  ) -> None:
    """Records an intra-day 360 radar emission for deduplication across 4-hour sweeps."""
    key = f"{bucket_date}:{entity_type.upper()}:{entity_id.lower()}"
    prev = self.fleet_360_emissions.get(key, {})
    merged_sectors = sorted(set(prev.get("breached_sectors", [])) | set(breached_sectors))
    prev_d = float(prev.get("composite_d", 0.0))
    prev_cri = int(prev.get("composite_cri", 0))
    self.fleet_360_emissions[key] = {
        "bucket_date": bucket_date,
        "entity_type": entity_type.upper(),
        "entity_id": entity_id.lower(),
        "breached_sectors": merged_sectors,
        "composite_d": round(max(prev_d, float(composite_d)), 2),
        "composite_cri": max(prev_cri, int(composite_cri)),
        "emission_count": int(prev.get("emission_count", 0)) + 1,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    # Evict oldest entries if dictionary grows beyond max_state_size
    while len(self.fleet_360_emissions) > self.max_state_size:
      oldest_key = next(iter(self.fleet_360_emissions))
      self.fleet_360_emissions.pop(oldest_key, None)
    self.save()

  def record_fleet_360_sweep(self, sweep_summary: Dict[str, Any]) -> None:
    """Persists summary telemetry for a completed fleetwide 360 radar sweep."""
    self.last_fleet_360_sweep_time = (
        sweep_summary.get("timestamp")
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    self.fleet_360_sweeps.append(sweep_summary)
    if len(self.fleet_360_sweeps) > 50:
      self.fleet_360_sweeps = self.fleet_360_sweeps[-50:]
    self.save()

  def should_emit_playbook_match(
      self,
      bucket_date: str,
      playbook_id: str,
      query_id: str,
      entity_id: str,
      effective_z: float,
      min_delta_z: float = 2.0,
  ) -> bool:
    """Intra-day deduplication check for scheduled Markdown playbook hunts."""
    key = f"{bucket_date}:{playbook_id.lower()}:{query_id.lower()}:{entity_id.lower()}"
    prev = self.playbook_emissions.get(key)
    if not prev:
      return True
    prev_z = float(prev.get("effective_z", 0.0))
    if (float(effective_z) - prev_z) >= min_delta_z:
      return True
    return False

  def record_playbook_emission(
      self,
      bucket_date: str,
      playbook_id: str,
      query_id: str,
      entity_id: str,
      effective_z: float,
      cri_score: int,
  ) -> None:
    """Records an intra-day playbook match emission for deduplication across sweeps."""
    key = f"{bucket_date}:{playbook_id.lower()}:{query_id.lower()}:{entity_id.lower()}"
    prev = self.playbook_emissions.get(key, {})
    prev_z = float(prev.get("effective_z", 0.0))
    prev_cri = int(prev.get("cri_score", 0))
    self.playbook_emissions[key] = {
        "bucket_date": bucket_date,
        "playbook_id": playbook_id,
        "query_id": query_id,
        "entity_id": entity_id.lower(),
        "effective_z": round(max(prev_z, float(effective_z)), 2),
        "cri_score": max(prev_cri, int(cri_score)),
        "emission_count": int(prev.get("emission_count", 0)) + 1,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    while len(self.playbook_emissions) > self.max_state_size:
      oldest_key = next(iter(self.playbook_emissions))
      self.playbook_emissions.pop(oldest_key, None)
    self.save()

  def record_playbook_run(self, run_summary: Dict[str, Any]) -> None:
    """Persists summary telemetry for a completed Markdown playbook hunt pass."""
    pb_id = str(run_summary.get("playbook_id", ""))
    ts = run_summary.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if pb_id and pb_id in self.playbooks:
      self.playbooks[pb_id]["last_run_time"] = ts
      self.playbooks[pb_id]["last_status"] = run_summary.get("status", "SUCCESS")
      self.playbooks[pb_id]["last_matches_found"] = run_summary.get("total_matches_found", 0)
      self.playbooks[pb_id]["last_events_emitted"] = run_summary.get("total_matches_emitted", 0)
      if run_summary.get("content_sha256"):
        self.playbooks[pb_id]["content_sha256"] = run_summary["content_sha256"]
    self.playbook_runs.append(run_summary)
    if len(self.playbook_runs) > 50:
      self.playbook_runs = self.playbook_runs[-50:]
    self.save()

  def reset(self) -> None:
    self.seen_case_ids.clear()
    self.recent_results.clear()
    self.triaged_count = 0
    self.fleet_360_emissions.clear()
    self.fleet_360_sweeps.clear()
    self.last_fleet_360_sweep_time = None
    self.playbook_emissions.clear()
    self.playbook_runs.clear()
    self.save()

  def get_activity_report(
      self,
      timeframe: str = "1h",
      hours: Optional[float] = None,
      tag: Optional[str] = None,
  ) -> Dict[str, Any]:
    """Generates an activity summary for cases triaged within a lookback window, optionally filtered by tag."""
    from src.formatters.case_wall_card import CaseWallCardFormatter

    now = datetime.now(timezone.utc)
    lookback_delta: Optional[timedelta] = None

    if hours is not None and hours > 0:
      lookback_delta = timedelta(hours=hours)
      timeframe_label = f"{hours}h"
    else:
      tf = (timeframe or "1h").lower().strip()
      timeframe_label = tf
      if tf in ("1h", "hour", "last_hour"):
        lookback_delta = timedelta(hours=1)
      elif tf in ("24h", "1d", "day", "today"):
        lookback_delta = timedelta(days=1)
      elif tf in ("7d", "week"):
        lookback_delta = timedelta(days=7)
      elif tf in ("all", "everything"):
        lookback_delta = None
      else:
        lookback_delta = timedelta(hours=1)

    cutoff = (now - lookback_delta) if lookback_delta else None
    requested_tags = [
        t.strip().upper() for t in (tag or "").split(",") if t.strip()
    ]

    filtered_cases = []
    verdicts: Dict[str, int] = {}
    strategies: Dict[str, int] = {}
    tags_summary: Dict[str, int] = {}

    for res in reversed(self.recent_results):
      ts_str = res.get("timestamp")
      if ts_str and cutoff:
        try:
          clean_ts = ts_str.replace("Z", "+00:00")
          dt = datetime.fromisoformat(clean_ts)
          if dt < cutoff:
            continue
        except Exception:
          pass

      # Ensure tags and common_vector are populated (backfilling legacy records if needed)
      rec_tags = res.get("tags")
      if rec_tags is None:
        p_vec = str(res.get("primary_vector") or "")
        sec_ran = bool(res.get("second_order_ran") or p_vec.startswith("tier2"))
        rec_tags = CaseWallCardFormatter.build_case_tags(
            calibrated_risk_index=float(res.get("cri") or 0.0),
            primary_vector=p_vec,
            model_name=str(res.get("strategy") or ""),
            second_order_ran=sec_ran,
        )
        res = dict(res)
        res["tags"] = rec_tags
        res.setdefault(
            "common_vector",
            CaseWallCardFormatter.normalize_common_vector(
                raw_vector=p_vec,
                model_name=str(res.get("strategy") or ""),
            ),
        )
        res.setdefault("second_order_ran", sec_ran)

      if requested_tags:
        upper_rec_tags = [str(rt).upper() for rt in rec_tags]
        if not all(
            any(req_t == urt or req_t in urt for urt in upper_rec_tags)
            for req_t in requested_tags
        ):
          continue

      filtered_cases.append(res)
      v = res.get("verdict", "UNKNOWN")
      verdicts[v] = verdicts.get(v, 0) + 1
      s = res.get("strategy", "UNKNOWN")
      strategies[s] = strategies.get(s, 0) + 1
      for t_item in rec_tags:
        tags_summary[t_item] = tags_summary.get(t_item, 0) + 1

    return {
        "status": "SUCCESS",
        "timeframe": timeframe_label,
        "tag_filter": requested_tags if requested_tags else None,
        "window_start": cutoff.strftime("%Y-%m-%dT%H:%M:%SZ") if cutoff else "ALL_TIME",
        "window_end": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_cases_triaged": len(filtered_cases),
        "summary_by_verdict": verdicts,
        "summary_by_tag": tags_summary,
        "summary_by_strategy": strategies,
        "cases": filtered_cases,
    }


class WatchdogDaemon:
  """Standing background monitor scanning open cases with a bounded worker pool."""

  def __init__(
      self,
      engine: Any,
      tenant_config: Optional[TenantConfig] = None,
      state_file: Optional[Path] = None,
  ):
    self.engine = engine
    self.tenant = tenant_config or TenantConfig()
    self.max_state_size = getattr(self.tenant, "watchdog_max_state_size", 2000)
    self.state = WatchdogState(state_file, max_state_size=self.max_state_size)
    self.interval_seconds = getattr(self.tenant, "watchdog_interval_seconds", 60)
    self.limit_per_scan = getattr(self.tenant, "watchdog_limit_per_scan", 5)
    self.scan_lookback_hours = getattr(self.tenant, "watchdog_scan_lookback_hours", 4)
    self.worker_concurrency = getattr(self.tenant, "watchdog_worker_concurrency", 3)
    self.queue_size = getattr(self.tenant, "watchdog_queue_size", 100)
    self.fleet_360_enabled = getattr(self.tenant, "fleet_360_enabled", True)
    self.fleet_360_interval_seconds = getattr(self.tenant, "fleet_360_interval_seconds", 14400)

    self._scan_task: Optional[asyncio.Task] = None
    self._fleet_360_task: Optional[asyncio.Task] = None
    self._playbook_task: Optional[asyncio.Task] = None
    self._task: Optional[asyncio.Task] = None  # Backward-compatibility alias
    self._workers: List[asyncio.Task] = []
    self._work_queue: Optional[asyncio.Queue] = None
    self._in_flight_case_ids: Set[str] = set()
    self._scan_lock = asyncio.Lock()
    self._fleet_360_lock = asyncio.Lock()
    self._playbook_lock = asyncio.Lock()
    self._active_worker_count = 0
    self._is_running = False
    self._playbook_scheduler_running = False
    self.playbook_runner = PlaybookRunner(
        tenant_config=self.tenant,
        risk_engine=getattr(self.engine, "risk_engine", None),
    )

  @property
  def is_running(self) -> bool:
    return self._is_running and self._scan_task is not None and not self._scan_task.done()

  @property
  def is_playbook_scheduler_running(self) -> bool:
    return (
        self._playbook_scheduler_running
        and self._playbook_task is not None
        and not self._playbook_task.done()
    )

  def _ensure_playbook_scheduler(self) -> None:
    """Starts the background playbook scheduler loop if any playbook is enabled."""
    has_enabled = any(pb.get("enabled", True) for pb in self.state.playbooks.values())
    if has_enabled and not self.is_playbook_scheduler_running:
      try:
        loop = asyncio.get_running_loop()
        self._playbook_scheduler_running = True
        self._playbook_task = loop.create_task(self._playbook_loop())
      except RuntimeError:
        pass

  def start(self) -> Dict[str, Any]:
    """Starts the background producer-consumer monitoring loop, worker pool, and 4h fleet 360 sweep."""
    if self.is_running:
      return {"status": "ALREADY_RUNNING", "interval_seconds": self.interval_seconds}

    self._is_running = True
    self._work_queue = asyncio.Queue(maxsize=self.queue_size)
    self._workers = [
        asyncio.create_task(self._worker_loop(i))
        for i in range(self.worker_concurrency)
    ]
    self._scan_task = asyncio.create_task(self._run_loop())
    self._task = self._scan_task
    if self.fleet_360_enabled:
      self._fleet_360_task = asyncio.create_task(self._fleet_360_loop())
    self._ensure_playbook_scheduler()
    logger.info(
        f"Watchdog daemon started. Polling every {self.interval_seconds}s "
        f"with {self.worker_concurrency} workers (queue capacity {self.queue_size}, "
        f"fleet_360_enabled={self.fleet_360_enabled}, fleet_360_interval={self.fleet_360_interval_seconds}s)."
    )
    return {
        "status": "STARTED",
        "interval_seconds": self.interval_seconds,
        "worker_concurrency": self.worker_concurrency,
        "queue_size": self.queue_size,
        "fleet_360_enabled": self.fleet_360_enabled,
        "fleet_360_interval_seconds": self.fleet_360_interval_seconds,
        "playbooks_registered": len(self.state.playbooks),
    }

  def stop(self) -> Dict[str, Any]:
    """Stops the background monitoring loop and worker tasks cleanly."""
    if not self.is_running and not self.is_playbook_scheduler_running:
      return {"status": "NOT_RUNNING"}

    self._is_running = False
    self._playbook_scheduler_running = False
    if self._scan_task and not self._scan_task.done():
      self._scan_task.cancel()
    if self._fleet_360_task and not self._fleet_360_task.done():
      self._fleet_360_task.cancel()
    if self._playbook_task and not self._playbook_task.done():
      self._playbook_task.cancel()
    for w in self._workers:
      if not w.done():
        w.cancel()
    self._workers.clear()
    self._in_flight_case_ids.clear()
    logger.info("Watchdog daemon stopped.")
    return {"status": "STOPPED"}

  def status(self) -> Dict[str, Any]:
    """Returns current runtime status and historical metrics."""
    q_size = self._work_queue.qsize() if self._work_queue else 0
    return {
        "is_running": self.is_running,
        "interval_seconds": self.interval_seconds,
        "limit_per_scan": self.limit_per_scan,
        "scan_lookback_hours": self.scan_lookback_hours,
        "worker_concurrency": self.worker_concurrency,
        "active_workers": self._active_worker_count,
        "queue_depth": q_size,
        "queue_max_size": self.queue_size,
        "last_scan_time": self.state.last_scan_time,
        "triaged_count": self.state.triaged_count,
        "seen_cases_count": len(self.state.seen_case_ids),
        "seen_case_ids": list(self.state.seen_case_ids.keys()),
        "recent_results": self.state.recent_results[-10:],
        "fleet_360_enabled": self.fleet_360_enabled,
        "fleet_360_interval_seconds": self.fleet_360_interval_seconds,
        "last_fleet_360_sweep_time": self.state.last_fleet_360_sweep_time,
        "fleet_360_tracked_entities": len(self.state.fleet_360_emissions),
        "fleet_360_recent_sweeps": self.state.fleet_360_sweeps[-5:],
        "playbook_scheduler_running": self.is_playbook_scheduler_running,
        "playbooks_registered": len(self.state.playbooks),
        "playbooks": list(self.state.playbooks.values()),
        "playbook_recent_runs": self.state.playbook_runs[-5:],
    }

  async def _worker_loop(self, worker_id: int) -> None:
    """Worker task consuming JIT hunt requests from the work queue."""
    logger.info(f"Watchdog worker #{worker_id} ready.")
    while self._is_running:
      try:
        assert self._work_queue is not None
        task_data = await self._work_queue.get()
      except asyncio.CancelledError:
        break
      except Exception as e:
        logger.error(f"Watchdog worker #{worker_id} error reading queue: {e}")
        break

      case_id = task_data["case_id"]
      case_title = task_data["case_title"]
      model_name = task_data["strategy"]
      target_entity = task_data["entity"]
      entity_type = task_data["entity_type"]
      req = task_data["req"]

      self._active_worker_count += 1
      try:
        logger.info(f"Worker #{worker_id} processing Case {case_id} ({target_entity}) [{model_name}].")
        hunt_resp = await self.engine.execute_jit_hunt(req)
        summary_record = {
            "case_id": case_id,
            "case_title": case_title,
            "entity": target_entity,
            "entity_type": entity_type,
            "strategy": model_name,
            "cri": hunt_resp.triage.calibrated_risk_index,
            "verdict": hunt_resp.triage.verdict,
            "primary_vector": hunt_resp.triage.primary_vector,
            "common_vector": hunt_resp.triage.common_vector,
            "second_order_ran": hunt_resp.triage.second_order_ran,
            "tags": hunt_resp.triage.tags,
            "case_wall_updated": hunt_resp.case_wall_updated,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        self.state.record_case(case_id, summary_record)
        logger.info(
            f"Worker #{worker_id} triaged Case {case_id}: "
            f"Verdict={hunt_resp.triage.verdict} (CRI={hunt_resp.triage.calibrated_risk_index})"
        )
      except Exception as e:
        logger.error(f"Worker #{worker_id} failed processing Case {case_id}: {e}")
        self.state.record_case(case_id)
      finally:
        self._in_flight_case_ids.discard(case_id)
        self._active_worker_count = max(0, self._active_worker_count - 1)
        self._work_queue.task_done()

  async def scan_once(self) -> List[Dict[str, Any]]:
    """Performs a single evaluation pass across newly discovered open cases.
    
    Guarded by an asyncio.Lock to strictly prevent overlapping scan passes.
    In daemon mode with active workers, enqueues tasks to the bounded queue.
    In standalone mode, executes tasks inline and returns triaged records.
    """
    if self._scan_lock.locked():
      logger.warning("Watchdog scan pass is already in progress. Skipping concurrent run.")
      return []

    async with self._scan_lock:
      return await self._do_scan_pass()

  async def _do_scan_pass(self) -> List[Dict[str, Any]]:
    self.state.last_scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not self.tenant.project_id or not self.tenant.customer_id:
      logger.warning(
          f"Watchdog scan paused: Missing required Chronicle configuration. "
          f"Please ensure CHRONICLE_PROJECT_ID and CHRONICLE_CUSTOMER_ID environment variables are set. "
          f"(Current: project_id='{self.tenant.project_id}', customer_id='{self.tenant.customer_id}')"
      )
      return []

    headers = self.tenant.get_auth_headers()
    custom_timeout = httpx.Timeout(30.0, read=120.0, write=120.0, pool=120.0)
    pass_results = []

    async with httpx.AsyncClient(headers=headers, timeout=custom_timeout, follow_redirects=True) as http_client:
      def _create_mcp_context():
        try:
          return streamable_http_client(self.tenant.mcp_url, headers=headers, timeout=60.0, sse_read_timeout=300.0)
        except TypeError:
          return streamable_http_client(self.tenant.mcp_url, headers=headers)

      mcp_context = _create_mcp_context()

      async with mcp_context as streams, ClientSession(streams[0], streams[1]) as session:
        await session.initialize()

        # Build sliding time-window filter
        if self.scan_lookback_hours and self.scan_lookback_hours > 0:
          lookback_ms = int(
              (datetime.now(timezone.utc) - timedelta(hours=self.scan_lookback_hours)).timestamp() * 1000
          )
          cases_filter = f"Status='OPENED' AND CreateTime >= {lookback_ms}"
        else:
          cases_filter = "Status='OPENED'"

        # 1. Fetch open cases
        try:
          list_cases_res = await session.call_tool(
              "list_cases",
              {
                  "projectId": self.tenant.project_id,
                  "customerId": self.tenant.customer_id,
                  "region": self.tenant.region,
                  "filter": cases_filter,
                  "orderBy": "CreateTime desc",
                  "pageSize": self.limit_per_scan * 2,
              },
          )
        except Exception as list_err:
          logger.error(
              f"Failed calling list_cases on OneMCP (project='{self.tenant.project_id}', customer='{self.tenant.customer_id}', filter='{cases_filter}'): {_unwrap_exception(list_err)}"
          )
          return []

        raw_cases = json.loads(list_cases_res.content[0].text) if list_cases_res.content else {}
        all_cases = raw_cases.get("cases", [])

        def _get_cid(c: Dict[str, Any]) -> str:
          return str(c.get("id") or (c.get("name", "").split("/")[-1] if "/" in str(c.get("name", "")) else ""))

        # Filter out already seen cases and in-flight cases
        unseen_cases = []
        for c in all_cases:
          cid = _get_cid(c)
          if cid and not self.state.is_seen(cid) and cid not in self._in_flight_case_ids:
            unseen_cases.append(c)
            if len(unseen_cases) >= self.limit_per_scan:
              break

        if not unseen_cases:
          logger.info(f"Watchdog scan complete: 0 new cases (out of {len(all_cases)} within horizon).")
          return []

        logger.info(f"Watchdog discovered {len(unseen_cases)} new uninvestigated cases.")

        for case in unseen_cases:
          case_id = _get_cid(case)
          if not case_id:
            continue

          case_title = case.get("displayName") or case.get("title", "Untitled Case")
          case_desc = case.get("description", "")

          try:
            # Check if this case was already triaged by the agent (e.g. across container restarts)
            try:
              comments_res = await session.call_tool(
                  "list_case_comments",
                  {
                      "projectId": self.tenant.project_id,
                      "customerId": self.tenant.customer_id,
                      "region": self.tenant.region,
                      "caseId": case_id,
                      "pageSize": 50,
                  },
              )
              raw_comments = json.loads(comments_res.content[0].text) if comments_res.content else {}
              comments_list = raw_comments.get("caseComments", raw_comments.get("comments", []))
              has_triage_comment = any(
                  "Statistical Outlier Report" in str(cm.get("comment", "")) or
                  "Autonomous Agentic UEBA Triage Report" in str(cm.get("comment", "")) or
                  "Composite Threat Distance" in str(cm.get("comment", "")) or
                  "Calibrated Risk Index" in str(cm.get("comment", ""))
                  for cm in comments_list
              )
              if has_triage_comment:
                logger.info(f"Case {case_id} already contains agent triage report on wall; caching as seen.")
                self.state.record_case(case_id)
                continue
            except Exception as comment_err:
              logger.debug(f"Could not verify existing comments on Case {case_id}: {comment_err}")

            # Query alerts in this case
            alerts_res = await session.call_tool(
                "list_case_alerts",
                {
                    "projectId": self.tenant.project_id,
                    "customerId": self.tenant.customer_id,
                    "region": self.tenant.region,
                    "caseId": case_id,
                },
            )
            raw_alerts = json.loads(alerts_res.content[0].text) if alerts_res.content else {}
            alerts = raw_alerts.get("caseAlerts", raw_alerts.get("alerts", []))

            target_entity = None
            entity_type = "USER"
            alert_name = case_title
            alert_desc = case_desc

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
                            "projectId": self.tenant.project_id,
                            "customerId": self.tenant.customer_id,
                            "region": self.tenant.region,
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
                  if e_type in ("USER", "USER_ID", "EMAIL", "USERNAME", "ACCOUNT", "USERUNIQNAME"):
                    target_entity = ident.lower()
                    entity_type = "USER"
                    break
                  elif e_type in ("HOSTNAME", "ASSET", "HOST", "COMPUTER"):
                    target_entity = ident.lower()
                    entity_type = "ASSET"
                    break
                  elif e_type in ("IP", "IP_ADDRESS", "INTERNAL_IP", "EXTERNAL_IP", "SOURCE_IP", "DESTINATION_IP", "INTERNAL IP", "EXTERNAL IP", "ADDRESS"):
                    target_entity = ident
                    entity_type = "IP"
                    break
                if target_entity:
                  break

            # Fallback to case entities
            if not target_entity:
              for ent in case.get("entities", []):
                ident = ent.get("identifier")
                if ident:
                  target_entity = ident
                  break

            # Inspect connector events for underlying UDM telemetry and fallback entities
            all_conn_events = []
            if alerts:
              for alert in alerts[:3]:
                alert_name_str = str(alert.get("name", ""))
                alert_numeric_id = alert_name_str.split("/")[-1] if "/" in alert_name_str else str(alert.get("id", ""))
                if not alert_numeric_id:
                  continue
                try:
                  events_res = await session.call_tool(
                      "list_connector_events",
                      {
                          "projectId": self.tenant.project_id,
                          "customerId": self.tenant.customer_id,
                          "region": self.tenant.region,
                          "caseId": case_id,
                          "caseAlertId": alert_numeric_id,
                          "expandEventJsonData": True,
                          "pageSize": 5,
                      },
                  )
                  if events_res.content:
                    events_data = json.loads(events_res.content[0].text)
                    conn_events = events_data.get("connectorEvents", [])
                    all_conn_events.extend(conn_events)
                    if not target_entity:
                      extracted = _extract_entity_from_connector_events(conn_events)
                      if extracted:
                        target_entity, entity_type = extracted
                        logger.info(
                            f"Extracted entity '{target_entity}' ({entity_type}) from connector events for Case {case_id}."
                        )
                except Exception as ev_err:
                  logger.debug(f"Could not inspect connector events for alert {alert_numeric_id}: {ev_err}")

            if not target_entity:
              logger.info(f"Case {case_id} had no extractable entities; marking as processed.")
              self.state.record_case(case_id)
              continue

            # Agentic Strategy Reasoner: Formulate Tier 1 360 Baseline Directive
            directive = StrategyDecider.decide_tier1_360(
                target_entity=target_entity,
                entity_type=entity_type,
                case_id=case_id,
                case_title=case_title,
                case_desc=case_desc,
                alerts=alerts,
            )
            target_entity = directive.target_entity or target_entity
            entity_type = directive.entity_type or entity_type
            model_name = directive.model_name
            skill = directive.selected_skill
            directive_query = directive.directive_query

            logger.info(
                f"Agentic Strategy Reasoner initialized [{model_name}] ({skill}) for Case {case_id} ({target_entity}): "
                f"H0='{directive.hypothesis_h0}'"
            )

            # Formulate JIT Hunt Request with full Agentic Directive
            req = JITHuntRequest(
                target_entity=target_entity,
                entity_type=entity_type,
                case_id=case_id,
                alert_name=alert_name,
                alert_description=alert_desc,
                query=directive_query,
                skill=skill,
                directive=directive,
                alerts=alerts,
                connector_events=all_conn_events,
                post_to_case_wall=True,
            )

            task_payload = {
                "case_id": case_id,
                "case_title": case_title,
                "entity": target_entity,
                "entity_type": entity_type,
                "strategy": model_name,
                "req": req,
            }

            # Producer-Consumer queue dispatch vs standalone execution
            if self.is_running and self._work_queue is not None:
              if self._work_queue.full():
                logger.warning(
                    f"Watchdog queue full ({self._work_queue.qsize()}/{self.queue_size}). "
                    f"Backpressure applied: skipping Case {case_id} for next cycle."
                )
                continue
              self._in_flight_case_ids.add(case_id)
              self._work_queue.put_nowait(task_payload)
              pass_results.append(task_payload)
            else:
              # Standalone inline execution
              self._in_flight_case_ids.add(case_id)
              try:
                hunt_resp = await self.engine.execute_jit_hunt(req)
                summary_record = {
                    "case_id": case_id,
                    "case_title": case_title,
                    "entity": target_entity,
                    "entity_type": entity_type,
                    "strategy": model_name,
                    "cri": hunt_resp.triage.calibrated_risk_index,
                    "verdict": hunt_resp.triage.verdict,
                    "primary_vector": hunt_resp.triage.primary_vector,
                    "common_vector": hunt_resp.triage.common_vector,
                    "second_order_ran": hunt_resp.triage.second_order_ran,
                    "tags": hunt_resp.triage.tags,
                    "case_wall_updated": hunt_resp.case_wall_updated,
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
                pass_results.append(summary_record)
                self.state.record_case(case_id, summary_record)
                logger.info(
                    f"Case {case_id} triaged: Verdict={hunt_resp.triage.verdict} "
                    f"(CRI={hunt_resp.triage.calibrated_risk_index})"
                )
              finally:
                self._in_flight_case_ids.discard(case_id)

          except Exception as e:
            logger.error(f"Failed processing Case {case_id} in watchdog: {_unwrap_exception(e)}")
            self.state.record_case(case_id)

        return pass_results

  async def _run_loop(self) -> None:
    """Internal loop executing periodic scan passes."""
    while self._is_running:
      try:
        await self.scan_once()
      except asyncio.CancelledError:
        logger.info("Watchdog scan loop cancelled.")
        break
      except Exception as e:
        logger.error(f"Error in watchdog scan pass: {_unwrap_exception(e)}")

      try:
        await asyncio.sleep(self.interval_seconds)
      except asyncio.CancelledError:
        break

  async def run_fleet_360_sweep_once(
      self,
      entity_types: Sequence[str] = ("USER", "ASSET"),
      spike_threshold_z: Optional[float] = None,
      spoke_inclusion_z: Optional[float] = None,
      min_observed: Optional[int] = None,
      max_outliers_per_sector: Optional[int] = None,
      inter_query_delay_sec: Optional[float] = None,
      ingest_events: Optional[bool] = None,
      now_utc: Optional[datetime] = None,
      lookback_days: int = 1,
      mcp_session: Optional[Any] = None,
  ) -> Dict[str, Any]:
    """Executes a single fleetwide 360° behavioral risk radar sweep across requested entity types.

    Guarded by an asyncio.Lock to prevent overlapping sweeps.
    Applies intra-day deduplication via WatchdogState so entities are only re-emitted
    on the same UTC bucket date if a new sector breaches >= 3.0σ or Composite D escalates by >= +2.0σ.
    """
    if self._fleet_360_lock.locked():
      logger.warning("Fleet 360 radar sweep is already in progress. Skipping concurrent run.")
      return {"status": "SKIPPED_CONCURRENT"}

    async with self._fleet_360_lock:
      return await self._do_fleet_360_sweep(
          entity_types=entity_types,
          spike_threshold_z=spike_threshold_z,
          spoke_inclusion_z=spoke_inclusion_z,
          min_observed=min_observed,
          max_outliers_per_sector=max_outliers_per_sector,
          inter_query_delay_sec=inter_query_delay_sec,
          ingest_events=ingest_events,
          now_utc=now_utc,
          lookback_days=lookback_days,
          mcp_session=mcp_session,
      )

  async def _do_fleet_360_sweep(
      self,
      entity_types: Sequence[str] = ("USER", "ASSET"),
      spike_threshold_z: Optional[float] = None,
      spoke_inclusion_z: Optional[float] = None,
      min_observed: Optional[int] = None,
      max_outliers_per_sector: Optional[int] = None,
      inter_query_delay_sec: Optional[float] = None,
      ingest_events: Optional[bool] = None,
      now_utc: Optional[datetime] = None,
      lookback_days: int = 1,
      mcp_session: Optional[Any] = None,
  ) -> Dict[str, Any]:
    sweep_ts = (now_utc or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    norm_entity_types = [str(e).upper().strip() for e in entity_types]
    logger.info(
        f"Fleet 360 radar sweep starting: timestamp={sweep_ts}, "
        f"entity_types={norm_entity_types}, lookback_days={lookback_days}."
    )
    risk_engine: RiskMetricsEngine = (
        getattr(self.engine, "risk_engine", None) or RiskMetricsEngine(self.tenant)
    )

    async def _run_with_session(session: Any) -> Dict[str, Any]:
      reports_by_type: Dict[str, Any] = {}
      total_outliers = 0
      total_emitted = 0
      total_suppressed = 0
      total_events = 0

      for et in entity_types:
        et_norm = str(et).upper().strip()
        rep = await risk_engine.run_fleet_360_sweep(
            session=session,
            entity_type=et_norm,
            spike_threshold_z=spike_threshold_z,
            spoke_inclusion_z=spoke_inclusion_z,
            min_observed=min_observed,
            max_outliers_per_sector=max_outliers_per_sector,
            inter_query_delay_sec=inter_query_delay_sec,
            ingest_events=ingest_events,
            now_utc=now_utc,
            lookback_days=lookback_days,
            should_emit_fn=self.state.should_emit_fleet_360,
            record_emit_fn=self.state.record_fleet_360_emission,
        )
        reports_by_type[et_norm] = rep
        total_outliers += int(rep.get("outliers_detected", 0))
        total_emitted += int(rep.get("outliers_emitted", 0))
        total_suppressed += int(rep.get("outliers_suppressed_dedup", 0))
        total_events += int(rep.get("udm_events_generated", 0))

      combined = {
          "status": "SUCCESS",
          "timestamp": sweep_ts,
          "entity_types": norm_entity_types,
          "total_outliers_detected": total_outliers,
          "total_outliers_emitted": total_emitted,
          "total_outliers_suppressed_dedup": total_suppressed,
          "total_udm_events_generated": total_events,
          "sweeps_by_entity_type": reports_by_type,
      }
      self.state.record_fleet_360_sweep({
          "timestamp": sweep_ts,
          "entity_types": combined["entity_types"],
          "total_outliers_detected": total_outliers,
          "total_outliers_emitted": total_emitted,
          "total_outliers_suppressed_dedup": total_suppressed,
          "total_udm_events_generated": total_events,
      })
      verdict_tag = (
          "EMITTED_UDM_EVENTS"
          if total_events > 0
          else ("SUPPRESSED_DUPLICATES" if total_suppressed > 0 else "NO_OUTLIERS_FOUND")
      )
      logger.info(
          f"Fleet 360 radar sweep complete [{verdict_tag}]: timestamp={sweep_ts}, "
          f"entity_types={combined['entity_types']}, outliers_detected={total_outliers}, "
          f"outliers_emitted={total_emitted}, suppressed_dedup={total_suppressed}, "
          f"udm_events_generated={total_events}."
      )
      return combined

    if mcp_session is not None:
      return await _run_with_session(mcp_session)

    if not self.tenant.project_id or not self.tenant.customer_id:
      logger.warning(
          "Fleet 360 radar sweep paused: Missing required Chronicle configuration "
          f"(project_id='{self.tenant.project_id}', customer_id='{self.tenant.customer_id}')."
      )
      return {"status": "SKIPPED_MISSING_CONFIG", "timestamp": sweep_ts}

    headers = self.tenant.get_auth_headers()
    custom_timeout = httpx.Timeout(30.0, read=120.0, write=120.0, pool=120.0)

    async with httpx.AsyncClient(headers=headers, timeout=custom_timeout, follow_redirects=True):
      def _create_mcp_context():
        try:
          return streamable_http_client(
              self.tenant.mcp_url, headers=headers, timeout=60.0, sse_read_timeout=300.0
          )
        except TypeError:
          return streamable_http_client(self.tenant.mcp_url, headers=headers)

      mcp_context = _create_mcp_context()
      async with mcp_context as streams, ClientSession(streams[0], streams[1]) as session:
        await session.initialize()
        return await _run_with_session(session)

  async def _fleet_360_loop(self) -> None:
    """Background 4-hour scheduler loop executing fleetwide Mode A 360° radar sweeps."""
    logger.info(
        f"Fleet 360 radar scheduler started (interval={self.fleet_360_interval_seconds}s)."
    )
    while self._is_running:
      try:
        await self.run_fleet_360_sweep_once()
      except asyncio.CancelledError:
        logger.info("Fleet 360 radar scheduler loop cancelled.")
        break
      except Exception as e:
        logger.error(f"Error in fleet 360 radar sweep: {_unwrap_exception(e)}")

      try:
        await asyncio.sleep(self.fleet_360_interval_seconds)
      except asyncio.CancelledError:
        break

  async def register_playbook(
      self,
      url: str,
      playbook_id: Optional[str] = None,
      interval_seconds: int = 14400,
      ingest_events: bool = True,
      unscope_seeded_to_fleet: bool = False,
      inter_query_delay_sec: float = 1.0,
      enabled: bool = True,
      run_immediately: bool = False,
      http_client: Optional[httpx.AsyncClient] = None,
      mcp_session: Optional[Any] = None,
  ) -> Dict[str, Any]:
    """Fetches, parses, AST-validates, and registers a Markdown hunting playbook subscription."""
    pb_id = (playbook_id or PlaybookRunner.derive_playbook_id(url)).strip().lower()
    md_text, norm_source, content_sha = await self.playbook_runner.fetch_markdown(
        url, http_client=http_client
    )
    specs = self.playbook_runner.parse_markdown_playbook(md_text)
    valid_count = sum(1 for s in specs if not s.ast_errors)
    invalid_count = len(specs) - valid_count
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    existing = self.state.playbooks.get(pb_id, {})
    record = {
        "playbook_id": pb_id,
        "url": url,
        "normalized_source": norm_source,
        "content_sha256": content_sha,
        "enabled": bool(enabled),
        "interval_seconds": max(60, int(interval_seconds)),
        "ingest_events": bool(ingest_events),
        "unscope_seeded_to_fleet": bool(unscope_seeded_to_fleet),
        "inter_query_delay_sec": float(inter_query_delay_sec),
        "queries_discovered": len(specs),
        "queries_ast_valid": valid_count,
        "queries_ast_invalid": invalid_count,
        "queries": [s.to_dict(include_query=False) for s in specs],
        "registered_at": existing.get("registered_at", now_iso),
        "updated_at": now_iso,
        "last_run_time": existing.get("last_run_time"),
        "last_status": existing.get("last_status", "REGISTERED"),
        "last_matches_found": existing.get("last_matches_found", 0),
        "last_events_emitted": existing.get("last_events_emitted", 0),
    }
    self.state.playbooks[pb_id] = record
    self.state.save()

    if enabled:
      self._ensure_playbook_scheduler()

    immediate_run_report = None
    if run_immediately:
      immediate_run_report = await self.run_playbook_once(
          playbook_id=pb_id,
          http_client=http_client,
          mcp_session=mcp_session,
      )

    return {
        "status": "REGISTERED",
        "playbook": self.state.playbooks[pb_id],
        "scheduler_running": self.is_playbook_scheduler_running,
        "immediate_run": immediate_run_report,
    }

  def stop_playbook(
      self,
      playbook_id: str,
      delete: bool = False,
  ) -> Dict[str, Any]:
    """Stops (disables) or deletes a registered Markdown playbook subscription."""
    pb_id = playbook_id.strip().lower()
    if pb_id not in self.state.playbooks:
      return {"status": "NOT_FOUND", "playbook_id": pb_id}

    if delete:
      removed = self.state.playbooks.pop(pb_id)
      self.state.save()
      if not any(pb.get("enabled", False) for pb in self.state.playbooks.values()):
        self._playbook_scheduler_running = False
        if self._playbook_task and not self._playbook_task.done():
          self._playbook_task.cancel()
      return {"status": "DELETED", "playbook_id": pb_id, "playbook": removed}

    self.state.playbooks[pb_id]["enabled"] = False
    self.state.playbooks[pb_id]["updated_at"] = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    self.state.save()

    if not any(pb.get("enabled", False) for pb in self.state.playbooks.values()):
      self._playbook_scheduler_running = False
      if self._playbook_task and not self._playbook_task.done():
        self._playbook_task.cancel()

    return {
        "status": "STOPPED",
        "playbook_id": pb_id,
        "playbook": self.state.playbooks[pb_id],
        "scheduler_running": self.is_playbook_scheduler_running,
    }

  def list_playbooks(self, playbook_id: Optional[str] = None) -> Dict[str, Any]:
    """Lists registered Markdown playbooks and recent execution history."""
    if playbook_id:
      pb_id = playbook_id.strip().lower()
      pb = self.state.playbooks.get(pb_id)
      if not pb:
        return {"status": "NOT_FOUND", "playbook_id": pb_id}
      runs = [r for r in self.state.playbook_runs if r.get("playbook_id") == pb_id]
      return {
          "status": "SUCCESS",
          "scheduler_running": self.is_playbook_scheduler_running,
          "playbook": pb,
          "recent_runs": runs[-10:],
      }

    return {
        "status": "SUCCESS",
        "scheduler_running": self.is_playbook_scheduler_running,
        "total_playbooks": len(self.state.playbooks),
        "playbooks": list(self.state.playbooks.values()),
        "recent_runs": self.state.playbook_runs[-15:],
    }

  async def run_playbook_once(
      self,
      playbook_id: Optional[str] = None,
      url: Optional[str] = None,
      ingest_events: Optional[bool] = None,
      unscope_seeded_to_fleet: Optional[bool] = None,
      inter_query_delay_sec: Optional[float] = None,
      lookback_days_override: Optional[int] = None,
      now_utc: Optional[datetime] = None,
      http_client: Optional[httpx.AsyncClient] = None,
      mcp_session: Optional[Any] = None,
  ) -> Dict[str, Any]:
    """Executes a single pass of a registered or ad-hoc Markdown hunting playbook."""
    if self._playbook_lock.locked():
      logger.warning("Playbook hunt pass is already in progress. Skipping concurrent run.")
      return {"status": "SKIPPED_CONCURRENT"}

    async with self._playbook_lock:
      pb_cfg: Dict[str, Any] = {}
      if playbook_id:
        pb_id_clean = playbook_id.strip().lower()
        pb_cfg = self.state.playbooks.get(pb_id_clean, {})
        if not pb_cfg and not url:
          raise KeyError(f"Playbook '{pb_id_clean}' is not registered.")
      else:
        pb_id_clean = PlaybookRunner.derive_playbook_id(url or "playbook")

      target_url = url or pb_cfg.get("url")
      if not target_url:
        raise ValueError("Either a registered 'playbook_id' or 'url' must be provided.")

      use_ingest = (
          bool(ingest_events)
          if ingest_events is not None
          else bool(pb_cfg.get("ingest_events", True))
      )
      use_unscope = (
          bool(unscope_seeded_to_fleet)
          if unscope_seeded_to_fleet is not None
          else bool(pb_cfg.get("unscope_seeded_to_fleet", False))
      )
      use_delay = (
          float(inter_query_delay_sec)
          if inter_query_delay_sec is not None
          else float(pb_cfg.get("inter_query_delay_sec", 1.0))
      )

      async def _run_with_session(session: Any) -> Dict[str, Any]:
        report = await self.playbook_runner.execute_playbook(
            session=session,
            source=target_url,
            playbook_id=pb_id_clean,
            ingest_events=use_ingest,
            unscope_seeded_to_fleet=use_unscope,
            inter_query_delay_sec=use_delay,
            lookback_days_override=lookback_days_override,
            now_utc=now_utc,
            should_emit_fn=self.state.should_emit_playbook_match,
            record_emit_fn=self.state.record_playbook_emission,
            http_client=http_client,
        )
        self.state.record_playbook_run({
            "timestamp": report["timestamp"],
            "playbook_id": report["playbook_id"],
            "source": report["source"],
            "content_sha256": report["content_sha256"],
            "status": report["status"],
            "queries_discovered": report["queries_discovered"],
            "queries_executed": report["queries_executed"],
            "queries_skipped": report["queries_skipped"],
            "total_matches_found": report["total_matches_found"],
            "total_matches_emitted": report["total_matches_emitted"],
            "total_matches_suppressed_dedup": report["total_matches_suppressed_dedup"],
            "total_udm_events_generated": report["total_udm_events_generated"],
        })
        return report

      if mcp_session is not None:
        return await _run_with_session(mcp_session)

      if not self.tenant.project_id or not self.tenant.customer_id:
        return {
            "status": "SKIPPED_MISSING_CONFIG",
            "playbook_id": pb_id_clean,
            "timestamp": (now_utc or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

      headers = self.tenant.get_auth_headers()
      custom_timeout = httpx.Timeout(30.0, read=120.0, write=120.0, pool=120.0)
      async with httpx.AsyncClient(headers=headers, timeout=custom_timeout, follow_redirects=True):
        def _create_mcp_context():
          try:
            return streamable_http_client(
                self.tenant.mcp_url, headers=headers, timeout=60.0, sse_read_timeout=300.0
            )
          except TypeError:
            return streamable_http_client(self.tenant.mcp_url, headers=headers)

        mcp_context = _create_mcp_context()
        async with mcp_context as streams, ClientSession(streams[0], streams[1]) as session:
          await session.initialize()
          return await _run_with_session(session)

  async def _playbook_loop(self) -> None:
    """Background scheduler loop executing registered Markdown playbooks when due."""
    logger.info("Markdown Playbook scheduler loop started.")
    while self._playbook_scheduler_running:
      try:
        now = datetime.now(timezone.utc)
        for pb_id, pb_cfg in list(self.state.playbooks.items()):
          if not pb_cfg.get("enabled", True):
            continue
          interval = max(60, int(pb_cfg.get("interval_seconds", 14400)))
          last_run_str = pb_cfg.get("last_run_time")
          is_due = True
          if last_run_str:
            try:
              last_dt = datetime.fromisoformat(str(last_run_str).replace("Z", "+00:00"))
              elapsed = (now - last_dt).total_seconds()
              is_due = elapsed >= interval
            except Exception:
              is_due = True

          if is_due:
            logger.info(f"Scheduled Markdown playbook '{pb_id}' is due; starting execution pass.")
            try:
              await self.run_playbook_once(playbook_id=pb_id)
            except Exception as pb_err:
              logger.error(f"Scheduled playbook '{pb_id}' execution failed: {_unwrap_exception(pb_err)}")
      except asyncio.CancelledError:
        logger.info("Markdown Playbook scheduler loop cancelled.")
        break
      except Exception as e:
        logger.error(f"Error in Markdown Playbook scheduler loop: {_unwrap_exception(e)}")

      try:
        await asyncio.sleep(15)
      except asyncio.CancelledError:
        break



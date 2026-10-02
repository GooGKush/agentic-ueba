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
from typing import Any, Dict, List, Optional, Set, Tuple

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
  """Persistent state tracking for processed cases with sliding-window FIFO eviction."""

  def __init__(self, state_file: Optional[Path] = None, max_state_size: int = 2000, max_results: int = 1000):
    self.state_file = state_file or Path("data/watchdog_state.json")
    self.max_state_size = max_state_size
    self.max_results = max_results
    self.seen_case_ids: OrderedDict[str, None] = OrderedDict()
    self.last_scan_time: Optional[str] = None
    self.triaged_count: int = 0
    self.recent_results: List[Dict[str, Any]] = []
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

  def reset(self) -> None:
    self.seen_case_ids.clear()
    self.recent_results.clear()
    self.triaged_count = 0
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

    self._scan_task: Optional[asyncio.Task] = None
    self._task: Optional[asyncio.Task] = None  # Backward-compatibility alias
    self._workers: List[asyncio.Task] = []
    self._work_queue: Optional[asyncio.Queue] = None
    self._in_flight_case_ids: Set[str] = set()
    self._scan_lock = asyncio.Lock()
    self._active_worker_count = 0
    self._is_running = False

  @property
  def is_running(self) -> bool:
    return self._is_running and self._scan_task is not None and not self._scan_task.done()

  def start(self) -> Dict[str, Any]:
    """Starts the background producer-consumer monitoring loop and worker pool."""
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
    logger.info(
        f"Watchdog daemon started. Polling every {self.interval_seconds}s "
        f"with {self.worker_concurrency} workers (queue capacity {self.queue_size})."
    )
    return {
        "status": "STARTED",
        "interval_seconds": self.interval_seconds,
        "worker_concurrency": self.worker_concurrency,
        "queue_size": self.queue_size,
    }

  def stop(self) -> Dict[str, Any]:
    """Stops the background monitoring loop and worker tasks cleanly."""
    if not self.is_running:
      return {"status": "NOT_RUNNING"}

    self._is_running = False
    if self._scan_task and not self._scan_task.done():
      self._scan_task.cancel()
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

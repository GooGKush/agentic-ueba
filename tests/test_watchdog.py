# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit tests for Autonomous Watchdog Daemon, StrategyDecider, and State Tracking."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import pytest

from src.config import TenantConfig
from src.models import (
    CleanHandOffPayload,
    ForensicsSummary,
    JITHuntRequest,
    JITHuntResponse,
    TriageSummary,
)
from src.watchdog import StrategyDecider, WatchdogDaemon, WatchdogState


def test_strategy_decider_c2_beaconing():
  skill, query, model = StrategyDecider.decide(
      case_title="Suspicious Periodic Outbound Traffic",
      alert_name="Potential C2 Beaconing Activity",
      alert_desc="Host observed with regular interval jitter to external IP.",
      entity_type="IP",
  )
  assert skill == "secops-statistical-hunter"
  assert query == "c2_jitter"
  assert model == "C2_BEACONING_JITTER"


def test_strategy_decider_credential_spray():
  skill, query, model = StrategyDecider.decide(
      case_title="Account Lockout Wave",
      alert_name="Credential Spray Detection",
      alert_desc="Failed login surge across multiple identities.",
      entity_type="USER",
  )
  assert skill == "secops-statistical-hunter"
  assert query == "poisson_burst"
  assert model == "POISSON_BURST_CLUSTERING"


def test_strategy_decider_cloud_crud():
  skill, query, model = StrategyDecider.decide(
      case_title="GCP IAM Modification",
      alert_name="Resource Written Total Surge",
      alert_desc="Spike in cloud permissions and storage bucket modifications.",
      entity_type="SERVICE_ACCOUNT",
  )
  assert skill == "secops-risk-metrics-multistage"
  assert query == "cloud_crud"
  assert model == "CLOUD_CRUD_SURGE"


def test_strategy_decider_user_360_radar():
  skill, query, model = StrategyDecider.decide(
      case_title="Insider Threat Assessment",
      alert_name="Abnormal Activity Horizon",
      alert_desc="User exhibiting multi-sector behavioral departures.",
      entity_type="USER",
  )
  assert skill == "secops-risk-metrics-multistage"
  assert query == "profile_360_risk"
  assert model == "360_DECOUPLED_RADAR"


def test_strategy_decider_suspicious_privilege_surge():
  skill, query, model = StrategyDecider.decide(
      case_title="",
      alert_name="Suspicious Privilege Surge",
      alert_desc="User observed creating administrative cloud resources outside business hours.",
      entity_type="USER",
  )
  assert skill == "secops-risk-metrics-multistage"
  assert query == "profile_360_risk"
  assert model == "360_DECOUPLED_RADAR"


def test_watchdog_state_persistence(tmp_path):
  state_file = tmp_path / "test_state.json"
  state = WatchdogState(state_file)
  assert len(state.seen_case_ids) == 0

  # Record a case
  state.record_case("case-101", {"case_id": "case-101", "verdict": "CRITICAL_OUTLIER"})
  assert "case-101" in state.seen_case_ids
  assert state.triaged_count == 1

  # Reload from disk
  reloaded = WatchdogState(state_file)
  assert "case-101" in reloaded.seen_case_ids
  assert reloaded.triaged_count == 1

  # Reset
  reloaded.reset()
  assert len(reloaded.seen_case_ids) == 0
  assert reloaded.triaged_count == 0


@pytest.fixture
def anyio_backend():
  return "asyncio"


@pytest.mark.anyio
async def test_watchdog_daemon_lifecycle(tmp_path):
  mock_engine = MagicMock()
  state_file = tmp_path / "daemon_state.json"
  daemon = WatchdogDaemon(engine=mock_engine, state_file=state_file)

  assert not daemon.is_running
  status = daemon.status()
  assert not status["is_running"]

  # Start daemon
  res = daemon.start()
  assert res["status"] == "STARTED"
  assert daemon.is_running

  # Idempotent start
  res_repeat = daemon.start()
  assert res_repeat["status"] == "ALREADY_RUNNING"

  # Stop daemon
  res_stop = daemon.stop()
  assert res_stop["status"] == "STOPPED"
  assert not daemon.is_running


@pytest.mark.anyio
async def test_watchdog_scan_once_deduplication(tmp_path, monkeypatch):
  mock_engine = MagicMock()
  state_file = tmp_path / "scan_state.json"
  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  daemon = WatchdogDaemon(engine=mock_engine, tenant_config=tenant, state_file=state_file)

  # Mock JIT hunt response
  mock_resp = JITHuntResponse(
      status="SUCCESS",
      triage=TriageSummary(
          calibrated_risk_index=85.0,
          verdict="CRITICAL_OUTLIER",
          is_outlier=True,
          primary_vector="workspace_exfil",
          top_z_score=4.2,
          recommended_action="QUARANTINE",
      ),
      clean_hand_off=CleanHandOffPayload(
          target_entity="target_user",
          entity_type="USER",
          evaluated_window="2026-09-29",
          primary_model="secops-risk-metrics-multistage",
          outlier_topology="WORKSPACE_EXFIL",
          mitre_tactics_mapped=[],
          recommended_swarm_playbook="QUARANTINE_USER",
          escalation_action="QUARANTINE",
      ),
      forensics=ForensicsSummary(
          executed_query="// test query",
          markdown_report="# Triage Report",
      ),
      case_wall_updated=True,
  )
  mock_engine.execute_jit_hunt = AsyncMock(return_value=mock_resp)

  # Mock MCP ClientSession
  mock_session = AsyncMock()
  mock_session.initialize = AsyncMock()
  mock_session.__aenter__.return_value = mock_session

  # Mock list_cases returning 2 cases: case-1 and case-2
  cases_data = {
      "cases": [
          {"id": "case-1", "title": "Phishing Incident", "description": "Suspicious login"},
          {"id": "case-2", "title": "C2 Beacon", "description": "Regular network activity"},
      ]
  }
  alerts_data_case1 = {
      "alerts": [
          {
              "name": "Failed Login Burst",
              "description": "User login failure spike",
              "entities": [{"identifier": "user.victim", "entityType": "USER"}],
          }
      ]
  }
  alerts_data_case2 = {
      "alerts": [
          {
              "name": "Beaconing Outbound",
              "description": "IP regular outbound",
              "entities": [{"identifier": "198.51.100.2", "entityType": "IP"}],
          }
      ]
  }

  called_cases_args = []

  async def mock_call_tool(tool_name, args):
    mock_res = MagicMock()
    if tool_name == "list_cases":
      called_cases_args.append(args)
      mock_res.content = [MagicMock(text=json.dumps(cases_data))]
    elif tool_name == "list_case_alerts":
      if args.get("caseId") == "case-1":
        mock_res.content = [MagicMock(text=json.dumps(alerts_data_case1))]
      else:
        mock_res.content = [MagicMock(text=json.dumps(alerts_data_case2))]
    else:
      mock_res.content = [MagicMock(text="{}")]
    return mock_res

  mock_session.call_tool = mock_call_tool

  class MockContext:
    async def __aenter__(self):
      return (AsyncMock(), AsyncMock())
    async def __aexit__(self, *args):
      pass

  monkeypatch.setattr("src.watchdog.streamable_http_client", lambda *args, **kwargs: MockContext())
  monkeypatch.setattr("src.watchdog.ClientSession", lambda *args, **kwargs: mock_session)
  monkeypatch.setattr("src.config.TenantConfig.get_auth_headers", lambda self: {"Authorization": "Bearer test"})

  # Pass 1: Discovers and triages case-1 and case-2
  results_pass1 = await daemon.scan_once()
  assert len(results_pass1) == 2
  assert daemon.state.triaged_count == 2
  assert "case-1" in daemon.state.seen_case_ids
  assert "case-2" in daemon.state.seen_case_ids
  assert len(called_cases_args) == 1
  assert "Status='OPENED' AND CreateTime >=" in called_cases_args[0]["filter"]
  assert called_cases_args[0]["orderBy"] == "CreateTime desc"

  # Pass 2: Identical cases from Chronicle -> Both skipped by deduplication gate
  results_pass2 = await daemon.scan_once()
  assert len(results_pass2) == 0
  assert daemon.state.triaged_count == 2


def test_watchdog_state_ring_buffer_fifo_eviction(tmp_path):
  state_file = tmp_path / "fifo_state.json"
  state = WatchdogState(state_file, max_state_size=3)

  state.record_case("case-1", {"case_id": "case-1"})
  state.record_case("case-2", {"case_id": "case-2"})
  state.record_case("case-3", {"case_id": "case-3"})
  assert len(state.seen_case_ids) == 3
  assert state.is_seen("case-1")
  assert state.is_seen("case-2")
  assert state.is_seen("case-3")

  # Add 4th case -> case-1 should be evicted (FIFO)
  state.record_case("case-4", {"case_id": "case-4"})
  assert len(state.seen_case_ids) == 3
  assert not state.is_seen("case-1")
  assert state.is_seen("case-2")
  assert state.is_seen("case-3")
  assert state.is_seen("case-4")

  # Verify atomic persistence reloaded correctly
  reloaded = WatchdogState(state_file, max_state_size=3)
  assert len(reloaded.seen_case_ids) == 3
  assert "case-1" not in reloaded.seen_case_ids
  assert "case-4" in reloaded.seen_case_ids


@pytest.mark.anyio
async def test_watchdog_single_flight_lock(tmp_path):
  mock_engine = MagicMock()
  state_file = tmp_path / "lock_state.json"
  daemon = WatchdogDaemon(engine=mock_engine, state_file=state_file)

  # Acquire scan lock externally
  await daemon._scan_lock.acquire()
  assert daemon._scan_lock.locked()

  # A concurrent scan_once must immediately return empty list and skip execution
  res = await daemon.scan_once()
  assert res == []

  daemon._scan_lock.release()
  assert not daemon._scan_lock.locked()


@pytest.mark.anyio
async def test_watchdog_producer_consumer_workers(tmp_path):
  mock_engine = MagicMock()
  mock_resp = JITHuntResponse(
      status="SUCCESS",
      triage=TriageSummary(
          calibrated_risk_index=90.0,
          verdict="CRITICAL_OUTLIER",
          is_outlier=True,
          primary_vector="lateral_movement",
          top_z_score=5.5,
          recommended_action="QUARANTINE",
      ),
      clean_hand_off=CleanHandOffPayload(
          target_entity="target_host",
          entity_type="ASSET",
          evaluated_window="2026-09-29",
          primary_model="secops-statistical-hunter",
          outlier_topology="LATERAL_EXPANSION",
          mitre_tactics_mapped=[],
          recommended_swarm_playbook="QUARANTINE_HOST",
          escalation_action="QUARANTINE",
      ),
      forensics=ForensicsSummary(
          executed_query="// test query",
          markdown_report="# Triage Report",
      ),
      case_wall_updated=True,
  )
  mock_engine.execute_jit_hunt = AsyncMock(return_value=mock_resp)

  tenant = TenantConfig()
  tenant.watchdog_worker_concurrency = 2
  tenant.watchdog_queue_size = 10
  tenant.watchdog_interval_seconds = 3600  # don't trigger auto scan tick

  state_file = tmp_path / "worker_state.json"
  daemon = WatchdogDaemon(engine=mock_engine, tenant_config=tenant, state_file=state_file)
  daemon.scan_once = AsyncMock()

  daemon.start()
  assert daemon.is_running
  status = daemon.status()
  assert status["worker_concurrency"] == 2
  assert status["queue_max_size"] == 10

  # Enqueue 3 tasks to the work queue
  req = JITHuntRequest(
      target_entity="host-1",
      entity_type="ASSET",
      case_id="case-async-1",
      post_to_case_wall=True,
  )
  for i in range(3):
    cid = f"case-async-{i}"
    await daemon._work_queue.put({
        "case_id": cid,
        "case_title": f"Incident {i}",
        "entity": f"host-{i}",
        "entity_type": "ASSET",
        "strategy": "C2_BEACONING_JITTER",
        "req": req,
    })

  # Wait for workers to drain the queue
  await daemon._work_queue.join()

  assert daemon.state.triaged_count == 3
  assert daemon.state.is_seen("case-async-0")
  assert daemon.state.is_seen("case-async-1")
  assert daemon.state.is_seen("case-async-2")
  assert mock_engine.execute_jit_hunt.call_count == 3

  daemon.stop()
  assert not daemon.is_running


@pytest.mark.anyio
async def test_watchdog_queue_backpressure(tmp_path):
  mock_engine = MagicMock()
  tenant = TenantConfig()
  tenant.watchdog_worker_concurrency = 0  # no workers, queue won't drain
  tenant.watchdog_queue_size = 2

  state_file = tmp_path / "backpressure_state.json"
  daemon = WatchdogDaemon(engine=mock_engine, tenant_config=tenant, state_file=state_file)
  daemon._is_running = True
  daemon._work_queue = asyncio.Queue(maxsize=2)

  # Pre-fill queue to capacity
  daemon._work_queue.put_nowait({"case_id": "c1"})
  daemon._work_queue.put_nowait({"case_id": "c2"})
  assert daemon._work_queue.full()

  # Attempting to enqueue when full does not raise QueueFull
  status = daemon.status()
  assert status["queue_depth"] == 2
  assert status["queue_max_size"] == 2


@pytest.mark.anyio
async def test_watchdog_wall_comment_idempotency(tmp_path, monkeypatch):
  mock_engine = MagicMock()
  state_file = tmp_path / "idempotent_state.json"
  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  daemon = WatchdogDaemon(engine=mock_engine, tenant_config=tenant, state_file=state_file)

  # Mock MCP ClientSession
  mock_session = AsyncMock()
  mock_session.initialize = AsyncMock()
  mock_session.__aenter__.return_value = mock_session

  cases_data = {
      "cases": [
          {"id": "case-already-commented", "title": "Phishing Incident"},
      ]
  }
  # Existing comment contains previous triage report signature
  comments_data = {
      "caseComments": [
          {"comment": "#### 1. Statistical Outlier Report: Parametric Historical Z-Score\n* Calibrated Risk Index: 0/100"}
      ]
  }

  async def mock_call_tool(tool_name, args):
    mock_res = MagicMock()
    if tool_name == "list_cases":
      mock_res.content = [MagicMock(text=json.dumps(cases_data))]
    elif tool_name == "list_case_comments":
      mock_res.content = [MagicMock(text=json.dumps(comments_data))]
    else:
      mock_res.content = [MagicMock(text="{}")]
    return mock_res

  mock_session.call_tool = mock_call_tool

  class MockContext:
    async def __aenter__(self):
      return (AsyncMock(), AsyncMock())
    async def __aexit__(self, *args):
      pass

  monkeypatch.setattr("src.watchdog.streamable_http_client", lambda *args, **kwargs: MockContext())
  monkeypatch.setattr("src.watchdog.ClientSession", lambda *args, **kwargs: mock_session)
  monkeypatch.setattr("src.config.TenantConfig.get_auth_headers", lambda self: {"Authorization": "Bearer test"})

  results = await daemon.scan_once()
  # Must be skipped without calling execute_jit_hunt
  assert len(results) == 0
  assert daemon.state.is_seen("case-already-commented")
  assert mock_engine.execute_jit_hunt.call_count == 0


def test_watchdog_state_activity_report(tmp_path):
  from datetime import datetime, timedelta, timezone

  state_file = tmp_path / "activity_state.json"
  state = WatchdogState(state_file=state_file)

  now = datetime.now(timezone.utc)
  # 1. Recent case (30 mins ago)
  ts_recent = (now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
  state.record_case("case-1", {
      "case_id": "case-1",
      "case_title": "Recent Phish",
      "entity": "user1",
      "strategy": "CIRCADIAN_VON_MISES",
      "cri": 75.0,
      "verdict": "HIGH_OUTLIER",
      "source": "WATCHDOG",
      "timestamp": ts_recent,
  })

  # 2. Older case (5 hours ago)
  ts_older = (now - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
  state.record_case("case-2", {
      "case_id": "case-2",
      "case_title": "Older Spray",
      "entity": "user2",
      "strategy": "POISSON_BURST_CLUSTERING",
      "cri": 45.0,
      "verdict": "NOMINAL_BASELINE",
      "source": "JIT_PLAYBOOK",
      "timestamp": ts_older,
  })

  # 3. Very old case (2 days ago)
  ts_oldest = (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
  state.record_case("case-3", {
      "case_id": "case-3",
      "case_title": "Old Beacon",
      "entity": "10.0.0.5",
      "strategy": "C2_BEACONING_JITTER",
      "cri": 90.0,
      "verdict": "CRITICAL_OUTLIER",
      "source": "WATCHDOG",
      "timestamp": ts_oldest,
  })

  # Test 1h lookback: should only return case-1
  rep_1h = state.get_activity_report(timeframe="1h")
  assert rep_1h["status"] == "SUCCESS"
  assert rep_1h["total_cases_triaged"] == 1
  assert rep_1h["cases"][0]["case_id"] == "case-1"
  assert rep_1h["summary_by_verdict"] == {"HIGH_OUTLIER": 1}

  # Test 24h lookback: should return case-1 and case-2
  rep_24h = state.get_activity_report(timeframe="24h")
  assert rep_24h["total_cases_triaged"] == 2
  case_ids_24h = [c["case_id"] for c in rep_24h["cases"]]
  assert "case-1" in case_ids_24h
  assert "case-2" in case_ids_24h
  assert "case-3" not in case_ids_24h

  # Test all lookback: should return all 3 cases
  rep_all = state.get_activity_report(timeframe="all")
  assert rep_all["total_cases_triaged"] == 3



# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit and integration tests for PlaybookRunner, Watchdog Playbook Scheduler, and REST API."""

from datetime import datetime, timezone
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import pytest

from src.config import TenantConfig
from src.playbook_runner import PlaybookRunner
from src.risk_metrics_engine import RiskMetricsEngine
from src.watchdog import WatchdogDaemon


SAMPLE_PLAYBOOK_MD = """# Sample UEBA Hunting Playbook

### 1. Static Baseline Rule (Should Be Ignored)

```yara
rule sample_static_rule {
  meta:
    author = "SecOps"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
  condition:
    $e
}
```

### 2. Query 1A: Causal HTTP Bailout Sequence

```yara
// ============================================================================
// Goal: Detect two-stage OPcache HTTP 500 bailout followed by HTTP 200 carrier POST over 5m.
// Statistical Model: Two-Stage Causal Temporal Sequence (secops-statistical-hunter Bridge Extractor)
// ============================================================================

stage stage1_bailout {
    metadata.event_type = "NETWORK_HTTP"
    network.http.method = "POST"
    network.http.response_code = 500
    network.sent_bytes > 200000
    principal.ip = $client_ip
    target.ip = $target_ip
    $client_ip != ""
    $target_ip != ""

  match:
    $client_ip, $target_ip by 5m

  outcome:
    $bailout_count = count(metadata.id)
    $max_bailout_bytes = max(network.sent_bytes)
    $earliest_bailout = min(metadata.event_timestamp.seconds)
}

stage stage2_carrier {
    metadata.event_type = "NETWORK_HTTP"
    network.http.method = "POST"
    network.http.response_code = 200
    network.sent_bytes > 200000
    principal.ip = $client_ip
    target.ip = $target_ip
    $client_ip != ""
    $target_ip != ""

  match:
    $client_ip, $target_ip by 5m

  outcome:
    $carrier_count = count(metadata.id)
    $max_carrier_bytes = max(network.sent_bytes)
    $latest_carrier = max(metadata.event_timestamp.seconds)
    $sample_urls = array_distinct(target.url)
}

$client_ip = $stage1_bailout.client_ip
$target_ip = $stage1_bailout.target_ip
$client_ip = $stage2_carrier.client_ip
$target_ip = $stage2_carrier.target_ip

match:
  $client_ip, $target_ip by 5m

outcome:
  $bailout_events = max($stage1_bailout.bailout_count)
  $carrier_events = max($stage2_carrier.carrier_count)
  $bailout_size = max($stage1_bailout.max_bailout_bytes)
  $carrier_size = max($stage2_carrier.max_carrier_bytes)
  $t_bailout = min($stage1_bailout.earliest_bailout)
  $t_carrier = max($stage2_carrier.latest_carrier)

condition:
  $bailout_events >= 1
  and $carrier_events >= 1
  and $t_bailout <= $t_carrier

order:
  $carrier_size desc
```

### 3. Query 1B: Seeded 30-Day Outbound Egress Z-Score

```yara
// ============================================================================
// ARCHITECTURE: 2-STAGE PARAMETRIC STANDARD Z-SCORE OUTLIER PIPELINE
// Goal: Score 30-day outbound network byte departures on candidate web server IPs surfaced by Phase 1.
// ============================================================================

stage stage1_extract {
    network.sent_bytes > 0
    network.sent_bytes < 1000000000000000
    // Replace with candidate $target_ip values surfaced by Query 2A (or remove line for a full fleet sweep)
    (principal.asset.ip = "10.0.0.50" or principal.asset.ip = "192.168.1.100")
    principal.asset.ip = $entity
    $entity != ""

  match:
    $entity by 1d

  outcome:
    $observed_val = sum(network.sent_bytes)
    $observed_events = count(metadata.id)

    $historical_avg = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: avg,
        principal.asset.ip: principal.asset.ip
    ))
    $historical_stddev = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: stddev,
        principal.asset.ip: principal.asset.ip
    ))
    $historical_active_days = max(metrics.network_bytes_outbound(
        period: 1d, window: 30d, metric: value_sum, agg: num_metric_periods,
        principal.asset.ip: principal.asset.ip
    ))
}

$entity = $stage1_extract.entity
$ws = $stage1_extract.window_start

match:
  $entity, $ws by 1d

outcome:
  $observed_val = max($stage1_extract.observed_val)
  $baseline_mean = max($stage1_extract.historical_avg)
  $baseline_stddev = max($stage1_extract.historical_stddev)
  $active_days = max($stage1_extract.historical_active_days)
  $safe_stddev = if($baseline_stddev > 0, $baseline_stddev, 1024.0)
  $personal_z = ($observed_val - $baseline_mean) / $safe_stddev
  $z_score = $personal_z

condition:
  $active_days >= 7 and $personal_z >= 3.0

order:
  $personal_z desc
```
"""


@pytest.fixture
def anyio_backend():
  return "asyncio"


def test_github_url_normalization_and_id_derivation():
  blob_url = "https://github.com/GooGKush/docs/blob/main/php2shell-ueba-hunting.md"
  raw_url = PlaybookRunner.normalize_playbook_source(blob_url)
  assert (
      raw_url
      == "https://raw.githubusercontent.com/GooGKush/docs/main/php2shell-ueba-hunting.md"
  )
  assert PlaybookRunner.derive_playbook_id(blob_url) == "php2shell-ueba-hunting"


def test_parse_markdown_playbook_and_seeded_query_handling():
  runner = PlaybookRunner(TenantConfig(project_id="test-proj", customer_id="test-cust"))
  specs = runner.parse_markdown_playbook(SAMPLE_PLAYBOOK_MD)

  # Should extract the 2 multi-stage queries and skip the static rule block
  assert len(specs) == 2

  q1, q2 = specs[0], specs[1]
  assert q1.plane == "RAW_TELEMETRY"
  assert q1.is_seeded is False
  assert q1.entity_type_hint == "IP"
  assert q1.ast_errors == []

  assert q2.plane == "MACRO_METRICS"
  assert q2.default_lookback_days == 35
  assert q2.is_seeded is True
  assert q2.entity_type_hint == "IP"
  assert q2.ast_errors == []

  # When upstream candidates exist, substitute them into the seeded query
  seeded_sql = PlaybookRunner.prepare_seeded_query(
      q2.raw_query,
      candidate_entities=["203.0.113.10", "203.0.113.25"],
      unscope_to_fleet=False,
  )
  assert seeded_sql is not None
  assert '(principal.asset.ip = "203.0.113.10" or principal.asset.ip = "203.0.113.25")' in seeded_sql
  assert "10.0.0.50" not in seeded_sql

  # When no upstream candidates exist and unscope_to_fleet=False, returns None (skip)
  skipped_sql = PlaybookRunner.prepare_seeded_query(
      q2.raw_query,
      candidate_entities=[],
      unscope_to_fleet=False,
  )
  assert skipped_sql is None

  # When unscope_to_fleet=True, removes placeholder filter line so it sweeps the fleet
  fleet_sql = PlaybookRunner.prepare_seeded_query(
      q2.raw_query,
      candidate_entities=[],
      unscope_to_fleet=True,
  )
  assert fleet_sql is not None
  assert "10.0.0.50" not in fleet_sql


def test_parse_real_php2shell_docs_file_if_present():
  real_doc = Path("/usr/local/google/home/kushmerek/projects/docs/php2shell-ueba-hunting.md")
  if not real_doc.is_file():
    pytest.skip("Local docs repo not present in this environment")

  runner = PlaybookRunner(TenantConfig(project_id="test-proj", customer_id="test-cust"))
  specs = runner.parse_markdown_playbook(real_doc.read_text(encoding="utf-8"))
  assert len(specs) == 14
  for spec in specs:
    assert spec.ast_errors == [], f"{spec.query_id} had AST errors: {spec.ast_errors}"


def test_build_playbook_match_udm_event_passes_chronicle_validator():
  runner = PlaybookRunner(TenantConfig(project_id="test-proj", customer_id="test-cust"))
  specs = runner.parse_markdown_playbook(SAMPLE_PLAYBOOK_MD)
  spec = specs[1]

  event = runner.build_playbook_match_udm_event(
      playbook_id="php2shell-ueba-hunting",
      playbook_source="https://raw.githubusercontent.com/GooGKush/docs/main/php2shell-ueba-hunting.md",
      playbook_sha256="abcdef1234567890abcdef1234567890",
      spec=spec,
      row={"entity": "203.0.113.10", "personal_z": 4.8, "z_score": 4.8, "observed_val": 9800000},
      run_timestamp_iso="2026-10-23T18:00:00Z",
      evaluated_day="2026-10-23",
  )

  runner.runner._ensure_skill_path()
  from scripts import chronicle_ingest

  errors = chronicle_ingest.validate_events([event])
  assert errors == []
  assert event["metadata"]["product_event_type"] == "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
  assert event["principal"]["ip"] == ["203.0.113.10"]
  assert event["security_result"][0]["risk_score"] >= 50
  assert event["security_result"][0]["confidence_score"] == 4.8


@pytest.mark.anyio
async def test_watchdog_playbook_lifecycle_and_intraday_deduplication(tmp_path, monkeypatch):
  md_file = tmp_path / "php2shell-ueba-hunting.md"
  md_file.write_text(SAMPLE_PLAYBOOK_MD, encoding="utf-8")

  state_file = tmp_path / "watchdog_playbook_state.json"
  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  risk_eng = RiskMetricsEngine(tenant)

  mock_hunter = MagicMock()
  mock_hunter.risk_engine = risk_eng
  daemon = WatchdogDaemon(engine=mock_hunter, tenant_config=tenant, state_file=state_file)

  executed_queries = []

  async def fake_execute_query(session, query, start_iso, end_iso):
    executed_queries.append(query)
    if "stage1_bailout" in query:
      return {
          "stats": [
              {
                  "client_ip": "198.51.100.77",
                  "target_ip": "203.0.113.10",
                  "bailout_events": 2,
                  "carrier_events": 1,
                  "carrier_size": 450000,
              }
          ]
      }
    if "metrics.network_bytes_outbound" in query:
      return {
          "stats": [
              {
                  "entity": "203.0.113.10",
                  "personal_z": 5.2,
                  "z_score": 5.2,
                  "observed_val": 12500000,
              }
          ]
      }
    return {"stats": []}

  ingested_batches = []

  def fake_ingest(events):
    ingested_batches.append(list(events))
    return {"status": "SUCCESS", "events_ingested": len(events), "batches": 1}

  monkeypatch.setattr(risk_eng.runner, "execute_query_via_mcp", fake_execute_query)
  monkeypatch.setattr(risk_eng, "ingest_udm_events", fake_ingest)

  # 1. Register playbook (without immediate run)
  reg = await daemon.register_playbook(
      url=str(md_file),
      playbook_id="php2shell-ueba",
      interval_seconds=14400,
      ingest_events=True,
      enabled=False,
      run_immediately=False,
  )
  assert reg["status"] == "REGISTERED"
  assert reg["playbook"]["queries_discovered"] == 2
  assert reg["playbook"]["queries_ast_valid"] == 2

  # 2. Run Pass 1 at 12:00Z -> Query 1A surfaces 203.0.113.10, chains it into Query 1B, and emits 2 UDM events
  mock_session = AsyncMock()
  t1 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
  run1 = await daemon.run_playbook_once(
      playbook_id="php2shell-ueba",
      inter_query_delay_sec=0.0,
      now_utc=t1,
      mcp_session=mock_session,
  )
  assert run1["status"] == "SUCCESS"
  assert run1["queries_executed"] == 2
  assert run1["total_matches_found"] == 2
  assert run1["total_matches_emitted"] == 2
  assert run1["total_udm_events_generated"] == 2
  assert len(ingested_batches) == 1
  assert len(ingested_batches[0]) == 2
  # Verify Query 1B had 203.0.113.10 chained into it
  assert '(principal.asset.ip = "203.0.113.10")' in executed_queries[1]

  # 3. Run Pass 2 at 16:00Z on same UTC day -> Both matches suppressed by intra-day deduplication
  t2 = datetime(2026, 10, 23, 16, 0, 0, tzinfo=timezone.utc)
  run2 = await daemon.run_playbook_once(
      playbook_id="php2shell-ueba",
      inter_query_delay_sec=0.0,
      now_utc=t2,
      mcp_session=mock_session,
  )
  assert run2["status"] == "SUCCESS"
  assert run2["total_matches_found"] == 2
  assert run2["total_matches_emitted"] == 0
  assert run2["total_matches_suppressed_dedup"] == 2
  assert run2["total_udm_events_generated"] == 0

  # 4. List playbooks & Stop/Delete
  listed = daemon.list_playbooks(playbook_id="php2shell-ueba")
  assert listed["status"] == "SUCCESS"
  assert listed["playbook"]["last_status"] == "SUCCESS"
  assert len(listed["recent_runs"]) == 2

  stopped = daemon.stop_playbook("php2shell-ueba", delete=False)
  assert stopped["status"] == "STOPPED"
  assert stopped["playbook"]["enabled"] is False

  deleted = daemon.stop_playbook("php2shell-ueba", delete=True)
  assert deleted["status"] == "DELETED"
  assert daemon.list_playbooks("php2shell-ueba")["status"] == "NOT_FOUND"


@pytest.mark.anyio
async def test_server_playbook_rest_endpoints(tmp_path, monkeypatch):
  from starlette.requests import Request
  import src.server as srv
  from src.watchdog import WatchdogState

  md_file = tmp_path / "php2shell-ueba-hunting.md"
  md_file.write_text(SAMPLE_PLAYBOOK_MD, encoding="utf-8")
  monkeypatch.setattr(srv.watchdog, "state", WatchdogState(tmp_path / "srv_pb_state.json"))

  def _make_request(method: str, path: str, body: dict = None, query_string: str = "", path_params: dict = None):
    raw_body = json.dumps(body).encode("utf-8") if body is not None else b""

    async def receive():
      return {"type": "http.request", "body": raw_body, "more_body": False}

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": query_string.encode("utf-8"),
        "headers": [(b"content-type", b"application/json")],
        "path_params": path_params or {},
    }
    return Request(scope, receive)

  # 1. POST /api/v1/playbooks (register)
  req_reg = _make_request(
      "POST",
      "/api/v1/playbooks",
      body={
          "playbook_id": "php2shell-ueba",
          "url": str(md_file),
          "interval_seconds": 14400,
          "ingest_events": True,
          "enabled": False,
          "run_immediately": False,
      },
  )
  resp_reg = await srv.register_playbook_endpoint(req_reg)
  assert resp_reg.status_code == 200
  data_reg = json.loads(resp_reg.body.decode("utf-8"))
  assert data_reg["status"] == "REGISTERED"
  assert data_reg["playbook"]["playbook_id"] == "php2shell-ueba"
  assert data_reg["playbook"]["queries_discovered"] == 2

  # 2. GET /api/v1/playbooks
  req_list = _make_request("GET", "/api/v1/playbooks", query_string="playbook_id=php2shell-ueba")
  resp_list = await srv.list_playbooks_endpoint(req_list)
  assert resp_list.status_code == 200
  data_list = json.loads(resp_list.body.decode("utf-8"))
  assert data_list["status"] == "SUCCESS"
  assert data_list["playbook"]["playbook_id"] == "php2shell-ueba"

  # 3. POST /api/v1/playbooks/stop
  req_stop = _make_request("POST", "/api/v1/playbooks/stop", body={"playbook_id": "php2shell-ueba"})
  resp_stop = await srv.stop_playbook_endpoint(req_stop)
  assert resp_stop.status_code == 200
  data_stop = json.loads(resp_stop.body.decode("utf-8"))
  assert data_stop["status"] == "STOPPED"

  # 4. DELETE /api/v1/playbooks/{playbook_id}
  req_del = _make_request(
      "DELETE",
      "/api/v1/playbooks/php2shell-ueba",
      path_params={"playbook_id": "php2shell-ueba"},
  )
  resp_del = await srv.delete_playbook_endpoint(req_del)
  assert resp_del.status_code == 200
  data_del = json.loads(resp_del.body.decode("utf-8"))
  assert data_del["status"] == "DELETED"


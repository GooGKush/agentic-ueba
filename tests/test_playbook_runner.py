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
  # 2 per-query match events + 1 cross-query convergence event for 203.0.113.10
  assert run1["total_udm_events_generated"] == 3
  assert len(run1["converged_entities"]) == 1
  assert run1["converged_entities"][0]["entity"] == "203.0.113.10"
  assert run1["converged_entities"][0]["distinct_queries_matched"] == 2
  assert len(ingested_batches) == 1
  assert len(ingested_batches[0]) == 3
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


@pytest.mark.anyio
async def test_option1_piecewise_unification_and_option3_capstone_udm_loopback(tmp_path, monkeypatch):
  capstone_md = """# Cloud Threats Playbook with Option 1 Piecewise & Option 3 Capstone

### 1. Query 3: Unified Cold-Start Hurdle & 30-Day MAD Secret Harvesting

```yara
// ============================================================================
// Goal: Detect secret harvesting across both cold-start (<5 active days) and mature (>=5 active days) identities.
// Statistical Model: Piecewise Two-Part Hurdle + 4-Stage 30-Day MAD
// ============================================================================

stage stage1_daily {
    metadata.event_type = "RESOURCE_READ"
    principal.user.userid = $user
    $user != ""

  match:
    $user by 1d

  outcome:
    $daily_val = count(metadata.id)
    $distinct_secrets = count_distinct(target.resource.name)
}

stage stage2_median {
    $user = $stage1_daily.user
    $daily_val = $stage1_daily.daily_val

  match:
    $user

  outcome:
    $median_val = percentile($daily_val, 50)
    $active_days = count($daily_val)
}

stage stage3_mad {
    $user = $stage1_daily.user
    $daily_val = $stage1_daily.daily_val
    $user = $stage2_median.user
    $median_val = $stage2_median.median_val

  match:
    $user

  outcome:
    $abs_dev = math.abs($daily_val - $median_val)
    $mad_raw = percentile($abs_dev, 50)
    $baseline_median = max($median_val)
    $baseline_days = max($stage2_median.active_days)
}

$user = $stage1_daily.user
$observed_val = $stage1_daily.daily_val
$observed_secrets = $stage1_daily.distinct_secrets
$day_bucket = $stage1_daily.window_start
$user = $stage3_mad.user

match:
  $user, $day_bucket

outcome:
  $obs = max($observed_val)
  $secrets = max($observed_secrets)
  $med = max($stage3_mad.baseline_median)
  $mad = max($stage3_mad.mad_raw)
  $raw_active_days = max($stage3_mad.baseline_days)
  $scaled_mad = $mad * 1.4826
  $safe_mad = if($scaled_mad > 0, $scaled_mad, 1.0)
  $modified_z = ($obs - $med) / $safe_mad
  $hurdle_rarity_boost = if($raw_active_days <= 4, 3.0, 1.0)
  $hurdle_threat_score = math.log($obs + 1) * $secrets * $hurdle_rarity_boost / 4.0
  $unified_threat_score = if($raw_active_days <= 4, $hurdle_threat_score, $modified_z)

condition:
  $obs >= 5 and $unified_threat_score >= 3.5

order:
  $unified_threat_score desc
```

### 2. Capstone Query: Multi-Scenario Entity Convergence via UDM Loopback

```yara
// ============================================================================
// Goal: Correlate entities matching >= 2 distinct queries in this playbook via PLAYBOOK_BEHAVIORAL_HUNT_MATCH.
// Statistical Model: 2-Stage UDM Loopback Euclidean L2 Norm Convergence
// ============================================================================

stage stage1_query_hits {
    metadata.event_type = "GENERIC_EVENT"
    metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"
    principal.user.userid = $entity
    security_result.rule_name = $rule_name
    $entity != ""
    $rule_name != ""

  match:
    $entity, $rule_name by 1d

  outcome:
    $query_z = max(security_result.confidence_score)
    $query_cri = max(security_result.risk_score)
}

$entity = $stage1_query_hits.entity
$day_bucket = $stage1_query_hits.window_start

match:
  $entity, $day_bucket by 1d

outcome:
  $distinct_queries = count_distinct($stage1_query_hits.rule_name)
  $triggered_queries = array_distinct($stage1_query_hits.rule_name)
  $capstone_threat_norm_sq = sum($stage1_query_hits.query_z * $stage1_query_hits.query_z)
  $max_single_cri = max($stage1_query_hits.query_cri)

condition:
  $distinct_queries >= 2 and $capstone_threat_norm_sq >= 25.0

order:
  $capstone_threat_norm_sq desc
```
"""
  md_file = tmp_path / "cloud-threats-ueba-hunting.md"
  md_file.write_text(capstone_md, encoding="utf-8")

  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  risk_eng = RiskMetricsEngine(tenant)
  runner = PlaybookRunner(tenant_config=tenant, risk_engine=risk_eng)

  specs = runner.parse_markdown_playbook(capstone_md)
  assert len(specs) == 2
  assert specs[0].ast_errors == []
  assert specs[0].is_capstone is False
  assert specs[0].entity_type_hint == "USER"

  assert specs[1].ast_errors == []
  assert specs[1].is_capstone is True
  assert specs[1].plane == "UDM_LOOPBACK_CONVERGENCE"
  assert specs[1].default_lookback_days == 7
  assert specs[1].entity_type_hint == "USER"

  events_order = []

  async def fake_execute(session, query, start_iso, end_iso):
    if "$indexed_events = count(metadata.id)" in query:
      events_order.append("VALIDATE_UDM_INDEXED")
      return {"stats": [{"run_id": "test_run", "indexed_events": 1}]}
    if "PLAYBOOK_BEHAVIORAL_HUNT_MATCH" in query:
      events_order.append("EXECUTE_CAPSTONE")
      return {
          "stats": [
              {
                  "entity": "svc-terraform@prod.iam.gserviceaccount.com",
                  "distinct_queries": 2,
                  "capstone_threat_norm_sq": 36.0,
              }
          ]
      }
    events_order.append("EXECUTE_UPSTREAM")
    return {
        "stats": [
            {
                "user": "svc-terraform@prod.iam.gserviceaccount.com",
                "unified_threat_score": 5.4,
                "obs": 42,
            }
        ]
    }

  ingested_events = []

  def fake_ingest(events):
    ingested_events.extend(events)
    events_order.append(f"INGEST_{len(events)}")
    return {"status": "SUCCESS", "events_ingested": len(events), "batches": 1}

  monkeypatch.setattr(risk_eng.runner, "execute_query_via_mcp", fake_execute)
  monkeypatch.setattr(risk_eng, "ingest_udm_events", fake_ingest)

  res = await runner.execute_playbook(
      session=AsyncMock(),
      source=str(md_file),
      run_id="run_cloud_threats_20261026_abc12345",
      scope_capstone_to_run_id=True,
      udm_validation_poll_sec=0.0,
      inter_query_delay_sec=0.0,
  )
  assert res["status"] == "SUCCESS"
  assert res["run_id"] == "run_cloud_threats_20261026_abc12345"
  # Upstream query executes -> UDM events flushed -> UDM index validated -> Capstone executes -> Capstone event flushed
  assert events_order == [
      "EXECUTE_UPSTREAM",
      "INGEST_1",
      "VALIDATE_UDM_INDEXED",
      "EXECUTE_CAPSTONE",
      "INGEST_1",
  ]
  assert res["udm_sync_validation"]["status"] == "VERIFIED"
  assert res["udm_sync_validation"]["expected_events"] == 1
  assert res["udm_sync_validation"]["indexed_events"] == 1
  assert res["udm_sync_validation"]["verified"] is True
  assert ingested_events[0]["metadata"]["product_log_id"] == "run_cloud_threats_20261026_abc12345"
  assert res["queries"][0]["matched_entities"][0]["score_field"] == "unified_threat_score"
  assert res["queries"][0]["matched_entities"][0]["effective_z"] == 5.4
  assert res["queries"][1]["matched_entities"][0]["score_field"] == "capstone_threat_norm_sq"
  assert res["queries"][1]["matched_entities"][0]["effective_z"] == 6.0


@pytest.mark.anyio
async def test_udm_indexing_lag_retry_and_partial_timeout(tmp_path, monkeypatch):
  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  risk_eng = RiskMetricsEngine(tenant)
  runner = PlaybookRunner(tenant_config=tenant, risk_engine=risk_eng)

  poll_counts = [0, 1, 2]
  seen_queries = []

  async def fake_execute(session, query, start_iso, end_iso):
    seen_queries.append(query)
    cnt = poll_counts.pop(0) if poll_counts else 2
    return {"stats": [{"run_id": "run_lag_test_001", "indexed_events": cnt}]}

  monkeypatch.setattr(risk_eng.runner, "execute_query_via_mcp", fake_execute)

  # 1. Succeeds on 3rd attempt when indexed_events reaches expected_events (2)
  val_ok = await runner.verify_udm_run_indexed(
      session=AsyncMock(),
      run_id="run_lag_test_001",
      expected_events=2,
      start_iso="2026-10-26T00:00:00Z",
      end_iso="2026-10-26T18:00:00Z",
      max_attempts=4,
      poll_interval_sec=0.0,
  )
  assert val_ok["status"] == "VERIFIED"
  assert val_ok["verified"] is True
  assert val_ok["attempts"] == 3
  assert val_ok["expected_events"] == 2
  assert val_ok["indexed_events"] == 2
  assert 'metadata.product_log_id = "run_lag_test_001"' in seen_queries[0]

  # 2. Reports PARTIAL_TIMEOUT if only 1 of 3 events is indexed after max_attempts
  poll_counts = [0, 1, 1]
  val_partial = await runner.verify_udm_run_indexed(
      session=AsyncMock(),
      run_id="run_lag_test_002",
      expected_events=3,
      start_iso="2026-10-26T00:00:00Z",
      end_iso="2026-10-26T18:00:00Z",
      max_attempts=3,
      poll_interval_sec=0.0,
  )
  assert val_partial["status"] == "PARTIAL_TIMEOUT"
  assert val_partial["verified"] is False
  assert val_partial["attempts"] == 3
  assert val_partial["expected_events"] == 3
  assert val_partial["indexed_events"] == 1


@pytest.mark.anyio
async def test_subthreading_io_offload_and_parallel_playbook_wave_concurrency(tmp_path, monkeypatch):
  import asyncio
  import threading
  from src.watchdog import WatchdogDaemon, WatchdogState

  md_file_a = tmp_path / "pb-alpha.md"
  md_file_b = tmp_path / "pb-beta.md"
  md_file_a.write_text(SAMPLE_PLAYBOOK_MD, encoding="utf-8")
  md_file_b.write_text(SAMPLE_PLAYBOOK_MD, encoding="utf-8")

  state_file = tmp_path / "watchdog_parallel_state.json"
  tenant = TenantConfig(project_id="test-proj", customer_id="test-cust")
  risk_eng = RiskMetricsEngine(tenant)
  mock_hunter = MagicMock()
  mock_hunter.risk_engine = risk_eng
  daemon = WatchdogDaemon(engine=mock_hunter, tenant_config=tenant, state_file=state_file)

  await daemon.register_playbook(
      playbook_id="pb-alpha",
      url=str(md_file_a),
      interval_seconds=3600,
      ingest_events=True,
      run_immediately=False,
  )
  await daemon.register_playbook(
      playbook_id="pb-beta",
      url=str(md_file_b),
      interval_seconds=3600,
      ingest_events=True,
      run_immediately=False,
  )

  active_queries = 0
  max_concurrent_queries = 0
  ingest_thread_names = []

  async def fake_execute(session, query, start_iso, end_iso):
    nonlocal active_queries, max_concurrent_queries
    active_queries += 1
    max_concurrent_queries = max(max_concurrent_queries, active_queries)
    await asyncio.sleep(0.03)
    active_queries -= 1
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

  def fake_ingest(events):
    ingest_thread_names.append(threading.current_thread().name)
    return {"status": "SUCCESS", "events_ingested": len(events), "batches": 1}

  monkeypatch.setattr(risk_eng.runner, "execute_query_via_mcp", fake_execute)
  monkeypatch.setattr(risk_eng, "ingest_udm_events", fake_ingest)

  mock_session = AsyncMock()
  # Launch pb-alpha, pb-beta, and a duplicate pb-alpha concurrently
  res_alpha_1, res_beta, res_alpha_dup = await asyncio.gather(
      daemon.run_playbook_once(playbook_id="pb-alpha", inter_query_delay_sec=0.0, mcp_session=mock_session),
      daemon.run_playbook_once(playbook_id="pb-beta", inter_query_delay_sec=0.0, mcp_session=mock_session),
      daemon.run_playbook_once(playbook_id="pb-alpha", inter_query_delay_sec=0.0, mcp_session=mock_session),
  )

  # Both distinct playbooks succeed in parallel
  assert res_alpha_1["status"] == "SUCCESS"
  assert res_beta["status"] == "SUCCESS"
  # Duplicate concurrent execution of pb-alpha is safely skipped by its per-playbook lock
  assert res_alpha_dup["status"] == "SKIPPED_CONCURRENT"
  # Both playbooks executed queries concurrently across the event loop
  assert max_concurrent_queries >= 2
  # Synchronous UDM ingestion was offloaded to the secops-ueba-io worker thread pool
  assert len(ingest_thread_names) >= 2
  assert all(name.startswith("secops-ueba-io") for name in ingest_thread_names)





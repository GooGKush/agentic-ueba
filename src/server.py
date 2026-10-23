# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Dual Interface Server (FastMCP + REST Gateway) for Agentic UEBA.

Exposes the autonomous JIT Threat Hunting Engine over two concurrent protocols:
1. REST Webhook (/api/v1/hunt/jit) for SecOps SOAR Playbooks using HTTP actions.
2. Model Context Protocol (/mcp via SSE / Streamable HTTP) for Agent-to-Agent invocations.
"""

import src._bootstrap

import contextlib
from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, Optional

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from src.autonomous_hunter import AutonomousHunterEngine
from src.config import TenantConfig, get_skills_root
from src.models import JITHuntRequest, JITHuntResponse
from src.watchdog import WatchdogDaemon

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SecOpsAgenticServer")

# Initialize default tenant and autonomous hunting engine
tenant_config = TenantConfig()
engine = AutonomousHunterEngine(tenant_config=tenant_config)
watchdog = WatchdogDaemon(engine=engine, tenant_config=tenant_config)

# Initialize FastMCP Server
mcp = FastMCP(
    name="SecOps-Agentic-UEBA-Hunter",
    instructions="Autonomous JIT Threat Hunter embedding SecOps Risk Metrics and Statistical Hunter skills."
)


# --- 1. MCP Tools (Agent-to-Agent Communication) ---

@mcp.tool()
async def control_watchdog(action: str = "status") -> Dict[str, Any]:
  """Controls the standing watchdog daemon. Action can be 'status', 'start', 'stop', or 'reset'."""
  act = action.lower().strip()
  if act == "start":
    return watchdog.start()
  elif act == "stop":
    return watchdog.stop()
  elif act == "reset":
    watchdog.state.reset()
    return {"status": "RESET_SUCCESSFUL"}
  return watchdog.status()


@mcp.tool()
async def hunt_entity(
    target_entity: str,
    entity_type: str = "USER",
    alert_name: Optional[str] = None,
    alert_description: Optional[str] = None,
    case_id: Optional[str] = None,
    skill: str = "auto",
    lookback_days: int = 14,
    post_to_case_wall: bool = True,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
  """Performs an autonomous JIT threat hunt for an entity, adapting the threat model to the alert context."""
  req = JITHuntRequest(
      target_entity=target_entity,
      entity_type=entity_type,
      alert_name=alert_name,
      alert_description=alert_description,
      case_id=case_id,
      skill=skill,
      lookback_days=lookback_days,
      post_to_case_wall=post_to_case_wall,
      project_id=project_id,
      customer_id=customer_id,
      region=region,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def profile_360_risk(
    username: str,
    lookback_days: int = 14,
    case_id: Optional[str] = None,
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
  """Executes a decoupled 360-degree behavioral risk radar profile across all 5 canonical sectors."""
  req = JITHuntRequest(
      target_entity=username,
      entity_type="USER",
      alert_name="360° Behavioral Risk Profiling",
      alert_description="Decoupled multi-sector behavioral health check across Auth, Cloud, Workspace, Egress, and DNS.",
      case_id=case_id,
      skill="risk-metrics",
      lookback_days=lookback_days,
      post_to_case_wall=bool(case_id),
      project_id=project_id,
      customer_id=customer_id,
      region=region,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def run_fleet_360_sweep(
    entity_types: str = "USER,ASSET",
    spike_threshold_z: float = 3.0,
    spoke_inclusion_z: float = 2.0,
    min_observed: int = 5,
    max_outliers_per_sector: int = 250,
    ingest_events: bool = True,
    lookback_days: int = 1,
) -> Dict[str, Any]:
  """Executes a deterministic Mode A fleetwide 360° behavioral risk radar sweep across all entities and emits one BEHAVIORAL_RISK_RADAR_360 UDM event for each entity with a vector spike >= spike_threshold_z."""
  types_list = [t.strip().upper() for t in entity_types.split(",") if t.strip()]
  return await watchdog.run_fleet_360_sweep_once(
      entity_types=types_list or ["USER", "ASSET"],
      spike_threshold_z=spike_threshold_z,
      spoke_inclusion_z=spoke_inclusion_z,
      min_observed=min_observed,
      max_outliers_per_sector=max_outliers_per_sector,
      ingest_events=ingest_events,
      lookback_days=lookback_days,
  )


@mcp.tool()
async def scan_open_cases(limit: int = 5) -> Dict[str, Any]:
  """Watchdog: Scans open SecOps cases, inspects alert telemetry, and executes autonomous hunts."""
  results = await engine.scan_and_triage_cases(limit=limit)
  return {"status": "SUCCESS", "cases_triaged": len(results), "results": results}


@mcp.tool()
async def hunt_c2_jitter(
    src_ip: str,
    min_conns: int = 25,
    cv_threshold: float = 0.20,
    case_id: Optional[str] = None,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Statistical Hunter: Detects robotic C2 beaconing timing regularity via Coefficient of Variation (CV <= 0.20)."""
  req = JITHuntRequest(
      target_entity=src_ip,
      entity_type="IP",
      alert_name="C2 Beaconing Jitter Investigation",
      query=f"Hunt for C2 beaconing with CV <= {cv_threshold} and min connections >= {min_conns}",
      skill="stats-hunter",
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def hunt_poisson_burst(
    entity: str,
    event_type: str = "USER_LOGIN",
    case_id: Optional[str] = None,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Statistical Hunter: Detects credential spray burst waves via Poisson Fano Factor dispersion (F > 4.0)."""
  req = JITHuntRequest(
      target_entity=entity,
      entity_type="USER",
      alert_name="Poisson Burst Spray Investigation",
      query=f"Hunt for Poisson burst clustering over {event_type} with Fano factor > 4.0",
      skill="stats-hunter",
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def hunt_cloud_crud(
    username: str,
    case_id: Optional[str] = None,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Risk Metrics: Evaluates cloud resource write surges with 30-day baseline and companion dimensions."""
  req = JITHuntRequest(
      target_entity=username,
      entity_type="USER",
      alert_name="Cloud CRUD Write Surge Investigation",
      query="Hunt for anomalous cloud resource writes against 30-day personal baseline",
      skill="risk-metrics",
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def hunt_hybrid_enrichment(
    username: str,
    raw_signature_field: str = "principal.ip",
    case_id: Optional[str] = None,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Dual-Plane Hybrid: Fuses 30-day macro baseline deviation with micro-telemetry raw event signatures."""
  req = JITHuntRequest(
      target_entity=username,
      entity_type="USER",
      alert_name="Dual-Plane Hybrid Threat Fusion",
      query=f"Execute hybrid 2-stage query fusing macro 30-day baseline with micro {raw_signature_field} signatures",
      skill="risk-metrics",
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def hunt_circadian_von_mises(
    username: str,
    case_id: Optional[str] = None,
    lookback_days: int = 14,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Risk Metrics: Evaluates off-hours temporal departures using 24-hour circular von Mises clock."""
  req = JITHuntRequest(
      target_entity=username,
      entity_type="USER",
      alert_name="Circadian von Mises Temporal Anomaly",
      query="circadian_von_mises",
      skill="risk-metrics",
      lookback_days=lookback_days,
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def hunt_macd_momentum(
    entity: str,
    case_id: Optional[str] = None,
    lookback_days: int = 14,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Risk Metrics: Detects instantaneous momentum acceleration diverging from 30-day anchor."""
  req = JITHuntRequest(
      target_entity=entity,
      entity_type="USER",
      alert_name="MACD Momentum Velocity Divergence",
      query="macd_momentum",
      skill="risk-metrics",
      lookback_days=lookback_days,
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def hunt_shannon_entropy(
    entity: str,
    case_id: Optional[str] = None,
    lookback_days: int = 7,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Statistical Hunter: Detects obfuscated command lines or DGA payloads via Shannon Character Entropy."""
  req = JITHuntRequest(
      target_entity=entity,
      entity_type="HOST",
      alert_name="Shannon Character-Class Entropy Investigation",
      query="shannon_entropy",
      skill="stats-hunter",
      lookback_days=lookback_days,
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def hunt_markov_transition(
    host: str,
    case_id: Optional[str] = None,
    lookback_days: int = 7,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Statistical Hunter: Detects rare Living-off-the-Land process transitions via Markov 2-Gram Surprisal."""
  req = JITHuntRequest(
      target_entity=host,
      entity_type="HOST",
      alert_name="Markov Process Transition Rarity Investigation",
      query="markov_transition",
      skill="stats-hunter",
      lookback_days=lookback_days,
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def hunt_zipfian_rarity(
    host: str,
    case_id: Optional[str] = None,
    lookback_days: int = 7,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Statistical Hunter: Detects rare administrative tools in the enterprise Zipfian power-law long tail."""
  req = JITHuntRequest(
      target_entity=host,
      entity_type="HOST",
      alert_name="Zipfian Process Rarity Investigation",
      query="zipfian_rarity",
      skill="stats-hunter",
      lookback_days=lookback_days,
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def hunt_ewma_burst(
    entity: str,
    case_id: Optional[str] = None,
    lookback_days: int = 7,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Statistical Hunter: Detects acute intraday kinetic rate surges via EWMA Velocity Divergence."""
  req = JITHuntRequest(
      target_entity=entity,
      entity_type="IP",
      alert_name="EWMA Burst Velocity Investigation",
      query="ewma_burst",
      skill="stats-hunter",
      lookback_days=lookback_days,
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def hunt_impossible_travel(
    username: str,
    case_id: Optional[str] = None,
    lookback_days: int = 14,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Statistical Hunter (v2.8.0): Detects supersonic geodesic travel velocity (math.geo_distance >= 900 km/h) across consecutive logins."""
  req = JITHuntRequest(
      target_entity=username,
      entity_type="USER",
      alert_name="Impossible Travel Geodesic Velocity Investigation",
      query="impossible_travel",
      skill="stats-hunter",
      lookback_days=lookback_days,
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def hunt_producer_consumer_inversion(
    host: str,
    case_id: Optional[str] = None,
    lookback_days: int = 14,
    post_to_case_wall: bool = True,
) -> Dict[str, Any]:
  """Statistical Hunter (v2.8.0): Detects endpoints shifting from net data consumers to net data producers (sent/total bytes >= 0.80 + Z-score spike)."""
  req = JITHuntRequest(
      target_entity=host,
      entity_type="HOST",
      alert_name="Producer-Consumer Byte Ratio Inversion Investigation",
      query="producer_consumer_inversion",
      skill="stats-hunter",
      lookback_days=lookback_days,
      case_id=case_id,
      post_to_case_wall=post_to_case_wall,
  )
  resp = await engine.execute_jit_hunt(req)
  return resp.model_dump()


@mcp.tool()
async def get_case_activity(timeframe: str = "1h", tag: Optional[str] = None) -> Dict[str, Any]:
  """Returns an activity summary report of cases touched by the agent (e.g. '1h', '24h', '7d', 'all'), optionally filtered by tag (e.g. 'RISK:CRITICAL', 'RISK:HIGH', 'VECTOR:EGRESS', 'SECOND_ORDER_HUNT')."""
  return watchdog.state.get_activity_report(timeframe=timeframe, tag=tag)


@mcp.tool()
async def compile_hunt_pipeline(
    statistical_model: str = "STANDARD_Z_SCORE",
    metrics: str = "auth_attempts_total",
    architecture: str = "single_metric",
    plane: str = "MACRO_METRICS",
    entity_type: str = "USER",
    entity_value: Optional[str] = None,
    custom_filter: Optional[str] = None,
    mode: str = "A",
    window_days: int = 1,
    sensitivity: str = "BALANCED",
) -> Dict[str, Any]:
  """Python Hybrid Engine (v2.0.0): Compiles an AST-validated multi-stage YARA-L 2.0 hunt pipeline, Pre-Flight specification card, and 1-shot probe query."""
  from src.pipeline_runner import PipelineRunner
  he = PipelineRunner(tenant_config).get_hybrid_engine()
  metric_list = [m.strip() for m in metrics.split(",") if m.strip()] if isinstance(metrics, str) else metrics
  return he.compile_hunt_pipeline(
      statistical_model=statistical_model,
      metrics=metric_list,
      architecture=architecture,
      plane=plane,
      entity_type=entity_type,
      entity_value=entity_value,
      custom_filter=custom_filter,
      mode=mode,
      window_days=window_days,
      sensitivity=sensitivity,
  )


@mcp.tool()
async def dispatch_hybrid_handoff(
    intent: str,
    entity_value: str = "fleet",
    entity_type: str = "HOSTNAME",
    lookback: str = "24h",
    sensitivity: str = "BALANCED",
) -> Dict[str, Any]:
  """Python Hybrid Engine (v2.0.0): Dispatches a federated handoff payload (secops-threat-hunt-handoff-v1) to secops-statistical-hunter."""
  from src.pipeline_runner import PipelineRunner
  he = PipelineRunner(tenant_config).get_hybrid_engine()
  return he.dispatch_hybrid_handoff(
      intent=intent,
      entity_value=entity_value,
      entity_type=entity_type,
      lookback=lookback,
      sensitivity=sensitivity,
  )


@mcp.tool()
async def manage_playbook(
    action: str = "list",
    url: Optional[str] = None,
    playbook_id: Optional[str] = None,
    interval_seconds: int = 14400,
    ingest_events: bool = True,
    unscope_seeded_to_fleet: bool = False,
    run_immediately: bool = False,
) -> Dict[str, Any]:
  """Registers, lists, or stops a periodic Markdown hunting playbook (e.g. from a GitHub URL)."""
  act = action.lower().strip()
  if act in ("register", "start", "add"):
    if not url:
      return {"status": "ERROR", "error_message": "'url' is required to register a playbook."}
    return await watchdog.register_playbook(
        url=url,
        playbook_id=playbook_id,
        interval_seconds=interval_seconds,
        ingest_events=ingest_events,
        unscope_seeded_to_fleet=unscope_seeded_to_fleet,
        enabled=True,
        run_immediately=run_immediately,
    )
  if act in ("stop", "pause", "disable"):
    if not playbook_id:
      return {"status": "ERROR", "error_message": "'playbook_id' is required to stop a playbook."}
    return watchdog.stop_playbook(playbook_id=playbook_id, delete=False)
  if act in ("delete", "remove"):
    if not playbook_id:
      return {"status": "ERROR", "error_message": "'playbook_id' is required to delete a playbook."}
    return watchdog.stop_playbook(playbook_id=playbook_id, delete=True)
  return watchdog.list_playbooks(playbook_id=playbook_id)


@mcp.tool()
async def run_markdown_playbook(
    url: Optional[str] = None,
    playbook_id: Optional[str] = None,
    ingest_events: bool = True,
    unscope_seeded_to_fleet: bool = False,
) -> Dict[str, Any]:
  """Executes an on-demand pass of a Markdown hunting playbook from a GitHub URL or registered playbook_id."""
  return await watchdog.run_playbook_once(
      playbook_id=playbook_id,
      url=url,
      ingest_events=ingest_events,
      unscope_seeded_to_fleet=unscope_seeded_to_fleet,
  )


# --- 2. REST Endpoints (Playbook-to-Agent Gateway) ---

@mcp.custom_route("/api/v1/cases/activity", methods=["GET"])
async def cases_activity_endpoint(request: Request) -> JSONResponse:
  """Returns an activity summary report of cases touched by the agent (e.g. ?timeframe=24h&tag=RISK:CRITICAL)."""
  timeframe = request.query_params.get("timeframe", "1h")
  hours_param = request.query_params.get("hours")
  tag = request.query_params.get("tag")
  hours = float(hours_param) if hours_param else None
  report = watchdog.state.get_activity_report(timeframe=timeframe, hours=hours, tag=tag)
  return JSONResponse(report, status_code=200)


@mcp.custom_route("/api/v1/cases/scan", methods=["POST"])
async def scan_cases_endpoint(request: Request) -> JSONResponse:
  """Watchdog REST endpoint to trigger an autonomous scan over open cases."""
  try:
    body = await request.json() if await request.body() else {}
    limit = int(body.get("limit", 5))
    results = await engine.scan_and_triage_cases(limit=limit)
    return JSONResponse({"status": "SUCCESS", "cases_triaged": len(results), "results": results})
  except Exception as e:
    error_msg = str(e)
    if hasattr(e, "exceptions") and e.exceptions:
      sub_errors = [f"{type(sub).__name__}: {sub}" for sub in e.exceptions]
      error_msg = f"{error_msg} (Sub-exceptions: {'; '.join(sub_errors)})"
    logger.exception(f"Case scan failed: {error_msg}")
    return JSONResponse({"status": "ERROR", "error_message": error_msg}, status_code=500)


@mcp.custom_route("/api/v1/hunt/jit", methods=["POST"])
async def jit_playbook_endpoint(request: Request) -> JSONResponse:
  """Primary REST endpoint called by Chronicle SOAR Playbooks via HTTP Request block."""
  try:
    body = await request.json()
    req = JITHuntRequest(**body)
    logger.info(f"Incoming JIT Playbook Request for entity: {req.target_entity} (Case: {req.case_id})")
    
    resp: JITHuntResponse = await engine.execute_jit_hunt(req)
    if req.case_id:
      try:
        watchdog.state.record_case(
            str(req.case_id),
            {
                "case_id": str(req.case_id),
                "case_title": req.alert_name or "JIT Playbook Investigation",
                "entity": req.target_entity,
                "entity_type": req.entity_type,
                "strategy": resp.clean_hand_off.outlier_topology or req.query or "JIT_HUNT",
                "cri": resp.triage.calibrated_risk_index,
                "verdict": resp.triage.verdict,
                "primary_vector": resp.triage.primary_vector,
                "common_vector": resp.triage.common_vector,
                "second_order_ran": resp.triage.second_order_ran,
                "tags": resp.triage.tags,
                "source": "JIT_PLAYBOOK",
                "case_wall_updated": resp.case_wall_updated,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        )
      except Exception as rec_err:
        logger.warning(f"Failed recording JIT case {req.case_id} to watchdog state: {rec_err}")
    return JSONResponse(resp.model_dump(), status_code=200)

  except Exception as e:
    error_msg = str(e)
    if hasattr(e, "exceptions") and e.exceptions:
      sub_errors = [f"{type(sub).__name__}: {sub}" for sub in e.exceptions]
      error_msg = f"{error_msg} (Sub-exceptions: {'; '.join(sub_errors)})"
    logger.exception(f"JIT Playbook execution failed: {error_msg}")
    return JSONResponse(
        {
            "status": "ERROR",
            "error_message": error_msg,
            "triage": {
                "calibrated_risk_index": 0.0,
                "verdict": "ERROR",
                "is_outlier": False,
                "primary_vector": "NONE",
                "top_z_score": 0.0,
                "recommended_action": "MANUAL_REVIEW",
            },
        },
        status_code=500,
    )


@mcp.custom_route("/healthz", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
  """Liveness and readiness health check for Cloud Run."""
  return JSONResponse({
      "status": "HEALTHY",
      "default_project_id": tenant_config.project_id,
      "default_customer_id": tenant_config.customer_id,
      "default_region": tenant_config.region,
      "skills_root": str(get_skills_root()),
      "watchdog_running": watchdog.is_running,
  })


# --- 3. Watchdog Daemon Control Routes ---

@mcp.custom_route("/api/v1/watchdog/status", methods=["GET"])
async def watchdog_status_endpoint(request: Request) -> JSONResponse:
  """Returns current status and metrics of the autonomous watchdog monitor."""
  return JSONResponse(watchdog.status(), status_code=200)


@mcp.custom_route("/api/v1/watchdog/start", methods=["POST"])
async def watchdog_start_endpoint(request: Request) -> JSONResponse:
  """Starts the autonomous watchdog monitor loop."""
  res = watchdog.start()
  return JSONResponse(res, status_code=200)


@mcp.custom_route("/api/v1/watchdog/stop", methods=["POST"])
async def watchdog_stop_endpoint(request: Request) -> JSONResponse:
  """Stops the autonomous watchdog monitor loop."""
  res = watchdog.stop()
  return JSONResponse(res, status_code=200)


@mcp.custom_route("/api/v1/watchdog/reset-state", methods=["POST"])
async def watchdog_reset_endpoint(request: Request) -> JSONResponse:
  """Resets seen cases in watchdog state to allow re-triaging."""
  watchdog.state.reset()
  return JSONResponse({"status": "RESET_SUCCESSFUL"}, status_code=200)


@mcp.custom_route("/api/v1/radar/fleet-sweep", methods=["POST"])
async def fleet_360_sweep_endpoint(request: Request) -> JSONResponse:
  """REST endpoint to trigger a Mode A fleetwide 360° behavioral risk radar sweep."""
  try:
    body = await request.json() if await request.body() else {}
    raw_types = body.get("entity_types", ["USER", "ASSET"])
    if isinstance(raw_types, str):
      entity_types = [t.strip().upper() for t in raw_types.split(",") if t.strip()]
    else:
      entity_types = [str(t).strip().upper() for t in raw_types if str(t).strip()]
    res = await watchdog.run_fleet_360_sweep_once(
        entity_types=entity_types or ["USER", "ASSET"],
        spike_threshold_z=(
            float(body["spike_threshold_z"]) if "spike_threshold_z" in body else None
        ),
        spoke_inclusion_z=(
            float(body["spoke_inclusion_z"]) if "spoke_inclusion_z" in body else None
        ),
        min_observed=int(body["min_observed"]) if "min_observed" in body else None,
        max_outliers_per_sector=(
            int(body["max_outliers_per_sector"])
            if "max_outliers_per_sector" in body
            else None
        ),
        ingest_events=bool(body["ingest_events"]) if "ingest_events" in body else None,
        lookback_days=int(body["lookback_days"]) if "lookback_days" in body else 1,
    )
    return JSONResponse(res, status_code=200)
  except Exception as e:
    logger.exception(f"Fleet 360 radar sweep failed: {e}")
    return JSONResponse({"status": "ERROR", "error_message": str(e)}, status_code=500)


# --- 4. Markdown Hunting Playbook Routes ---

@mcp.custom_route("/api/v1/playbooks", methods=["GET"])
async def list_playbooks_endpoint(request: Request) -> JSONResponse:
  """Lists registered Markdown playbooks, their schedule status, and recent runs."""
  playbook_id = request.query_params.get("playbook_id")
  res = watchdog.list_playbooks(playbook_id=playbook_id)
  status_code = 404 if res.get("status") == "NOT_FOUND" else 200
  return JSONResponse(res, status_code=status_code)


@mcp.custom_route("/api/v1/playbooks", methods=["POST"])
async def register_playbook_endpoint(request: Request) -> JSONResponse:
  """Registers or updates a Markdown hunting playbook from a GitHub URL or local path."""
  try:
    body = await request.json() if await request.body() else {}
    url = body.get("url") or body.get("source")
    if not url:
      return JSONResponse(
          {"status": "ERROR", "error_message": "Missing required field 'url'."},
          status_code=400,
      )
    res = await watchdog.register_playbook(
        url=str(url),
        playbook_id=body.get("playbook_id"),
        interval_seconds=int(body.get("interval_seconds", 14400)),
        ingest_events=bool(body.get("ingest_events", True)),
        unscope_seeded_to_fleet=bool(body.get("unscope_seeded_to_fleet", False)),
        inter_query_delay_sec=float(body.get("inter_query_delay_sec", 1.0)),
        enabled=bool(body.get("enabled", True)),
        run_immediately=bool(body.get("run_immediately", False)),
    )
    return JSONResponse(res, status_code=200)
  except Exception as e:
    logger.exception(f"Playbook registration failed: {e}")
    return JSONResponse({"status": "ERROR", "error_message": str(e)}, status_code=500)


@mcp.custom_route("/api/v1/playbooks/run", methods=["POST"])
async def run_playbook_endpoint(request: Request) -> JSONResponse:
  """Executes a single pass of a registered or ad-hoc Markdown hunting playbook."""
  try:
    body = await request.json() if await request.body() else {}
    playbook_id = body.get("playbook_id")
    url = body.get("url") or body.get("source")
    if not playbook_id and not url:
      return JSONResponse(
          {
              "status": "ERROR",
              "error_message": "Provide either 'playbook_id' or 'url' in request body.",
          },
          status_code=400,
      )
    res = await watchdog.run_playbook_once(
        playbook_id=playbook_id,
        url=url,
        ingest_events=bool(body["ingest_events"]) if "ingest_events" in body else None,
        unscope_seeded_to_fleet=(
            bool(body["unscope_seeded_to_fleet"])
            if "unscope_seeded_to_fleet" in body
            else None
        ),
        inter_query_delay_sec=(
            float(body["inter_query_delay_sec"])
            if "inter_query_delay_sec" in body
            else None
        ),
        lookback_days_override=(
            int(body["lookback_days"]) if "lookback_days" in body else None
        ),
    )
    return JSONResponse(res, status_code=200)
  except KeyError as ke:
    return JSONResponse({"status": "NOT_FOUND", "error_message": str(ke)}, status_code=404)
  except Exception as e:
    logger.exception(f"Playbook run failed: {e}")
    return JSONResponse({"status": "ERROR", "error_message": str(e)}, status_code=500)


@mcp.custom_route("/api/v1/playbooks/stop", methods=["POST"])
async def stop_playbook_endpoint(request: Request) -> JSONResponse:
  """Stops (disables) or deletes a scheduled Markdown playbook subscription."""
  try:
    body = await request.json() if await request.body() else {}
    playbook_id = body.get("playbook_id")
    if not playbook_id:
      return JSONResponse(
          {"status": "ERROR", "error_message": "Missing required field 'playbook_id'."},
          status_code=400,
      )
    delete = bool(body.get("delete", False))
    res = watchdog.stop_playbook(playbook_id=str(playbook_id), delete=delete)
    status_code = 404 if res.get("status") == "NOT_FOUND" else 200
    return JSONResponse(res, status_code=status_code)
  except Exception as e:
    logger.exception(f"Playbook stop failed: {e}")
    return JSONResponse({"status": "ERROR", "error_message": str(e)}, status_code=500)


@mcp.custom_route("/api/v1/playbooks/{playbook_id}", methods=["DELETE"])
async def delete_playbook_endpoint(request: Request) -> JSONResponse:
  """Deletes a registered Markdown playbook subscription by ID."""
  playbook_id = request.path_params.get("playbook_id", "")
  res = watchdog.stop_playbook(playbook_id=str(playbook_id), delete=True)
  status_code = 404 if res.get("status") == "NOT_FOUND" else 200
  return JSONResponse(res, status_code=status_code)


# Build standard ASGI app supporting both MCP SSE and HTTP REST routes
app = mcp.streamable_http_app()


@contextlib.asynccontextmanager
async def combined_lifespan(application):
  async with mcp.session_manager.run():
    if tenant_config.watchdog_enabled:
      logger.info("Auto-starting Watchdog daemon on server startup.")
      watchdog.start()
    else:
      watchdog._ensure_playbook_scheduler()
    try:
      yield
    finally:
      if watchdog.is_running or watchdog.is_playbook_scheduler_running:
        logger.info("Stopping Watchdog daemon on server shutdown.")
        watchdog.stop()


app.router.lifespan_context = combined_lifespan


if __name__ == "__main__":
  import uvicorn
  port = int(os.environ.get("PORT", "8080"))
  uvicorn.run("src.server:app", host="0.0.0.0", port=port, log_level="info")

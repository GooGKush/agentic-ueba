# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Dual Interface Server (FastMCP + REST Gateway) for Agentic UEBA.

Exposes the autonomous JIT Threat Hunting Engine over two concurrent protocols:
1. REST Webhook (/api/v1/hunt/jit) for SecOps SOAR Playbooks using HTTP actions.
2. Model Context Protocol (/mcp via SSE / Streamable HTTP) for Agent-to-Agent invocations.
"""

import contextlib
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


# --- 2. REST Endpoints (Playbook-to-Agent Gateway) ---

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


# Build standard ASGI app supporting both MCP SSE and HTTP REST routes
app = mcp.streamable_http_app()


@contextlib.asynccontextmanager
async def combined_lifespan(application):
  async with mcp.session_manager.run():
    if tenant_config.watchdog_enabled:
      logger.info("Auto-starting Watchdog daemon on server startup.")
      watchdog.start()
    try:
      yield
    finally:
      if watchdog.is_running:
        logger.info("Stopping Watchdog daemon on server shutdown.")
        watchdog.stop()


app.router.lifespan_context = combined_lifespan


if __name__ == "__main__":
  import uvicorn
  port = int(os.environ.get("PORT", "8080"))
  uvicorn.run("src.server:app", host="0.0.0.0", port=port, log_level="info")

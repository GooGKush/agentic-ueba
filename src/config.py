# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Multi-tenant configuration and environment resolution for Agentic UEBA."""

import os
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


DEFAULT_ALLOWED_TOOLS = [
    # UDM Telemetry
    "udm_search",
    "search_raw_logs",
    
    # Entity Intelligence
    "search_entity",
    "summarize_entity",
    "get_involved_entity",
    
    # Alert & Case Triage (SecOps SOAR)
    "get_case",
    "get_case_alert",
    "list_case_alerts",
    "create_case_comment",
    
    # Threat Intelligence
    "get_ioc_match",
]


try:
  import dotenv
  dotenv.load_dotenv()
except ImportError:
  pass


class TenantConfig(BaseModel):
  """Dynamic tenant configuration with environment variable fallbacks."""

  project_id: str = Field(
      default_factory=lambda: os.environ.get("CHRONICLE_PROJECT_ID", "gus-sdl")
  )
  customer_id: str = Field(
      default_factory=lambda: os.environ.get("CHRONICLE_CUSTOMER_ID", "8cbac5ae-8267-4da7-b405-cdbc6fa3f1d5")
  )
  region: str = Field(
      default_factory=lambda: os.environ.get("CHRONICLE_REGION", "us")
  )
  mcp_url_override: Optional[str] = Field(
      default_factory=lambda: os.environ.get("CHRONICLE_MCP_URL")
  )
  model: str = Field(
      default_factory=lambda: os.environ.get("GEMINI_MODEL", "gemini-2.5-pro")
  )
  fallback_models: List[str] = Field(
      default_factory=lambda: [
          m.strip()
          for m in os.environ.get(
              "GEMINI_FALLBACK_MODELS",
              "gemini-2.5-flash,gemini-2.0-flash,gemini-1.5-pro",
          ).split(",")
          if m.strip()
      ]
  )
  allowed_tools: List[str] = Field(
      default_factory=lambda: (
          os.environ.get("ENABLED_MCP_TOOLS", "").split(",")
          if os.environ.get("ENABLED_MCP_TOOLS")
          else DEFAULT_ALLOWED_TOOLS
      )
  )
  watchdog_enabled: bool = Field(
      default_factory=lambda: os.environ.get("WATCHDOG_ENABLED", "false").lower() in ("true", "1", "yes")
  )
  watchdog_interval_seconds: int = Field(
      default_factory=lambda: int(os.environ.get("WATCHDOG_INTERVAL_SECONDS", "60"))
  )
  watchdog_limit_per_scan: int = Field(
      default_factory=lambda: int(os.environ.get("WATCHDOG_LIMIT_PER_SCAN", "5"))
  )
  watchdog_scan_lookback_hours: int = Field(
      default_factory=lambda: int(os.environ.get("WATCHDOG_SCAN_LOOKBACK_HOURS", "4"))
  )
  watchdog_max_state_size: int = Field(
      default_factory=lambda: int(os.environ.get("WATCHDOG_MAX_STATE_SIZE", "2000"))
  )
  watchdog_worker_concurrency: int = Field(
      default_factory=lambda: int(os.environ.get("WATCHDOG_WORKER_CONCURRENCY", "3"))
  )
  watchdog_queue_size: int = Field(
      default_factory=lambda: int(os.environ.get("WATCHDOG_QUEUE_SIZE", "100"))
  )
  fleet_360_enabled: bool = Field(
      default_factory=lambda: os.environ.get("FLEET_360_ENABLED", "false").lower() in ("true", "1", "yes")
  )
  fleet_360_interval_seconds: int = Field(
      default_factory=lambda: int(os.environ.get("FLEET_360_INTERVAL_SECONDS", "14400"))
  )
  fleet_360_spike_threshold_z: float = Field(
      default_factory=lambda: float(os.environ.get("FLEET_360_SPIKE_THRESHOLD_Z", "3.0"))
  )
  fleet_360_spoke_inclusion_z: float = Field(
      default_factory=lambda: float(os.environ.get("FLEET_360_SPOKE_INCLUSION_Z", "2.0"))
  )
  fleet_360_min_observed: int = Field(
      default_factory=lambda: int(os.environ.get("FLEET_360_MIN_OBSERVED", "5"))
  )
  fleet_360_max_outliers_per_sector: int = Field(
      default_factory=lambda: int(os.environ.get("FLEET_360_MAX_OUTLIERS_PER_SECTOR", "250"))
  )
  fleet_360_inter_query_delay_sec: float = Field(
      default_factory=lambda: float(os.environ.get("FLEET_360_INTER_QUERY_DELAY_SEC", "1.5"))
  )
  fleet_360_ingest_events: bool = Field(
      default_factory=lambda: os.environ.get("FLEET_360_INGEST_EVENTS", "true").lower() in ("true", "1", "yes")
  )
  fleet_360_emit_all_spokes: bool = Field(
      default_factory=lambda: os.environ.get("FLEET_360_EMIT_ALL_SPOKES", "true").lower() in ("true", "1", "yes")
  )

  @property
  def mcp_url(self) -> str:
    """Resolves regional or multi-regional SecOps OneMCP endpoint."""
    if self.mcp_url_override:
      return self.mcp_url_override
    return f"https://chronicle.{self.region}.rep.googleapis.com/mcp"

  def get_auth_headers(self) -> Dict[str, str]:
    """Generates GCP Bearer token and project routing header via ADC."""
    import google.auth
    from google.auth.transport.requests import Request

    creds, _ = google.auth.default(
        scopes=[
            "https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/chronicle",
        ]
    )
    creds.refresh(Request())
    headers = {"Authorization": f"Bearer {creds.token}"}
    if self.project_id:
      headers["x-goog-user-project"] = self.project_id
    return headers


def get_skills_root() -> Path:
  """Resolves canonical skills root without hardcoding.
  
  Priority:
  1. SKILLS_ROOT environment variable (e.g. /app/skills in container)
  2. ~/projects/ (local projects development root)
  3. ~/.gemini/skills/ (local deployment mirror)
  4. /app/skills (container staging location)
  """
  env_root = os.environ.get("SKILLS_ROOT")
  if env_root and Path(env_root).is_dir():
    return Path(env_root)

  user_home = Path.home()
  home_projects = user_home / "projects"
  if home_projects.is_dir():
    return home_projects

  installed_mirror = user_home / ".gemini" / "skills"
  if installed_mirror.is_dir():
    return installed_mirror

  return Path("/app/skills")

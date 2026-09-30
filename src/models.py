# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Pydantic data models and Clean Hand-Off (CH) contracts for Agentic UEBA."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MetricEvaluation(BaseModel):
  """Individual metric statistical evaluation against baseline."""
  metric_name: str
  observed_value: float
  personal_30d_mean: float
  personal_z_score: float
  cohort_peer_mean: Optional[float] = None
  cohort_peer_stddev: Optional[float] = None
  peer_z_score: Optional[float] = None
  cri_score: int
  severity: str  # "NOMINAL" | "LOW_OUTLIER" | "MEDIUM_OUTLIER" | "HIGH_OUTLIER" | "CRITICAL_OUTLIER"


class CleanHandOffPayload(BaseModel):
  """Standardized Clean Hand-Off contract between Tier 1 and Tier 2."""
  target_entity: str
  entity_type: str = "USER"  # "USER" | "ASSET" | "IP"
  evaluated_window: str
  primary_model: str
  metrics_evaluated: List[MetricEvaluation] = Field(default_factory=list)
  outlier_topology: str = "UNKNOWN"
  mitre_tactics_mapped: List[str] = Field(default_factory=list)
  recommended_swarm_playbook: str = "DEFAULT_INVESTIGATION"
  escalation_action: str = "MONITOR"


class StrategyDirective(BaseModel):
  """Formulated threat hunt hypothesis and model execution directive."""
  selected_skill: str = "secops-statistical-hunter"
  model_name: str = "GEMINI_REACT_AUTONOMOUS"
  directive_query: str = ""
  target_entity: str = ""
  entity_type: str = "USER"
  threat_summary: str = ""
  hypothesis_h0: str = ""
  hypothesis_h1: str = ""
  selection_rationale: str = ""
  flight_card_title: str = ""
  investigation_tier: str = "TIER_1_BASELINE"  # "TIER_1_BASELINE" | "TIER_2_DEEP_DIVE"
  outlier_vector: Optional[str] = None
  recommended_avenues: List[str] = Field(default_factory=list)


class JITHuntRequest(BaseModel):
  """Incoming JIT request payload from SecOps Playbook or caller."""
  target_entity: str = Field(..., description="Target username, hostname, or IP to investigate")
  entity_type: str = Field(default="USER", description="'USER', 'ASSET', or 'IP'")
  
  # Addressable query from Playbook block
  query: Optional[str] = Field(
      default=None,
      description="Natural language instruction from Playbook block, e.g. 'Assess data exfiltration risk'",
  )

  # Context from triggering alert
  case_id: Optional[str] = Field(default=None, description="Chronicle SOAR Case ID")
  alert_id: Optional[str] = Field(default=None, description="Chronicle SOAR Alert ID")
  alert_name: Optional[str] = Field(default=None, description="Title of the triggering alert")
  alert_description: Optional[str] = Field(default=None, description="Description/TTP of triggering alert")
  
  # Pre-formulated strategy directive (optional, populated by Agentic Strategy Reasoner)
  directive: Optional[StrategyDirective] = None

  # Analytical parameters
  skill: str = Field(default="auto", description="'auto', 'risk-metrics', or 'stats-hunter'")
  lookback_days: int = Field(default=14, ge=1, le=30)
  post_to_case_wall: bool = Field(default=True, description="Whether to write report to Case Wall via OneMCP")
  
  # Multi-tenant overrides (optional; falls back to environment defaults)
  project_id: Optional[str] = None
  customer_id: Optional[str] = None
  region: Optional[str] = None


class TriageSummary(BaseModel):
  """Machine-readable triage summary for Playbook automated branching and containment."""
  calibrated_risk_index: float = Field(ge=0.0, le=100.0)
  verdict: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "BENIGN"
  is_outlier: bool
  primary_vector: str
  top_z_score: float
  radar_dimensions: Dict[str, float] = Field(default_factory=dict)
  recommended_action: str
  entities_to_quarantine: List[str] = Field(
      default_factory=list,
      description="Specific user accounts, hostnames, or IPs recommended for automated containment",
  )
  mitre_tactics: List[str] = Field(
      default_factory=list,
      description="Mapped MITRE ATT&CK tactics, e.g. ['TA0006', 'TA0010']",
  )


class ForensicsSummary(BaseModel):
  """Detailed technical forensic evidence."""
  executed_query: str
  markdown_report: str
  radar_svg: Optional[str] = None


class JITHuntResponse(BaseModel):
  """Unified response payload returned to Playbook or MCP caller."""
  status: str = "SUCCESS"
  triage: TriageSummary
  clean_hand_off: Optional[CleanHandOffPayload] = None
  forensics: ForensicsSummary
  case_wall_updated: bool = False
  error_message: Optional[str] = None

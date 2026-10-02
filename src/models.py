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


class CandidateHypothesis(BaseModel):
  """A defended secondary hunt hypothesis with a calibrated confidence score."""
  hypothesis_title: str
  selected_skill: str = "secops-risk-metrics-multistage"
  model_name: str
  directive_query: str
  target_metric: Optional[str] = Field(
      default=None,
      description="Selected metric from the 38-metric catalog (e.g. 'workspace_total_download_actions', 'http_queries_fail', 'dns_queries_fail', 'file_executions_total', 'resource_written_total')",
  )
  fusion_metrics: List[str] = Field(
      default_factory=list,
      description="2 compatible metrics for Cross-Vector / Roll-Up Fusion, or 3 sibling metrics for Triad Multilevel",
  )
  identifier_field: Optional[str] = Field(
      default=None,
      description="UDM dimension field, e.g. 'principal.user.userid', 'target.user.userid', 'principal.asset.hostname'",
  )
  hypothesis_h0: str = ""
  hypothesis_h1: str = ""
  evidentiary_defense: str = ""
  confidence_score: float = Field(default=0.50, ge=0.0, le=1.0)
  confidence_band: str = "ANALYST_REVIEW"  # "AUTO_EXECUTE" | "ANALYST_REVIEW" | "SUPPRESSED"
  confidence_breakdown: str = ""
  pivot_reason: Optional[str] = None


class StrategyDirective(BaseModel):
  """Formulated threat hunt hypothesis and model execution directive."""
  selected_skill: str = "secops-statistical-hunter"
  model_name: str = "GEMINI_REACT_AUTONOMOUS"
  directive_query: str = ""
  target_entity: str = ""
  entity_type: str = "USER"
  target_metric: Optional[str] = Field(
      default=None,
      description="Selected metric from the 38-metric catalog when executing a dynamic metric pipeline",
  )
  fusion_metrics: List[str] = Field(
      default_factory=list,
      description="2 compatible metrics for Cross-Vector / Roll-Up Fusion, or 3 sibling metrics for Triad Multilevel",
  )
  identifier_field: Optional[str] = Field(
      default=None,
      description="UDM dimension field, e.g. 'principal.user.userid', 'target.user.userid', 'principal.asset.hostname'",
  )
  threat_summary: str = ""
  hypothesis_h0: str = ""
  hypothesis_h1: str = ""
  selection_rationale: str = ""
  evidentiary_defense: str = ""
  confidence_score: float = Field(default=0.80, ge=0.0, le=1.0)
  confidence_band: str = "AUTO_EXECUTE"  # "AUTO_EXECUTE" | "ANALYST_REVIEW" | "SUPPRESSED"
  confidence_breakdown: str = ""
  pivot_reason: Optional[str] = None
  flight_card_title: str = ""
  investigation_tier: str = "TIER_1_BASELINE"  # "TIER_1_BASELINE" | "TIER_2_DEEP_DIVE" | "TIER_2B_PIVOT"
  outlier_vector: Optional[str] = None
  recommended_avenues: List[str] = Field(default_factory=list)
  candidate_hypotheses: List[CandidateHypothesis] = Field(default_factory=list)


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
  alerts: List[Dict[str, Any]] = Field(default_factory=list, description="Case alert metadata list")
  connector_events: List[Dict[str, Any]] = Field(
      default_factory=list,
      description="Raw UDM connector events extracted from case alerts",
  )
  
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
  common_vector: str = Field(
      default="NONE",
      description="Normalized common behavioral vector shared across 360 radar and deep-dive models (e.g. AUTH, CLOUD, WORKSPACE, EGRESS, DNS, WEB, FLOWS, ALERTS, ENDPOINT, MULTI_SECTOR)",
  )
  second_order_ran: bool = Field(
      default=False,
      description="True if a Tier 2A or Tier 2B second-order investigation was executed",
  )
  tags: List[str] = Field(
      default_factory=list,
      description="Filterable case tags: binary risk finding (RISK:CRITICAL | RISK:HIGH), common vector (VECTOR:<SECTOR>), and SECOND_ORDER_HUNT",
  )
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

  def model_post_init(self, __context: Any) -> None:
    from src.formatters.case_wall_card import CaseWallCardFormatter
    if not self.common_vector or self.common_vector == "NONE":
      self.common_vector = CaseWallCardFormatter.normalize_common_vector(
          raw_vector=self.primary_vector
      )
    if not self.tags:
      self.tags = CaseWallCardFormatter.build_case_tags(
          calibrated_risk_index=self.calibrated_risk_index,
          primary_vector=self.primary_vector,
          second_order_ran=self.second_order_ran,
          is_outlier=self.is_outlier,
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

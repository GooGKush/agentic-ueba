# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit tests for DynamicProtocolAdapter and Agentic UEBA models."""

from pathlib import Path
import pytest

from src.config import TenantConfig, get_skills_root
from src.dynamic_protocol_adapter import DynamicProtocolAdapter
from src.models import (
    CleanHandOffPayload,
    JITHuntRequest,
    JITHuntResponse,
    TriageSummary,
    ForensicsSummary,
)


def test_tenant_config_dynamic_properties():
  t = TenantConfig(
      project_id="test-proj",
      customer_id="cust-1234",
      region="europe-west1",
  )
  assert t.mcp_url == "https://chronicle.europe-west1.rep.googleapis.com/mcp"
  assert "udm_search" in t.allowed_tools
  assert "create_case_comment" in t.allowed_tools


def test_protocol_adapter_risk_metrics():
  skills_root = get_skills_root()
  adapter = DynamicProtocolAdapter(skills_root)
  
  skill_dir = adapter.get_skill_path("secops-risk-metrics-multistage")
  raw_md = (skill_dir / "SKILL.md").read_text()
  adapted_skill = adapter.adapt_skill_text(raw_md)

  # Turn-taking lifecycle must be stripped from the skill text
  assert "## 🔄 THE 3-STATE ACTIVE HUNT LIFECYCLE" not in adapted_skill
  assert "MANDATORY STEP 1: PRE-FLIGHT CLEARANCE" not in adapted_skill
  assert "dedicate Turn 1 to pre-flight alignment" not in adapted_skill

  # Invariants must be preserved in persona
  persona = adapter.build_jit_persona(
      skill_name="secops-risk-metrics-multistage",
      project_id="test-project",
      customer_id="test-customer",
      region="us",
  )
  assert "Zero Data Simulation" in persona
  assert "Zero-Hallucination Compiler Grammar Contract" in persona
  assert "AUTONOMOUS JIT EXECUTION PROTOCOL" in persona


def test_protocol_adapter_stats_hunter():
  skills_root = get_skills_root()
  adapter = DynamicProtocolAdapter(skills_root)
  
  persona = adapter.build_jit_persona(
      skill_name="secops-statistical-hunter",
      project_id="test-project",
      customer_id="test-customer",
      region="us",
  )
  
  assert "AUTONOMOUS JIT EXECUTION PROTOCOL" in persona
  assert "Zero Generative Simulation" in persona or "Zero Data Simulation" in persona or "ZERO DATA SIMULATION" in persona.upper()


def test_jit_hunt_models():
  req = JITHuntRequest(
      target_entity="frank.kolzig",
      case_id="CASE-101",
      alert_name="AWS Suspicious Privilege Escalation",
  )
  assert req.target_entity == "frank.kolzig"
  assert req.skill == "auto"

  triage = TriageSummary(
      calibrated_risk_index=84.2,
      verdict="CRITICAL_OUTLIER",
      is_outlier=True,
      primary_vector="cloud_crud",
      top_z_score=4.5,
      recommended_action="SUSPEND_USER",
  )

  forensics = ForensicsSummary(
      executed_query="stage s1 { ... }",
      markdown_report="# Headline\nAnomalous activity detected.",
  )

  resp = JITHuntResponse(
      status="SUCCESS",
      triage=triage,
      forensics=forensics,
      case_wall_updated=True,
  )

  d = resp.model_dump()
  assert d["status"] == "SUCCESS"
  assert d["triage"]["calibrated_risk_index"] == 84.2
  assert d["case_wall_updated"] is True

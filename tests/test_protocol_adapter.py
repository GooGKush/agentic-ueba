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


def test_native_secops_zero_bigquery_backend_attribution():
  """Verify JIT persona and sanitizer enforce 100% Native SecOps architecture (zero BigQuery backend dependency)."""
  skills_root = get_skills_root()
  adapter = DynamicProtocolAdapter(skills_root)

  for skill in ("secops-risk-metrics-multistage", "secops-statistical-hunter"):
    persona = adapter.build_jit_persona(
        skill_name=skill,
        project_id="test-project",
        customer_id="test-customer",
        region="us",
    )
    assert "NATIVE GOOGLE SECOPS ARCHITECTURE (ZERO BIGQUERY DEPENDENCY)" in persona
    assert "pre-computed BigQuery" not in persona
    assert "BigQuery summary tables" not in persona
    assert "BigQuery roll-up" not in persona

  raw_text = (
      "Google SecOps aggregates telemetry into pre-computed BigQuery summary tables "
      "via BigQuery roll-up pipelines in a BigQuery backend."
  )
  cleaned = DynamicProtocolAdapter.sanitize_bq_backend_references(raw_text)
  assert "BigQuery" not in cleaned
  assert "native SecOps pre-computed Risk Analytics metric stores" in cleaned
  assert "native SecOps pre-computed roll-up pipelines" in cleaned
  assert "native SecOps backend" in cleaned


def test_bilateral_ueba_harness_protocol_and_persona():
  """Verify Bilateral UEBA Harness & Telemetry Physics Guardrail are loaded into JIT personas."""
  skills_root = get_skills_root()
  adapter = DynamicProtocolAdapter(skills_root)

  risk_persona = adapter.build_jit_persona(
      skill_name="secops-risk-metrics-multistage",
      project_id="test-project",
      customer_id="test-customer",
      region="us",
  )
  assert "BILATERAL UEBA HARNESS & TELEMETRY PHYSICS GUARDRAIL" in risk_persona
  assert "Never Declare UEBA a Poor Fit" in risk_persona
  assert "consultative/mitre-attack-killchain.md" in risk_persona
  assert "The Bilateral UEBA Harness & Telemetry Physics Guardrail" in risk_persona
  assert "CTI & Threat Report Mapping" in risk_persona
  assert "360° Entity Behavioral Risk Radar & Multi-Sector Threat Fusion" in risk_persona
  raw_risk_md = (adapter.get_skill_path("secops-risk-metrics-multistage") / "SKILL.md").read_text()
  assert "clearance question" not in adapter.adapt_skill_text(raw_risk_md)

  stats_persona = adapter.build_jit_persona(
      skill_name="secops-statistical-hunter",
      project_id="test-project",
      customer_id="test-customer",
      region="us",
  )
  assert "BILATERAL UEBA HARNESS & TELEMETRY PHYSICS GUARDRAIL" in stats_persona
  assert "The Bilateral UEBA Harness & Telemetry Physics Guardrail" in stats_persona
  assert "Bilateral UEBA Harness Co-Execution" in stats_persona
  assert "Template-First Formulation Directive" in stats_persona
  assert "6 Mandatory Root Outcome Variables Protocol" in stats_persona
  assert "Strict Visual Axis-Type Isolation" in stats_persona

  bilateral_persona = adapter.build_bilateral_jit_persona(
      project_id="test-project",
      customer_id="test-customer",
      region="us",
  )
  assert "HEMISPHERE 1: MACRO PLANE (secops-risk-metrics-multistage)" in bilateral_persona
  assert "HEMISPHERE 2: MICRO PLANE (secops-statistical-hunter)" in bilateral_persona
  assert "PLAYBOOK_BEHAVIORAL_HUNT_MATCH" in bilateral_persona
  assert "CTI & Threat Report Mapping" in bilateral_persona
  assert "Bilateral UEBA Harness Co-Execution" in bilateral_persona



# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Unit tests for DynamicProtocolAdapter and Agentic UEBA models."""

from datetime import datetime, timezone
import logging
from pathlib import Path
import re
import pytest

from src import harness_truth as ht
from src.config import TenantConfig, get_skills_root
import src.dynamic_protocol_adapter as dpa
from src.dynamic_protocol_adapter import DynamicProtocolAdapter
from src.models import (
    CleanHandOffPayload,
    JITHuntRequest,
    JITHuntResponse,
    MetricEvaluation,
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


def test_triage_and_metric_defaults_follow_harness_cri_bands():
  """Verdict, severity and action defaults come from the harness bands; explicit values are kept."""
  critical = TriageSummary(calibrated_risk_index=92.0, is_outlier=True, primary_vector="egress", top_z_score=6.9)
  assert critical.verdict == ht.verdict_for(92.0) == "CRITICAL_OUTLIER"
  assert critical.recommended_action == ht.recommended_action(92.0)
  medium = TriageSummary(calibrated_risk_index=50.0, is_outlier=True, primary_vector="auth", top_z_score=3.0)
  assert (medium.verdict, medium.recommended_action) == (ht.verdict_for(50.0), ht.recommended_action(50.0))

  # CRI N/A (missing data or error) is representable and maps to NOT_EVALUATED / MONITOR.
  missing = TriageSummary(calibrated_risk_index=None, is_outlier=False, primary_vector="NONE", top_z_score=None)
  assert missing.verdict == ht.verdict_for(None) == "NOT_EVALUATED"
  assert missing.recommended_action == ht.recommended_action(None)
  assert missing.model_dump()["calibrated_risk_index"] is None
  with pytest.raises(ValueError):
    TriageSummary(calibrated_risk_index=101.0, is_outlier=True, primary_vector="x", top_z_score=9.0)

  # Backward compatible: callers that pass a verdict and an action keep them.
  explicit = TriageSummary(
      calibrated_risk_index=84.2, verdict="CRITICAL_OUTLIER", is_outlier=True,
      primary_vector="cloud_crud", top_z_score=4.5, recommended_action="SUSPEND_USER")
  assert (explicit.verdict, explicit.recommended_action) == ("CRITICAL_OUTLIER", "SUSPEND_USER")

  # The documented verdict vocabulary is the harness band vocabulary.
  verdict_doc = TriageSummary.model_json_schema()["properties"]["verdict"]["description"]
  for verdict in set(ht.BAND_VERDICTS.values()):
    assert verdict in verdict_doc

  metric = MetricEvaluation(
      metric_name="auth_attempts_total", observed_value=12.0, personal_30d_mean=4.0,
      personal_z_score=1.9, cri_score=30)
  assert metric.severity == ht.verdict_for(30) == "LOW_OUTLIER"
  unscored = MetricEvaluation(
      metric_name="auth_attempts_total", observed_value=12.0, personal_30d_mean=4.0,
      personal_z_score=1.9, cri_score=None)
  assert unscored.severity == ht.verdict_for(None)
  assert MetricEvaluation(
      metric_name="m", observed_value=1.0, personal_30d_mean=1.0, personal_z_score=0.0,
      cri_score=0, severity="NOMINAL_BASELINE").severity == "NOMINAL_BASELINE"

  hand_off = CleanHandOffPayload(target_entity="alice", evaluated_window="2026-10-29", primary_model="m")
  assert hand_off.escalation_action == ht.recommended_action(None)


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
  # secops-statistical-hunter v3.0.0 replaced the "Bilateral UEBA Harness Co-Execution" bullet of
  # its routing interceptor with row 3 ("Bilateral Co-Execution") of the canonical routing table.
  assert "Bilateral Co-Execution" in stats_persona
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
  # Same v3.0.0 equivalent as above, now carried by both hemispheres.
  micro_hemisphere = bilateral_persona.split("HEMISPHERE 2: MICRO PLANE (secops-statistical-hunter)", 1)[1]
  assert "Bilateral Co-Execution" in micro_hemisphere


RISK_SKILL = "secops-risk-metrics-multistage"
STATS_SKILL = "secops-statistical-hunter"
# 06:00Z on Oct 30: Mode A scores Oct 29, whatever the wall clock says when the suite runs.
FIXED_NOW = datetime(2026, 10, 30, 6, 0, tzinfo=timezone.utc)
ROUTING_TABLE_RE = re.compile(
    r"<!-- CANONICAL_SKILL_ROUTING_TABLE_START -->.*?<!-- CANONICAL_SKILL_ROUTING_TABLE_END -->", re.S)


def _raw_and_adapted(adapter, skill):
  raw = (adapter.get_skill_path(skill) / "SKILL.md").read_text(encoding="utf-8")
  return raw, adapter.adapt_skill_text(raw)


def test_jit_personas_carry_the_remediated_always_loaded_rules():
  """The adapter strips the turn machine but keeps every always-loaded rule SKILL.md states."""
  adapter = DynamicProtocolAdapter(get_skills_root())
  risk_raw, risk_adapted = _raw_and_adapted(adapter, RISK_SKILL)
  stats_raw, stats_adapted = _raw_and_adapted(adapter, STATS_SKILL)

  for raw, adapted in ((risk_raw, risk_adapted), (stats_raw, stats_adapted)):
    # Canonical routing table (frozen WS8-02 contract) survives byte-for-byte; in the stats
    # skill it sits inside State 1 Step 0 of the lifecycle block.
    table = ROUTING_TABLE_RE.search(raw)
    assert table, "skill lost its canonical routing table markers"
    assert table.group(0) in adapted
    # Sub-day cron stays micro; nightly / multi-day cadence is Scheduled Exfiltration.
    assert "Scheduled Exfiltration" in adapted

  # Scheduled Exfiltration two-answer rule (risk-metrics steering section).
  assert "**Scheduled Exfiltration**: Offer both" in risk_adapted
  # Telemetry-physics guardrail of both skills: no 30-day raw scans of high-volume telemetry.
  assert "no 30d raw VPC/DNS/HTTP/Auth scans" in risk_adapted
  assert "no 30d raw VPC/DNS/HTTP/Auth scans" in stats_adapted
  assert "Pre-Flight Routing Interceptor" in stats_adapted
  # Mode A default: the last complete UTC day; Entity Graph joins start two days earlier.
  assert "Mode A defaults to the last complete UTC day" in risk_adapted
  # D4 tenant identifier coverage (principal.ip vs principal.asset.hostname) stays binding.
  assert "Identifier Coverage Probe (`D4`)" in stats_adapted
  # Execution and report contracts of State 2 are domain rules, not turn-taking.
  assert "Deterministic 5-Pillar Forensic Triage Report Structure" in risk_adapted
  assert "Zero-Telemetry Clean Hunt Exemption" in risk_adapted
  assert "Mandatory 5-Section Triage Report Delivery" in stats_adapted
  assert "Forensic Evidence Breakdown (6 Mandatory Evidence Pillars)" in stats_adapted

  # The human-in-the-loop turn machine is gone.
  for adapted in (risk_adapted, stats_adapted):
    for interactive in (
        "## 🔄 THE 3-STATE ACTIVE HUNT LIFECYCLE",
        "Phase 1A: Consultative Vector",
        "Turn 1 Tool Invariant",
        "State 2 Entry Condition",
        "Universal Pre-Flight Gate",
        "Explicit Clearance Question",
        "Would you like me to proceed",
        "### 🔁 State 3",
    ):
      assert interactive not in adapted
  assert "clearance question" not in risk_adapted


def test_jit_protocol_thresholds_bands_and_caps_come_from_the_harness(monkeypatch):
  protocol = dpa.render_autonomous_jit_protocol()

  hits, sum_z_sq = ht.loopback_thresholds()
  assert f">= {hits} distinct hits and sum(Z_i^2) >= {sum_z_sq}" in protocol
  for low, high, _, label, emoji in ht.cri_bands():
    assert f"CRI {low}–{high} ({emoji} {label}): verdict `{ht.verdict_for(low)}`" in protocol
  assert f"verdict `{ht.verdict_for(None)}`; recommended_action `{ht.recommended_action(None)}`" in protocol
  assert ht.RECOMMENDATION_NOTE in protocol
  assert f"at least {ht.min_baseline_days()} active baseline days" in protocol
  anchor_z = ht.constants().DEFAULT_ANOMALY_THRESHOLD
  assert f"{ht.calculate_cri(anchor_z)} at Z = {anchor_z}" in protocol
  caps = ht.mode_caps()
  assert f"macro Mode B covers at most {caps['mode_b_macro_days']} days" in protocol
  assert f"micro raw windows at most {caps['mode_b_micro_days']} days" in protocol
  # The in-query CRI rule quotes the skill's own PIECEWISE_CRI retirement message (and its replacement).
  assert ht.retirement_message("PIECEWISE_CRI") in protocol
  assert "templates/radar_360/" in protocol
  assert "Mode A, the default for every query" in protocol
  # Stale v2.x wording is gone.
  assert "6-section" not in protocol
  assert "If 5 risk dimensions" not in protocol

  # Nothing is a local copy: change the harness and the protocol follows.
  real_retirement = ht.retirement_message
  monkeypatch.setattr(ht, "loopback_thresholds", lambda: (3, 36.0))
  monkeypatch.setattr(ht, "min_baseline_days", lambda: 9)
  monkeypatch.setattr(ht, "retirement_message", lambda name: (
      "PIECEWISE_CRI retired for this test" if str(name).upper() == "PIECEWISE_CRI" else real_retirement(name)))
  protocol = dpa.render_autonomous_jit_protocol()
  assert ">= 3 distinct hits and sum(Z_i^2) >= 36.0" in protocol
  assert "at least 9 active baseline days" in protocol
  assert "PIECEWISE_CRI retired for this test" in protocol


def test_jit_personas_bind_the_mode_a_and_entity_graph_windows():
  adapter = DynamicProtocolAdapter(get_skills_root())
  day = ht.mode_a_day(FIXED_NOW)
  start, end = ht.mode_a_window(day)
  ecg_start, ecg_end = ht.ecg_window(day)
  personas = [
      adapter.build_jit_persona(
          skill_name=skill, project_id="p", customer_id="c", region="us", now=FIXED_NOW,
          include_templates=False, include_references=False)
      for skill in (RISK_SKILL, STATS_SKILL)
  ]
  personas.append(adapter.build_bilateral_jit_persona(
      project_id="p", customer_id="c", region="us", now=FIXED_NOW,
      include_templates=False, include_references=False))
  for persona in personas:
    assert f"Scored day D (last complete UTC day): {day.isoformat()}" in persona
    assert f'Mode A window: startTime "{start}", endTime "{end}"' in persona
    assert f'Entity Graph window: startTime "{ecg_start}", endTime "{ecg_end}"' in persona
    assert ht.event_day_pin(day) in persona


def test_template_library_includes_radar_360_and_excludes_retired_templates(tmp_path):
  adapter = DynamicProtocolAdapter(get_skills_root())
  risk_dir = adapter.get_skill_path(RISK_SKILL)
  radar_templates = sorted((risk_dir / "templates" / "radar_360").glob("*.yl2"))
  assert radar_templates, "templates/radar_360/ is missing from secops-risk-metrics-multistage"
  library = adapter.load_templates(risk_dir)
  for path in radar_templates:
    assert f"--- TEMPLATE FILE: {path.relative_to(risk_dir)} ---" in library
  for skill in (RISK_SKILL, STATS_SKILL):
    names = re.findall(r"--- TEMPLATE FILE: (\S+) ---", adapter.load_templates(adapter.get_skill_path(skill)))
    assert names
    assert not [n for n in names if ht.is_retired(Path(n).name)]

  # A stale mirror (e.g. an old SKILLS_ROOT deployment) that still ships retired templates.
  skill_dir = tmp_path / RISK_SKILL
  (skill_dir / "SKILL.md").parent.mkdir(parents=True)
  (skill_dir / "SKILL.md").write_text("# stub\n", encoding="utf-8")
  files = {
      "templates/stage2_math_models/piecewise_cri.yl2": "// retired",
      "templates/pipelines/circadian_von_mises_2stage.yl2": "// retired",
      "templates/pipelines/standard_z_score_2stage.yl2": "// active",
      "templates/radar_360/user_1_auth_risk.yl2": "// active",
  }
  for rel, body in files.items():
    (skill_dir / rel).parent.mkdir(parents=True, exist_ok=True)
    (skill_dir / rel).write_text(body + "\n", encoding="utf-8")
  library = DynamicProtocolAdapter(tmp_path).load_templates(skill_dir)
  assert "--- TEMPLATE FILE: templates/pipelines/standard_z_score_2stage.yl2 ---" in library
  assert "--- TEMPLATE FILE: templates/radar_360/user_1_auth_risk.yl2 ---" in library
  assert "piecewise_cri.yl2" not in library
  assert "circadian_von_mises_2stage.yl2" not in library


def test_bilateral_persona_carries_real_micro_references(caplog):
  adapter = DynamicProtocolAdapter(get_skills_root())
  persona = adapter.build_bilateral_jit_persona(
      project_id="p", customer_id="c", region="us", include_templates=False)
  micro = persona.split("=== [HEMISPHERE 2: MICRO PLANE (secops-statistical-hunter)] ===", 1)[1]
  refs = re.findall(r"=== \[REFERENCE: ([^\]]+)\] ===", micro)
  ref_dir = adapter.get_skill_path(STATS_SKILL) / "references"
  assert refs, "the micro hemisphere carries no secops-statistical-hunter reference"
  assert all((ref_dir / r).is_file() for r in refs)

  # A requested reference that does not exist is reported, not silently dropped.
  with caplog.at_level(logging.WARNING, logger="DynamicProtocolAdapter"):
    assert adapter.load_references(ref_dir.parent, target_refs=["no-such-guide.md"]) == ""
  assert "no-such-guide.md" in caplog.text


# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Standardized Case Wall Forensic Triage Card Formatter for Agentic UEBA.

Formats comprehensive SOC Flight Cards in Markdown for Google Chronicle SOAR
Case Walls, detailing the problem statement, tested hypotheses (H0 vs H1),
underlying UDM touchpoints, statistical metrics table, and actionable SOC guidance.
"""

from typing import Any, Dict, List, Optional
from src.models import StrategyDirective


class CaseWallCardFormatter:
  """Formats structured, visual, markdown-based flight cards for Case Wall comments."""

  @staticmethod
  def render_risk_bar(cri: float) -> str:
    """Generates a Unicode calibrated risk index meter bar."""
    filled_blocks = min(10, max(0, int(round(cri / 10.0))))
    bar = "█" * filled_blocks + "░" * (10 - filled_blocks)
    if cri >= 80:
      badge = "🔴 **CRITICAL OUTLIER**"
    elif cri >= 60:
      badge = "🟠 **HIGH OUTLIER**"
    elif cri >= 40:
      badge = "🟡 **MEDIUM ELEVATION**"
    else:
      badge = "🟢 **NOMINAL BASELINE**"
    return f"`{cri:.0f}/100` [{bar}] {badge}"

  @classmethod
  def format_card(
      cls,
      target_entity: str,
      entity_type: str,
      model_name: str,
      calibrated_risk_index: float,
      is_outlier: bool,
      case_id: Optional[str] = None,
      evaluated_window: str = "7-Day Sliding Horizon",
      rows_count: int = 0,
      directive: Optional[StrategyDirective] = None,
      metrics_table_rows: Optional[List[Dict[str, str]]] = None,
      soc_guidance: Optional[str] = None,
  ) -> str:
    """Renders a full 5-section Markdown Case Wall Triage Card."""
    risk_bar = cls.render_risk_bar(calibrated_risk_index)

    # 1. Header & Verdict Banner
    card_title = directive.flight_card_title if directive and directive.flight_card_title else f"Autonomous UEBA Triage Card: `{target_entity}`"
    threat_summary = directive.threat_summary if directive and directive.threat_summary else f"Statistical & Behavioral Anomaly Assessment for {entity_type} `{target_entity}`."
    
    # Hypotheses
    h0 = directive.hypothesis_h0 if directive and directive.hypothesis_h0 else "Activity conforms to normal baseline patterns without statistically significant departures."
    h1 = directive.hypothesis_h1 if directive and directive.hypothesis_h1 else "Observed telemetry exhibits anomalous clustering, periodicity, or volume indicative of threat behavior."
    rationale = directive.selection_rationale if directive and directive.selection_rationale else f"Model selected based on {entity_type} topology and triggering alert context."

    tier_label = directive.investigation_tier if directive and directive.investigation_tier else "TIER_1_BASELINE"
    tier_display = (
        "Tier 1: 360° Behavioral Radar Baseline"
        if tier_label == "TIER_1_BASELINE"
        else f"Tier 2: Targeted Deep Dive ({directive.outlier_vector or 'Outlier Sweep'})"
        if directive and directive.outlier_vector
        else "Tier 2: Targeted Deep Dive"
    )

    lines = [
        f"## 🛡️ {card_title}",
        "",
        f"**Calibrated Risk Index**: {risk_bar}  ",
        f"**Target Entity**: `{target_entity}` ({entity_type}) | **Investigation Phase**: `{tier_display}`  ",
        f"**Case ID**: {case_id or 'Ad-Hoc'} | **Window**: {evaluated_window} ({rows_count} telemetry records)  ",
        "",
        "---",
        "",
        "### 🎯 Problem Statement & Threat Touchpoints",
        f"> {threat_summary}",
        "",
        "### 🔬 Investigation Hypotheses & Model Selection",
        f"- **Analytical Model**: `{model_name}`",
        f"- **Selection Rationale**: {rationale}",
        f"- **Null Hypothesis ($H_0$)**: {h0}",
        f"- **Alternative Threat Hypothesis ($H_1$)**: {h1}",
        "",
        "### 📊 Forensic Evidence & Flight Metrics",
    ]

    # Metrics Table
    if metrics_table_rows:
      lines.extend([
          "| Metric / Dimension | Observed Value | Baseline / Threshold | Statistical Assessment |",
          "| :--- | :--- | :--- | :--- |",
      ])
      for r in metrics_table_rows:
        lines.append(f"| {r.get('metric', '')} | {r.get('observed', '')} | {r.get('threshold', '')} | {r.get('assessment', '')} |")
    else:
      lines.extend([
          "| Metric / Dimension | Observed Value | Baseline / Threshold | Statistical Assessment |",
          "| :--- | :--- | :--- | :--- |",
          f"| **Anomaly Gate** | `{is_outlier}` | `False` | {'⚠️ Statistically Significant Departure' if is_outlier else '✅ Within Expected Distribution'} |",
          f"| **Evaluated Telemetry** | `{rows_count} records` | `$\\ge 5$ required` | {'Sufficient Observation Power' if rows_count >= 5 else 'Limited Sample Size'} |",
      ])

    # SOC Analyst Guidance
    lines.extend([
        "",
        "### 🔍 SOC Analyst Operational Guidance",
    ])

    if soc_guidance:
      lines.append(f"> {soc_guidance}")
    elif is_outlier:
      lines.append(
          f"> **ESCALATION RECOMMENDED**: Telemetry for `{target_entity}` satisfies the alternative hypothesis ($H_1$) with CRI score {calibrated_risk_index:.0f}/100. "
          f"Investigate downstream lateral connections and stage credential/host containment playbooks."
      )
    else:
      lines.append(
          f"> **BENIGN / NOMINAL ACTIVITY**: Telemetry for `{target_entity}` supports the null hypothesis ($H_0$) with CRI score {calibrated_risk_index:.0f}/100. "
          f"No containment actions required. Logged as baseline operational activity."
      )

    # 🧭 Recommended Avenues to Pursue
    avenues = directive.recommended_avenues if directive and directive.recommended_avenues else []
    if not avenues:
      if is_outlier:
        avenues = [
            f"Cross-correlate `{target_entity}` outbound connections against Google Threat Intelligence (GCTI) and WHOIS NRD feeds.",
            f"Review process execution lineage for Living-off-the-Land (LotL) binary invocations spawned on or by `{target_entity}`.",
            f"Check credential and IAM token activity for anomalous concurrent logins from foreign geolocation.",
        ]
      else:
        avenues = [
            f"Continue passive monitoring of `{target_entity}` across trailing 30-day baseline.",
            f"If alert recurs, verify upstream log source parser health and rule threshold calibration.",
        ]

    lines.extend([
        "",
        "### 🧭 Recommended Avenues to Pursue",
    ])
    for i, avenue in enumerate(avenues, 1):
      lines.append(f"{i}. {avenue}")

    return "\n".join(lines)

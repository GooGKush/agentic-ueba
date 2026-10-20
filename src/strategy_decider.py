# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Agentic Strategy Reasoner & Confidence-Gated Hypothesis Pivot Engine for SecOps Threat Hunting.

Ingests rich multi-source context (Case metadata, Alert outcomes, GCTI findings,
Tier 1 6-spoke 360° radar telemetry, and raw UDM connector events) to identify attacker
touchpoints, formulate testable hypotheses (H0 vs H1) with explicit evidentiary defenses,
score each candidate hypothesis on a calibrated [0.00 - 1.00] confidence scale, and
select optimal single-metric, cross-vector fusion, or raw micro-math models across
SecOps Risk Metrics (all 38 catalog metrics) and Statistical Outlier Hunter engines.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from google import genai
from google.genai import types
from src.models import CandidateHypothesis, StrategyDirective

logger = logging.getLogger("AgenticStrategyReasoner")


class StrategyDecider:
  """Agentic Strategy Reasoner that formulates defended threat hypotheses and confidence-gated pivots."""

  # Threshold gates on the [0.00 - 1.00] hybrid confidence scale
  TIER_2A_AUTO_EXECUTE_THRESHOLD = 0.75
  TIER_2B_PIVOT_AUTO_EXECUTE_THRESHOLD = 0.80
  ANALYST_REVIEW_MIN_THRESHOLD = 0.45
  MAX_SECONDARY_HUNTS = 2

  # Canonical mapping from 360° radar sector names to default metrics & UDM families
  SECTOR_TO_METRIC_USER: Dict[str, str] = {
      "Auth": "auth_attempts_fail",
      "Cloud": "resource_creation_total",
      "Workspace": "workspace_total_download_actions",
      "Egress": "network_bytes_outbound",
      "DNS": "dns_queries_fail",
      "Web": "http_queries_total",
  }

  SECTOR_TO_METRIC_ASSET: Dict[str, str] = {
      "Auth": "auth_attempts_fail",
      "Egress": "network_bytes_outbound",
      "DNS": "dns_queries_fail",
      "Flows": "network_flows_outbound",
      "Alerts": "alert_event_name_count",
      "Web": "http_queries_total",
  }

  # Maps metric/model families to UDM event types and keywords for deterministic confidence scoring
  FAMILY_SIGNALS: Dict[str, Dict[str, Any]] = {
      "Auth": {
          "udm_events": {"USER_LOGIN", "USER_LOGOUT"},
          "keywords": {"login", "auth", "spray", "brute", "credential", "password", "mfa", "kerberos", "saml", "oauth"},
          "metrics": {"auth_attempts_total", "auth_attempts_fail", "auth_attempts_success", "workspace_auth_attempts_total"},
      },
      "Workspace": {
          "udm_events": {"USER_RESOURCE_ACCESS", "USER_RESOURCE_UPDATE_CONTENT"},
          "keywords": {"workspace", "drive", "download", "hoarding", "doc", "sheet", "gmail", "exfil"},
          "metrics": {
              "workspace_total_download_actions",
              "workspace_total_change_actions",
              "workspace_emails_sent_total",
              "workspace_network_bytes_outbound",
              "workspace_network_bytes_inbound",
          },
      },
      "Cloud": {
          "udm_events": {
              "RESOURCE_CREATION",
              "USER_RESOURCE_CREATION",
              "RESOURCE_DELETION",
              "USER_RESOURCE_DELETION",
              "RESOURCE_WRITTEN",
              "RESOURCE_READ",
              "RESOURCE_PERMISSIONS_CHANGE",
          },
          "keywords": {"cloud", "iam", "bucket", "resource_written", "resource_creation", "service account", "terraform", "gcp", "aws"},
          "metrics": {
              "resource_creation_total",
              "resource_creation_success",
              "resource_creation_fail",
              "resource_deletion_total",
              "resource_deletion_success",
              "resource_deletion_fail",
              "resource_read_total",
              "resource_read_success",
              "resource_read_fail",
              "resource_written_total",
              "resource_written_success",
              "resource_written_fail",
          },
      },
      "Egress": {
          "udm_events": {"NETWORK_CONNECTION", "NETWORK_FLOW"},
          "keywords": {"beacon", "jitter", "c2", "egress", "outbound", "exfil", "elephant", "bytes", "bandwidth", "rat"},
          "metrics": {
              "network_bytes_outbound",
              "network_bytes_inbound",
              "network_bytes_total",
              "network_flows_outbound",
              "network_flows_inbound",
              "network_flows_total",
          },
      },
      "DNS": {
          "udm_events": {"NETWORK_DNS"},
          "keywords": {"dns", "dga", "nxdomain", "tunneling", "subdomain", "domain"},
          "metrics": {"dns_queries_fail", "dns_queries_total", "dns_queries_success", "dns_bytes_outbound"},
      },
      "Web": {
          "udm_events": {"NETWORK_HTTP"},
          "keywords": {"http", "web", "proxy", "user_agent", "uri", "url", "scraping", "whois", "nrd"},
          "metrics": {"http_queries_total", "http_queries_fail", "http_queries_success"},
      },
      "Endpoint": {
          "udm_events": {"PROCESS_LAUNCH", "FILE_CREATION", "FILE_MODIFICATION"},
          "keywords": {"process", "binary", "sha256", "powershell", "cmd.exe", "lotl", "markov", "zipf", "entropy", "base64", "dropper"},
          "metrics": {"file_executions_total", "file_executions_success", "file_executions_fail"},
      },
      "Alerts": {
          "udm_events": {"SCAN_UNCATEGORIZED", "EDR_ALERT"},
          "keywords": {"edr", "crowdstrike", "sentinelone", "carbonblack", "alert_event_name_count"},
          "metrics": {"alert_event_name_count"},
      },
  }

  @classmethod
  def infer_family(
      cls,
      model_name: str,
      target_metric: Optional[str] = None,
      fusion_metrics: Optional[Sequence[str]] = None,
      outlier_vector: Optional[str] = None,
  ) -> str:
    """Infers primary telemetry sector family for confidence scoring and zero-telemetry lockout."""
    if outlier_vector and outlier_vector in cls.FAMILY_SIGNALS:
      return outlier_vector
    if target_metric:
      for fam, spec in cls.FAMILY_SIGNALS.items():
        if target_metric in spec["metrics"]:
          return fam
    if fusion_metrics:
      for m in fusion_metrics:
        for fam, spec in cls.FAMILY_SIGNALS.items():
          if m in spec["metrics"]:
            return fam
    m_up = (model_name or "").upper()
    if any(k in m_up for k in ("C2_", "ELEPHANT_FLOW", "DIVERSITY_DEFICIT")):
      return "Egress"
    if any(k in m_up for k in ("POISSON_BURST", "BETA_BINOMIAL", "LATERAL_EXPANSION", "CIRCADIAN")):
      return "Auth"
    if any(k in m_up for k in ("CLOUD_", "REPOSITORY")):
      return "Cloud"
    if any(k in m_up for k in ("MARKOV", "SHANNON", "ZIPFIAN", "FILE_PREVALENCE")):
      return "Endpoint"
    if any(k in m_up for k in ("DOMAIN_PREVALENCE", "WHOIS", "HTTP_")):
      return "Web"
    return outlier_vector or "Egress"

  @classmethod
  def build_signature(
      cls,
      model_name: str,
      target_metric: Optional[str] = None,
      fusion_metrics: Optional[Sequence[str]] = None,
      target_entity: Optional[str] = None,
  ) -> str:
    """Builds a canonical deduplication signature for an executed hypothesis."""
    fusion_list = list(fusion_metrics or [])
    return f"{model_name}|{target_metric or ''}|{','.join(sorted(fusion_list))}"

  @classmethod
  def family_for_query(cls, directive_query: str) -> str:
    """Maps a directive query identifier to its telemetry family for Zero-Telemetry lockout."""
    q = (directive_query or "").lower()
    if "poisson" in q or "circadian" in q or "lateral" in q:
      return "Auth"
    if "cloud" in q:
      return "Cloud"
    if "c2_jitter" in q or "elephant" in q or "ewma" in q:
      return "Egress"
    if "shannon" in q or "markov" in q or "zipf" in q:
      return "Endpoint"
    return "Egress"

  @classmethod
  def analyze_360_insights(
      cls,
      radar_result: Optional[Dict[str, Any]],
      ctx: Optional[Dict[str, Any]] = None,
      entity_type: str = "USER",
  ) -> Dict[str, Any]:
    """Synthesizes deeper UEBA insights from a Tier 1 360° Behavioral Radar report and case context.

    Identifies:
    1. Multi-sector MITRE ATT&CK Kill-Chain Archetypes (v1.9.1) across active & sub-threshold spokes.
    2. Dormant / Sparse Baseline Awakenings (observed > 0 on a 30d baseline mean < 1.0 -> TWO_PART_HURDLE).
    3. Variance-Masked Sub-Threshold Drift (1.25 <= Z < 3.0 with high historical stddev -> 4-stage MAD).
    4. Cross-Entity Kill-Chain Bridge opportunities (companion USER <-> ASSET/IP in case telemetry).
    5. Explicit warrant assessment (`secondary_warranted` and `warrant_reasons`) for secondary UEBA hunts.
    """
    radar_result = radar_result or {}
    ctx = ctx or {}
    sector_z = radar_result.get("sector_z_scores", {})
    sector_obs = radar_result.get("sector_observed_counts", {})
    sector_avg = radar_result.get("sector_baseline_avg", {})
    sector_std = radar_result.get("sector_baseline_std", {})
    outlier_sectors = list(radar_result.get("outlier_sectors", []))
    if not outlier_sectors and sector_z:
      outlier_sectors = [s for s, z in sorted(sector_z.items(), key=lambda x: x[1], reverse=True) if abs(float(z)) >= 2.0]

    subthreshold_sectors = list(radar_result.get("subthreshold_sectors", []))
    if not subthreshold_sectors and sector_z:
      subthreshold_sectors = [
          s for s, z in sorted(sector_z.items(), key=lambda x: x[1], reverse=True) if 1.25 <= float(z) < 2.0
      ]

    dormant_awakening_sectors = list(radar_result.get("dormant_awakening_sectors", []))
    if not dormant_awakening_sectors and sector_z and sector_avg:
      dormant_awakening_sectors = [
          s
          for s, z in sorted(sector_z.items(), key=lambda x: x[1], reverse=True)
          if sector_obs.get(s, 0) > 0 and float(sector_avg.get(s, 0.0)) < 1.0 and float(z) >= 1.5
      ]

    variance_masked_sectors = list(radar_result.get("variance_masked_sectors", []))
    if not variance_masked_sectors and sector_z and sector_std:
      variance_masked_sectors = [
          s
          for s, z in sorted(sector_z.items(), key=lambda x: x[1], reverse=True)
          if 1.25 <= float(z) < 3.0 and float(sector_std.get(s, 0.0)) >= max(float(sector_avg.get(s, 0.0)) * 1.5, 5.0)
      ]

    elevated = set(outlier_sectors) | set(subthreshold_sectors)
    matched_archetypes: List[Dict[str, Any]] = []
    if "Cloud" in elevated and "Workspace" in elevated:
      matched_archetypes.append({
          "archetype": "CLOUD_DISCOVERY_TO_COLLECTION",
          "tactics": ["TA0007 Discovery", "TA0009 Collection"],
          "sectors": ["Cloud", "Workspace"],
          "fusion_metrics": ["resource_read_total", "workspace_total_download_actions"],
      })
    if "Alerts" in elevated and "Egress" in elevated:
      matched_archetypes.append({
          "archetype": "DEFENSE_EVASION_ALERT_TO_EXFILTRATION",
          "tactics": ["TA0005 Defense Evasion", "TA0010 Exfiltration"],
          "sectors": ["Alerts", "Egress"],
          "fusion_metrics": ["alert_event_name_count", "network_bytes_outbound"],
      })
    if "Auth" in elevated and "Web" in elevated:
      matched_archetypes.append({
          "archetype": (
              "C2_BEACON_TO_RARE_DESTINATION_EXFIL"
              if str(entity_type).upper() in ("ASSET", "HOST", "IP")
              else "INITIAL_ACCESS_TO_DISCOVERY"
          ),
          "tactics": ["TA0001 Initial Access", "TA0007 Discovery"],
          "sectors": ["Auth", "Web"],
          "fusion_metrics": ["auth_attempts_success", "http_queries_fail"],
      })
    if "Auth" in elevated and ("Flows" in elevated or "Egress" in elevated):
      matched_archetypes.append({
          "archetype": "CREDENTIAL_ACCESS_TO_LATERAL_MOVEMENT",
          "tactics": ["TA0006 Credential Access", "TA0008 Lateral Movement"],
          "sectors": ["Auth", "Flows" if "Flows" in elevated else "Egress"],
          "fusion_metrics": ["auth_attempts_fail", "network_flows_total"],
      })
    if "Workspace" in elevated and "Egress" in elevated:
      matched_archetypes.append({
          "archetype": "WORKSPACE_HOARDING_TO_EGRESS",
          "tactics": ["TA0009 Collection", "TA0010 Exfiltration"],
          "sectors": ["Workspace", "Egress"],
          "fusion_metrics": ["workspace_total_download_actions", "network_bytes_outbound"],
      })
    if "Workspace" in elevated and "Web" in elevated:
      matched_archetypes.append({
          "archetype": "EXFILTRATION_OVER_WEB_SERVICE",
          "tactics": ["TA0009 Collection", "TA0010 Exfiltration"],
          "sectors": ["Workspace", "Web"],
          "fusion_metrics": ["workspace_total_download_actions", "http_queries_total"],
      })
    if "Web" in elevated and "Auth" in elevated and str(entity_type).upper() in ("ASSET", "HOST", "IP"):
      matched_archetypes.append({
          "archetype": "RECON_TO_INITIAL_ACCESS",
          "tactics": ["TA0043 Reconnaissance", "TA0001 Initial Access"],
          "sectors": ["Web", "Auth"],
          "fusion_metrics": ["http_queries_fail", "auth_attempts_success"],
      })
    if "Cloud" in elevated and "Endpoint" in elevated:
      matched_archetypes.append({
          "archetype": "RESOURCE_DEV_TO_EXECUTION",
          "tactics": ["TA0042 Resource Development", "TA0002 Execution"],
          "sectors": ["Cloud", "Endpoint"],
          "fusion_metrics": ["resource_creation_total", "file_executions_total"],
      })

    # Companion entities for cross-entity kill-chain bridging
    primary_ent = str(ctx.get("primary_entity") or radar_result.get("entity") or "").lower()
    ent_up = str(entity_type or ctx.get("entity_type") or "USER").upper()
    companion_entities: List[Dict[str, str]] = []
    if ent_up in ("USER", "USER_ID", "EMAIL", "SERVICE_ACCOUNT"):
      for h in ctx.get("extracted_hosts", []):
        if h and h.lower() != primary_ent:
          companion_entities.append({
              "entity": h,
              "entity_type": "ASSET",
              "bridge_path": (
                  "USER_WORKSPACE_HOARDING_TO_HOST_EGRESS"
                  if "Workspace" in elevated
                  else "USER_CREDENTIAL_TO_HOST_EXECUTION"
              ),
          })
      for ip in ctx.get("extracted_ips", []):
        if ip and ip.lower() != primary_ent:
          companion_entities.append({
              "entity": ip,
              "entity_type": "IP",
              "bridge_path": "USER_CREDENTIAL_TO_HOST_EXECUTION",
          })
    else:
      for u in ctx.get("extracted_users", []):
        if u and u.lower() != primary_ent:
          companion_entities.append({
              "entity": u,
              "entity_type": "USER",
              "bridge_path": "HOST_EXECUTION_TO_CLOUD_SA_ACCESS",
          })

    warrant_reasons: List[str] = []
    top_z = max((float(v) for v in sector_z.values()), default=0.0)
    composite_d = float(radar_result.get("composite_d", 0.0))
    cri = float(radar_result.get("calibrated_risk_index", 0.0))

    if outlier_sectors:
      warrant_reasons.append(f"Primary 360° sector breach in {', '.join(outlier_sectors)} (peak Z = {top_z:+.2f}σ).")
    if len(subthreshold_sectors) >= 2 and composite_d >= 2.0:
      warrant_reasons.append(
          f"Multi-spoke sub-threshold convergence across {', '.join(subthreshold_sectors)} (joint Euclidean D = {composite_d:.2f}σ)."
      )
    if variance_masked_sectors:
      warrant_reasons.append(
          f"Potential historical variance masking in {', '.join(variance_masked_sectors)} (high 30d stddev may suppress classical Z; 4-Stage Non-Parametric MAD warranted)."
      )
    if dormant_awakening_sectors:
      warrant_reasons.append(
          f"Dormant baseline awakening in {', '.join(dormant_awakening_sectors)} (30d baseline mean < 1.0; Two-Part Hurdle / sparse-history math warranted)."
      )
    if matched_archetypes:
      arch_names = [a["archetype"] for a in matched_archetypes]
      warrant_reasons.append(f"Multi-sector MITRE ATT&CK kill-chain topology matched: {', '.join(arch_names)}.")

    secondary_warranted = bool(
        radar_result.get("is_outlier")
        or top_z >= 2.0
        or cri >= 40.0
        or (len(subthreshold_sectors) >= 2 and composite_d >= 2.0)
        or len(variance_masked_sectors) >= 1
        or len(dormant_awakening_sectors) >= 1
    )

    recommended_focus_sector = radar_result.get("top_sector") or "Auth"
    if not outlier_sectors:
      if variance_masked_sectors:
        recommended_focus_sector = variance_masked_sectors[0]
      elif dormant_awakening_sectors:
        recommended_focus_sector = dormant_awakening_sectors[0]
      elif subthreshold_sectors:
        recommended_focus_sector = subthreshold_sectors[0]

    return {
        "active_sectors": outlier_sectors,
        "subthreshold_sectors": subthreshold_sectors,
        "dormant_awakening_sectors": dormant_awakening_sectors,
        "variance_masked_sectors": variance_masked_sectors,
        "matched_killchain_archetypes": matched_archetypes,
        "companion_entities": companion_entities,
        "secondary_warranted": secondary_warranted,
        "warrant_reasons": warrant_reasons,
        "recommended_focus_sector": recommended_focus_sector,
    }

  @classmethod
  def score_hypothesis_confidence(
      cls,
      model_name: str,
      target_metric: Optional[str] = None,
      fusion_metrics: Optional[Sequence[str]] = None,
      outlier_vector: Optional[str] = None,
      ctx: Optional[Dict[str, Any]] = None,
      radar_result: Optional[Dict[str, Any]] = None,
      is_pivot: bool = False,
      prior_refuted: bool = False,
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
      llm_proposed_confidence: Optional[float] = None,
      target_entity_override: Optional[str] = None,
  ) -> Tuple[float, str, str]:
    """Computes an evidence-anchored confidence score [0.00 - 1.00], band, and breakdown string."""
    ctx = ctx or {}
    fusion_list = list(fusion_metrics or [])
    sig = cls.build_signature(model_name, target_metric, fusion_list, target_entity_override)

    if executed_signatures and sig in executed_signatures:
      return 0.0, "SUPPRESSED", "VETO (0.00): Hypothesis signature already executed in this investigation."

    primary_family = cls.infer_family(model_name, target_metric, fusion_list, outlier_vector)
    if empty_families and primary_family in empty_families:
      return 0.10, "SUPPRESSED", f"VETO (0.10): Prior query confirmed 0 telemetry records in `{primary_family}` family."

    score = 0.25  # Base prior for any structured hypothesis
    reasons: List[str] = ["Base(0.25)"]

    sector_z = (radar_result or {}).get("sector_z_scores", {})
    sector_obs = (radar_result or {}).get("sector_observed_counts", {})
    outlier_sectors = (radar_result or {}).get("outlier_sectors", [])
    subthreshold_sectors = (radar_result or {}).get("subthreshold_sectors", [])
    variance_masked = (radar_result or {}).get("variance_masked_sectors", [])
    dormant_awakening = (radar_result or {}).get("dormant_awakening_sectors", [])

    # 1. Tier 1 360° Spoke Magnitude Signal (+0.00 to +0.45)
    raw_z = sector_z.get(primary_family, sector_z.get(outlier_vector or "", None))
    if raw_z is None and outlier_vector and (primary_family == outlier_vector or not sector_z):
      raw_z = 2.5
    target_z = abs(float(raw_z or 0.0))
    if target_z >= 3.0:
      score += 0.45
      reasons.append(f"Tier1_{primary_family}_Z={target_z:+.2f}σ(+0.45)")
    elif target_z >= 2.0:
      score += 0.35
      reasons.append(f"Tier1_{primary_family}_Z={target_z:+.2f}σ(+0.35)")
    elif target_z >= 1.5:
      score += 0.20
      reasons.append(f"Tier1_{primary_family}_Z={target_z:+.2f}σ(+0.20)")
    elif target_z >= 1.25:
      score += 0.15
      reasons.append(f"Tier1_{primary_family}_SubThresholdZ={target_z:+.2f}σ(+0.15)")

    # Multi-Vector Fusion bonus when 2+ sectors are elevated in Tier 1
    if len(fusion_list) >= 2 and (len(outlier_sectors) >= 2 or len(outlier_sectors) + len(subthreshold_sectors) >= 2):
      score += 0.20
      elev_names = (list(outlier_sectors) + list(subthreshold_sectors))[:2]
      reasons.append(f"MultiSectorOutliers({','.join(elev_names)})(+0.20)")

    # Variance-Masked 4-Stage MAD bonus & Dormancy Awakening Two-Part Hurdle bonus
    m_up = (model_name or "").upper()
    if m_up == "MAD" and (primary_family in variance_masked or (outlier_vector and outlier_vector in variance_masked)):
      score += 0.25
      reasons.append(f"VarianceMaskedBaseline({primary_family})(+0.25)")
    if m_up in ("TWO_PART_HURDLE", "BAYESIAN_GAMMA", "POISSON") and (
        primary_family in dormant_awakening or (outlier_vector and outlier_vector in dormant_awakening)
    ):
      score += 0.25
      reasons.append(f"DormantBaselineAwakening({primary_family})(+0.25)")
    if target_entity_override:
      score += 0.20
      reasons.append(f"CrossEntityBridge({target_entity_override})(+0.20)")

    # 2. Case / Alert UDM Touchpoint Alignment (+0.00 to +0.35)
    fam_spec = cls.FAMILY_SIGNALS.get(primary_family, {})
    udm_events = set(ctx.get("udm_event_types", []))
    text_corpus = (
        f"{ctx.get('case_title', '')} "
        f"{ctx.get('case_description', '')} "
        f"{' '.join(ctx.get('alerts', []))} "
        f"{' '.join(ctx.get('rule_generators', []))} "
        f"{' '.join(ctx.get('threat_associations', []))}"
    ).lower()

    if udm_events and fam_spec.get("udm_events") and (udm_events & fam_spec["udm_events"]):
      score += 0.30
      matched_ev = next(iter(udm_events & fam_spec["udm_events"]))
      reasons.append(f"UDM_Event({matched_ev})(+0.30)")
    elif any(kw in text_corpus for kw in fam_spec.get("keywords", set())):
      score += 0.22
      reasons.append(f"AlertSignal({primary_family})(+0.22)")

    # 3. Epistemic Pivot Signal (+0.15 when prior Tier 2A refuted H1 OR confirmed an outlier warranting 2nd-order progression)
    if is_pivot and (target_z >= 2.0 or len(outlier_sectors) >= 1 or variance_masked or dormant_awakening):
      score += 0.15
      if prior_refuted:
        reasons.append("EpistemicRefutationPivot(+0.15)")
      else:
        reasons.append("ConfirmedOutlierProgressionPivot(+0.15)")

    # Blend modestly with LLM proposed confidence if provided, bounded by evidence
    if llm_proposed_confidence is not None:
      blended = (0.75 * score) + (0.25 * float(llm_proposed_confidence))
      score = blended

    # 4. Zero-Telemetry Dampener: If Tier 1 ran and observed 0 events in that spoke AND no UDM match
    if radar_result and primary_family in sector_obs and not target_entity_override:
      if sector_obs.get(primary_family, 0) == 0 and not (udm_events & fam_spec.get("udm_events", set())) and target_z < 1.0:
        if primary_family != "Endpoint":  # Endpoint isn't always a User 360 spoke
          score = min(score, 0.35)
          reasons.append(f"ZeroSpokeEventsCap({primary_family}=0->max 0.35)")

    score = round(min(0.98, max(0.05, score)), 2)
    auto_gate = cls.TIER_2B_PIVOT_AUTO_EXECUTE_THRESHOLD if is_pivot else cls.TIER_2A_AUTO_EXECUTE_THRESHOLD

    if score >= auto_gate:
      band = "AUTO_EXECUTE"
    elif score >= cls.ANALYST_REVIEW_MIN_THRESHOLD:
      band = "ANALYST_REVIEW"
    else:
      band = "SUPPRESSED"

    breakdown = f"Score {score:.2f} (Gate {auto_gate:.2f}): " + " + ".join(reasons)
    return score, band, breakdown

  @classmethod
  def format_hypothesis_for_avenue(cls, cand: CandidateHypothesis) -> str:
    """Formats a CandidateHypothesis into a rich markdown string for Case Wall presentation."""
    badge = (
        "🟢 AUTO-EXECUTED"
        if cand.confidence_band == "AUTO_EXECUTE"
        else ("🟡 HELD FOR ANALYST REVIEW" if cand.confidence_band == "ANALYST_REVIEW" else "⚪ LOW CONFIDENCE")
    )
    metric_tag = (
        f"Fusion({', '.join(cand.fusion_metrics)})"
        if cand.fusion_metrics
        else (f"Metric: `{cand.target_metric}`" if cand.target_metric else f"Engine: `{cand.selected_skill}`")
    )
    return (
        f"**[{cand.confidence_score:.2f}/1.00 {badge}]** `{cand.model_name}` ({metric_tag}) — **{cand.hypothesis_title}**\n"
        f"   - **Hypothesis ($H_1$ vs $H_0$)**: *$H_1$: {cand.hypothesis_h1} | $H_0$: {cand.hypothesis_h0}*\n"
        f"   - **Defense of Hypothesis**: {cand.evidentiary_defense}\n"
        f"   - **Confidence Audit**: `{cand.confidence_breakdown}`"
    )

  @classmethod
  def decide_tier1_360(
      cls,
      target_entity: str,
      entity_type: str = "USER",
      case_id: Optional[str] = None,
      case_title: str = "",
      case_desc: str = "",
      alerts: Optional[List[Dict[str, Any]]] = None,
  ) -> StrategyDirective:
    """Tier 1: Establishes a 6-spoke 360° multi-sector baseline across key entities."""
    return StrategyDirective(
        selected_skill="secops-risk-metrics-multistage",
        model_name="360_DECOUPLED_RADAR",
        directive_query="profile_360_risk",
        target_entity=target_entity,
        entity_type=entity_type,
        investigation_tier="TIER_1_BASELINE",
        confidence_score=0.95,
        confidence_band="AUTO_EXECUTE",
        confidence_breakdown="Score 0.95 (Mandatory Tier 1 6-Sector 30-Day Baseline Sweep)",
        evidentiary_defense=(
            f"Entity `{target_entity}` ({entity_type}) was extracted directly from case/alert telemetry. "
            "Executing a decoupled 6-spoke 30-day behavioral baseline (Auth, Cloud, Workspace, Egress, DNS, Web/Alerts) "
            "establishes objective sector Z-scores before committing to narrow secondary models."
        ),
        threat_summary=f"Establish 30-day 6-sector behavioral baseline for {entity_type} `{target_entity}` across canonical telemetry families.",
        hypothesis_h0=f"Activity for `{target_entity}` across all 6 canonical sectors conforms to historical 30-day operational baselines (|Z| < 2.0σ).",
        hypothesis_h1=f"Target entity `{target_entity}` exhibits statistically significant baseline drift (|Z| >= 2.0σ) in one or more behavioral sectors.",
        selection_rationale="Initial 6-spoke baseline establishes ground truth across orthogonal telemetry domains before executing confidence-gated Tier 2 deep dives.",
        flight_card_title=f"Tier 1 360° Behavioral Radar: `{target_entity}`",
        recommended_avenues=[
            "Evaluate all 6 sector Z-scores; automatically launch Tier 2 deep dive if any candidate hypothesis scores >= 0.75 confidence.",
            "If 2+ orthogonal sectors exceed |Z| >= 2.0σ, prioritize Cross-Vector or Roll-Up Sector Fusion (D = sqrt(Z_a^2 + Z_b^2)).",
            "Cross-reference observed sector volumes against approved change windows or scheduled batch workloads.",
        ],
    )

  @classmethod
  async def decide_tier2_deep_dive(
      cls,
      target_entity: str,
      entity_type: str,
      outlier_vector: str,
      case_info: Dict[str, Any],
      alerts: List[Dict[str, Any]],
      connector_events: List[Dict[str, Any]],
      radar_result: Optional[Dict[str, Any]] = None,
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
  ) -> StrategyDirective:
    """Tier 2A: Formulates confidence-scored deep dive (single metric, fusion, or micro-math) from 360° radar + alert context."""
    return await cls.decide_agentic(
        case_info=case_info,
        alerts=alerts,
        connector_events=connector_events,
        default_entity=target_entity,
        default_entity_type=entity_type,
        tier="TIER_2_DEEP_DIVE",
        outlier_vector=outlier_vector,
        radar_result=radar_result,
        executed_signatures=executed_signatures,
        empty_families=empty_families,
    )

  @classmethod
  def decide_tier2_pivot(
      cls,
      target_entity: str,
      entity_type: str,
      tier2a_directive: StrategyDirective,
      tier2a_result: Dict[str, Any],
      radar_result: Optional[Dict[str, Any]] = None,
      case_info: Optional[Dict[str, Any]] = None,
      alerts: Optional[List[Dict[str, Any]]] = None,
      connector_events: Optional[List[Dict[str, Any]]] = None,
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
      secondary_hunts_run: int = 1,
  ) -> Optional[StrategyDirective]:
    """Tier 2B Epistemic Pivot Reasoner: Evaluates Tier 2A outcome and sparks a high-confidence (>=0.80) pivot if warranted."""
    if secondary_hunts_run >= cls.MAX_SECONDARY_HUNTS:
      return None
    case_info = case_info or {}
    alerts = alerts or []
    connector_events = connector_events or []
    executed_signatures = executed_signatures or set()
    empty_families = empty_families or set()
    t2a_outlier = bool(tier2a_result.get("is_outlier", False))
    t2a_model = tier2a_directive.model_name
    t2a_metric = tier2a_directive.target_metric
    sector_z = (radar_result or {}).get("sector_z_scores", {})
    outlier_sectors = (radar_result or {}).get("outlier_sectors", [])
    sector_metrics = (radar_result or {}).get(
        "sector_metrics",
        cls.SECTOR_TO_METRIC_ASSET if entity_type.upper() in ("ASSET", "HOST", "IP") else cls.SECTOR_TO_METRIC_USER,
    )

    ctx = cls._build_context_summary(
        case_info=case_info,
        alerts=alerts,
        connector_events=connector_events,
        default_entity=target_entity,
        default_entity_type=entity_type,
        tier="TIER_2B_PIVOT",
        outlier_vector=tier2a_directive.outlier_vector,
        radar_result=radar_result,
    )
    radar_insights = ctx.get("radar_insights") or cls.analyze_360_insights(radar_result, ctx, entity_type)

    # Classify Tier 2A post-data outcome shape & MITRE progression (v1.9.1)
    stats_rows = int(tier2a_result.get("stats_rows", 0) or 0)
    active_sec = tier2a_directive.outlier_vector or (outlier_sectors[0] if outlier_sectors else "")
    if t2a_outlier:
      outcome_class = "FLEET_WAVE" if stats_rows >= 10 else "ACUTE_OUTLIER"
    elif active_sec in radar_insights.get("dormant_awakening_sectors", []):
      outcome_class = "SPARSE_BASELINE"
    else:
      outcome_class = "CLEAN_OR_SUBTHRESHOLD"
    tier2a_directive.post_data_outcome_class = outcome_class
    tier2a_directive.radar_insights = radar_insights

    candidates: List[CandidateHypothesis] = []

    # CASE A: 2+ sectors in Tier 1 are anomalous -> Propose Cross-Vector / Roll-Up Fusion!
    if len(outlier_sectors) >= 2 and "FUSION" not in t2a_model and "KILLCHAIN" not in t2a_model:
      sec_a, sec_b = outlier_sectors[0], outlier_sectors[1]
      m_a = sector_metrics.get(sec_a, "workspace_total_download_actions")
      m_b = sector_metrics.get(sec_b, "network_bytes_outbound")
      z_a_val = sector_z.get(sec_a, 0.0)
      z_b_val = sector_z.get(sec_b, 0.0)
      pivot_why = (
          f"Tier 2A (`{t2a_model}`) evaluated `{sec_a}` in isolation, while Tier 1 360° Radar simultaneously flagged "
          f"orthogonal sector `{sec_b}` (Z = {z_b_val:+.2f}σ) alongside `{sec_a}` (Z = {z_a_val:+.2f}σ). "
          f"Fusing `{m_a}` and `{m_b}` tests whether these two anomalies form a single multi-stage kill chain."
      )
      score, band, breakdown = cls.score_hypothesis_confidence(
          model_name="DUAL_SECTOR_FUSION_3STAGE",
          fusion_metrics=[m_a, m_b],
          outlier_vector=sec_a,
          ctx=ctx,
          radar_result=radar_result,
          is_pivot=True,
          prior_refuted=not t2a_outlier,
          executed_signatures=executed_signatures,
          empty_families=empty_families,
      )
      candidates.append(
          CandidateHypothesis(
              hypothesis_title=f"Cross-Vector Fusion: {sec_a} (`{m_a}`) × {sec_b} (`{m_b}`)",
              selected_skill="secops-risk-metrics-multistage",
              model_name="DUAL_SECTOR_FUSION_3STAGE",
              directive_query="sector_fusion",
              target_metric=m_a,
              fusion_metrics=[m_a, m_b],
              hypothesis_h0=f"Concurrent elevations in `{m_a}` and `{m_b}` are independent benign operational fluctuations.",
              hypothesis_h1=f"Entity `{target_entity}` is executing a coupled multi-sector attack chain across `{m_a}` and `{m_b}` (D >= 3.0σ).",
              evidentiary_defense=pivot_why,
              confidence_score=score,
              confidence_band=band,
              confidence_breakdown=breakdown,
              pivot_reason=pivot_why,
          )
      )

    # CASE A2: Matched MITRE ATT&CK Kill-Chain Archetype across active + sub-threshold sectors
    matched_archs = radar_insights.get("matched_killchain_archetypes", [])
    if matched_archs and len(outlier_sectors) < 2 and "KILLCHAIN" not in t2a_model and "FUSION" not in t2a_model:
      top_arch = matched_archs[0]
      arch_id = top_arch["archetype"]
      f_metrics = top_arch["fusion_metrics"]
      if arch_id != "WORKSPACE_HOARDING_TO_EGRESS":
        pivot_why = (
            f"360° Radar topology matched MITRE ATT&CK kill-chain `{arch_id}` ({' -> '.join(top_arch['tactics'])}) "
            f"across `{', '.join(top_arch['sectors'])}`. Executing multi-stage kill-chain fusion on `{f_metrics[0]}` + `{f_metrics[1]}`."
        )
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name=f"KILLCHAIN_{arch_id}",
            target_metric=f_metrics[0],
            fusion_metrics=f_metrics,
            outlier_vector=active_sec,
            ctx=ctx,
            radar_result=radar_result,
            is_pivot=True,
            prior_refuted=not t2a_outlier,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
        )
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"MITRE ATT&CK Kill-Chain Progression: `{arch_id}`",
                selected_skill="secops-risk-metrics-multistage",
                model_name=f"KILLCHAIN_{arch_id}",
                directive_query="killchain_archetype",
                target_metric=f_metrics[0],
                fusion_metrics=f_metrics,
                killchain_archetype=arch_id,
                hypothesis_h0=f"Sub-threshold activity across {', '.join(top_arch['sectors'])} is uncorrelated background noise.",
                hypothesis_h1=f"Entity `{target_entity}` is progressing along MITRE ATT&CK kill-chain `{arch_id}`.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

    # CASE B: Tier 2A CONFIRMED an outlier (ACUTE_OUTLIER) -> Perform Second-Order Verification / Kill-Chain Progression!
    if t2a_outlier:
      # B-Conf-1: Confirmed Workspace Download Surge -> Pivot to Workspace Exfiltration Triad (Downloads + Changes + Emails vs Peer Cohort)
      if active_sec == "Workspace" and t2a_model != "PART_OF_THE_WHOLE_TRIAD_MULTILEVEL":
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) confirmed an acute Workspace anomaly on `{target_entity}`. "
            "Pivoting to `PART_OF_THE_WHOLE_TRIAD_MULTILEVEL` verifies whether the user is simultaneously staging document modifications "
            "(`workspace_total_change_actions`) and outbound emails (`workspace_emails_sent`) relative to their enterprise peer cohort."
        )
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name="PART_OF_THE_WHOLE_TRIAD_MULTILEVEL",
            target_metric="workspace_total_download_actions",
            fusion_metrics=[
                "workspace_total_download_actions",
                "workspace_total_change_actions",
                "workspace_emails_sent",
            ],
            outlier_vector="Workspace",
            ctx=ctx,
            radar_result=radar_result,
            is_pivot=True,
            prior_refuted=False,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
        )
        candidates.append(
            CandidateHypothesis(
                hypothesis_title="Workspace Exfiltration Triad vs Peer Cohort (Download + Change + Email)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="PART_OF_THE_WHOLE_TRIAD_MULTILEVEL",
                directive_query="workspace_triad",
                target_metric="workspace_total_download_actions",
                fusion_metrics=[
                    "workspace_total_download_actions",
                    "workspace_total_change_actions",
                    "workspace_emails_sent",
                ],
                hypothesis_h0="Confirmed download spike is an isolated administrative backup shared by the team cohort.",
                hypothesis_h1=f"User `{target_entity}` exhibits a coupled Workspace exfiltration triad departing from peer cohort norms.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # B-Conf-2: Confirmed Cloud CRUD Surge -> Pivot to Cloud Repository Scope & Caller IP Attribution
      elif active_sec == "Cloud" and t2a_model != "CLOUD_REPOSITORY_SCOPE":
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) confirmed a Cloud CRUD surge on `{target_entity}`. "
            "Pivoting to `CLOUD_REPOSITORY_SCOPE` attributes the exact target cloud resource (`target.resource.name`) and origin caller IP (`principal.ip`)."
        )
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name="CLOUD_REPOSITORY_SCOPE",
            target_metric="resource_read_total",
            outlier_vector="Cloud",
            ctx=ctx,
            radar_result=radar_result,
            is_pivot=True,
            prior_refuted=False,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
        )
        candidates.append(
            CandidateHypothesis(
                hypothesis_title="Cloud Repository Scope & Caller IP Attribution (`cloud_repository_scope_dual_branch`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="CLOUD_REPOSITORY_SCOPE",
                directive_query="cloud_repo_scope",
                target_metric="resource_read_total",
                outcome_mode="total",
                hypothesis_h0="Cloud CRUD surge targets standard CI/CD deployment buckets from known corporate IPs.",
                hypothesis_h1=f"Identity `{target_entity}` is accessing sensitive cloud repositories from an anomalous caller IP.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # B-Conf-3: Confirmed Egress / DNS / Web Outlier -> Pivot to Rare Destination Entity Context Graph Verification
      elif active_sec in ("Egress", "DNS", "Web") and "RARE_DESTINATION" not in t2a_model and "DOMAIN_PREVALENCE" not in t2a_model:
        ecg_model = (
            "HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE"
            if active_sec == "Web"
            else "RARE_DESTINATION_ECG_3STAGE"
        )
        ecg_metric = (
            "http_queries_total"
            if active_sec == "Web"
            else ("dns_queries_total" if active_sec == "DNS" else "network_bytes_outbound")
        )
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) confirmed an outlier in `{active_sec}`. "
            f"Pivoting to `{ecg_model}` enriches the confirmed behavioral surge with Entity Context Graph `DERIVED_CONTEXT` "
            "to verify whether the destination domains/IPs have ultra-low enterprise fleet prevalence (`day_max <= 3`)."
        )
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name=ecg_model,
            target_metric=ecg_metric,
            outlier_vector=active_sec,
            ctx=ctx,
            radar_result=radar_result,
            is_pivot=True,
            prior_refuted=False,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
        )
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"Rare Destination Entity Graph Verification (`{ecg_model}`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name=ecg_model,
                directive_query="dynamic_metric",
                target_metric=ecg_metric,
                hypothesis_h0="Confirmed network/DNS/web surge communicates with established high-prevalence enterprise infrastructure.",
                hypothesis_h1=f"Confirmed `{active_sec}` outlier on `{target_entity}` is contacting rare external C2/exfiltration destinations (`day_max <= 3`).",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # B-Conf-4: Confirmed Auth Outlier -> Pivot to Brute-Force-to-Compromise Dual-Sector Fusion (auth_attempts_fail + auth_attempts_success)
      elif active_sec == "Auth" and "FUSION" not in t2a_model:
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) confirmed an authentication anomaly on `{target_entity}`. "
            "Pivoting to `DUAL_SECTOR_FUSION_3STAGE` across `auth_attempts_fail` and `auth_attempts_success` verifies "
            "whether the credential attack culminated in a successful authentication breach (MITRE T1110 -> T1078)."
        )
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name="DUAL_SECTOR_FUSION_3STAGE",
            target_metric="auth_attempts_fail",
            fusion_metrics=["auth_attempts_fail", "auth_attempts_success"],
            outlier_vector="Auth",
            ctx=ctx,
            radar_result=radar_result,
            is_pivot=True,
            prior_refuted=False,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
        )
        candidates.append(
            CandidateHypothesis(
                hypothesis_title="Credential Attack Breach Verification (`auth_attempts_fail` × `auth_attempts_success`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="DUAL_SECTOR_FUSION_3STAGE",
                directive_query="sector_fusion",
                target_metric="auth_attempts_fail",
                fusion_metrics=["auth_attempts_fail", "auth_attempts_success"],
                hypothesis_h0="Authentication failures were blocked by IAM controls without any successful login breach.",
                hypothesis_h1=f"Credential attack on `{target_entity}` was followed by an anomalous surge in successful logins (`auth_attempts_success`).",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # B-Conf-5: Confirmed Alerts / Endpoint Outlier -> Pivot to MITRE Kill-Chain Execution/Alert-to-Exfiltration
      elif active_sec in ("Alerts", "Endpoint", "Flows") and "KILLCHAIN" not in t2a_model:
        kc_arch = (
            "DEFENSE_EVASION_ALERT_TO_EXFILTRATION"
            if active_sec == "Alerts"
            else "EXECUTION_TO_EXFILTRATION"
        )
        kc_metrics = (
            ["alert_event_name_count", "network_bytes_outbound"]
            if active_sec == "Alerts"
            else ["file_executions_total", "network_bytes_outbound"]
        )
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) confirmed an endpoint/alert anomaly on `{target_entity}`. "
            f"Pivoting to MITRE Kill-Chain `{kc_arch}` tests whether the endpoint execution/alert surge triggered outbound data exfiltration."
        )
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name=f"KILLCHAIN_{kc_arch}",
            target_metric=kc_metrics[0],
            fusion_metrics=kc_metrics,
            outlier_vector=active_sec,
            ctx=ctx,
            radar_result=radar_result,
            is_pivot=True,
            prior_refuted=False,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
        )
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"MITRE Kill-Chain Progression: `{kc_arch}`",
                selected_skill="secops-risk-metrics-multistage",
                model_name=f"KILLCHAIN_{kc_arch}",
                directive_query="killchain_archetype",
                target_metric=kc_metrics[0],
                fusion_metrics=kc_metrics,
                killchain_archetype=kc_arch,
                hypothesis_h0="Confirmed endpoint/alert activity remained local with no outbound network exfiltration.",
                hypothesis_h1=f"Endpoint anomaly on `{target_entity}` progressed to outbound data exfiltration (`network_bytes_outbound`).",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

    # CASE C: Tier 2A REFUTED H1 (is_outlier == False), but an active sector anomaly, variance-masked drift, or UDM signal remains unexplained!
    if not t2a_outlier:
      active_z = abs(float(sector_z.get(active_sec, 0.0)))
      variance_masked = radar_insights.get("variance_masked_sectors", [])
      dormant_awakening = radar_insights.get("dormant_awakening_sectors", [])

      # C1: If C2_BEACONING_JITTER refuted periodic beaconing on an Egress spike -> Pivot to MACD_MOMENTUM_VELOCITY or ELEPHANT_FLOW
      if t2a_model == "C2_BEACONING_JITTER" and (active_z >= 2.0 or "Egress" in outlier_sectors):
        pivot_why = (
            f"Tier 2A (`C2_BEACONING_JITTER`) returned high timing jitter (`NOMINAL`), refuting periodic robotic C2 polling. "
            f"However, Tier 1 `Egress` volume remains anomalous (Z = {sector_z.get('Egress', active_z):+.2f}σ). "
            "Ruling out periodic beaconing implies the outbound spike is an acute bulk transfer or kinetic surge; "
            "pivoting to `MACD_MOMENTUM_VELOCITY` on `network_bytes_outbound` tests for rapid exfiltration acceleration."
        )
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name="MACD_MOMENTUM_VELOCITY",
            target_metric="network_bytes_outbound",
            outlier_vector="Egress",
            ctx=ctx,
            radar_result=radar_result,
            is_pivot=True,
            prior_refuted=True,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
        )
        candidates.append(
            CandidateHypothesis(
                hypothesis_title="Bulk Egress Acceleration (MACD Dual-Spine Velocity)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="MACD_MOMENTUM_VELOCITY",
                directive_query="macd_momentum",
                target_metric="network_bytes_outbound",
                hypothesis_h0="Outbound byte volume reflects normal background workload variance.",
                hypothesis_h1="Non-periodic outbound volume surge is driven by acute bulk data staging and exfiltration acceleration.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # C2: If POISSON_BURST_CLUSTERING refuted credential spray on an Auth spike -> Pivot to CIRCADIAN_VON_MISES on auth_attempts_total
      if t2a_model == "POISSON_BURST_CLUSTERING" and (active_z >= 2.0 or "Auth" in outlier_sectors):
        pivot_why = (
            f"Tier 2A (`POISSON_BURST_CLUSTERING`) found no high-frequency Fano burst dispersion, ruling out automated brute-force spraying. "
            f"Because Tier 1 `Auth` telemetry is still elevated (Z = {sector_z.get('Auth', active_z):+.2f}σ), "
            "pivoting to `CIRCADIAN_VON_MISES` tests whether valid or semi-valid credentials are being used at anomalous off-hours angles."
        )
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name="CIRCADIAN_VON_MISES",
            target_metric="auth_attempts_total",
            outlier_vector="Auth",
            ctx=ctx,
            radar_result=radar_result,
            is_pivot=True,
            prior_refuted=True,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
        )
        candidates.append(
            CandidateHypothesis(
                hypothesis_title="Off-Hours Identity Access (Circadian von Mises Departure)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="CIRCADIAN_VON_MISES",
                directive_query="circadian_von_mises",
                target_metric="auth_attempts_total",
                hypothesis_h0="Authentication events align with the user's normal diurnal operating schedule.",
                hypothesis_h1="Compromised credentials or hijacked sessions are authenticating during anomalous circadian hours.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # C3: If another anomalous sector exists in Tier 1 that wasn't the primary vector of Tier 2A
      for sec in outlier_sectors:
        if sec != active_sec:
          sec_metric = sector_metrics.get(sec, "http_queries_total")
          sec_z = sector_z.get(sec, 0.0)
          pivot_why = (
              f"Tier 2A (`{t2a_model}`) did not confirm $H_1$ on `{active_sec}`, but Tier 1 360° Radar identified a "
              f"separate significant anomaly in `{sec}` (Z = {sec_z:+.2f}σ on `{sec_metric}`). "
              f"Pivoting to `LONGITUDINAL_CUSUM_DRIFT` on `{sec_metric}` directly evaluates this uninvestigated outlier vector."
          )
          score, band, breakdown = cls.score_hypothesis_confidence(
              model_name="LONGITUDINAL_CUSUM_DRIFT",
              target_metric=sec_metric,
              outlier_vector=sec,
              ctx=ctx,
              radar_result=radar_result,
              is_pivot=True,
              prior_refuted=True,
              executed_signatures=executed_signatures,
              empty_families=empty_families,
          )
          candidates.append(
              CandidateHypothesis(
                  hypothesis_title=f"Secondary Outlier Sweep: {sec} (`{sec_metric}`)",
                  selected_skill="secops-risk-metrics-multistage",
                  model_name="LONGITUDINAL_CUSUM_DRIFT",
                  directive_query="dynamic_metric",
                  target_metric=sec_metric,
                  hypothesis_h0=f"Elevated `{sec_metric}` count reflects routine operational workload.",
                  hypothesis_h1=f"Sustained cumulative drift in `{sec_metric}` (Z = {sec_z:+.2f}σ) indicates unauthorized activity.",
                  evidentiary_defense=pivot_why,
                  confidence_score=score,
                  confidence_band=band,
                  confidence_breakdown=breakdown,
                  pivot_reason=pivot_why,
              )
          )

      # C4: If CLOUD_CRUD_SURGE on total volume was refuted -> Pivot to CLOUD_REPOSITORY_SCOPE (outcome_mode="fail") for Access-Denied Recon
      if t2a_model == "CLOUD_CRUD_SURGE" or (active_sec == "Cloud" and t2a_model != "CLOUD_REPOSITORY_SCOPE"):
        pivot_why = (
            f"Tier 2A (`{t2a_model}`) did not find a total-volume CRUD breach on `{target_entity}`. "
            "Pivoting to `CLOUD_REPOSITORY_SCOPE` in `fail` mode (`resource_*_fail`) tests whether the identity triggered "
            "Access-Denied reconnaissance spikes against restricted cloud repositories that were diluted in total CRUD counts."
        )
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name="CLOUD_REPOSITORY_SCOPE",
            target_metric="resource_read_fail",
            outlier_vector="Cloud",
            ctx=ctx,
            radar_result=radar_result,
            is_pivot=True,
            prior_refuted=True,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
        )
        candidates.append(
            CandidateHypothesis(
                hypothesis_title="Cloud Access-Denied Reconnaissance (`CLOUD_REPOSITORY_SCOPE` fail mode)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="CLOUD_REPOSITORY_SCOPE",
                directive_query="cloud_repo_scope",
                target_metric="resource_read_fail",
                outcome_mode="fail",
                hypothesis_h0="Cloud access failures reflect benign misconfigured IAM bindings.",
                hypothesis_h1=f"Identity `{target_entity}` is enumerating restricted cloud repositories, generating anomalous `resource_*_fail` spikes.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # C5: Parametric Model Refuted on Variance-Masked or Elevated Sector -> Pivot to True 4-Stage Non-Parametric MAD!
      if t2a_model in ("MACD_MOMENTUM_VELOCITY", "LONGITUDINAL_CUSUM_DRIFT", "STANDARD_Z_SCORE", "CIRCADIAN_VON_MISES") and (
          active_sec in variance_masked or active_z >= 2.0
      ):
        mad_metric = t2a_metric or sector_metrics.get(active_sec, "network_bytes_outbound")
        pivot_why = (
            f"Parametric Tier 2A model (`{t2a_model}`) returned sub-threshold results on `{mad_metric}`. "
            "When historical bursts pollute the 30-day standard deviation (`stddev`), parametric Z-scores are compressed. "
            f"Pivoting to 4-Stage Non-Parametric `MAD` (`mad_robust_z_4stage.yl2`) scores `{mad_metric}` against the 30-day median and MAD scale (`$modified_z`) to unmask variance-suppressed outliers."
        )
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name="MAD",
            target_metric=mad_metric,
            outlier_vector=active_sec,
            ctx=ctx,
            radar_result=radar_result,
            is_pivot=True,
            prior_refuted=True,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
        )
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"Variance-Resistant 4-Stage Non-Parametric MAD (`{mad_metric}`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="MAD",
                directive_query="dynamic_metric",
                target_metric=mad_metric,
                hypothesis_h0=f"Observed `{mad_metric}` volume is within normal median absolute deviation bounds (`$modified_z < 3.5`).",
                hypothesis_h1=f"Prior 30-day bursts inflated parametric `stddev` on `{mad_metric}`, masking a true median-anchored outlier (`$modified_z >= 3.5`).",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

      # C6: Dormant / Sparse Baseline Sector -> Pivot to TWO_PART_HURDLE
      if active_sec in dormant_awakening and t2a_model != "TWO_PART_HURDLE":
        hurdle_metric = t2a_metric or sector_metrics.get(active_sec, "resource_creation_total")
        pivot_why = (
            f"360° Radar indicates `{active_sec}` (`{hurdle_metric}`) has a near-zero 30-day baseline mean (`SPARSE_BASELINE`). "
            "Pivoting to `TWO_PART_HURDLE` evaluates the Bernoulli probability of dormancy awakening ($P(\\text{active}) < 0.10$) alongside conditional intensity."
        )
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name="TWO_PART_HURDLE",
            target_metric=hurdle_metric,
            outlier_vector=active_sec,
            ctx=ctx,
            radar_result=radar_result,
            is_pivot=True,
            prior_refuted=True,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
        )
        candidates.append(
            CandidateHypothesis(
                hypothesis_title=f"Dormancy Awakening Two-Part Hurdle (`{hurdle_metric}`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="TWO_PART_HURDLE",
                directive_query="dynamic_metric",
                target_metric=hurdle_metric,
                hypothesis_h0=f"Sparse activity in `{hurdle_metric}` reflects normal periodic maintenance.",
                hypothesis_h1=f"Dormant baseline break on `{target_entity}` in `{hurdle_metric}` violates historical activation probability.",
                evidentiary_defense=pivot_why,
                confidence_score=score,
                confidence_band=band,
                confidence_breakdown=breakdown,
                pivot_reason=pivot_why,
            )
        )

    # CASE D: Cross-Entity Kill-Chain Bridge when companion entities (USER <-> ASSET/IP) exist in Case Telemetry
    for comp in radar_insights.get("companion_entities", [])[:1]:
      comp_ent = comp["entity"]
      comp_type = comp["entity_type"]
      bridge_path = comp["bridge_path"]
      if comp_type in ("ASSET", "HOST", "IP"):
        bridge_model = "ZIPFIAN_PROCESS_RARITY"
        bridge_skill = "secops-statistical-hunter"
        bridge_query = "zipfian_rarity"
        bridge_metric = "file_executions_total"
      else:
        bridge_model = "CLOUD_REPOSITORY_SCOPE"
        bridge_skill = "secops-risk-metrics-multistage"
        bridge_query = "cloud_repo_scope"
        bridge_metric = "resource_read_total"
      pivot_why = (
          f"Case telemetry links primary {entity_type} `{target_entity}` to companion {comp_type} `{comp_ent}` (`{bridge_path}`). "
          f"Bridging the UEBA investigation across the entity boundary to `{comp_ent}` tests for multi-stage lateral/execution progression."
      )
      score, band, breakdown = cls.score_hypothesis_confidence(
          model_name=bridge_model,
          target_metric=bridge_metric,
          outlier_vector=active_sec,
          ctx=ctx,
          radar_result=radar_result,
          is_pivot=True,
          prior_refuted=not t2a_outlier,
          executed_signatures=executed_signatures,
          empty_families=empty_families,
          target_entity_override=comp_ent,
      )
      candidates.append(
          CandidateHypothesis(
              hypothesis_title=f"Cross-Entity Kill-Chain Bridge (`{bridge_path}` -> `{comp_ent}`)",
              selected_skill=bridge_skill,
              model_name=bridge_model,
              directive_query=bridge_query,
              target_entity=comp_ent,
              entity_type=comp_type,
              target_metric=bridge_metric,
              hypothesis_h0=f"Companion {comp_type} `{comp_ent}` exhibits only routine baseline operations.",
              hypothesis_h1=f"Attack chain bridged from `{target_entity}` to companion {comp_type} `{comp_ent}` via `{bridge_path}`.",
              evidentiary_defense=pivot_why,
              confidence_score=score,
              confidence_band=band,
              confidence_breakdown=breakdown,
              pivot_reason=pivot_why,
          )
      )

    if not candidates:
      return None

    candidates.sort(key=lambda c: c.confidence_score, reverse=True)
    top = candidates[0]

    # Attach remaining candidates to tier2a_directive so they appear on the Case Wall even if < 0.80
    for c in candidates:
      if c.confidence_band != "SUPPRESSED":
        tier2a_directive.candidate_hypotheses.append(c)
        formatted = cls.format_hypothesis_for_avenue(c)
        if formatted not in tier2a_directive.recommended_avenues:
          tier2a_directive.recommended_avenues.insert(0, formatted)

    if top.confidence_score < cls.TIER_2B_PIVOT_AUTO_EXECUTE_THRESHOLD:
      return None

    remaining = [c for c in candidates[1:] if c.confidence_band != "SUPPRESSED"]
    piv_entity = top.target_entity or target_entity
    piv_entity_type = top.entity_type or entity_type
    return StrategyDirective(
        selected_skill=top.selected_skill,
        model_name=top.model_name,
        directive_query=top.directive_query,
        target_entity=piv_entity,
        entity_type=piv_entity_type,
        target_metric=top.target_metric,
        fusion_metrics=list(top.fusion_metrics),
        killchain_archetype=top.killchain_archetype,
        outcome_mode=top.outcome_mode,
        identifier_field=top.identifier_field,
        threat_summary=top.hypothesis_title,
        hypothesis_h0=top.hypothesis_h0,
        hypothesis_h1=top.hypothesis_h1,
        selection_rationale=top.evidentiary_defense,
        evidentiary_defense=top.evidentiary_defense,
        confidence_score=top.confidence_score,
        confidence_band=top.confidence_band,
        confidence_breakdown=top.confidence_breakdown,
        pivot_reason=top.pivot_reason,
        flight_card_title=f"Tier 2B Autonomous Pivot — {top.hypothesis_title}: `{piv_entity}`",
        investigation_tier="TIER_2B_PIVOT",
        outlier_vector=tier2a_directive.outlier_vector,
        radar_insights=radar_insights,
        post_data_outcome_class=outcome_class,
        candidate_hypotheses=remaining,
        recommended_avenues=[cls.format_hypothesis_for_avenue(c) for c in remaining] or [
            f"Correlate `{piv_entity}` pivot findings with endpoint EDR and identity session logs.",
        ],
    )

  @classmethod
  def _build_context_summary(
      cls,
      case_info: Dict[str, Any],
      alerts: List[Dict[str, Any]],
      connector_events: List[Dict[str, Any]],
      default_entity: Optional[str] = None,
      default_entity_type: str = "USER",
      tier: str = "TIER_1_BASELINE",
      outlier_vector: Optional[str] = None,
      radar_result: Optional[Dict[str, Any]] = None,
  ) -> Dict[str, Any]:
    """Extracts structured UDM touchpoints from case, alerts, and connector events."""
    case_title = case_info.get("displayName") or case_info.get("title", "")
    case_desc = case_info.get("description", "")
    case_id = str(case_info.get("id") or case_info.get("name", "").split("/")[-1])

    alert_names = [a.get("displayName") or a.get("name", "") for a in alerts]
    rule_generators = [a.get("ruleGenerator", "") for a in alerts if a.get("ruleGenerator")]
    for a in alerts:
      if a.get("description") and a.get("description") not in case_desc:
        case_desc = f"{case_desc} {a.get('description')}".strip()

    udm_event_types = set()
    udm_log_types = set()
    target_apps = set()
    threat_associations = set()
    extracted_users = set()
    extracted_hosts = set()
    extracted_ips = set()
    outcome_metrics = {}

    for ev in connector_events:
      raw_str = ev.get("eventJsonData", {}).get("rawEvent") or "{}"
      try:
        raw_obj = json.loads(raw_str) if isinstance(raw_str, str) else raw_str
      except Exception:
        raw_obj = {}

      fields = raw_obj.get("_rawDataFields", {}) if isinstance(raw_obj, dict) else {}
      if fields.get("event_metadata_eventType"):
        udm_event_types.add(fields.get("event_metadata_eventType"))
      if fields.get("event_metadata_logType"):
        udm_log_types.add(fields.get("event_metadata_logType"))
      if fields.get("event_target_application"):
        target_apps.add(fields.get("event_target_application"))

      for k, v in fields.items():
        if "threat" in k and "name" in k and v:
          threat_associations.add(str(v))
        if "detection_outcomes" in k and v:
          short_k = k.replace("detection_outcomes_", "")
          outcome_metrics[short_k] = str(v)

      u = fields.get("event_target_user_emailAddresses_1") or fields.get("event_principal_user_userid")
      if u:
        extracted_users.add(str(u).lower())

      h = fields.get("event_principal_hostname") or fields.get("event_principal_asset_hostname")
      if h:
        extracted_hosts.add(str(h).lower())

      ip = fields.get("event_principal_asset_ip_1") or fields.get("event_principal_ip_1")
      if ip:
        extracted_ips.add(str(ip))

    for a in alerts:
      for ent in a.get("entities", []) or []:
        if isinstance(ent, dict):
          etype = str(ent.get("type") or ent.get("entityType") or "").upper()
          val = str(ent.get("value") or ent.get("identifier") or ent.get("name") or "").strip()
          if not val:
            continue
          if etype in ("USER", "USER_ID", "EMAIL"):
            extracted_users.add(val.lower())
          elif etype in ("ASSET", "HOST", "HOSTNAME", "MACHINE"):
            extracted_hosts.add(val.lower())
          elif etype in ("IP", "IP_ADDRESS"):
            extracted_ips.add(val)

    target_entity = default_entity
    entity_type = default_entity_type
    if not target_entity:
      if extracted_users:
        target_entity = next(iter(extracted_users))
        entity_type = "USER"
      elif extracted_hosts:
        target_entity = next(iter(extracted_hosts))
        entity_type = "ASSET"
      elif extracted_ips:
        target_entity = next(iter(extracted_ips))
        entity_type = "IP"
      else:
        target_entity = "unknown_entity"
        entity_type = "USER"

    base_ctx = {
        "case_id": case_id,
        "case_title": case_title,
        "case_description": case_desc,
        "alerts": alert_names,
        "rule_generators": rule_generators,
        "udm_event_types": list(udm_event_types),
        "udm_log_types": list(udm_log_types),
        "target_applications": list(target_apps),
        "threat_associations": list(threat_associations),
        "outcome_metrics": outcome_metrics,
        "extracted_users": sorted(extracted_users),
        "extracted_hosts": sorted(extracted_hosts),
        "extracted_ips": sorted(extracted_ips),
        "primary_entity": target_entity,
        "entity_type": entity_type,
        "investigation_tier": tier,
        "outlier_vector": outlier_vector,
        "radar_result": radar_result,
    }
    if radar_result:
      base_ctx["radar_insights"] = cls.analyze_360_insights(
          radar_result=radar_result,
          ctx=base_ctx,
          entity_type=entity_type,
      )
    return base_ctx

  @classmethod
  async def decide_agentic(
      cls,
      case_info: Dict[str, Any],
      alerts: List[Dict[str, Any]],
      connector_events: List[Dict[str, Any]],
      default_entity: Optional[str] = None,
      default_entity_type: str = "USER",
      tier: str = "TIER_1_BASELINE",
      outlier_vector: Optional[str] = None,
      radar_result: Optional[Dict[str, Any]] = None,
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
  ) -> StrategyDirective:
    """Agentically analyzes case, alert, 360° radar, and UDM telemetry to formulate a defended hunting directive."""
    context_summary = cls._build_context_summary(
        case_info=case_info,
        alerts=alerts,
        connector_events=connector_events,
        default_entity=default_entity,
        default_entity_type=default_entity_type,
        tier=tier,
        outlier_vector=outlier_vector,
        radar_result=radar_result,
    )

    if tier == "TIER_1_BASELINE" and not outlier_vector:
      return cls.decide_tier1_360(
          target_entity=context_summary["primary_entity"],
          entity_type=context_summary["entity_type"],
          case_id=context_summary["case_id"],
          case_title=context_summary["case_title"],
          case_desc=context_summary["case_description"],
          alerts=alerts,
      )

    # 1. Attempt LLM Reasoning via Gemini 2.5 with v1.8.0 Metric Catalog & Confidence Rubric
    llm_directive = await cls._reason_with_gemini(
        context_summary,
        executed_signatures=executed_signatures,
        empty_families=empty_families,
    )
    if llm_directive:
      return llm_directive

    # 2. Deterministic Fallback Reasoner (UDM-aware, v1.8.0 catalog-aware, confidence-calibrated)
    return cls._deterministic_reasoner(
        context_summary,
        executed_signatures=executed_signatures,
        empty_families=empty_families,
    )

  @classmethod
  async def _reason_with_gemini(
      cls,
      ctx: Dict[str, Any],
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
  ) -> Optional[StrategyDirective]:
    """Uses Gemini to reason about UDM touchpoints, select situational metrics/fusions, and defend hypotheses."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
      return None

    try:
      client = genai.Client()
      prompt = f"""You are a Lead SecOps Detection Engineer and UEBA Threat Hunter.
Analyze the following security incident context, alerts, Tier 1 360° radar results, and UDM connector event touchpoints:

{json.dumps(ctx, indent=2)}

Already Executed Signatures (DO NOT REPEAT): {list(executed_signatures or [])}
Empty Telemetry Families (DO NOT SELECT): {list(empty_families or [])}

### POSITIVE SITUATIONAL METRIC SELECTION (v1.8.0 38-Metric Malachite Catalog)
Choose the metric(s) that match the actual situation in the case and Tier 1 360° radar — do NOT default to auth or network if the signal is in Workspace, Web/HTTP, DNS, Cloud CRUD, Endpoint Process Execution, or Security/EDR Alerts:
- **Workspace / SaaS (`principal.user.userid`)**: `workspace_total_download_actions`, `workspace_total_change_actions`, `workspace_emails_sent_total`, `workspace_network_bytes_outbound`, `workspace_auth_attempts_total`
- **Web & HTTP Proxy (`principal.user.userid` or `principal.asset.hostname`)**: `http_queries_total`, `http_queries_fail`, `http_queries_success`
- **DNS Resolution (`principal.user.userid` or `principal.asset.hostname`)**: `dns_queries_fail`, `dns_queries_total`, `dns_queries_success`, `dns_bytes_outbound`
- **Network Bytes & Flows (`principal.user.userid` or `principal.asset.hostname`)**: `network_bytes_outbound`, `network_bytes_inbound`, `network_bytes_total`, `network_flows_outbound`, `network_flows_inbound`, `network_flows_total`
- **Authentication (`target.user.userid` or `principal.asset.hostname`)**: `auth_attempts_fail`, `auth_attempts_success`, `auth_attempts_total`
- **Cloud Resource CRUD (Composite roll-up, `principal.user.userid`)**: `resource_creation_total`, `resource_deletion_total`, `resource_written_total`, `resource_read_total`
- **Endpoint Process Executions (Composite roll-up, `principal.asset.hostname`)**: `file_executions_total`, `file_executions_fail`
- **Security / EDR Alerts (Composite roll-up, `principal.asset.hostname`)**: `alert_event_name_count`

### Available Analytical Engines & Models with "Use When..." Guidance:
1. **Engine: `secops-risk-metrics-multistage` (30-Day Baselines, Dynamic Single-Metric & Cross-Vector Fusion DAGs)**
   - `DUAL_SECTOR_FUSION_3STAGE` / `MULTI_SECTOR_FUSION_4STAGE` (`directive_query`: `"sector_fusion"`): Use when **2+ sectors** in the Tier 1 360° radar are elevated (|Z| >= 1.5σ) OR when the case bridges two behavioral vectors (e.g. `workspace_total_download_actions` + `network_bytes_outbound`, `file_executions_total` + `dns_queries_fail`, `alert_event_name_count` + `http_queries_total`). Populate `fusion_metrics: ["<metric_a>", "<metric_b>"]`.
   - `LONGITUDINAL_CUSUM_DRIFT` (`directive_query`: `"dynamic_metric"`): Use with ANY `target_metric` (e.g. `workspace_total_download_actions`, `dns_queries_fail`, `http_queries_fail`) for creeping multi-day accumulation.
   - `MACD_MOMENTUM_VELOCITY` (`directive_query`: `"macd_momentum"`): Use with ANY `target_metric` when kinetic acceleration (12h fast vs 26h slow spine divergence) is suspected.
   - `CIRCADIAN_VON_MISES` (`directive_query`: `"circadian_von_mises"`): Use with ANY `target_metric` when off-hours activity or impossible travel velocity (`kph`) is observed.
   - `PART_OF_THE_WHOLE_MULTILEVEL` (`directive_query`: `"dynamic_metric"`): Use with ANY `target_metric` to compare entity Z-score against enterprise fleet peers.
   - `CLOUD_CRUD_SURGE` (`directive_query`: `"cloud_crud"`): Use when Cloud resource creation/deletion/IAM mutations surge.
   - `HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE` / `HYBRID_METRIC_WHOIS_DOMAIN_LIFECYCLE_2STAGE` (`directive_query`: `"dynamic_metric"`): Use strictly with `http_queries_total` when investigating HTTP request counts to rare (`DERIVED_CONTEXT` prevalence) or newly registered (`WHOIS`) domains.
   - `RARE_DESTINATION_ECG_3STAGE` / `FUSION_RARE_DESTINATION_3STAGE` (`directive_query`: `"dynamic_metric"`): Use when investigating DNS volume (`dns_queries_total`, `dns_queries_fail` keyed on `network.dns.questions.name`) or outbound bytes (`network_bytes_outbound`) to low-prevalence destinations (`DERIVED_CONTEXT`).
   - `HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE` vs `HYBRID_METRIC_FLEET_PREVALENCE_2STAGE` (`directive_query`: `"dynamic_metric"`): Use `HYBRID_METRIC_DERIVED_FILE_PREVALENCE_2STAGE` (`file_executions_total`) to filter to rare binaries (dropping rollout binaries), or `HYBRID_METRIC_FLEET_PREVALENCE_2STAGE` to normalize a surge against an enterprise rollout (Patch Tuesday Shield).

2. **Engine: `secops-statistical-hunter` (Raw Telemetry Micro-Math)**
   - `C2_BEACONING_JITTER` (`directive_query`: `"c2_jitter"`): Use when Egress is an outlier or alert indicates periodic robotic callback (CV <= 0.20).
   - `POISSON_BURST_CLUSTERING` (`directive_query`: `"poisson_burst"`): Use when Auth failures pulse in high-dispersion waves (Fano > 4.0).
   - `ELEPHANT_FLOW_CONCENTRATION` (`directive_query`: `"elephant_flow"`): Use when mass data extraction or heavy Pareto/Gini concentration is suspected.
   - `PRIVILEGED_LATERAL_EXPANSION` (`directive_query`: `"lateral_expansion"`): Use when an account expands login breadth to unseen hosts.
   - `MARKOV_TRANSITION_RARITY` (`directive_query`: `"markov_transition"`): Use for suspicious parent-child process execution lineage (LotL).
   - `SHANNON_CHARACTER_ENTROPY` (`directive_query`: `"shannon_entropy"`): Use for Base64/obfuscated command lines or DGA queries.
   - `ZIPFIAN_PROCESS_RARITY` (`directive_query`: `"zipfian_rarity"`): Use for rare long-tail binary execution on endpoints.
   - `EWMA_BURST_VELOCITY` (`directive_query`: `"ewma_burst"`): Use for intraday kinetic rate bursts.

Provide:
1. The primary hypothesis to execute (`hypothesis_h0`, `hypothesis_h1`, `evidentiary_defense` citing specific Tier 1 Z-scores and UDM touchpoints, and `confidence_score` between 0.0 and 1.0).
2. 2 to 3 additional `candidate_hypotheses` with full H0, H1, `evidentiary_defense`, `target_metric` / `fusion_metrics`, and `confidence_score`.

Output valid JSON matching this schema:
{{
  "selected_skill": "secops-risk-metrics-multistage" | "secops-statistical-hunter",
  "model_name": "<EXACT_MODEL_NAME>",
  "directive_query": "<directive_query_key>",
  "target_entity": "{ctx['primary_entity']}",
  "entity_type": "{ctx['entity_type']}",
  "target_metric": "<metric_name_from_38_catalog_or_null>",
  "fusion_metrics": ["<metric_a>", "<metric_b>"],
  "investigation_tier": "{ctx.get('investigation_tier', 'TIER_2_DEEP_DIVE')}",
  "outlier_vector": "{ctx.get('outlier_vector') or ''}",
  "threat_summary": "<concise summary of identified threat problem and UDM touchpoints>",
  "hypothesis_h0": "<the benign baseline explanation being tested>",
  "hypothesis_h1": "<the attacker threat pivot hypothesis being tested>",
  "selection_rationale": "<why this mathematical model and metric were chosen>",
  "evidentiary_defense": "<detailed defense citing Tier 1 Z-scores, UDM event types, and alert context>",
  "confidence_score": 0.85,
  "flight_card_title": "<professional title for SOC Case Wall card>",
  "candidate_hypotheses": [
    {{
      "hypothesis_title": "<short title>",
      "selected_skill": "secops-risk-metrics-multistage" | "secops-statistical-hunter",
      "model_name": "<MODEL_NAME>",
      "directive_query": "<directive_query_key>",
      "target_metric": "<metric_name_or_null>",
      "fusion_metrics": [],
      "hypothesis_h0": "<null hypothesis>",
      "hypothesis_h1": "<alternative threat hypothesis>",
      "evidentiary_defense": "<why this follow-up hunt is warranted by the evidence>",
      "confidence_score": 0.68
    }}
  ]
}}
"""
      resp = client.models.generate_content(
          model="gemini-2.5-flash",
          contents=prompt,
          config=types.GenerateContentConfig(
              response_mime_type="application/json",
              temperature=0.1,
          ),
      )
      if resp and resp.text:
        data = json.loads(resp.text)
        raw_cands = data.pop("candidate_hypotheses", []) or []
        llm_conf = data.get("confidence_score", 0.80)
        score, band, breakdown = cls.score_hypothesis_confidence(
            model_name=data.get("model_name", ""),
            target_metric=data.get("target_metric"),
            fusion_metrics=data.get("fusion_metrics"),
            outlier_vector=data.get("outlier_vector") or ctx.get("outlier_vector"),
            ctx=ctx,
            radar_result=ctx.get("radar_result"),
            executed_signatures=executed_signatures,
            empty_families=empty_families,
            llm_proposed_confidence=llm_conf,
        )
        data["confidence_score"] = score
        data["confidence_band"] = band
        data["confidence_breakdown"] = breakdown
        if not data.get("evidentiary_defense"):
          data["evidentiary_defense"] = data.get("selection_rationale", "")

        scored_cands: List[CandidateHypothesis] = []
        for rc in raw_cands:
          c_score, c_band, c_break = cls.score_hypothesis_confidence(
              model_name=rc.get("model_name", ""),
              target_metric=rc.get("target_metric"),
              fusion_metrics=rc.get("fusion_metrics"),
              outlier_vector=ctx.get("outlier_vector"),
              ctx=ctx,
              radar_result=ctx.get("radar_result"),
              executed_signatures=executed_signatures,
              empty_families=empty_families,
              llm_proposed_confidence=rc.get("confidence_score"),
          )
          rc["confidence_score"] = c_score
          rc["confidence_band"] = c_band
          rc["confidence_breakdown"] = c_break
          cand_obj = CandidateHypothesis(**rc)
          if cand_obj.confidence_band != "SUPPRESSED":
            scored_cands.append(cand_obj)

        scored_cands.sort(key=lambda x: x.confidence_score, reverse=True)
        data["candidate_hypotheses"] = scored_cands
        if scored_cands and not data.get("recommended_avenues"):
          data["recommended_avenues"] = [cls.format_hypothesis_for_avenue(c) for c in scored_cands]
        return StrategyDirective(**data)
    except Exception as e:
      logger.debug(f"Gemini strategy reasoning bypassed: {e}")
      return None

  @classmethod
  def _finalize_directive_with_confidence(
      cls,
      directive: StrategyDirective,
      ctx: Dict[str, Any],
      secondary_candidates: List[CandidateHypothesis],
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
  ) -> StrategyDirective:
    """Applies evidence-anchored confidence scoring to a primary directive and its follow-up hypotheses."""
    radar_result = ctx.get("radar_result")
    score, band, breakdown = cls.score_hypothesis_confidence(
        model_name=directive.model_name,
        target_metric=directive.target_metric,
        fusion_metrics=directive.fusion_metrics,
        outlier_vector=directive.outlier_vector,
        ctx=ctx,
        radar_result=radar_result,
        executed_signatures=executed_signatures,
        empty_families=empty_families,
    )
    directive.confidence_score = score
    directive.confidence_band = band
    directive.confidence_breakdown = breakdown
    if not directive.evidentiary_defense:
      directive.evidentiary_defense = directive.selection_rationale

    valid_cands: List[CandidateHypothesis] = []
    for cand in secondary_candidates:
      c_score, c_band, c_break = cls.score_hypothesis_confidence(
          model_name=cand.model_name,
          target_metric=cand.target_metric,
          fusion_metrics=cand.fusion_metrics,
          outlier_vector=cand.outlier_vector if hasattr(cand, "outlier_vector") else directive.outlier_vector,
          ctx=ctx,
          radar_result=radar_result,
          executed_signatures=executed_signatures,
          empty_families=empty_families,
          llm_proposed_confidence=cand.confidence_score,
      )
      cand.confidence_score = c_score
      cand.confidence_band = c_band
      cand.confidence_breakdown = c_break
      if cand.confidence_band != "SUPPRESSED":
        valid_cands.append(cand)

    if len(valid_cands) < 2:
      existing_models = {directive.model_name} | {c.model_name for c in valid_cands}
      base_metric = directive.target_metric or "network_bytes_outbound"
      companion_metric = "auth_attempts_fail" if base_metric != "auth_attempts_fail" else "network_bytes_outbound"
      fallback_pool = [
          CandidateHypothesis(
              hypothesis_title=f"Cross-Vector Sector Fusion (`{base_metric}` + `{companion_metric}`)",
              selected_skill="secops-risk-metrics-multistage",
              model_name="DUAL_SECTOR_FUSION_3STAGE",
              directive_query="sector_fusion",
              target_metric=base_metric,
              fusion_metrics=[base_metric, companion_metric],
              hypothesis_h0=f"Observed `{base_metric}` deviation is an isolated single-sector fluctuation.",
              hypothesis_h1=f"Anomalous `{base_metric}` activity is correlated with `{companion_metric}` in a multi-stage kill chain.",
              evidentiary_defense=f"Evaluates joint Euclidean threat distance across `{base_metric}` and `{companion_metric}` for `{directive.target_entity}`.",
              confidence_score=0.72,
          ),
          CandidateHypothesis(
              hypothesis_title="Diurnal Phase Departure (`CIRCADIAN_VON_MISES`)",
              selected_skill="secops-risk-metrics-multistage",
              model_name="CIRCADIAN_VON_MISES",
              directive_query="circadian_von_mises",
              target_metric="auth_attempts_total",
              hypothesis_h0="Entity activity aligns with historical working-hours schedule.",
              hypothesis_h1="Activity occurred at an anomalous circadian clock phase indicative of off-hours session abuse.",
              evidentiary_defense=f"Tests circular von Mises hourly baseline departure for `{directive.target_entity}`.",
              confidence_score=0.68,
          ),
          CandidateHypothesis(
              hypothesis_title="Derived Context Domain Prevalence (`HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE`)",
              selected_skill="secops-risk-metrics-multistage",
              model_name="HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE",
              directive_query="dynamic_metric",
              target_metric="http_queries_total",
              hypothesis_h0="Outbound destinations are widely prevalent across the enterprise fleet.",
              hypothesis_h1="Entity is communicating with rare or first-seen domains (`day_max <= 3` in `DERIVED_CONTEXT`).",
              evidentiary_defense=f"Enriches `{directive.target_entity}` network activity with Entity Graph `DERIVED_CONTEXT` prevalence.",
              confidence_score=0.65,
          ),
      ]
      for fb in fallback_pool:
        if len(valid_cands) >= 2:
          break
        if fb.model_name in existing_models:
          continue
        fb_score, fb_band, fb_break = cls.score_hypothesis_confidence(
            model_name=fb.model_name,
            target_metric=fb.target_metric,
            fusion_metrics=fb.fusion_metrics,
            outlier_vector=directive.outlier_vector,
            ctx=ctx,
            radar_result=radar_result,
            executed_signatures=executed_signatures,
            empty_families=empty_families,
            llm_proposed_confidence=fb.confidence_score,
        )
        fb.confidence_score = fb_score
        fb.confidence_band = fb_band
        fb.confidence_breakdown = fb_break
        valid_cands.append(fb)
        existing_models.add(fb.model_name)

    valid_cands.sort(key=lambda x: x.confidence_score, reverse=True)
    directive.candidate_hypotheses = valid_cands
    if valid_cands:
      directive.recommended_avenues = [cls.format_hypothesis_for_avenue(c) for c in valid_cands]
    if radar_result and not directive.radar_insights:
      directive.radar_insights = ctx.get("radar_insights") or cls.analyze_360_insights(
          radar_result=radar_result,
          ctx=ctx,
          entity_type=directive.entity_type,
      )
    if directive.target_metric and not directive.killchain_progression:
      try:
        from src.pipeline_runner import PipelineRunner
        fmt_cls = PipelineRunner().get_triage_formatter()
        if fmt_cls:
          directive.killchain_progression = fmt_cls.get_mitre_progression(directive.target_metric)
      except Exception:
        pass
    return directive

  @classmethod
  def _deterministic_reasoner(
      cls,
      ctx: Dict[str, Any],
      executed_signatures: Optional[Set[str]] = None,
      empty_families: Optional[Set[str]] = None,
  ) -> StrategyDirective:
    """Robust, regex-safe, UDM-aware and v1.9.1 38-metric-aware heuristic reasoner with hypothesis defense."""
    text_corpus = (
        f"{ctx.get('case_title', '')} "
        f"{ctx.get('case_description', '')} "
        f"{' '.join(ctx.get('alerts', []))} "
        f"{' '.join(ctx.get('rule_generators', []))} "
        f"{' '.join(ctx.get('threat_associations', []))}"
    ).lower()

    udm_events = ctx.get("udm_event_types", [])
    target_entity = ctx.get("primary_entity", "unknown")
    entity_type = ctx.get("entity_type", "USER")
    threats = ctx.get("threat_associations", [])
    outcomes = ctx.get("outcome_metrics", {})

    outlier_vector = ctx.get("outlier_vector")
    radar_result = ctx.get("radar_result") or {}
    radar_insights = ctx.get("radar_insights") or (
        cls.analyze_360_insights(radar_result, ctx, entity_type) if radar_result else {}
    )
    outlier_sectors = radar_result.get("outlier_sectors", [])
    variance_masked_sectors = radar_result.get("variance_masked_sectors", []) or radar_insights.get("variance_masked_sectors", [])
    dormant_awakening_sectors = radar_result.get("dormant_awakening_sectors", []) or radar_insights.get("dormant_awakening_sectors", [])
    sector_z = radar_result.get("sector_z_scores", {})
    sector_avg = radar_result.get("sector_baseline_avg", {})
    sector_std = radar_result.get("sector_baseline_std", {})
    is_host = str(entity_type).upper() in ("ASSET", "HOST", "IP")
    sector_metrics = radar_result.get(
        "sector_metrics",
        cls.SECTOR_TO_METRIC_ASSET if is_host else cls.SECTOR_TO_METRIC_USER,
    )
    tier = ctx.get("investigation_tier", "TIER_2_DEEP_DIVE" if outlier_vector else "TIER_1_BASELINE")

    # --- 0. Multi-Vector Cross-Sector or Roll-Up Fusion when 2+ sectors are outliers in Tier 1 ---
    if len(outlier_sectors) >= 2 and re.search(r"\b(fusion|multi[-\s]?sector|kill[-\s]?chain|correlat)\b", text_corpus):
      sec_a, sec_b = outlier_sectors[0], outlier_sectors[1]
      m_a = sector_metrics.get(sec_a, "workspace_total_download_actions")
      m_b = sector_metrics.get(sec_b, "network_bytes_outbound")
      z_a = sector_z.get(sec_a, 3.0)
      z_b = sector_z.get(sec_b, 2.5)
      defense = (
          f"Tier 1 360° Radar surfaced concurrent anomalies across two orthogonal sectors: "
          f"`{sec_a}` (`{m_a}`, Z = {z_a:+.2f}σ) and `{sec_b}` (`{m_b}`, Z = {z_b:+.2f}σ). "
          f"Executing a 3-stage Cross-Vector Fusion computes the joint Euclidean threat distance D = sqrt(Z_a^2 + Z_b^2)."
      )
      directive = StrategyDirective(
          selected_skill="secops-risk-metrics-multistage",
          model_name="DUAL_SECTOR_FUSION_3STAGE",
          directive_query="sector_fusion",
          target_entity=target_entity,
          entity_type=entity_type,
          target_metric=m_a,
          fusion_metrics=[m_a, m_b],
          investigation_tier=tier,
          outlier_vector=sec_a,
          threat_summary=f"Multi-vector behavioral anomaly on `{target_entity}` spanning `{m_a}` and `{m_b}`.",
          hypothesis_h0=f"Concurrent deviations in `{m_a}` and `{m_b}` reflect unrelated routine activity.",
          hypothesis_h1=f"Coordinated multi-sector attack chain combining `{m_a}` and `{m_b}` on `{target_entity}`.",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"Tier 2 Cross-Vector Fusion ({sec_a} × {sec_b}): `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

    # --- Outlier Vector Priority Dispatch for Tier 2 Secondary Sweeps ---
    if outlier_vector:
      z_val = sector_z.get(outlier_vector, 2.5)
      m_for_vec = sector_metrics.get(outlier_vector, "network_bytes_outbound")

      # Sub-Threshold Variance-Masked Drift -> 4-Stage Non-Parametric MAD
      if outlier_vector in variance_masked_sectors and outlier_vector not in outlier_sectors:
        std_val = sector_std.get(outlier_vector, 10.0)
        avg_val = sector_avg.get(outlier_vector, 1.0)
        defense = (
            f"Tier 1 360° Radar flagged a variance-masked sub-threshold anomaly in `{outlier_vector}` "
            f"(`{m_for_vec}`, Z = {z_val:+.2f}σ, μ = {avg_val:.2f}, σ = {std_val:.2f}). "
            "Because historical standard deviation is inflated by heavy-tailed variance, executing 4-Stage Non-Parametric "
            "`MAD` (`mad_robust_z_4stage.yl2` over 30d) tests median-based robust deviation ($Z_{mod} = 0.6745 |x - \\text{median}| / \\text{MAD}$)."
        )
        cands = [
            CandidateHypothesis(
                hypothesis_title=f"Longitudinal CUSUM Drift on `{m_for_vec}`",
                selected_skill="secops-risk-metrics-multistage",
                model_name="LONGITUDINAL_CUSUM_DRIFT",
                directive_query="dynamic_metric",
                target_metric=m_for_vec,
                hypothesis_h0=f"Sub-threshold `{m_for_vec}` volume reflects stationary background noise.",
                hypothesis_h1=f"Multi-day cumulative drift in `{m_for_vec}` is accumulating under the parametric Z-score threshold.",
                evidentiary_defense=f"Complements 4-stage `MAD` with cumulative sum tracking across `{m_for_vec}`.",
                confidence_score=0.78,
            ),
        ]
        directive = StrategyDirective(
            selected_skill="secops-risk-metrics-multistage",
            model_name="MAD",
            directive_query="dynamic_metric",
            target_entity=target_entity,
            entity_type=entity_type,
            target_metric=m_for_vec,
            investigation_tier=tier,
            outlier_vector=outlier_vector,
            threat_summary=f"Secondary Deep Dive: Variance-masked sub-threshold drift in `{outlier_vector}` (`{m_for_vec}`, Z = {z_val:+.2f}σ, σ = {std_val:.2f}) on `{target_entity}`.",
            hypothesis_h0=f"Elevated `{m_for_vec}` volume is within normal heavy-tailed operational variance.",
            hypothesis_h1=f"True outlier in `{m_for_vec}` masked by inflated parametric standard deviation ($Z_{{mod}} \\ge 3.5$).",
            selection_rationale=defense,
            evidentiary_defense=defense,
            flight_card_title=f"Tier 2 Non-Parametric 4-Stage MAD (`{m_for_vec}`): `{target_entity}`",
        )
        return cls._finalize_directive_with_confidence(directive, ctx, cands, executed_signatures, empty_families)

      # Sub-Threshold Dormant Baseline Awakening -> TWO_PART_HURDLE
      if outlier_vector in dormant_awakening_sectors and outlier_vector not in outlier_sectors:
        avg_val = sector_avg.get(outlier_vector, 0.05)
        defense = (
            f"Tier 1 360° Radar detected a dormant baseline awakening in `{outlier_vector}` "
            f"(`{m_for_vec}`, Z = {z_val:+.2f}σ, historical μ = {avg_val:.2f}). "
            "Applying `TWO_PART_HURDLE` (`two_part_hurdle_2stage.yl2`) explicitly evaluates zero-inflated dormancy awakening "
            "combined with post-hurdle volume intensity."
        )
        cands = [
            CandidateHypothesis(
                hypothesis_title=f"4-Stage Non-Parametric MAD on `{m_for_vec}`",
                selected_skill="secops-risk-metrics-multistage",
                model_name="MAD",
                directive_query="dynamic_metric",
                target_metric=m_for_vec,
                hypothesis_h0=f"Activity in `{m_for_vec}` conforms to median historical behavior.",
                hypothesis_h1=f"Post-awakening activity in `{m_for_vec}` exceeds robust median absolute deviation thresholds.",
                evidentiary_defense=f"Provides non-parametric corroboration for dormant baseline awakening on `{m_for_vec}`.",
                confidence_score=0.76,
            ),
        ]
        directive = StrategyDirective(
            selected_skill="secops-risk-metrics-multistage",
            model_name="TWO_PART_HURDLE",
            directive_query="dynamic_metric",
            target_entity=target_entity,
            entity_type=entity_type,
            target_metric=m_for_vec,
            investigation_tier=tier,
            outlier_vector=outlier_vector,
            threat_summary=f"Secondary Deep Dive: Dormant baseline awakening in `{outlier_vector}` (`{m_for_vec}`, μ = {avg_val:.2f}) on `{target_entity}`.",
            hypothesis_h0=f"Sporadic `{m_for_vec}` activity represents benign infrequent usage.",
            hypothesis_h1=f"Zero-inflated dormant vector `{m_for_vec}` awakened with anomalous intensity (`TWO_PART_HURDLE`).",
            selection_rationale=defense,
            evidentiary_defense=defense,
            flight_card_title=f"Tier 2 Dormant Baseline Hurdle (`{m_for_vec}`): `{target_entity}`",
        )
        return cls._finalize_directive_with_confidence(directive, ctx, cands, executed_signatures, empty_families)

      if outlier_vector == "Workspace":
        ws_metric = "workspace_total_change_actions" if "change" in text_corpus else "workspace_total_download_actions"
        defense = (
            f"Tier 1 360° Radar flagged a significant outlier in the `Workspace` sector (Z = {z_val:+.2f}σ on `{ws_metric}`). "
            f"Pairing `{ws_metric}` with `network_bytes_outbound` via `DUAL_SECTOR_FUSION_3STAGE` or evaluating "
            f"`MACD_MOMENTUM_VELOCITY` directly tests whether Google Drive/Workspace document access is accelerating toward exfiltration."
        )
        cands = [
            CandidateHypothesis(
                hypothesis_title=f"Workspace × Network Outbound Exfiltration Fusion (`{ws_metric}` + `network_bytes_outbound`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="DUAL_SECTOR_FUSION_3STAGE",
                directive_query="sector_fusion",
                target_metric=ws_metric,
                fusion_metrics=[ws_metric, "network_bytes_outbound"],
                hypothesis_h0="Workspace file downloads are local productivity actions without outbound network staging.",
                hypothesis_h1=f"Downloaded Workspace assets (`{ws_metric}`) are being actively exfiltrated over outbound network flows (`network_bytes_outbound`).",
                evidentiary_defense=f"Correlates the observed `{ws_metric}` spike (Z = {z_val:+.2f}σ) with outbound byte volume for `{target_entity}`.",
                confidence_score=0.82,
            ),
            CandidateHypothesis(
                hypothesis_title=f"Peer Cohort Multilevel Comparison on `{ws_metric}`",
                selected_skill="secops-risk-metrics-multistage",
                model_name="PART_OF_THE_WHOLE_MULTILEVEL",
                directive_query="dynamic_metric",
                target_metric=ws_metric,
                hypothesis_h0=f"Elevated `{ws_metric}` volume is shared across the enterprise fleet (e.g. company-wide policy doc).",
                hypothesis_h1=f"User `{target_entity}` is an isolated fleet-wide outlier in `{ws_metric}` ($Z_{{enterprise}} \\ge 3.0\\sigma$).",
                evidentiary_defense=f"Distinguishes isolated insider hoarding of `{ws_metric}` from legitimate department-wide document distribution.",
                confidence_score=0.72,
            ),
            CandidateHypothesis(
                hypothesis_title="Workspace Insider Triad Multilevel Decomposition (Downloads + Changes + Emails)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="PART_OF_THE_WHOLE_TRIAD_MULTILEVEL",
                directive_query="workspace_triad",
                target_metric="workspace_total_download_actions",
                fusion_metrics=[
                    "workspace_total_download_actions",
                    "workspace_total_change_actions",
                    "workspace_emails_sent_total",
                ],
                hypothesis_h0="Workspace activity is confined to a single routine productivity channel.",
                hypothesis_h1="Coordinated insider hoarding across Workspace downloads, permission modifications, and external email forwarding.",
                evidentiary_defense=f"Decomposes the Workspace Z = {z_val:+.2f}σ signal across all 3 Workspace insider vectors against enterprise peers.",
                confidence_score=0.79,
            ),
        ]
        directive = StrategyDirective(
            selected_skill="secops-risk-metrics-multistage",
            model_name="MACD_MOMENTUM_VELOCITY",
            directive_query="macd_momentum",
            target_entity=target_entity,
            entity_type=entity_type,
            target_metric=ws_metric,
            investigation_tier=tier,
            outlier_vector=outlier_vector,
            threat_summary=f"Secondary Deep Dive: Workspace sector outlier (`{ws_metric}`, Z = {z_val:+.2f}σ) on `{target_entity}`.",
            hypothesis_h0=f"Observed `{ws_metric}` count reflects routine document collaboration.",
            hypothesis_h1=f"Acute MACD velocity divergence in `{ws_metric}` indicating bulk Workspace data hoarding prior to exfiltration.",
            selection_rationale=defense,
            evidentiary_defense=defense,
            flight_card_title=f"Tier 2 Workspace Velocity Analysis (`{ws_metric}`): `{target_entity}`",
        )
        return cls._finalize_directive_with_confidence(directive, ctx, cands, executed_signatures, empty_families)

      elif outlier_vector == "Web":
        web_metric = "http_queries_fail" if ("fail" in text_corpus or "error" in text_corpus or "404" in text_corpus) else "http_queries_total"
        defense = (
            f"Tier 1 360° Radar identified an outlier in `Web & Proxy Activity` (`{web_metric}`, Z = {z_val:+.2f}σ). "
            f"Evaluating `{web_metric}` via `MACD_MOMENTUM_VELOCITY` tests for automated web scraping, proxy probing, or C2 over HTTP."
        )
        cands = [
            CandidateHypothesis(
                hypothesis_title="First-Contact / Rare Destination HTTP Domain Prevalence (`http_queries_total`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="HYBRID_METRIC_DERIVED_DOMAIN_PREVALENCE_2STAGE",
                directive_query="dynamic_metric",
                target_metric="http_queries_total",
                hypothesis_h0="HTTP requests target established enterprise SaaS domains.",
                hypothesis_h1=f"Host/User `{target_entity}` is sending `http_queries_total` traffic to rare domains seen on <= 3 fleet hosts.",
                evidentiary_defense=f"Combines `http_queries_total` 30-day baseline Z-score (Z = {z_val:+.2f}σ) with Entity Graph `DERIVED_CONTEXT` domain prevalence (`timestamp.get_date`).",
                confidence_score=0.78,
            ),
            CandidateHypothesis(
                hypothesis_title="HTTP Error Ratio Surge (`http_queries_fail` / `http_queries_total`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="FAILURE_RATIO_SURGE",
                directive_query="failure_ratio_surge",
                target_metric="http_queries_fail",
                fusion_metrics=["http_queries_fail", "http_queries_total"],
                hypothesis_h0="HTTP requests maintain a normal success-to-failure ratio.",
                hypothesis_h1="Elevated HTTP failure ratio indicating web directory brute-forcing, vulnerability scanning, or dead C2 endpoints.",
                evidentiary_defense=f"Evaluates 3-stage `FAILURE_RATIO_SURGE` across `http_queries_fail` and `http_queries_total` for `{target_entity}`.",
                confidence_score=0.76,
            ),
        ]
        directive = StrategyDirective(
            selected_skill="secops-risk-metrics-multistage",
            model_name="MACD_MOMENTUM_VELOCITY",
            directive_query="macd_momentum",
            target_entity=target_entity,
            entity_type=entity_type,
            target_metric=web_metric,
            investigation_tier=tier,
            outlier_vector=outlier_vector,
            threat_summary=f"Secondary Deep Dive: Web/HTTP sector outlier (`{web_metric}`, Z = {z_val:+.2f}σ) on `{target_entity}`.",
            hypothesis_h0=f"Elevated `{web_metric}` traffic stems from standard browser or CDN requests.",
            hypothesis_h1=f"Rapid momentum surge in `{web_metric}` driven by automated web reconnaissance or HTTP exfiltration.",
            selection_rationale=defense,
            evidentiary_defense=defense,
            flight_card_title=f"Tier 2 Web & Proxy Velocity (`{web_metric}`): `{target_entity}`",
        )
        return cls._finalize_directive_with_confidence(directive, ctx, cands, executed_signatures, empty_families)

      elif outlier_vector == "Egress":
        if re.search(r"\b(elephant\s+flow|mass\s+data\s+extraction|bigquery|table\s+dumping|gini)\b", text_corpus):
          defense = (
              f"Tier 1 `Egress` sector is anomalous (Z = {z_val:+.2f}σ on `network_bytes_outbound`) and case context references bulk data extraction. "
              "Evaluating `ELEPHANT_FLOW_CONCENTRATION` tests whether outbound bytes are concentrated into a heavy Pareto/Gini tail."
          )
          directive = StrategyDirective(
              selected_skill="secops-statistical-hunter",
              model_name="ELEPHANT_FLOW_CONCENTRATION",
              directive_query="elephant_flow",
              target_entity=target_entity,
              entity_type=entity_type,
              target_metric="network_bytes_outbound",
              investigation_tier=tier,
              outlier_vector=outlier_vector,
              threat_summary=f"Secondary Deep Dive: Egress volume surge on `{target_entity}` exhibiting heavy Pareto/Gini concentration.",
              hypothesis_h0="Egress volume surge reflects standard batch analytical ETL query jobs.",
              hypothesis_h1="Anomalous Pareto / Gini tail concentration in egress volume indicating unauthorized table dumping.",
              selection_rationale=defense,
              evidentiary_defense=defense,
              flight_card_title=f"Tier 2 Elephant Flow Concentration: `{target_entity}`",
          )
          return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

        defense = (
            f"Tier 1 360° Radar flagged a significant `Egress` outlier (Z = {z_val:+.2f}σ on `network_bytes_outbound`). "
            "Testing `C2_BEACONING_JITTER` first determines whether the outbound traffic is driven by automated periodic C2 polling ($CV \\le 0.30$); "
            "if refuted, the engine will pivot to bulk `MACD_MOMENTUM_VELOCITY` or Cross-Vector Fusion."
        )
        cands = [
            CandidateHypothesis(
                hypothesis_title="Bulk Outbound Momentum Acceleration (`network_bytes_outbound`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="MACD_MOMENTUM_VELOCITY",
                directive_query="macd_momentum",
                target_metric="network_bytes_outbound",
                hypothesis_h0="Outbound bytes reflect routine background transfers.",
                hypothesis_h1="Non-periodic outbound byte surge represents acute staging and bulk exfiltration acceleration.",
                evidentiary_defense=f"If `C2_BEACONING_JITTER` rules out periodic polling, the Z = {z_val:+.2f}σ `network_bytes_outbound` spike must be evaluated for bulk momentum.",
                confidence_score=0.76,
            ),
        ]
        directive = StrategyDirective(
            selected_skill="secops-statistical-hunter",
            model_name="C2_BEACONING_JITTER",
            directive_query="c2_jitter",
            target_entity=target_entity,
            entity_type=entity_type,
            target_metric="network_bytes_outbound",
            investigation_tier=tier,
            outlier_vector=outlier_vector,
            threat_summary=f"Secondary Deep Dive: Outlier in Network Egress (Z = {z_val:+.2f}σ) on `{target_entity}`; evaluating robotic periodic beaconing.",
            hypothesis_h0="Outbound network connections originate from stochastic application background traffic ($CV > 0.30$).",
            hypothesis_h1="Host established automated, low-jitter periodic polling to external C2 exfiltration infrastructure ($CV \\le 0.30$).",
            selection_rationale=defense,
            evidentiary_defense=defense,
            flight_card_title=f"Tier 2 C2 Beaconing Jitter Analysis: `{target_entity}`",
        )
        return cls._finalize_directive_with_confidence(directive, ctx, cands, executed_signatures, empty_families)

      elif outlier_vector == "Auth":
        if re.search(r"\b(lateral|breadth|expansion|unseen)\b", text_corpus):
          defense = (
              f"Tier 1 `Auth` sector is anomalous (Z = {z_val:+.2f}σ) with lateral movement indicators in the case text. "
              "Evaluating `PRIVILEGED_LATERAL_EXPANSION` tests whether the account is authenticating to previously unseen endpoints."
          )
          directive = StrategyDirective(
              selected_skill="secops-statistical-hunter",
              model_name="PRIVILEGED_LATERAL_EXPANSION",
              directive_query="lateral_expansion",
              target_entity=target_entity,
              entity_type=entity_type,
              target_metric="auth_attempts_success",
              investigation_tier=tier,
              outlier_vector=outlier_vector,
              threat_summary=f"Secondary Deep Dive: Auth outlier on `{target_entity}`; evaluating privileged lateral machine expansion.",
              hypothesis_h0="Logins reflect routine administrative access across normal host baseline.",
              hypothesis_h1="Compromised account expanding authentication radius across previously unaccessed target machines.",
              selection_rationale=defense,
              evidentiary_defense=defense,
              flight_card_title=f"Tier 2 Lateral Expansion Analysis: `{target_entity}`",
          )
          return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

        defense = (
            f"Tier 1 360° Radar flagged an `Auth` sector anomaly (Z = {z_val:+.2f}σ on `auth_attempts_fail`). "
            "Testing `POISSON_BURST_CLUSTERING` evaluates whether failures occur in high-dispersion automated spray waves ($Fano > 4.0$); "
            "if refuted, a pivot to `CIRCADIAN_VON_MISES` will test for off-hours session abuse."
        )
        cands = [
            CandidateHypothesis(
                hypothesis_title="Off-Hours Circadian Authentication Departure (`auth_attempts_total`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="CIRCADIAN_VON_MISES",
                directive_query="circadian_von_mises",
                target_metric="auth_attempts_total",
                hypothesis_h0="Logins occur within the user's normal working hours.",
                hypothesis_h1="Authentication activity occurs at an anomalous circadian clock angle indicative of stolen credentials.",
                evidentiary_defense=f"Tests temporal departure on `auth_attempts_total` given the Tier 1 Auth Z = {z_val:+.2f}σ deviation.",
                confidence_score=0.74,
            ),
        ]
        directive = StrategyDirective(
            selected_skill="secops-statistical-hunter",
            model_name="POISSON_BURST_CLUSTERING",
            directive_query="poisson_burst",
            target_entity=target_entity,
            entity_type=entity_type,
            target_metric="auth_attempts_fail",
            investigation_tier=tier,
            outlier_vector=outlier_vector,
            threat_summary=f"Secondary Deep Dive: Authentication failure surge (Z = {z_val:+.2f}σ) targeting `{target_entity}`; testing Poisson dispersion.",
            hypothesis_h0="Failures stem from benign user password expiration or expired cached credentials ($Fano \\le 4.0$).",
            hypothesis_h1="Identity subjected to automated, high-dispersion Poisson credential spray bursts ($Fano > 4.0$).",
            selection_rationale=defense,
            evidentiary_defense=defense,
            flight_card_title=f"Tier 2 Poisson Burst Clustering: `{target_entity}`",
        )
        return cls._finalize_directive_with_confidence(directive, ctx, cands, executed_signatures, empty_families)

      elif outlier_vector == "Cloud":
        defense = (
            f"Tier 1 360° Radar flagged a `Cloud` sector outlier (Z = {z_val:+.2f}σ on `resource_creation_total`). "
            "Executing `CLOUD_CRUD_SURGE` evaluates 30-day resource creation and deletion baselines across vendor/product companions."
        )
        cands = [
            CandidateHypothesis(
                hypothesis_title="Cloud Resource × Auth Roll-Up Sector Fusion (`resource_creation_total` + `auth_attempts_fail`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="DUAL_SECTOR_FUSION_3STAGE",
                directive_query="sector_fusion",
                target_metric="resource_creation_total",
                fusion_metrics=["resource_creation_total", "auth_attempts_fail"],
                hypothesis_h0="Cloud provisioning is an authorized CI/CD deployment.",
                hypothesis_h1="Cloud resource creation surge is coupled with anomalous authentication activity on the same identity.",
                evidentiary_defense=f"Rolls up composite `resource_creation_total` (Z = {z_val:+.2f}σ) and fuses with identity authentication baseline.",
                confidence_score=0.71,
            ),
            CandidateHypothesis(
                hypothesis_title="Cloud Repository Scope & Permission Recon (`CLOUD_REPOSITORY_SCOPE`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="CLOUD_REPOSITORY_SCOPE",
                directive_query="cloud_repo_scope",
                target_metric="resource_read_total",
                outcome_mode="fail" if ("fail" in text_corpus or "denied" in text_corpus) else "total",
                hypothesis_h0="Cloud resource reads align with normal service account scope.",
                hypothesis_h1="Identity is enumerating cloud buckets/repositories outside its historical behavioral scope.",
                evidentiary_defense=f"Evaluates `build_cloud_repository_scope_query` on `{target_entity}` following the Cloud Z = {z_val:+.2f}σ signal.",
                confidence_score=0.77,
            ),
        ]
        directive = StrategyDirective(
            selected_skill="secops-risk-metrics-multistage",
            model_name="CLOUD_CRUD_SURGE",
            directive_query="cloud_crud",
            target_entity=target_entity,
            entity_type=entity_type,
            target_metric="resource_creation_total",
            investigation_tier=tier,
            outlier_vector=outlier_vector,
            threat_summary=f"Secondary Deep Dive: Cloud sector outlier (Z = {z_val:+.2f}σ) on `{target_entity}`; testing IAM and resource mutation velocity.",
            hypothesis_h0="Administrative modifications reflect normal Infrastructure-as-Code deployments.",
            hypothesis_h1="Compromised credentials generating unauthorized service account keys or escalating IAM permissions.",
            selection_rationale=defense,
            evidentiary_defense=defense,
            flight_card_title=f"Tier 2 Cloud Infrastructure CRUD Surge: `{target_entity}`",
        )
        return cls._finalize_directive_with_confidence(directive, ctx, cands, executed_signatures, empty_families)

      elif outlier_vector == "DNS":
        dns_metric = "dns_bytes_outbound" if "tunnel" in text_corpus else "dns_queries_fail"
        if re.search(r"\b(entropy|dga|obfuscated)\b", text_corpus):
          defense = (
              f"Tier 1 `DNS` sector is anomalous (Z = {z_val:+.2f}σ) and alert context indicates algorithmic domain generation. "
              "Testing `SHANNON_CHARACTER_ENTROPY` measures character randomness in queried domain strings."
          )
          directive = StrategyDirective(
              selected_skill="secops-statistical-hunter",
              model_name="SHANNON_CHARACTER_ENTROPY",
              directive_query="shannon_entropy",
              target_entity=target_entity,
              entity_type=entity_type,
              target_metric=dns_metric,
              investigation_tier=tier,
              outlier_vector=outlier_vector,
              threat_summary=f"Secondary Deep Dive: DNS query outlier on `{target_entity}`; testing algorithmic DGA query entropy.",
              hypothesis_h0="Query strings conform to normal enterprise domain resolution patterns.",
              hypothesis_h1="Adversary utilizing Domain Generation Algorithms (DGA) with high character entropy to establish C2.",
              selection_rationale=defense,
              evidentiary_defense=defense,
              flight_card_title=f"Tier 2 DNS DGA Entropy Analysis: `{target_entity}`",
          )
          return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

        defense = (
            f"Tier 1 360° Radar flagged a `DNS` sector outlier (Z = {z_val:+.2f}σ on `{dns_metric}`). "
            f"Applying `LONGITUDINAL_CUSUM_DRIFT` directly to `{dns_metric}` evaluates whether NXDOMAIN / DNS traffic is accumulating over a multi-day tunneling or C2 reconnaissance horizon."
        )
        cands = [
            CandidateHypothesis(
                hypothesis_title=f"Rare Destination DNS ECG Filter (`{dns_metric}` via `network.dns.questions.name`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="RARE_DESTINATION_ECG_3STAGE",
                directive_query="dynamic_metric",
                target_metric=dns_metric,
                hypothesis_h0="DNS queries resolve high-prevalence enterprise domains.",
                hypothesis_h1=f"DNS surge (`{dns_metric}`) contacts low-prevalence domains (`<= 3` fleet hosts) in Entity Graph `DERIVED_CONTEXT`.",
                evidentiary_defense=f"Uses v1.8.1 `rare_destination_ecg_3stage.yl2` keyed on `network.dns.questions.name` and `timestamp.get_date` freshness filter.",
                confidence_score=0.75,
            ),
            CandidateHypothesis(
                hypothesis_title=f"DNS × Network Outbound Fusion (`{dns_metric}` + `network_bytes_outbound`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="DUAL_SECTOR_FUSION_3STAGE",
                directive_query="sector_fusion",
                target_metric=dns_metric,
                fusion_metrics=[dns_metric, "network_bytes_outbound"],
                hypothesis_h0="DNS failures are isolated resolver misconfigurations.",
                hypothesis_h1=f"DNS resolution anomalies (`{dns_metric}`) are paired with active outbound data transfer (`network_bytes_outbound`).",
                evidentiary_defense=f"Tests whether the DNS Z = {z_val:+.2f}σ anomaly correlates with outbound byte exfiltration.",
                confidence_score=0.73,
            ),
        ]
        directive = StrategyDirective(
            selected_skill="secops-risk-metrics-multistage",
            model_name="LONGITUDINAL_CUSUM_DRIFT",
            directive_query="dynamic_metric",
            target_entity=target_entity,
            entity_type=entity_type,
            target_metric=dns_metric,
            investigation_tier=tier,
            outlier_vector=outlier_vector,
            threat_summary=f"Secondary Deep Dive: DNS surge (`{dns_metric}`, Z = {z_val:+.2f}σ) on `{target_entity}`; testing longitudinal CUSUM drift.",
            hypothesis_h0="DNS failures conform to benign transient network misconfigurations.",
            hypothesis_h1=f"Low-and-slow creeping DNS tunneling or domain reconnaissance in `{dns_metric}` over sliding timeline.",
            selection_rationale=defense,
            evidentiary_defense=defense,
            flight_card_title=f"Tier 2 Longitudinal CUSUM Drift (`{dns_metric}`): `{target_entity}`",
        )
        return cls._finalize_directive_with_confidence(directive, ctx, cands, executed_signatures, empty_families)

      elif outlier_vector in ("Flows", "Alerts"):
        target_m = "alert_event_name_count" if outlier_vector == "Alerts" else "network_flows_outbound"
        defense = (
            f"Tier 1 360° Radar flagged a significant `{outlier_vector}` outlier (Z = {z_val:+.2f}σ on `{target_m}`). "
            "Testing `EWMA_BURST_VELOCITY` captures intraday kinetic acceleration while preparing a Roll-Up Fusion if corroborated."
        )
        cands = [
            CandidateHypothesis(
                hypothesis_title=f"Roll-Up Sector Fusion (`{target_m}` + `network_bytes_outbound`)",
                selected_skill="secops-risk-metrics-multistage",
                model_name="DUAL_SECTOR_FUSION_3STAGE",
                directive_query="sector_fusion",
                target_metric=target_m,
                fusion_metrics=[target_m, "network_bytes_outbound"],
                hypothesis_h0=f"Elevated `{target_m}` is an isolated scanner or noisy rule.",
                hypothesis_h1=f"Anomalous `{target_m}` activity on `{target_entity}` coincides with outbound data exfiltration (`network_bytes_outbound`).",
                evidentiary_defense=f"Fuses `{target_m}` (Z = {z_val:+.2f}σ) with `network_bytes_outbound` using v1.8.0 roll-up fusion.",
                confidence_score=0.77,
            ),
            CandidateHypothesis(
                hypothesis_title="MITRE ATT&CK Kill-Chain: Defense Evasion Alert to Exfiltration",
                selected_skill="secops-risk-metrics-multistage",
                model_name="KILLCHAIN_DEFENSE_EVASION_ALERT_TO_EXFILTRATION",
                directive_query="killchain_archetype",
                target_metric="alert_event_name_count",
                fusion_metrics=["alert_event_name_count", "network_bytes_outbound"],
                killchain_archetype="DEFENSE_EVASION_ALERT_TO_EXFILTRATION",
                hypothesis_h0="Security alerts on host are uncoupled from outbound network bytes.",
                hypothesis_h1="Security/EDR alert surge (`alert_event_name_count`) is coupled with active outbound data exfiltration (`network_bytes_outbound`).",
                evidentiary_defense=f"Executes `DEFENSE_EVASION_ALERT_TO_EXFILTRATION` kill-chain archetype on `{target_entity}`.",
                confidence_score=0.79,
            ),
        ]
        directive = StrategyDirective(
            selected_skill="secops-statistical-hunter",
            model_name="EWMA_BURST_VELOCITY",
            directive_query="ewma_burst",
            target_entity=target_entity,
            entity_type=entity_type,
            target_metric=target_m,
            investigation_tier=tier,
            outlier_vector=outlier_vector,
            threat_summary=f"Secondary Deep Dive: Kinetic rate burst on `{target_entity}` ({outlier_vector} sector, `{target_m}`).",
            hypothesis_h0="Telemetry surge reflects scheduled backup operations or batch sync jobs.",
            hypothesis_h1="Kinetic acceleration indicating automated data staging or aggressive scanning.",
            selection_rationale=defense,
            evidentiary_defense=defense,
            flight_card_title=f"Tier 2 EWMA Kinetic Burst Velocity: `{target_entity}`",
        )
        return cls._finalize_directive_with_confidence(directive, ctx, cands, executed_signatures, empty_families)

    # --- Direct Case/Alert Situational Dispatch ---
    # 1. Network / C2 Beaconing Indicators
    if re.search(r"\b(beacon|beaconing|jitter|command\s+and\s+control|periodic\s+connection|outbound\s+regularity)\b", text_corpus) or (
        re.search(r"\bc2\b", text_corpus) and "ec2" not in text_corpus
    ):
      threat_label = threats[0] if threats else "Command & Control"
      defense = (
          f"Alert telemetry on `{target_entity}` explicitly references {threat_label} periodic communication. "
          "Applying `C2_BEACONING_JITTER` measures inter-arrival timing variance ($CV = \\sigma / \\mu$) across outbound flows."
      )
      directive = StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="C2_BEACONING_JITTER",
          directive_query="c2_jitter",
          target_entity=target_entity,
          entity_type=entity_type,
          target_metric="network_bytes_outbound",
          investigation_tier=tier,
          threat_summary=f"Host `{target_entity}` associated with {threat_label} periodic network communication or C2 telemetry.",
          hypothesis_h0="Outbound network connections originate from stochastic application background traffic ($CV > 0.30$).",
          hypothesis_h1="Host established automated, low-jitter periodic polling to external C2 exfiltration infrastructure ($CV \\le 0.30$).",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"C2 Beaconing Jitter Analysis: `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

    # 2. Credential Spray / Burst Login Indicators
    if re.search(r"\b(spray|brute\s+force|failed\s+login\s+surge|poisson|fano|mimikatz|pwdump|credential\s+theft)\b", text_corpus) or (
        "USER_LOGIN" in udm_events and ("fail" in text_corpus or "excessive" in text_corpus)
    ) or (
        entity_type in ("USER", "USER_ID", "EMAIL") and re.search(r"\b(agenttesla|stealer|infostealer|keylogger)\b", text_corpus)
    ):
      defense = (
          f"Case telemetry for `{target_entity}` contains authentication failure / credential theft indicators (`USER_LOGIN`). "
          "Evaluating `POISSON_BURST_CLUSTERING` tests whether login failures violate Poisson randomness ($Fano > 4.0$)."
      )
      directive = StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="POISSON_BURST_CLUSTERING",
          directive_query="poisson_burst",
          target_entity=target_entity,
          entity_type=entity_type,
          target_metric="auth_attempts_fail",
          investigation_tier=tier,
          threat_summary=f"Excessive authentication failures or credential spray attempts targeting `{target_entity}`.",
          hypothesis_h0="Failures stem from benign user password expiration or expired cached credentials ($Fano \\le 4.0$).",
          hypothesis_h1="Identity subjected to automated, high-dispersion Poisson credential spray bursts ($Fano > 4.0$).",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"Poisson Burst Clustering: `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

    # 3. Information-Theoretic: Obfuscated Command Line / High Entropy
    if re.search(r"\b(entropy|shannon|obfuscated|base64|obfuscation|encoded\s+command)\b", text_corpus):
      defense = (
          f"Alert context on `{target_entity}` indicates encoded or obfuscated command execution. "
          "Applying `SHANNON_CHARACTER_ENTROPY` quantifies character-class randomness ($H > 4.5$ bits/char)."
      )
      directive = StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="SHANNON_CHARACTER_ENTROPY",
          directive_query="shannon_entropy",
          target_entity=target_entity,
          entity_type=entity_type,
          target_metric="file_executions_total",
          investigation_tier=tier,
          threat_summary=f"High-entropy command line strings or Base64 obfuscation detected on `{target_entity}`.",
          hypothesis_h0="Execution reflects benign administrative scripts or package installer hashes.",
          hypothesis_h1="Adversary executing obfuscated Base64 or encrypted command payloads to evade signature rules ($H > 4.5$).",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"Shannon Character Entropy: `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

    # 4. Process Parent-Child Transitions / Living off the Land
    if re.search(r"\b(markov|process\s+transition|parent\s+child|lotl|living\s+off\s+the\s+land|transition\s+rarity)\b", text_corpus):
      defense = (
          f"Alert context on `{target_entity}` indicates anomalous parent-child process lineage. "
          "Applying `MARKOV_TRANSITION_RARITY` computes 2-gram conditional transition surprisal."
      )
      directive = StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="MARKOV_TRANSITION_RARITY",
          directive_query="markov_transition",
          target_entity=target_entity,
          entity_type=entity_type,
          target_metric="file_executions_total",
          investigation_tier=tier,
          threat_summary=f"Rare process parent-child execution sequence on `{target_entity}`.",
          hypothesis_h0="Process lineage represents scheduled maintenance scripts or approved enterprise tools.",
          hypothesis_h1="Anomalous transition surprisal sequence characteristic of Living-off-the-Land execution chaining.",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"Markov Process Transition Rarity: `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

    # 5. Zipfian Power-Law / Long-Tail Rare Administrative Tools & File IoC Ingress
    if re.search(r"\b(zipf|zipfian|long\s+tail|rare\s+binary|rare\s+admin\s+tool|rare\s+process)\b", text_corpus) or (
        "FILE" in udm_events or "files" in udm_events or re.search(r"\b(file\s+ioc|target\.file|sha256|dropper|payload|trojan|malware)\b", text_corpus) or re.search(r"\b(agenttesla|originlogger|redline|vidar|lumma|raccoon|stealer|rat)\b", text_corpus)
    ):
      threat_label = threats[0] if threats else "Malware Dropper / IoC"
      defense = (
          f"Case telemetry on `{target_entity}` indicates binary dropper or file IoC activity ({threat_label}). "
          "Applying `ZIPFIAN_PROCESS_RARITY` evaluates fleet-wide power-law prevalence of executed binaries."
      )
      cands = [
          CandidateHypothesis(
              hypothesis_title="Process Execution × Outbound Network Roll-Up Fusion (`file_executions_total` + `network_bytes_outbound`)",
              selected_skill="secops-risk-metrics-multistage",
              model_name="DUAL_SECTOR_FUSION_3STAGE",
              directive_query="sector_fusion",
              target_metric="file_executions_total",
              fusion_metrics=["file_executions_total", "network_bytes_outbound"],
              hypothesis_h0="Executed binary is a standalone local utility with no external network callback.",
              hypothesis_h1="Anomalous process execution (`file_executions_total` roll-up) is paired with outbound C2/exfiltration bytes (`network_bytes_outbound`).",
              evidentiary_defense="Uses v1.8.0 4-stage roll-up sector fusion to correlate rare binary execution on the host with outbound network bytes.",
              confidence_score=0.79,
          ),
      ]
      directive = StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="ZIPFIAN_PROCESS_RARITY",
          directive_query="zipfian_rarity",
          target_entity=target_entity,
          entity_type=entity_type,
          target_metric="file_executions_total",
          investigation_tier=tier,
          threat_summary=f"File IoC or malicious payload delivery ({threat_label}) targeting `{target_entity}`.",
          hypothesis_h0="Executable binaries on host conform to widely adopted enterprise software baselines.",
          hypothesis_h1=f"Adversary executed long-tail rare binaries or subordinate tools associated with {threat_label} intrusion.",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"Zipfian Long-Tail Process Rarity: `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, cands, executed_signatures, empty_families)

    # 6. Intraday Kinetic Burst / EWMA Acceleration
    if re.search(r"\b(ewma|burst\s+velocity|exponentially\s+weighted|kinetic\s+burst|rate\s+acceleration)\b", text_corpus):
      defense = f"Alert telemetry on `{target_entity}` indicates acute intraday rate acceleration; evaluating EWMA burst velocity."
      directive = StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="EWMA_BURST_VELOCITY",
          directive_query="ewma_burst",
          target_entity=target_entity,
          entity_type=entity_type,
          investigation_tier=tier,
          threat_summary=f"Rapid rate acceleration and kinetic volume burst detected on `{target_entity}`.",
          hypothesis_h0="Telemetry surge reflects scheduled backup operations or batch sync jobs.",
          hypothesis_h1="Kinetic acceleration indicating automated data staging or aggressive scanning.",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"EWMA Kinetic Burst Velocity: `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

    # 7. Circadian von Mises Temporal Anomaly / Off-Hours Access
    if re.search(r"\b(circadian|von\s+mises|off-hours|after-hours|unusual\s+time|temporal\s+departure|temporal\s+anomaly|nighttime|impossible\s+travel|unusual_interval_time)\b", text_corpus) or "kph" in outcomes:
      kph = outcomes.get("kph", "anomalous")
      dist = outcomes.get("distance_kilometers", "geographic")
      circ_metric = "workspace_total_download_actions" if "workspace" in text_corpus else "auth_attempts_total"
      defense = (
          f"UDM detection outcomes on `{target_entity}` report temporal/geographic velocity (`kph={kph}`, `distance={dist}`). "
          f"Applying `CIRCADIAN_VON_MISES` on `{circ_metric}` penalizes hourly volume by circular clock distance."
      )
      directive = StrategyDirective(
          selected_skill="secops-risk-metrics-multistage",
          model_name="CIRCADIAN_VON_MISES",
          directive_query="circadian_von_mises",
          target_entity=target_entity,
          entity_type=entity_type,
          target_metric=circ_metric,
          investigation_tier=tier,
          threat_summary=f"Temporal departure or impossible travel velocity ({kph} km/h, {dist} km) on identity `{target_entity}`.",
          hypothesis_h0="Authentication is a nominal VPN session rotation or authorized concurrent cloud sync.",
          hypothesis_h1="Stolen session token or compromised credential used from an anomalous circadian window.",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"Circadian Temporal Departure (`{circ_metric}`): `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

    # 8. Workspace / Google Drive Hoarding or Change Surge (Situational Non-Auth/Non-Network Metric Selection!)
    if re.search(r"\b(workspace|google\s+drive|drive\s+download|document\s+hoarding|mass\s+download|workspace_total_download_actions)\b", text_corpus):
      ws_metric = "workspace_total_change_actions" if "change" in text_corpus else "workspace_total_download_actions"
      defense = (
          f"Case context specifically implicates Google Workspace / Drive activity on `{target_entity}`. "
          f"Selecting `{ws_metric}` (rather than generic auth/network) and applying `MACD_MOMENTUM_VELOCITY` directly tests 30-day Workspace download/change baselines."
      )
      cands = [
          CandidateHypothesis(
              hypothesis_title=f"Workspace × Network Outbound Fusion (`{ws_metric}` + `network_bytes_outbound`)",
              selected_skill="secops-risk-metrics-multistage",
              model_name="DUAL_SECTOR_FUSION_3STAGE",
              directive_query="sector_fusion",
              target_metric=ws_metric,
              fusion_metrics=[ws_metric, "network_bytes_outbound"],
              hypothesis_h0="Workspace downloads remain local to corporate managed storage.",
              hypothesis_h1=f"Workspace hoarding (`{ws_metric}`) is coupled with outbound network exfiltration (`network_bytes_outbound`).",
              evidentiary_defense=f"Correlates `{ws_metric}` with `network_bytes_outbound` via 3-stage Cross-Vector Fusion.",
              confidence_score=0.80,
          ),
      ]
      directive = StrategyDirective(
          selected_skill="secops-risk-metrics-multistage",
          model_name="MACD_MOMENTUM_VELOCITY",
          directive_query="macd_momentum",
          target_entity=target_entity,
          entity_type=entity_type,
          target_metric=ws_metric,
          investigation_tier=tier,
          threat_summary=f"Google Workspace data hoarding / download acceleration (`{ws_metric}`) on `{target_entity}`.",
          hypothesis_h0=f"Workspace `{ws_metric}` activity reflects normal project file access.",
          hypothesis_h1=f"User `{target_entity}` is executing an anomalous surge in `{ws_metric}` indicative of insider data hoarding.",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"Workspace Velocity Analysis (`{ws_metric}`): `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, cands, executed_signatures, empty_families)

    # 9. MACD Dual-Spine Momentum & Velocity Divergence
    if re.search(r"\b(macd|momentum\s+velocity|dual\s+spine|divergence\s+velocity|acceleration\s+surge)\b", text_corpus):
      chosen_metric = "http_queries_total" if "http" in text_corpus else ("dns_queries_total" if "dns" in text_corpus else "network_bytes_outbound")
      defense = f"Alert specifies dual-spine momentum divergence on `{target_entity}`; evaluating `MACD_MOMENTUM_VELOCITY` on `{chosen_metric}`."
      directive = StrategyDirective(
          selected_skill="secops-risk-metrics-multistage",
          model_name="MACD_MOMENTUM_VELOCITY",
          directive_query="macd_momentum",
          target_entity=target_entity,
          entity_type=entity_type,
          target_metric=chosen_metric,
          investigation_tier=tier,
          threat_summary=f"MACD dual-spine momentum and velocity divergence (`{chosen_metric}`) detected on `{target_entity}`.",
          hypothesis_h0="Volume acceleration conforms to legitimate scheduled workload operations.",
          hypothesis_h1=f"Dual-spine MACD velocity divergence in `{chosen_metric}` revealing active staging of unauthorized egress.",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"MACD Momentum Velocity Divergence (`{chosen_metric}`): `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

    # 10. Cloud Infrastructure / IAM Indicators
    if re.search(r"\b(resource[_\s]+written|resource[_\s]+creation|cloud\s+crud|cloud\s+permissions?|cloud\s+iam|iam\s+modifications?|bucket\s+(change|modification)s?|iam\s+surge|scoutsuite)\b", text_corpus):
      defense = (
          f"Case telemetry on `{target_entity}` indicates cloud resource or IAM mutations. "
          "Applying `CLOUD_CRUD_SURGE` evaluates `resource_creation_total` and `resource_deletion_total` against 30-day baselines."
      )
      directive = StrategyDirective(
          selected_skill="secops-risk-metrics-multistage",
          model_name="CLOUD_CRUD_SURGE",
          directive_query="cloud_crud",
          target_entity=target_entity,
          entity_type=entity_type,
          target_metric="resource_creation_total",
          investigation_tier=tier,
          threat_summary=f"Anomalous Cloud API reconnaissance or IAM modifications by `{target_entity}`.",
          hypothesis_h0="Administrative modifications reflect normal Infrastructure-as-Code deployments.",
          hypothesis_h1="Compromised credentials generating unauthorized service account keys or escalating IAM permissions.",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"Cloud Infrastructure CRUD Surge: `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

    # 11. Elephant Flow Mass Data Extraction
    if re.search(r"\b(elephant\s+flow|mass\s+data\s+extraction|bigquery\s+exfiltration|table\s+dumping|gini\s+concentration)\b", text_corpus):
      defense = f"Case telemetry on `{target_entity}` indicates bulk table dumping or elephant flow concentration."
      directive = StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="ELEPHANT_FLOW_CONCENTRATION",
          directive_query="elephant_flow",
          target_entity=target_entity,
          entity_type=entity_type,
          target_metric="network_bytes_outbound",
          investigation_tier=tier,
          threat_summary=f"Mass data extraction or anomalous egress volume detected on `{target_entity}`.",
          hypothesis_h0="Data access represents standard batch analytical ETL query jobs.",
          hypothesis_h1="Anomalous Pareto / Gini tail concentration in egress volume indicating unauthorized table dumping.",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"Elephant Flow Concentration: `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

    # 12. User Entity / General Insider Threat / Baseline Drift
    if entity_type in ("USER", "USER_ID", "EMAIL") or re.search(r"\b(insider|lateral|exfiltration|data\s+hoarding|unusual\s+access|privilege\s+surge)\b", text_corpus):
      defense = (
          f"Entity `{target_entity}` is a user identity with general behavioral risk indicators. "
          "Running the 6-spoke `360_DECOUPLED_RADAR` establishes 30-day Z-scores across Auth, Cloud, Workspace, Egress, DNS, and Web."
      )
      directive = StrategyDirective(
          selected_skill="secops-risk-metrics-multistage",
          model_name="360_DECOUPLED_RADAR",
          directive_query="profile_360_risk",
          target_entity=target_entity,
          entity_type=entity_type,
          investigation_tier=tier,
          threat_summary=f"Behavioral departure investigation across user `{target_entity}` telemetry.",
          hypothesis_h0="User activity across Auth, Cloud, Workspace, Egress, DNS, and Web conforms to historical 30-day baseline.",
          hypothesis_h1="Multi-sector behavioral drift indicating insider threat, token theft, or lateral account movement.",
          selection_rationale=defense,
          evidentiary_defense=defense,
          flight_card_title=f"360° Decoupled Behavioral Radar: `{target_entity}`",
      )
      return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

    # 13. Generic Fallback
    defense = f"Autonomous investigation across UDM telemetry for `{target_entity}`."
    directive = StrategyDirective(
        selected_skill="secops-statistical-hunter",
        model_name="GEMINI_REACT_AUTONOMOUS",
        directive_query="auto",
        target_entity=target_entity,
        entity_type=entity_type,
        investigation_tier=tier,
        threat_summary=f"Investigation into alert activity on `{target_entity}`.",
        hypothesis_h0="Telemetry conforms to benign operational activity.",
        hypothesis_h1="Telemetry contains statistical outliers or unauthorized access patterns.",
        selection_rationale=defense,
        evidentiary_defense=defense,
        flight_card_title=f"Autonomous Security Triage: `{target_entity}`",
    )
    return cls._finalize_directive_with_confidence(directive, ctx, [], executed_signatures, empty_families)

  @staticmethod
  def decide(
      case_title: str = "",
      alert_name: str = "",
      alert_desc: str = "",
      entity_type: str = "USER",
  ) -> Tuple[str, str, str]:
    """Synchronous backward-compatibility method."""
    ctx = {
        "case_title": case_title,
        "alerts": [alert_name],
        "case_description": alert_desc,
        "entity_type": entity_type,
        "primary_entity": "target_entity",
    }
    directive = StrategyDecider._deterministic_reasoner(ctx)
    return directive.selected_skill, directive.directive_query, directive.model_name

# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Strategy decider for mapping security alerts and entities to optimal threat hunt strategies."""

from typing import Tuple


class StrategyDecider:
  """Inspects alert context and entity type to select the optimal threat hunt strategy."""

  @staticmethod
  def decide(
      case_title: str = "",
      alert_name: str = "",
      alert_desc: str = "",
      entity_type: str = "USER",
  ) -> Tuple[str, str, str]:
    """Returns (skill_name, directive_query, model_name)."""
    context = f"{case_title} {alert_name} {alert_desc}".lower()

    # 1. Network / C2 Beaconing Indicators
    if any(k in context for k in ("beacon", "jitter", "c2", "command and control", "periodic connection", "outbound regularity")):
      return "secops-statistical-hunter", "c2_jitter", "C2_BEACONING_JITTER"

    # 2. Credential Spray / Burst Login Indicators
    if any(k in context for k in ("spray", "brute force", "failed login surge", "poisson", "fano")):
      return "secops-statistical-hunter", "poisson_burst", "POISSON_BURST_CLUSTERING"

    # 3. Cloud Infrastructure / IAM Indicators
    if any(k in context for k in ("resource_written", "resource_creation", "cloud crud", "cloud permission", "bucket change", "iam surge")):
      return "secops-risk-metrics-multistage", "cloud_crud", "CLOUD_CRUD_SURGE"

    # 4. User Entity / General Insider Threat / Baseline Drift
    if entity_type in ("USER", "USER_ID", "EMAIL") or any(k in context for k in ("insider", "lateral", "exfiltration", "data hoarding", "unusual access", "privilege surge")):
      return "secops-risk-metrics-multistage", "profile_360_risk", "360_DECOUPLED_RADAR"

    # 5. Open-ended / Ad-Hoc Alert Directive (Gemini ReAct)
    return "auto", f"Investigate alert '{alert_name}': {alert_desc}", "GEMINI_REACT_AUTONOMOUS"

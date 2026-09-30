# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Agentic Strategy Reasoner for SecOps Threat Hunting.

Ingests rich multi-source context (Case metadata, Alert outcomes, GCTI findings,
and raw UDM connector events) to identify attacker touchpoints, formulate testable
hypotheses (H0 vs H1), and select optimal analytical models across SecOps Risk Metrics
and Statistical Outlier Hunter engines.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from google import genai
from google.genai import types
from src.models import StrategyDirective

logger = logging.getLogger("AgenticStrategyReasoner")


class StrategyDecider:
  """Agentic Strategy Reasoner that formulates threat hypotheses from UDM touchpoints."""

  @classmethod
  async def decide_agentic(
      cls,
      case_info: Dict[str, Any],
      alerts: List[Dict[str, Any]],
      connector_events: List[Dict[str, Any]],
      default_entity: Optional[str] = None,
      default_entity_type: str = "USER",
  ) -> StrategyDirective:
    """Agentically analyzes case, alert, and UDM telemetry to formulate a hunting directive."""
    case_title = case_info.get("displayName") or case_info.get("title", "")
    case_desc = case_info.get("description", "")
    case_id = str(case_info.get("id") or case_info.get("name", "").split("/")[-1])

    # Extract Touchpoints from Alerts
    alert_names = [a.get("displayName") or a.get("name", "") for a in alerts]
    alert_descriptions = [a.get("description", "") for a in alerts if a.get("description")]
    rule_generators = [a.get("ruleGenerator", "") for a in alerts if a.get("ruleGenerator")]

    # Extract Touchpoints from UDM Connector Events
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

      # Check threat associations
      for k, v in fields.items():
        if "threat" in k and "name" in k and v:
          threat_associations.add(str(v))
        if "detection_outcomes" in k and v:
          short_k = k.replace("detection_outcomes_", "")
          outcome_metrics[short_k] = str(v)

      # User extraction
      u = fields.get("event_target_user_emailAddresses_1") or fields.get("event_principal_user_userid")
      if u:
        extracted_users.add(str(u).lower())

      # Host extraction
      h = fields.get("event_principal_hostname") or fields.get("event_principal_asset_hostname")
      if h:
        extracted_hosts.add(str(h).lower())

      # IP extraction
      ip = fields.get("event_principal_asset_ip_1") or fields.get("event_principal_ip_1")
      if ip:
        extracted_ips.add(str(ip))

    # Resolve primary entity
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

    # Context Bundle for Reasoning
    context_summary = {
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
        "primary_entity": target_entity,
        "entity_type": entity_type,
    }

    # 1. Attempt LLM Reasoning via Gemini 2.5
    llm_directive = await cls._reason_with_gemini(context_summary)
    if llm_directive:
      return llm_directive

    # 2. Deterministic Fallback Reasoner (UDM-aware, regex-safe)
    return cls._deterministic_reasoner(context_summary)

  @classmethod
  async def _reason_with_gemini(cls, ctx: Dict[str, Any]) -> Optional[StrategyDirective]:
    """Uses Gemini to reason about the UDM touchpoints and form hypotheses."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
      return None

    try:
      client = genai.Client()
      prompt = f"""You are a Lead SecOps Detection Engineer and UEBA Threat Hunter.
Analyze the following security incident context, alerts, and UDM connector event touchpoints:

{json.dumps(ctx, indent=2)}

Available Analytical Engines & Models:
1. Engine: secops-statistical-hunter
   - C2_BEACONING_JITTER: Inverted CV regularity on outbound network flows. Use when outbound network connections or malicious downloads (infostealers, RATs, droppers) are observed.
   - POISSON_BURST_CLUSTERING: Fano Factor dispersion (variance-to-mean ratio) on authentication bursts or failed SU/login spikes.
   - SHANNON_CHARACTER_ENTROPY: Character entropy on suspicious command lines, Base64 strings, or obfuscated scripts.
   - MARKOV_TRANSITION_RARITY: Parent-child process transition surprisal for Living-off-the-Land (LotL) execution.
   - ZIPFIAN_PROCESS_RARITY: Long-tail rarity on administrative binaries and utility invocations across fleet.
   - EWMA_BURST_VELOCITY: Exponentially weighted moving average velocity bursts on kinetic telemetry.
   - ELEPHANT_FLOW_CONCENTRATION: Pareto / Gini concentration on massive data exfiltration or BigQuery extracts.

2. Engine: secops-risk-metrics-multistage
   - 360_DECOUPLED_RADAR: Multi-sector 30-day baseline drift across Auth, Cloud, Workspace, Egress, and DNS.
   - CIRCADIAN_VON_MISES: Angular temporal departure from historical user working hours (e.g. Impossible Travel off-hours access).
   - CLOUD_CRUD_SURGE: Z-score spikes on cloud resource creation/deletion, IAM key minting, or permission updates.
   - MACD_MOMENTUM_VELOCITY: Dual-spine MACD momentum velocity on rapidly accelerating user or service account activity.

Formulate the threat touchpoints, state the Null Hypothesis (H0: benign baseline explanation) and Alternative Threat Hypothesis (H1: attacker execution / exfiltration pivot), and select the optimal model.

Output must be valid JSON matching this schema:
{{
  "selected_skill": "secops-statistical-hunter" | "secops-risk-metrics-multistage",
  "model_name": "<EXACT_MODEL_NAME_FROM_LIST>",
  "directive_query": "<query_key_e.g._c2_jitter_or_poisson_burst_or_profile_360_risk>",
  "target_entity": "{ctx['primary_entity']}",
  "entity_type": "{ctx['entity_type']}",
  "threat_summary": "<concise summary of identified threat problem and UDM touchpoints>",
  "hypothesis_h0": "<the benign baseline explanation being tested>",
  "hypothesis_h1": "<the attacker threat pivot hypothesis being tested>",
  "selection_rationale": "<why this mathematical test was chosen based on the telemetry>",
  "flight_card_title": "<professional title for SOC Case Wall card>"
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
        return StrategyDirective(**data)
    except Exception as e:
      logger.debug(f"Gemini strategy reasoning bypassed: {e}")
      return None

  @classmethod
  def _deterministic_reasoner(cls, ctx: Dict[str, Any]) -> StrategyDirective:
    """Robust, regex-safe, UDM-aware heuristic reasoner."""
    text_corpus = (
        f"{ctx.get('case_title', '')} "
        f"{ctx.get('case_description', '')} "
        f"{' '.join(ctx.get('alerts', []))} "
        f"{' '.join(ctx.get('rule_generators', []))} "
        f"{' '.join(ctx.get('threat_associations', []))}"
    ).lower()

    udm_events = ctx.get("udm_event_types", [])
    udm_logs = ctx.get("udm_log_types", [])
    target_entity = ctx.get("primary_entity", "unknown")
    entity_type = ctx.get("entity_type", "USER")
    threats = ctx.get("threat_associations", [])
    outcomes = ctx.get("outcome_metrics", {})

    # 1. Network / C2 Beaconing Indicators (timing regularity, periodic beaconing, C2 framework)
    if re.search(r"\b(beacon|beaconing|jitter|command\s+and\s+control|periodic\s+connection|outbound\s+regularity)\b", text_corpus) or (
        re.search(r"\bc2\b", text_corpus) and "ec2" not in text_corpus
    ):
      threat_label = threats[0] if threats else "Command & Control"
      return StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="C2_BEACONING_JITTER",
          directive_query="c2_jitter",
          target_entity=target_entity,
          entity_type=entity_type,
          threat_summary=f"Host `{target_entity}` associated with {threat_label} periodic network communication or C2 telemetry.",
          hypothesis_h0="Outbound network connections originate from stochastic application background traffic ($CV > 0.30$).",
          hypothesis_h1="Host established automated, low-jitter periodic polling to external C2 exfiltration infrastructure ($CV \\le 0.30$).",
          selection_rationale="Applied Inverted Coefficient of Variation regularity modeling over sliding outbound network flows.",
          flight_card_title=f"C2 Beaconing Jitter Analysis: `{target_entity}`",
      )

    # 2. Credential Spray / Burst Login Indicators / Credential Stealer on Identity
    if re.search(r"\b(spray|brute\s+force|failed\s+login\s+surge|poisson|fano|mimikatz|pwdump|credential\s+theft)\b", text_corpus) or (
        "USER_LOGIN" in udm_events and ("fail" in text_corpus or "excessive" in text_corpus)
    ) or (
        entity_type in ("USER", "USER_ID", "EMAIL") and re.search(r"\b(agenttesla|stealer|infostealer|keylogger)\b", text_corpus)
    ):
      return StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="POISSON_BURST_CLUSTERING",
          directive_query="poisson_burst",
          target_entity=target_entity,
          entity_type=entity_type,
          threat_summary=f"Excessive authentication failures or credential spray attempts targeting `{target_entity}`.",
          hypothesis_h0="Failures stem from benign user password expiration or expired cached credentials ($Fano \\le 4.0$).",
          hypothesis_h1="Identity subjected to automated, high-dispersion Poisson credential spray bursts ($Fano > 4.0$).",
          selection_rationale="Fano Factor dispersion ($F = \\sigma^2 / \\mu$) evaluation over hourly authentication bins.",
          flight_card_title=f"Poisson Burst Clustering: `{target_entity}`",
      )

    # 3. Information-Theoretic: Obfuscated Command Line / High Entropy
    if re.search(r"\b(entropy|shannon|obfuscated|base64|obfuscation|encoded\s+command)\b", text_corpus):
      return StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="SHANNON_CHARACTER_ENTROPY",
          directive_query="shannon_entropy",
          target_entity=target_entity,
          entity_type=entity_type,
          threat_summary=f"High-entropy command line strings or Base64 obfuscation detected on `{target_entity}`.",
          hypothesis_h0="Execution reflects benign administrative scripts or package installer hashes.",
          hypothesis_h1="Adversary executing obfuscated Base64 or encrypted command payloads to evade signature rules ($H > 4.5$).",
          selection_rationale="Shannon Character-Class Entropy ($H = -\\sum p_i \\log_2 p_i$) measurement on process command lines.",
          flight_card_title=f"Shannon Character Entropy: `{target_entity}`",
      )

    # 4. Process Parent-Child Transitions / Living off the Land
    if re.search(r"\b(markov|process\s+transition|parent\s+child|lotl|living\s+off\s+the\s+land|transition\s+rarity)\b", text_corpus):
      return StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="MARKOV_TRANSITION_RARITY",
          directive_query="markov_transition",
          target_entity=target_entity,
          entity_type=entity_type,
          threat_summary=f"Rare process parent-child execution sequence on `{target_entity}`.",
          hypothesis_h0="Process lineage represents scheduled maintenance scripts or approved enterprise tools.",
          hypothesis_h1="Anomalous transition surprisal sequence characteristic of Living-off-the-Land execution chaining.",
          selection_rationale="Markov 2-Gram transition rarity and surprisal score on process execution chains.",
          flight_card_title=f"Markov Process Transition Rarity: `{target_entity}`",
      )

    # 5. Zipfian Power-Law / Long-Tail Rare Administrative Tools & File IoC Ingress
    if re.search(r"\b(zipf|zipfian|long\s+tail|rare\s+binary|rare\s+admin\s+tool|rare\s+process)\b", text_corpus) or (
        "FILE" in udm_events or "files" in udm_events or re.search(r"\b(file\s+ioc|target\.file|sha256|dropper|payload|trojan|malware)\b", text_corpus) or re.search(r"\b(agenttesla|originlogger|redline|vidar|lumma|raccoon|stealer|rat)\b", text_corpus)
    ):
      threat_label = threats[0] if threats else "Malware Dropper / IoC"
      return StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="ZIPFIAN_PROCESS_RARITY",
          directive_query="zipfian_rarity",
          target_entity=target_entity,
          entity_type=entity_type,
          threat_summary=f"File IoC or malicious payload delivery ({threat_label}) targeting `{target_entity}`.",
          hypothesis_h0="Executable binaries on host conform to widely adopted enterprise software baselines.",
          hypothesis_h1=f"Adversary executed long-tail rare binaries or subordinate tools associated with {threat_label} intrusion.",
          selection_rationale="Zipfian power-law fleet distribution over executable images following file IoC ingress.",
          flight_card_title=f"Zipfian Long-Tail Process Rarity: `{target_entity}`",
      )

    # 6. Intraday Kinetic Burst / EWMA Acceleration
    if re.search(r"\b(ewma|burst\s+velocity|exponentially\s+weighted|kinetic\s+burst|rate\s+acceleration)\b", text_corpus):
      return StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="EWMA_BURST_VELOCITY",
          directive_query="ewma_burst",
          target_entity=target_entity,
          entity_type=entity_type,
          threat_summary=f"Rapid rate acceleration and kinetic volume burst detected on `{target_entity}`.",
          hypothesis_h0="Telemetry surge reflects scheduled backup operations or batch sync jobs.",
          hypothesis_h1="Kinetic acceleration indicating automated data staging or aggressive scanning.",
          selection_rationale="Exponentially Weighted Moving Average (EWMA) trailing rate velocity modeling.",
          flight_card_title=f"EWMA Kinetic Burst Velocity: `{target_entity}`",
      )

    # 7. Circadian von Mises Temporal Anomaly / Off-Hours Access
    if re.search(r"\b(circadian|von\s+mises|off-hours|after-hours|unusual\s+time|temporal\s+departure|temporal\s+anomaly|nighttime|impossible\s+travel|unusual_interval_time)\b", text_corpus) or "kph" in outcomes:
      kph = outcomes.get("kph", "anomalous")
      dist = outcomes.get("distance_kilometers", "geographic")
      return StrategyDirective(
          selected_skill="secops-risk-metrics-multistage",
          model_name="CIRCADIAN_VON_MISES",
          directive_query="circadian_von_mises",
          target_entity=target_entity,
          entity_type=entity_type,
          threat_summary=f"Temporal departure or impossible travel velocity ({kph} km/h, {dist} km) on identity `{target_entity}`.",
          hypothesis_h0="Authentication is a nominal VPN session rotation or authorized concurrent cloud sync.",
          hypothesis_h1="Stolen session token or compromised credential used from an anomalous circadian window.",
          selection_rationale="Evaluated angular time-of-day departure against historical user activity baseline.",
          flight_card_title=f"Circadian Temporal Departure: `{target_entity}`",
      )

    # 8. MACD Dual-Spine Momentum & Velocity Divergence
    if re.search(r"\b(macd|momentum\s+velocity|dual\s+spine|divergence\s+velocity|acceleration\s+surge)\b", text_corpus):
      return StrategyDirective(
          selected_skill="secops-risk-metrics-multistage",
          model_name="MACD_MOMENTUM_VELOCITY",
          directive_query="macd_momentum",
          target_entity=target_entity,
          entity_type=entity_type,
          threat_summary=f"MACD dual-spine momentum and velocity divergence detected on `{target_entity}`.",
          hypothesis_h0="Volume acceleration conforms to legitimate scheduled workload operations.",
          hypothesis_h1="Dual-spine MACD velocity divergence revealing active staging of unauthorized egress.",
          selection_rationale="Short-term (12h) vs Long-term (26h) MACD signal line momentum divergence.",
          flight_card_title=f"MACD Momentum Velocity Divergence: `{target_entity}`",
      )

    # 9. Cloud Infrastructure / IAM Indicators
    if re.search(r"\b(resource[_\s]+written|resource[_\s]+creation|cloud\s+crud|cloud\s+permissions?|cloud\s+iam|iam\s+modifications?|bucket\s+(change|modification)s?|iam\s+surge|scoutsuite)\b", text_corpus):
      return StrategyDirective(
          selected_skill="secops-risk-metrics-multistage",
          model_name="CLOUD_CRUD_SURGE",
          directive_query="cloud_crud",
          target_entity=target_entity,
          entity_type=entity_type,
          threat_summary=f"Anomalous Cloud API reconnaissance or IAM modifications by `{target_entity}`.",
          hypothesis_h0="Administrative modifications reflect normal Infrastructure-as-Code deployments.",
          hypothesis_h1="Compromised credentials generating unauthorized service account keys or escalating IAM permissions.",
          selection_rationale="Z-Score velocity evaluation on 30-day baseline `metrics.cloud_resources_written`.",
          flight_card_title=f"Cloud Infrastructure CRUD Surge: `{target_entity}`",
      )

    # 10. Elephant Flow Mass Data Extraction
    if re.search(r"\b(elephant\s+flow|mass\s+data\s+extraction|bigquery\s+exfiltration|table\s+dumping|gini\s+concentration)\b", text_corpus):
      return StrategyDirective(
          selected_skill="secops-statistical-hunter",
          model_name="ELEPHANT_FLOW_CONCENTRATION",
          directive_query="elephant_flow",
          target_entity=target_entity,
          entity_type=entity_type,
          threat_summary=f"Mass data extraction or anomalous egress volume detected on `{target_entity}`.",
          hypothesis_h0="Data access represents standard batch analytical ETL query jobs.",
          hypothesis_h1="Anomalous Pareto / Gini tail concentration in egress volume indicating unauthorized table dumping.",
          selection_rationale="Elephant Flow Gini concentration index across query results and network egress.",
          flight_card_title=f"Elephant Flow Concentration: `{target_entity}`",
      )

    # 11. User Entity / General Insider Threat / Baseline Drift
    if entity_type in ("USER", "USER_ID", "EMAIL") or re.search(r"\b(insider|lateral|exfiltration|data\s+hoarding|unusual\s+access|privilege\s+surge)\b", text_corpus):
      return StrategyDirective(
          selected_skill="secops-risk-metrics-multistage",
          model_name="360_DECOUPLED_RADAR",
          directive_query="profile_360_risk",
          target_entity=target_entity,
          entity_type=entity_type,
          threat_summary=f"Behavioral departure investigation across user `{target_entity}` telemetry.",
          hypothesis_h0="User activity across Auth, Cloud, Workspace, and Egress conforms to historical 30-day baseline.",
          hypothesis_h1="Multi-sector behavioral drift indicating insider threat, token theft, or lateral account movement.",
          selection_rationale="Decoupled 5-Sector Euclidean distance ($D = \\sqrt{\\sum Z_i^2}$) against 30-day personal baseline.",
          flight_card_title=f"360° Decoupled Behavioral Radar: `{target_entity}`",
      )

    # 12. Generic Fallback
    return StrategyDirective(
        selected_skill="secops-statistical-hunter",
        model_name="GEMINI_REACT_AUTONOMOUS",
        directive_query="auto",
        target_entity=target_entity,
        entity_type=entity_type,
        threat_summary=f"Investigation into alert activity on `{target_entity}`.",
        hypothesis_h0="Telemetry conforms to benign operational activity.",
        hypothesis_h1="Telemetry contains statistical outliers or unauthorized access patterns.",
        selection_rationale="Autonomous investigation using Gemini ReAct tool loop.",
        flight_card_title=f"Autonomous Security Triage: `{target_entity}`",
    )

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

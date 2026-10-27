# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Dynamic Protocol Adapter for Agentic UEBA (Strategy 2).

Ingests canonical threat hunting skills from an external, read-only SKILLS_ROOT,
preserves 100% of the domain intelligence (compiler invariants, AST syntax rules,
mathematical models, and query templates), and dynamically substitutes the
human-in-the-loop 3-state conversational lifecycle with an autonomous JIT
execution contract.
"""

import logging
import os
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("DynamicProtocolAdapter")

# The unified autonomous JIT protocol injected into every adapted skill.
AUTONOMOUS_JIT_PROTOCOL = """
## ⚡ AUTONOMOUS JIT EXECUTION PROTOCOL (PRE-APPROVED)

1. PRE-APPROVED EXECUTION MANDATE:
   - You are operating in autonomous JIT mode on behalf of a SecOps Playbook or Incident Response case.
   - You have FULL PRE-APPROVAL. DO NOT ask for clearance, DO NOT prompt for Mode A vs Mode B, and DO NOT halt after syntax verification.
   - Anti-Auth defaulting breaks and consultative pauses are SUSPENDED. Proceed directly to investigation.

2. TWO-STEP INVESTIGATION PIPELINE:
   - Step 1 (Syntax/Availability Verification): Execute exactly ONE 1-shot compiler probe via `udm_search(..., maxEvents=1)` with strict ISO 8601 UTC timestamps.
   - Step 2 (Direct Multi-Stage Execution): Immediately dispatch the assembled multi-stage YARA-L query via `udm_search`.
   - Step 3 (Forensic Augmentation):
     * If 5 risk dimensions are calculated, invoke `generate_behavioral_radar`.
     * If investigating a specific Case ID and `post_to_case_wall=true`, call `create_case_comment` with the final report.

3. DUAL OUTPUT CONTRACT:
   Your final response MUST include BOTH:
   a) A machine-readable ```json_triage ... ``` code block adhering to the triage schema.
   b) The canonical 6-section human-readable forensic report with KaTeX math and Unicode visual bars.

4. COMPILER & AST INVARIANTS REMAIN 100% BINDING:
   All AST syntax constraints, match variable bindings ($user, $host by 1d), safe dispersion floors,
   and template assembly rules defined below are non-negotiable.

5. NATIVE GOOGLE SECOPS ARCHITECTURE (ZERO BIGQUERY DEPENDENCY):
   - All UDM event telemetry, Entity Context Graph (`graph.*`), and 30-day behavioral baselines (`metrics.*`) are computed, stored, and queried 100% natively within Google SecOps.
   - BigQuery does NOT drive, store, or back Google SecOps UEBA in any capacity whatsoever. If BigQuery disappeared tomorrow, it would have zero impact on SecOps UEBA.
   - Never state, imply, or explain that SecOps UEBA or `metrics.*` relies on external warehouse summary tables. BigQuery is solely a monitored customer cloud resource (e.g., `bigquery.googleapis.com` in GCP audit logs) that could be the target of an attack.

6. BILATERAL UEBA HARNESS & TELEMETRY PHYSICS GUARDRAIL (`metrics.*` + `stats-hunter` + `agentic_ueba`):
   - **Never Declare UEBA a Poor Fit**: Never dismiss UEBA for an exploit, vulnerability, CTI report, or detection gap (e.g., `http2shell`, web-to-shell, living-off-the-land, Shadow AI) because `metrics.*` is bucketed `by 1d` and cannot measure sub-hour correlations. Instead, synthesize a multi-horizon **Bilateral UEBA Harness**:
     * **Macro Plane (`secops-risk-metrics-multistage`, 30d `by 1d`)**: Owns all 30-day volumetric/failure baselines (`metrics.*`), peer cohorts, CUSUM slow drift, 360° sweeps, Entity Context Graph prevalence (`rolling_max <= 3`), and same-entity multi-sector fusion.
     * **Micro / Windowed Plane (`secops-statistical-hunter`, raw `UDM_EVENTS`)**: Owns short-window correlations (`by 5m`, `by 1h`, `by 2h`, `by 1d` over bounded 1h–24h windows for high-volume logs or 7d–14d for sparse/filtered events) and structural models that daily `metrics.*` counters cannot measure: parent-to-child process lineage (`MARKOV_2GRAM_TRANSITION_RARITY`), CLI/URI obfuscation (`SHANNON_ENTROPY_CHARACTER`), sub-hour burst clustering (`POISSON_BURST_CLUSTERING` / `EWMA_BURST_VELOCITY`), callback jitter (`C2_BEACONING_JITTER`), and long-tail rarity (`ZIPFIAN_PROCESS_RARITY`).
     * **Strict Telemetry Physics & Window Guardrail**: NEVER use `secops-statistical-hunter` for 30-day baselines over high-volume telemetry (`VPC flow logs`, `DNS`, `HTTP`, `Auth`, or `Process` counts). Raw 30-day scans over high-volume logs hit the 1M row scan cap or time out; all 30-day volumetric baselines belong strictly to `secops-risk-metrics-multistage` (`metrics.*`).
     * **Connective Tissue (`agentic_ueba` / `PlaybookRunner`)**: Chain macro and micro stages via Option 1 (In-DAG Piecewise Unification), Option 2 (Upstream Candidate Entity/IP Seeding `/* UPSTREAM_CANDIDATE_IPS */`), or Option 3 (Native UDM Loopback `metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"` requiring >= 2 distinct hits and sum(Z_i^2) >= 25.0).
"""


class DynamicProtocolAdapter:
  """Adapts canonical human-facing SecOps skills into autonomous JIT engine personas."""

  _BQ_BACKEND_PATTERNS = (
      (re.compile(r"pre-computed\s+BigQuery\s+summary\s+tables", re.I), "native SecOps pre-computed Risk Analytics metric stores"),
      (re.compile(r"pre-computed\s+BigQuery\s+roll-up\s+pipelines", re.I), "native SecOps pre-computed roll-up pipelines"),
      (re.compile(r"BigQuery\s+summary\s+tables", re.I), "native SecOps Risk Analytics metric stores"),
      (re.compile(r"BigQuery\s+roll-up\s+pipelines", re.I), "native SecOps pre-computed roll-up pipelines"),
      (re.compile(r"(?<!zero\s)(?<!no\s)BigQuery\s+backend", re.I), "native SecOps backend"),
  )

  @classmethod
  def sanitize_bq_backend_references(cls, text: str) -> str:
    """Strips any language implying BigQuery backs or drives SecOps UEBA storage/compute."""
    if not text:
      return ""
    cleaned = text
    for pat, repl in cls._BQ_BACKEND_PATTERNS:
      cleaned = pat.sub(repl, cleaned)
    return cleaned

  def __init__(self, skills_root: Path):
    self.skills_root = Path(skills_root)

  def get_skill_path(self, skill_name: str) -> Path:
    """Finds canonical skill directory under SKILLS_ROOT."""
    candidates = [
        self.skills_root / skill_name,
        self.skills_root / "projects" / skill_name,
        self.skills_root / f"secops-{skill_name}",
    ]
    for c in candidates:
      if c.is_dir() and (c / "SKILL.md").exists():
        return c
    raise FileNotFoundError(
        f"Skill '{skill_name}' not found under SKILLS_ROOT: {self.skills_root}"
    )

  @staticmethod
  def _extract_preserved_domain_sections(lifecycle_block: str) -> str:
    """Extracts non-interactive domain intelligence embedded inside the 3-state lifecycle block."""
    preserved: List[str] = []

    # 1. secops-risk-metrics-multistage v2.1.3: 360° Radar & CTI/Threat Report Mapping
    radar_cti_match = re.search(
        r"(### 🕸️ 360° Entity Behavioral Risk Radar & Multi-Sector Threat Fusion.*?)(?=### 🔍 Phase 1B:|$)",
        lifecycle_block,
        re.DOTALL,
    )
    if radar_cti_match:
      block = radar_cti_match.group(1).strip()
      block = re.sub(
          r"\s*\*\*Transition Directly to Phase 1B\*\*:[^\n]*",
          "",
          block,
      )
      preserved.append(block)

    # 2. secops-statistical-hunter v2.8.3: Bilateral UEBA Harness Co-Execution
    coexec_match = re.search(
        r"(- \*\*Bilateral UEBA Harness Co-Execution\*\*:[^\n]+)",
        lifecycle_block,
    )
    if coexec_match:
      preserved.append("### 🤝 Bilateral UEBA Harness Co-Execution\n" + coexec_match.group(1).strip())

    # 3. secops-statistical-hunter v2.8.3: Template-First Formulation Directive
    tpl_match = re.search(
        r"(\* \*Template-First Formulation Directive\*:.*?)(?=\s*\* \*Canonical Pre-Flight Specification Card Structure\*:|$)",
        lifecycle_block,
        re.DOTALL,
    )
    if tpl_match:
      preserved.append(tpl_match.group(1).strip())

    # 4. secops-statistical-hunter v2.8.3: 6 Mandatory Root Outcome Variables & Affirmative Compiler Grammar
    grammar_match = re.search(
        r"(\* \*6 Mandatory Root Outcome Variables Protocol\*:.*?)(?=\n5\. \*\*Compile-Time Verification Protocol|$)",
        lifecycle_block,
        re.DOTALL,
    )
    if grammar_match:
      preserved.append(grammar_match.group(1).strip())

    # 5. secops-statistical-hunter v2.8.3: Strict Visual Axis-Type Isolation & Post-Query Verification
    visual_match = re.search(
        r"(## 🎨 Strict Visual Axis-Type Isolation & Post-Query Verification.*?)(?=\n---\s*$|$)",
        lifecycle_block,
        re.DOTALL,
    )
    if visual_match:
      preserved.append(visual_match.group(1).strip())

    return "\n\n".join(preserved)

  def adapt_skill_text(self, raw_skill_md: str) -> str:
    """Strips the interactive human-in-the-loop turn machine and injects JIT protocol."""
    # Pattern to match the interactive 3-state lifecycle block
    pattern = re.compile(
        r"## 🔄 (?:THE )?3-STATE ACTIVE HUNT LIFECYCLE.*?(?=## 🛡️ Non-Negotiable Execution)",
        re.DOTALL,
    )
    match = pattern.search(raw_skill_md)
    if match:
      preserved_domain = self._extract_preserved_domain_sections(match.group(0))
      replacement = AUTONOMOUS_JIT_PROTOCOL.rstrip()
      if preserved_domain:
        replacement = f"{replacement}\n\n{preserved_domain}"
      adapted = (
          raw_skill_md[: match.start()]
          + replacement
          + "\n\n"
          + raw_skill_md[match.end() :]
      )
      logger.info("Successfully swapped 3-state lifecycle with Autonomous JIT Protocol.")
      return adapted

    logger.warning(
        "3-state lifecycle demarcation not found; appending JIT protocol to bottom."
    )
    return raw_skill_md + "\n\n" + AUTONOMOUS_JIT_PROTOCOL

  def load_templates(self, skill_dir: Path) -> str:
    """Loads all .yl2 pipeline templates from the skill's templates/ directory."""
    tpl_dir = skill_dir / "templates"
    if not tpl_dir.is_dir():
      logger.warning(f"No templates directory found at {tpl_dir}")
      return ""

    blocks = []
    for p in sorted(tpl_dir.rglob("*.yl2")):
      if p.is_file():
        rel = p.relative_to(skill_dir)
        try:
          content = p.read_text(encoding="utf-8").rstrip()
          blocks.append(f"--- TEMPLATE FILE: {rel} ---\n{content}")
        except Exception as e:
          logger.warning(f"Failed reading template {p}: {e}")

    if not blocks:
      return ""

    return (
        "=== [CANONICAL TEMPLATE LIBRARY: ASSEMBLE FROM THESE] ===\n"
        "Multi-stage queries MUST assemble from these templates rather than from memory.\n\n"
        + "\n\n".join(blocks)
        + "\n=======================================================\n"
    )

  def load_references(self, skill_dir: Path, target_refs: Optional[List[str]] = None) -> str:
    """Loads companion reference guides from the skill's references/ directory."""
    ref_dir = skill_dir / "references"
    if not ref_dir.is_dir():
      return ""

    blocks = []
    EXCLUDED_REFS = {"consultative-worksheet.md", "interaction-flow-template.md"}
    hybrid_engine_script = skill_dir / "scripts" / "ueba_hybrid_engine.py"
    if (
        hybrid_engine_script.is_file()
        and os.environ.get("SECOPS_DISABLE_HYBRID_TOOLS") != "1"
        and os.environ.get("SECOPS_HYBRID_FULL_MARKDOWN") != "1"
    ):
      EXCLUDED_REFS = EXCLUDED_REFS | {
          "metrics-catalog.md",
          "udm-hunting-field-dictionary.md",
          "malachite-function-factory-matrix.md",
          "calibrated-risk-index-guide.md",
          "chart-specifications-guide.md",
          "clean-handoff-udm-schema.md",
      }
    if target_refs:
      paths = [ref_dir / r if not r.endswith(".md") else ref_dir / r for r in target_refs]
    else:
      paths = sorted([p for p in ref_dir.rglob("*.md") if p.name not in EXCLUDED_REFS])

    for p in paths:
      if p.is_file():
        try:
          rel_name = str(p.relative_to(ref_dir))
          content = p.read_text(encoding="utf-8").strip()
          blocks.append(f"=== [REFERENCE: {rel_name}] ===\n{content}\n==============================")
        except Exception as e:
          logger.warning(f"Failed reading reference {p}: {e}")

    return "\n\n".join(blocks)

  def build_jit_persona(
      self,
      skill_name: str,
      project_id: str,
      customer_id: str,
      region: str,
      include_templates: bool = True,
      include_references: bool = True,
  ) -> str:
    """Builds a complete, self-contained JIT persona with tenant binding."""
    skill_dir = self.get_skill_path(skill_name)
    raw_md = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    
    adapted_skill = self.sanitize_bq_backend_references(self.adapt_skill_text(raw_md))
    template_section = self.sanitize_bq_backend_references(self.load_templates(skill_dir)) if include_templates else ""
    reference_section = self.sanitize_bq_backend_references(self.load_references(skill_dir)) if include_references else ""

    return f"""You are an autonomous Google SecOps JIT Threat Hunting Agent.

### ENVIRONMENT CONFIGURATION (MANDATORY TENANT BINDING) ###
Whenever a tool asks for routing parameters, you MUST supply these exact values:
- projectId: "{project_id}"
- region: "{region}"
- customerId: "{customer_id}"

{adapted_skill}

{template_section}

{reference_section}
""".strip()

  def build_bilateral_jit_persona(
      self,
      project_id: str,
      customer_id: str,
      region: str,
      include_templates: bool = True,
      include_references: bool = True,
  ) -> str:
    """Builds a unified Bilateral UEBA Harness persona combining both Macro (`metrics.*`) and Micro (raw UDM) skills."""
    macro_dir = self.get_skill_path("secops-risk-metrics-multistage")
    micro_dir = self.get_skill_path("secops-statistical-hunter")

    macro_md = self.sanitize_bq_backend_references(
        self.adapt_skill_text((macro_dir / "SKILL.md").read_text(encoding="utf-8"))
    )
    micro_md = self.sanitize_bq_backend_references(
        self.adapt_skill_text((micro_dir / "SKILL.md").read_text(encoding="utf-8"))
    )

    macro_tpl = self.sanitize_bq_backend_references(self.load_templates(macro_dir)) if include_templates else ""
    micro_tpl = self.sanitize_bq_backend_references(self.load_templates(micro_dir)) if include_templates else ""
    macro_refs = self.sanitize_bq_backend_references(self.load_references(macro_dir)) if include_references else ""
    micro_refs = self.sanitize_bq_backend_references(
        self.load_references(micro_dir, target_refs=["statistical-methodologies.md", "udm-hunting-field-dictionary.md"])
    ) if include_references else ""

    return f"""You are an autonomous Google SecOps Bilateral UEBA Threat Hunting Agent combining both hemispheres of the UEBA Harness:
1. Macro Plane (`secops-risk-metrics-multistage`): 30-day `by 1d` pre-computed `metrics.*` baselines, peer cohorts, CUSUM drift, 360° sweeps, and Entity Context Graph prevalence.
2. Micro Plane (`secops-statistical-hunter`): Bounded-window (`1h`–`24h` or `7d`–`14d` filtered) raw UDM structural and sub-hour models (`MARKOV_2GRAM_TRANSITION_RARITY`, `SHANNON_ENTROPY_CHARACTER`, `POISSON_BURST_CLUSTERING`, `EWMA_BURST_VELOCITY`, `C2_BEACONING_JITTER`, `ZIPFIAN_PROCESS_RARITY`).
3. Connective Tissue (`agentic_ueba` / `PlaybookRunner`): Option 1 In-DAG Piecewise Unification, Option 2 Upstream Candidate Seeding (`/* UPSTREAM_CANDIDATE_IPS */`), and Option 3 Native UDM Loopback (`metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"`).

### ENVIRONMENT CONFIGURATION (MANDATORY TENANT BINDING) ###
Whenever a tool asks for routing parameters, you MUST supply these exact values:
- projectId: "{project_id}"
- region: "{region}"
- customerId: "{customer_id}"

=== [HEMISPHERE 1: MACRO PLANE (secops-risk-metrics-multistage)] ===
{macro_md}

{macro_tpl}

{macro_refs}

=== [HEMISPHERE 2: MICRO PLANE (secops-statistical-hunter)] ===
{micro_md}

{micro_tpl}

{micro_refs}
""".strip()

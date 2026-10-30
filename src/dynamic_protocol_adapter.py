# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Dynamic Protocol Adapter for Agentic UEBA (Strategy 2).

Ingests canonical threat hunting skills from an external, read-only SKILLS_ROOT,
preserves 100% of the domain intelligence (compiler invariants, AST syntax rules,
mathematical models, and query templates), and dynamically substitutes the
human-in-the-loop 3-state conversational lifecycle with an autonomous JIT
execution contract.

Harness values in that contract (CRI bands, verdicts and recommended actions,
loopback thresholds, the baseline maturity gate, window caps and the Mode A /
Entity Graph windows) are rendered from src/harness_truth.py, never copied here.
"""

from datetime import datetime
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from src import harness_truth

logger = logging.getLogger("DynamicProtocolAdapter")

# secops-statistical-hunter references loaded into the micro hemisphere of the bilateral persona.
MICRO_HEMISPHERE_REFERENCES = ("statistical-models-taxonomy.md", "multi-stage-query-guide.md")

_CONTAINMENT_PLACEHOLDER = "<DOMAIN_CONTAINMENT_ACTION>"

# The unified autonomous JIT protocol injected into every adapted skill. The {fields} are
# rendered from harness_truth by render_autonomous_jit_protocol().
AUTONOMOUS_JIT_PROTOCOL_TEMPLATE = """
## ⚡ AUTONOMOUS JIT EXECUTION PROTOCOL (PRE-APPROVED)

1. PRE-APPROVED EXECUTION MANDATE:
   - You are operating in autonomous JIT mode on behalf of a SecOps Playbook or Incident Response case.
   - You have FULL PRE-APPROVAL. DO NOT ask for clearance, DO NOT prompt for Mode A vs Mode B, and DO NOT halt after syntax verification.
   - Anti-Auth defaulting breaks and consultative pauses are SUSPENDED. Proceed directly to investigation.
   - Where skill text or references describe Turn 1 (probe, Pre-Flight card, query preview, request for clearance) and Turn 2 (execution and report), Turn 1 is JIT Step 1 and Turn 2 is JIT Step 2 below; clearance is already granted.
   - The canonical skill routing table and the Telemetry Physics & Window Guardrail stay binding: run each model only in the plane that owns it.

2. TWO-STEP INVESTIGATION PIPELINE:
   - Step 1 (Syntax/Availability Verification): Execute exactly ONE 1-shot compiler probe via `udm_search(..., maxEvents=1)` with strict ISO 8601 UTC timestamps.
   - Step 2 (Direct Multi-Stage Execution): Immediately dispatch the assembled multi-stage YARA-L query via `udm_search`.
   - Step 3 (Forensic Augmentation):
     * If 360° radar sector Z-scores are calculated, invoke `generate_behavioral_radar`.
     * If investigating a specific Case ID and `post_to_case_wall=true`, call `create_case_comment` with the final report.

3. EVALUATION WINDOWS (mode prompts are suspended, so these defaults apply):
   - Mode A, the default for every query, scores the last complete UTC day D as `[D, D+1)`: use the exact startTime/endTime under EVALUATION WINDOW BINDING. Entity Graph (`graph.*`) joins use its Entity Graph window, with every event stage pinned to D.
   - Windows end at D+1 (today 00:00:00Z), not at the current time, so the macro and micro planes score the same complete UTC day. Use a target date, a timeline or Today So Far (labeled partial UTC day) only when the directive asks for one: macro Mode B covers at most {mode_b_macro_days} days (Longitudinal CUSUM: {mode_b_cusum_macro_days} days) and micro raw windows at most {mode_b_micro_days} days; Mode C and helper-backed models need a client that can run local scripts (G5).

4. DUAL OUTPUT CONTRACT:
   Your final response MUST include BOTH:
   a) A machine-readable ```json_triage ... ``` code block adhering to the triage schema, with `verdict` and `recommended_action` set by the Calibrated Risk Index band:
{band_contract}
      {recommendation_note}
   b) The skill's canonical human-readable forensic report with every section in order (zero-outlier runs included), KaTeX math and Unicode visual bars.

5. COMPILER & AST INVARIANTS REMAIN 100% BINDING:
   All AST syntax constraints, match variable bindings ($user, $host by 1d), safe dispersion floors,
   and template assembly rules defined below are non-negotiable, including:
   - `math.sqrt(...)` (bare `sqrt(` does not compile); at most 20 outcome variables per `outcome:` block; no compound arithmetic inside `if()` branches (gate multiplicatively: `if(c, 1.0, 0.0) * (a - b) / d`).
   - Count-metric dispersion floor `max(sigma, sqrt(max(mu, 1)))` (byte metrics use the skills' byte floors); Z roots over 30-day baselines require at least {min_baseline_days} active baseline days (sparser entities route to the skills' novelty / hurdle models).
   - CRI is computed in Python from the executed query's Z / Z-equivalent scores (harness `calculate_cri`: 0 for Z <= 0, {anchor_cri} at Z = {anchor_z}). Never compute CRI inside YARA-L: no in-query CRI ladders. {piecewise_cri_retirement}
   - 360° radar = the decoupled canonical sector queries in `templates/radar_360/`, copied verbatim with only the entity substituted.
   - Never use a retired model, archetype or template; the skills' retirement messages name the replacement.

6. NATIVE GOOGLE SECOPS ARCHITECTURE (ZERO BIGQUERY DEPENDENCY):
   - All UDM event telemetry, Entity Context Graph (`graph.*`), and 30-day behavioral baselines (`metrics.*`) are computed, stored, and queried 100% natively within Google SecOps.
   - BigQuery does NOT drive, store, or back Google SecOps UEBA in any capacity whatsoever. If BigQuery disappeared tomorrow, it would have zero impact on SecOps UEBA.
   - Never state, imply, or explain that SecOps UEBA or `metrics.*` relies on external warehouse summary tables. BigQuery is solely a monitored customer cloud resource (e.g., `bigquery.googleapis.com` in GCP audit logs) that could be the target of an attack.

7. BILATERAL UEBA HARNESS & TELEMETRY PHYSICS GUARDRAIL (`metrics.*` + `stats-hunter` + `agentic_ueba`):
   - **Never Declare UEBA a Poor Fit**: Never dismiss UEBA for an exploit, vulnerability, CTI report, or detection gap (e.g., `http2shell`, web-to-shell, living-off-the-land, Shadow AI) because `metrics.*` is bucketed `by 1d` and cannot measure sub-hour correlations. Instead, synthesize a multi-horizon **Bilateral UEBA Harness**:
     * **Macro Plane (`secops-risk-metrics-multistage`, 30d `by 1d`)**: Owns all 30-day volumetric/failure baselines (`metrics.*`), peer cohorts, CUSUM slow drift, 360° sweeps, Entity Context Graph prevalence (`rolling_max <= 3`), and same-entity multi-sector fusion.
     * **Micro / Windowed Plane (`secops-statistical-hunter`, raw `UDM_EVENTS`)**: Owns short-window correlations (`by 5m`, `by 1h`, `by 2h`, `by 1d` over bounded 1h–24h windows for high-volume logs or 7d–14d for sparse/filtered events) and structural models that daily `metrics.*` counters cannot measure: parent-to-child process lineage (`MARKOV_2GRAM_TRANSITION_RARITY`), CLI/URI obfuscation (`SHANNON_ENTROPY_CHARACTER`), sub-hour burst clustering (`POISSON_BURST_CLUSTERING` / `EWMA_BURST_VELOCITY`), callback jitter (`C2_BEACONING_JITTER`), and long-tail rarity (`ZIPFIAN_PROCESS_RARITY`).
     * **Strict Telemetry Physics & Window Guardrail**: NEVER use `secops-statistical-hunter` for 30-day baselines over high-volume telemetry (`VPC flow logs`, `DNS`, `HTTP`, `Auth`, or `Process` counts). Raw 30-day scans over high-volume logs hit the 1M row scan cap or time out; all 30-day volumetric baselines belong strictly to `secops-risk-metrics-multistage` (`metrics.*`).
     * **Connective Tissue (`agentic_ueba` / `PlaybookRunner`)**: Chain macro and micro stages via Option 1 (In-DAG Piecewise Unification), Option 2 (Upstream Candidate Entity/IP Seeding `/* UPSTREAM_CANDIDATE_IPS */`), or Option 3 (Native UDM Loopback `metadata.product_event_type = "PLAYBOOK_BEHAVIORAL_HUNT_MATCH"` requiring >= {loopback_min_hits} distinct hits and sum(Z_i^2) >= {loopback_sum_z_sq}).
"""


def _render_band_contract() -> str:
  """CRI band -> json_triage verdict / recommended action lines, from harness_truth."""
  lines = []
  for low, high, _, label, emoji in reversed(harness_truth.cri_bands()):
    action = harness_truth.recommended_action(low, containment_action=_CONTAINMENT_PLACEHOLDER)
    action_text = (
        "= the domain containment action (e.g. ISOLATE_HOST, LOCK_ACCOUNT, REVOKE_IAM_ROLES, THROTTLE_EGRESS)"
        if action == _CONTAINMENT_PLACEHOLDER
        else f"`{action}`"
    )
    lines.append(
        f"      - CRI {low}–{high} ({emoji} {label}): verdict `{harness_truth.verdict_for(low)}`; "
        f"recommended_action {action_text}"
    )
  lines.append(
      f"      - CRI N/A (missing data or error): verdict `{harness_truth.verdict_for(None)}`; "
      f"recommended_action `{harness_truth.recommended_action(None)}`"
  )
  return "\n".join(lines)


def render_autonomous_jit_protocol() -> str:
  """The autonomous JIT protocol with every harness value read from harness_truth."""
  min_hits, sum_z_sq = harness_truth.loopback_thresholds()
  caps = harness_truth.mode_caps()
  anchor_z = harness_truth.constants().DEFAULT_ANOMALY_THRESHOLD
  return AUTONOMOUS_JIT_PROTOCOL_TEMPLATE.format(
      band_contract=_render_band_contract(),
      recommendation_note=harness_truth.RECOMMENDATION_NOTE,
      min_baseline_days=harness_truth.min_baseline_days(),
      anchor_z=anchor_z,
      anchor_cri=harness_truth.calculate_cri(anchor_z),
      # The in-query CRI ladder model's retirement, in the skill's own words (names the replacement).
      piecewise_cri_retirement=harness_truth.retirement_message("PIECEWISE_CRI") or "",
      mode_b_macro_days=caps["mode_b_macro_days"],
      mode_b_cusum_macro_days=caps["mode_b_cusum_macro_days"],
      mode_b_micro_days=caps["mode_b_micro_days"],
      loopback_min_hits=min_hits,
      loopback_sum_z_sq=sum_z_sq,
  )


def render_window_binding(now: Optional[datetime] = None) -> str:
  """This run's Mode A and Entity Graph windows, computed by harness_truth."""
  day = harness_truth.mode_a_day(now)
  start, end = harness_truth.mode_a_window(day)
  ecg_start, ecg_end = harness_truth.ecg_window(day)
  return (
      "### EVALUATION WINDOW BINDING (MODE A DEFAULT, UTC) ###\n"
      f"- Scored day D (last complete UTC day): {day.isoformat()}\n"
      f'- Mode A window: startTime "{start}", endTime "{end}"\n'
      f'- Entity Graph window: startTime "{ecg_start}", endTime "{ecg_end}"; '
      f"pin every event stage to D with `{harness_truth.event_day_pin(day)}`"
  )


def __getattr__(name: str) -> Any:
  """Keeps `AUTONOMOUS_JIT_PROTOCOL` importable; it is rendered from the harness on access."""
  if name == "AUTONOMOUS_JIT_PROTOCOL":
    return render_autonomous_jit_protocol()
  raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
    """Extracts the always-loaded domain rules embedded inside the 3-state lifecycle block.

    The rest of the block (Phase 1A consultation, Pre-Flight card, query preview and
    clearance turn, the State 2 entry condition and State 3 pivots) is the
    human-in-the-loop turn machine that the JIT protocol replaces. Preserved sections
    are returned in document order.
    """
    preserved: List[Tuple[int, str]] = []
    next_item = r"(?=^\d+\. \*\*|^#{2,3} |\Z)"

    # 1. Canonical cross-skill routing (secops-statistical-hunter State 1 Step 0): the
    #    precedence rule, its telemetry-physics guardrail and the frozen routing table.
    routing_match = re.search(
        r"^\d+\. \*\*Pre-Flight Routing Interceptor.*?" + next_item,
        lifecycle_block,
        re.DOTALL | re.MULTILINE,
    ) or re.search(
        r"<!-- CANONICAL_SKILL_ROUTING_TABLE_START -->.*?<!-- CANONICAL_SKILL_ROUTING_TABLE_END -->",
        lifecycle_block,
        re.DOTALL,
    )
    if routing_match:
      preserved.append((
          routing_match.start(),
          "### 🔀 Canonical Cross-Skill Routing\n" + routing_match.group(0).strip(),
      ))

    # 2. secops-risk-metrics-multistage: 360° Radar & CTI/Threat Report Mapping
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
      preserved.append((radar_cti_match.start(), block))

    # 3. secops-statistical-hunter: Template-First Formulation Directive
    tpl_match = re.search(
        r"(\* \*Template-First Formulation Directive\*:.*?)(?=\s*\* \*Canonical Pre-Flight Specification Card Structure\*:|$)",
        lifecycle_block,
        re.DOTALL,
    )
    if tpl_match:
      preserved.append((tpl_match.start(), tpl_match.group(1).strip()))

    # 4. secops-statistical-hunter: 6 Mandatory Root Outcome Variables & Affirmative Compiler Grammar
    grammar_match = re.search(
        r"\* \*6 Mandatory Root Outcome Variables Protocol\*:.*?" + next_item,
        lifecycle_block,
        re.DOTALL | re.MULTILINE,
    )
    if grammar_match:
      preserved.append((grammar_match.start(), grammar_match.group(0).strip()))

    # 5. secops-statistical-hunter: Compile-Time Verification & Identifier Coverage Probe (D4)
    probe_match = re.search(
        r"^\d+\. \*\*Compile-Time Verification Protocol.*?" + next_item,
        lifecycle_block,
        re.DOTALL | re.MULTILINE,
    )
    if probe_match:
      preserved.append((
          probe_match.start(),
          "### 🧪 Compile-Time Verification & Identifier Coverage\n" + probe_match.group(0).strip(),
      ))

    # 6. Both skills: State 2 execution and report contracts, minus the turn-taking entry condition
    state2_match = re.search(
        r"^### 📊 State 2:.*?(?=^### 🔁 State 3|^## |\Z)",
        lifecycle_block,
        re.DOTALL | re.MULTILINE,
    )
    if state2_match:
      block = re.sub(
          r"^\d+\. \*\*State 2 Entry Condition\*\*:.*?(?=^\d+\. \*\*|\Z)",
          "",
          state2_match.group(0),
          flags=re.DOTALL | re.MULTILINE,
      )
      preserved.append((state2_match.start(), re.sub(r"\n-{3,}\s*$", "", block.strip())))

    # 7. secops-statistical-hunter: Strict Visual Axis-Type Isolation & Post-Query Verification
    visual_match = re.search(
        r"(## 🎨 Strict Visual Axis-Type Isolation & Post-Query Verification.*?)(?=\n---\s*$|$)",
        lifecycle_block,
        re.DOTALL,
    )
    if visual_match:
      preserved.append((visual_match.start(), visual_match.group(1).strip()))

    return "\n\n".join(text for _, text in sorted(preserved))

  def adapt_skill_text(self, raw_skill_md: str) -> str:
    """Strips the interactive human-in-the-loop turn machine and injects JIT protocol."""
    jit_protocol = render_autonomous_jit_protocol()
    # Pattern to match the interactive 3-state lifecycle block
    pattern = re.compile(
        r"## 🔄 (?:THE )?3-STATE ACTIVE HUNT LIFECYCLE.*?(?=## 🛡️ Non-Negotiable Execution)",
        re.DOTALL,
    )
    match = pattern.search(raw_skill_md)
    if match:
      preserved_domain = self._extract_preserved_domain_sections(match.group(0))
      replacement = jit_protocol.rstrip()
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
    return raw_skill_md + "\n\n" + jit_protocol

  def load_templates(self, skill_dir: Path) -> str:
    """Loads all active .yl2 pipeline templates from the skill's templates/ directory.

    Templates the skills have retired (harness_truth.is_retired) are skipped, so a stale
    SKILLS_ROOT mirror cannot reintroduce them into a persona.
    """
    tpl_dir = skill_dir / "templates"
    if not tpl_dir.is_dir():
      logger.warning(f"No templates directory found at {tpl_dir}")
      return ""

    blocks = []
    for p in sorted(tpl_dir.rglob("*.yl2")):
      if p.is_file():
        rel = p.relative_to(skill_dir)
        if harness_truth.is_retired(p.name):
          logger.info(f"Skipping retired template {rel}: {harness_truth.retirement_message(p.name)}")
          continue
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
      paths = [ref_dir / (r if r.endswith(".md") else f"{r}.md") for r in target_refs]
      for missing in (p for p in paths if not p.is_file()):
        logger.warning(f"Requested reference {missing.name} not found under {ref_dir}")
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
      now: Optional[datetime] = None,
  ) -> str:
    """Builds a complete, self-contained JIT persona with tenant and evaluation-window binding."""
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

{render_window_binding(now)}

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
      now: Optional[datetime] = None,
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
        self.load_references(micro_dir, target_refs=list(MICRO_HEMISPHERE_REFERENCES))
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

{render_window_binding(now)}

=== [HEMISPHERE 1: MACRO PLANE (secops-risk-metrics-multistage)] ===
{macro_md}

{macro_tpl}

{macro_refs}

=== [HEMISPHERE 2: MICRO PLANE (secops-statistical-hunter)] ===
{micro_md}

{micro_tpl}

{micro_refs}
""".strip()

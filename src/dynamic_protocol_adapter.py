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
"""


class DynamicProtocolAdapter:
  """Adapts canonical human-facing SecOps skills into autonomous JIT engine personas."""

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

  def adapt_skill_text(self, raw_skill_md: str) -> str:
    """Strips the interactive human-in-the-loop turn machine and injects JIT protocol."""
    # Pattern to match the interactive 3-state lifecycle block
    pattern = re.compile(
        r"## 🔄 (?:THE )?3-STATE ACTIVE HUNT LIFECYCLE.*?(?=## 🛡️ Non-Negotiable Execution)",
        re.DOTALL,
    )
    if pattern.search(raw_skill_md):
      adapted = pattern.sub(AUTONOMOUS_JIT_PROTOCOL + "\n\n", raw_skill_md)
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
    if target_refs:
      paths = [ref_dir / r if not r.endswith(".md") else ref_dir / r for r in target_refs]
    else:
      paths = sorted([p for p in ref_dir.glob("*.md") if p.name not in EXCLUDED_REFS])

    for p in paths:
      if p.is_file():
        try:
          content = p.read_text(encoding="utf-8").strip()
          blocks.append(f"=== [REFERENCE: {p.name}] ===\n{content}\n==============================")
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
    
    adapted_skill = self.adapt_skill_text(raw_md)
    template_section = self.load_templates(skill_dir) if include_templates else ""
    reference_section = self.load_references(skill_dir) if include_references else ""

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

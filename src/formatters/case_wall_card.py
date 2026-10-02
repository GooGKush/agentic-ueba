# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Standardized Case Wall Forensic Triage Card Formatter for Agentic UEBA.

Formats comprehensive SOC Flight Cards in Markdown for Google Chronicle SOAR
Case Walls, detailing the problem statement, tested hypotheses (H0 vs H1),
evidentiary defense, calibrated confidence scale, underlying UDM touchpoints,
statistical metrics table, and defended follow-up hypotheses.
"""

import html
import re
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

  @staticmethod
  def render_confidence_bar(score: float, band: str = "AUTO_EXECUTE") -> str:
    """Generates a Unicode hypothesis confidence meter bar [0.00 - 1.00]."""
    clamped = min(1.0, max(0.0, float(score)))
    filled = int(round(clamped * 10))
    bar = "▰" * filled + "▱" * (10 - filled)
    if band == "AUTO_EXECUTE" or clamped >= 0.75:
      label = "🟢 **AUTO-EXECUTED (HIGH CONFIDENCE)**"
    elif band == "ANALYST_REVIEW" or clamped >= 0.45:
      label = "🟡 **ANALYST REVIEW (MODERATE CONFIDENCE)**"
    else:
      label = "⚪ **LOW CONFIDENCE**"
    return f"`{clamped:.2f}/1.00` [{bar}] {label}"

  @staticmethod
  def normalize_common_vector(
      raw_vector: Optional[str] = None,
      model_name: Optional[str] = None,
      target_metric: Optional[str] = None,
  ) -> str:
    """Normalizes any 360° radar sector, deep-dive model, or metric into a canonical Common Vector."""
    combined = f"{raw_vector or ''} {model_name or ''} {target_metric or ''}".lower()

    if any(k in combined for k in ("fusion", "multi_sector", "dual_sector", "rollup_sector")):
      return "MULTI_SECTOR"
    if any(k in combined for k in ("workspace", "drive")):
      return "WORKSPACE"
    if any(k in combined for k in ("cloud", "resource_creation", "resource_deletion", "resource_written", "resource_read", "iam")):
      return "CLOUD"
    if any(k in combined for k in ("dns", "nxdomain", "dga")):
      return "DNS"
    if any(k in combined for k in ("web", "http", "proxy", "whois", "domain_prevalence")):
      return "WEB"
    if any(k in combined for k in ("alert_event_name", "alerts")):
      return "ALERTS"
    if any(k in combined for k in ("endpoint", "file_executions", "markov", "zipf", "shannon", "obfuscation", "file_prevalence", "fleet_prevalence")):
      return "ENDPOINT"
    if any(k in combined for k in ("auth", "login", "poisson_burst", "spray", "lateral_expansion", "circadian")):
      return "AUTH"
    if any(k in combined for k in ("flows", "network_flows", "ewma")):
      return "FLOWS"
    if any(k in combined for k in ("egress", "network_bytes", "c2", "jitter", "beaconing", "elephant_flow", "macd", "rare_destination")):
      return "EGRESS"
    return "MULTI_SECTOR"

  @classmethod
  def build_case_tags(
      cls,
      calibrated_risk_index: float,
      primary_vector: Optional[str] = None,
      model_name: Optional[str] = None,
      target_metric: Optional[str] = None,
      second_order_ran: bool = False,
      investigation_tier: Optional[str] = None,
      is_outlier: bool = False,
  ) -> List[str]:
    """Builds the deterministic Case Wall tag taxonomy for filtering cases of interest.

    Taxonomy:
    1. Binary Risk Finding Tag (emitted strictly when a risk finding exists, CRI >= 60):
       - `RISK:CRITICAL` (CRI >= 80)
       - `RISK:HIGH` (60 <= CRI < 80)
    2. Common Vector Tag (shared across 360° Radar and deep-dive models when a finding or second-order hunt occurs):
       - `VECTOR:<SECTOR>` (e.g. `VECTOR:EGRESS`, `VECTOR:AUTH`, `VECTOR:CLOUD`, `VECTOR:WORKSPACE`,
         `VECTOR:DNS`, `VECTOR:WEB`, `VECTOR:FLOWS`, `VECTOR:ALERTS`, `VECTOR:ENDPOINT`, `VECTOR:MULTI_SECTOR`)
    3. Generic Second-Order Investigation Tag (emitted whenever a Tier 2A or Tier 2B hunt was executed):
       - `SECOND_ORDER_HUNT`
    """
    tags: List[str] = []
    cri = float(calibrated_risk_index or 0.0)
    is_tier2 = second_order_ran or (
        investigation_tier in ("TIER_2_DEEP_DIVE", "TIER_2B_PIVOT")
    )
    has_finding = cri >= 60.0

    # 1. Binary Risk Finding Taxonomy (Critical vs High)
    if cri >= 80.0:
      tags.append("RISK:CRITICAL")
    elif cri >= 60.0:
      tags.append("RISK:HIGH")

    # 2. Common Vector Tag (emitted when there is a finding, outlier, or second-order hunt)
    if has_finding or is_outlier or is_tier2:
      common_vec = cls.normalize_common_vector(
          raw_vector=primary_vector,
          model_name=model_name,
          target_metric=target_metric,
      )
      tags.append(f"VECTOR:{common_vec}")

    # 3. Generic Second-Order Investigation Tag
    if is_tier2:
      tags.append("SECOND_ORDER_HUNT")

    return tags

  @staticmethod
  def render_tags_line(tags: List[str]) -> str:
    """Renders tags as inline code badges for Case Wall filtering."""
    if not tags:
      return "`NONE (Nominal Baseline)`"
    return " ".join(f"`{t}`" for t in tags)

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
      primary_vector: Optional[str] = None,
      second_order_ran: bool = False,
      tags: Optional[List[str]] = None,
  ) -> str:
    """Renders a full 5-section Markdown Case Wall Triage Card with Hypothesis Defense & Confidence Scale."""
    risk_bar = cls.render_risk_bar(calibrated_risk_index)

    # 1. Header & Verdict Banner
    card_title = directive.flight_card_title if directive and directive.flight_card_title else f"Autonomous UEBA Triage Card: `{target_entity}`"
    threat_summary = directive.threat_summary if directive and directive.threat_summary else f"Statistical & Behavioral Anomaly Assessment for {entity_type} `{target_entity}`."
    
    # Hypotheses & Defense
    h0 = directive.hypothesis_h0 if directive and directive.hypothesis_h0 else "Activity conforms to normal baseline patterns without statistically significant departures."
    h1 = directive.hypothesis_h1 if directive and directive.hypothesis_h1 else "Observed telemetry exhibits anomalous clustering, periodicity, or volume indicative of threat behavior."
    rationale = directive.selection_rationale if directive and directive.selection_rationale else f"Model selected based on {entity_type} topology and triggering alert context."
    defense = directive.evidentiary_defense if directive and getattr(directive, "evidentiary_defense", "") else rationale

    tier_label = directive.investigation_tier if directive and directive.investigation_tier else "TIER_1_BASELINE"
    if tier_label == "TIER_1_BASELINE":
      tier_display = "Tier 1: 360° Behavioral Radar Baseline"
    elif tier_label == "TIER_2B_PIVOT":
      tier_display = f"Tier 2B: Autonomous Hypothesis Pivot ({directive.outlier_vector or 'Multi-Vector'})"
    else:
      tier_display = (
          f"Tier 2: Targeted Deep Dive ({directive.outlier_vector})"
          if directive and directive.outlier_vector
          else "Tier 2: Targeted Deep Dive"
      )

    resolved_tags = (
        tags
        if tags is not None
        else cls.build_case_tags(
            calibrated_risk_index=calibrated_risk_index,
            primary_vector=primary_vector or (directive.outlier_vector if directive else None),
            model_name=model_name,
            target_metric=getattr(directive, "target_metric", None) if directive else None,
            second_order_ran=second_order_ran,
            investigation_tier=tier_label,
            is_outlier=is_outlier,
        )
    )
    tags_display = cls.render_tags_line(resolved_tags)

    lines = [
        f"## 🛡️ {card_title}",
        "",
        f"**Calibrated Risk Index**: {risk_bar}  ",
        f"**Case Triage Tags**: {tags_display}  ",
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
    ]

    if directive and getattr(directive, "fusion_metrics", None):
      lines.append(f"- **Fused Telemetry Vectors**: `{directive.fusion_metrics[0]}` × `{directive.fusion_metrics[1]}`")
    elif directive and getattr(directive, "target_metric", None):
      lines.append(f"- **Target Telemetry Metric**: `metrics.{directive.target_metric}`")

    if directive and getattr(directive, "confidence_score", None) is not None:
      conf_bar = cls.render_confidence_bar(directive.confidence_score, getattr(directive, "confidence_band", "AUTO_EXECUTE"))
      lines.append(f"- **Hypothesis Confidence Scale**: {conf_bar}")
      if getattr(directive, "confidence_breakdown", ""):
        lines.append(f"- **Confidence Derivation**: `{directive.confidence_breakdown}`")

    if directive and getattr(directive, "pivot_reason", None):
      lines.append(f"- **🔗 Autonomous Pivot Lineage**: {directive.pivot_reason}")

    lines.extend([
        f"- **Defense of Hypothesis**: {defense}",
        f"- **Null Hypothesis ($H_0$)**: {h0}",
        f"- **Alternative Threat Hypothesis ($H_1$)**: {h1}",
        "",
        "### 📊 Forensic Evidence & Flight Metrics",
    ])

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

    # 🧭 Recommended Avenues to Pursue (with Structured Hypothesis Defense & Confidence Scores)
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

  @classmethod
  def _format_inline_html(cls, text: str) -> str:
    """Converts inline Markdown (**bold**, *italic*, `code`) and LaTeX ($H_0$, $\\sigma$) to safevalues-compliant HTML."""
    if not text:
      return ""

    # 1. Extract inline code spans first so their contents are not altered by math/bold regexes
    code_spans: List[str] = []

    def _stash_code(match: re.Match) -> str:
      inner = match.group(1)
      # Clean any inline LaTeX inside backticks (e.g. `$\ge 5$ required`)
      inner_clean = (
          inner.replace("$\\ge", "≥")
          .replace("\\ge", "≥")
          .replace("$\\le", "≤")
          .replace("\\le", "≤")
          .replace("\\sigma", "σ")
          .replace("\\mu", "μ")
          .replace("$", "")
      )
      idx = len(code_spans)
      code_spans.append(f"<code>{html.escape(inner_clean, quote=False)}</code>")
      return f"\x00CODE_{idx}\x00"

    text = re.sub(r"`([^`]+)`", _stash_code, text)

    # 2. Escape raw HTML characters in remaining text
    text = html.escape(text, quote=False)

    # 3. Convert inline LaTeX math expressions ($...$) to clean HTML / Unicode
    def _convert_math(match: re.Match) -> str:
      expr = match.group(1).strip()
      expr = (
          expr.replace("\\ge", "≥")
          .replace("\\le", "≤")
          .replace("\\sigma", "σ")
          .replace("\\mu", "μ")
          .replace("&gt;=", "≥")
          .replace("&lt;=", "≤")
          .replace("^2", "²")
      )
      expr = re.sub(r"\bH_0\b", "H<sub>0</sub>", expr)
      expr = re.sub(r"\bH_1\b", "H<sub>1</sub>", expr)
      expr = re.sub(r"\bZ_([A-Za-z0-9]+)\b", r"Z<sub>\1</sub>", expr)
      if expr in ("Z", "D", "CV", "H", "F"):
        return f"<i>{expr}</i>"
      return expr

    text = re.sub(r"\$([^$\n]+)\$", _convert_math, text)
    # Catch any unescaped LaTeX tokens outside $...$
    text = (
        text.replace("\\ge", "≥")
        .replace("\\le", "≤")
        .replace("\\sigma", "σ")
        .replace("\\mu", "μ")
    )
    text = re.sub(r"\bH_0\b", "H<sub>0</sub>", text)
    text = re.sub(r"\bH_1\b", "H<sub>1</sub>", text)

    # 4. Bold (**text**) and Italic (*text*)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", text)

    # 5. Restore inline code spans
    for idx, code_html in enumerate(code_spans):
      text = text.replace(f"\x00CODE_{idx}\x00", code_html)

    return text.strip()

  @classmethod
  def to_soar_html(cls, markdown_text: str) -> str:
    """Converts Markdown triage cards into Chronicle SOAR Case Wall HTML.

    Grounded in Chronicle SOAR UI source code:
    - `evidence_activity.ng.html` binds `[innerHTML]="sanitizeContent(commentForClient)"`
      inside `<p class="u-word-break--word u-white-space--pre-wrap ...">` with `[tnShowMore]="500"`.
    - `show-more.directive.ts` runs `sanitizeHtmlAssertUnchanged()` against `safevalues`
      `DEFAULT_SANITIZER_TABLE`, which strips `style` and `class` attributes while allowing
      semantic HTML tags (`h3`, `h4`, `p`, `blockquote`, `ul`, `ol`, `li`, `table`, `thead`,
      `tbody`, `tr`, `th`, `td`, `strong`, `em`, `code`, `pre`, `hr`, `br`, `sub`, `sup`)
      and standard HTML table attributes (`border`, `cellpadding`, `cellspacing`, `width`, `align`).
    - Because the container `<p>` applies `white-space: pre-wrap`, block-level HTML tags
      must be emitted compactly without extraneous `\\n` characters between tags to avoid
      phantom vertical whitespace.
    """
    if not markdown_text:
      return ""

    stripped = markdown_text.strip()
    # Idempotency check if already converted to SOAR HTML
    if (
        (stripped.startswith("<h3>") or stripped.startswith("<h2>") or stripped.startswith("<h4>"))
        and ("<strong>" in stripped or "</table>" in stripped or "</ul>" in stripped)
        and "\n## " not in stripped
    ):
      return stripped

    lines = stripped.splitlines()
    blocks: List[str] = []
    i = 0
    n = len(lines)

    while i < n:
      raw_line = lines[i]
      line = raw_line.strip()

      # Skip empty lines (block elements provide natural vertical spacing)
      if not line:
        i += 1
        continue

      # 1. Fenced code block (```...```)
      if line.startswith("```"):
        i += 1
        code_lines: List[str] = []
        while i < n and not lines[i].strip().startswith("```"):
          code_lines.append(html.escape(lines[i], quote=False))
          i += 1
        if i < n:
          i += 1  # Skip closing ```
        blocks.append(f"<pre><code>{chr(10).join(code_lines)}</code></pre>")
        continue

      # 2. Horizontal Rule (--- or ***)
      if re.match(r"^[-*_]{3,}$", line):
        blocks.append("<hr>")
        i += 1
        continue

      # 3. Headings (#, ##, ###, ####)
      heading_match = re.match(r"^(#{1,6})\s+(.*)$", line)
      if heading_match:
        level = len(heading_match.group(1))
        content = cls._format_inline_html(heading_match.group(2))
        tag = "h3" if level <= 2 else "h4"
        blocks.append(f"<{tag}>{content}</{tag}>")
        i += 1
        continue

      # 4. Blockquotes (> ...)
      if line.startswith(">"):
        quote_lines: List[str] = []
        while i < n and lines[i].strip().startswith(">"):
          q_text = re.sub(r"^>\s?", "", lines[i].strip())
          q_text = re.sub(
              r"^\[!WARNING\]\s*",
              "**⚠️ WARNING:** ",
              q_text,
              flags=re.IGNORECASE,
          )
          q_text = re.sub(
              r"^\[!IMPORTANT\]\s*",
              "**❗ IMPORTANT:** ",
              q_text,
              flags=re.IGNORECASE,
          )
          q_text = re.sub(
              r"^\[!NOTE\]\s*",
              "**ℹ️ NOTE:** ",
              q_text,
              flags=re.IGNORECASE,
          )
          quote_lines.append(cls._format_inline_html(q_text))
          i += 1
        blocks.append(f"<blockquote>{'<br>'.join(quote_lines)}</blockquote>")
        continue

      # 5. Markdown Tables (| col1 | col2 |)
      if line.startswith("|") and line.endswith("|"):
        table_lines: List[str] = []
        while i < n and lines[i].strip().startswith("|") and lines[i].strip().endswith("|"):
          table_lines.append(lines[i].strip())
          i += 1

        parsed_rows: List[List[str]] = []
        for t_line in table_lines:
          # Protect absolute-value notation like |Z| before splitting on pipe delimiters
          safe_t_line = re.sub(r"\|([A-Za-z_][A-Za-z0-9_]*)\|", r"∣\1∣", t_line)
          cells = [c.strip() for c in safe_t_line.strip("|").split("|")]
          # Skip Markdown alignment separator rows (e.g., | :--- | :--- |)
          if all(re.match(r"^:?-{2,}:?$", c) for c in cells if c):
            continue
          parsed_rows.append([cls._format_inline_html(c) for c in cells])

        if parsed_rows:
          header_cells = "".join(f'<th align="left">{c}</th>' for c in parsed_rows[0])
          thead_html = f"<thead><tr>{header_cells}</tr></thead>"
          tbody_rows = []
          for row in parsed_rows[1:]:
            row_cells = "".join(f"<td>{c}</td>" for c in row)
            tbody_rows.append(f"<tr>{row_cells}</tr>")
          tbody_html = f"<tbody>{''.join(tbody_rows)}</tbody>" if tbody_rows else ""
          blocks.append(
              f'<table border="1" cellpadding="6" cellspacing="0" width="100%">{thead_html}{tbody_html}</table>'
          )
        continue

      # 6. Unordered Lists (- ... or * ...)
      if re.match(r"^[-*]\s+", line):
        ul_items: List[str] = []
        while i < n and re.match(r"^[-*]\s+", lines[i].strip()):
          item_text = re.sub(r"^[-*]\s+", "", lines[i].strip())
          ul_items.append(f"<li>{cls._format_inline_html(item_text)}</li>")
          i += 1
        blocks.append(f"<ul>{''.join(ul_items)}</ul>")
        continue

      # 7. Ordered Lists (1. ... with optional indented sub-bullets)
      if re.match(r"^\d+\.\s+", line):
        ol_items: List[str] = []
        while i < n and re.match(r"^\d+\.\s+", lines[i].strip()):
          item_text = re.sub(r"^\d+\.\s+", "", lines[i].strip())
          item_html = cls._format_inline_html(item_text)
          i += 1
          sub_bullets: List[str] = []
          while i < n and re.match(r"^\s{2,}[-*]\s+", lines[i]):
            sub_text = re.sub(r"^[-*]\s+", "", lines[i].strip())
            sub_bullets.append(f"<li>{cls._format_inline_html(sub_text)}</li>")
            i += 1
          if sub_bullets:
            item_html = f"{item_html}<ul>{''.join(sub_bullets)}</ul>"
          ol_items.append(f"<li>{item_html}</li>")
        blocks.append(f"<ol>{''.join(ol_items)}</ol>")
        continue

      # 8. Standard Paragraphs / Metadata Lines
      para_lines: List[str] = []
      while (
          i < n
          and lines[i].strip()
          and not lines[i].strip().startswith(("```", "#", ">", "|"))
          and not re.match(r"^[-*_]{3,}$", lines[i].strip())
          and not re.match(r"^[-*]\s+", lines[i].strip())
          and not re.match(r"^\d+\.\s+", lines[i].strip())
      ):
        para_lines.append(cls._format_inline_html(lines[i].strip()))
        i += 1
      if para_lines:
        blocks.append(f"<p>{'<br>'.join(para_lines)}</p>")

    return "".join(blocks)


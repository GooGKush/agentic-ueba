# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
"""Runtime adapter to the canonical UEBA harness (single source of truth).

agentic_ueba does not re-declare harness constants. This module loads them at
runtime from the canonical skills resolved by `get_skills_root()`:

* `secops-risk-metrics-multistage/scripts/ueba_constants.py` (byte-identical in
  both skills): the CRI formula and 26/46/70/90 bands, sensitivity tiers,
  loopback and write-back thresholds, Mode B/C caps and Z-equivalent score
  semantics.
* The skills' retired-model registries (`preflight_validator.py`,
  `ueba_hybrid_engine.py`, `multistage_query_builder.py`).

Other skill scripts are reached through `skill_module(skill, rel_path)`.

Three things are defined here because the skills state them as rules (or in
private code) rather than as exported constants:

* The CRI band -> verdict / recommended-action mapping, taken from the
  operational guidance (Tiers 1-5) in
  `secops-risk-metrics-multistage/references/calibrated-risk-index-guide.md`.
  Actions are recommendations only; agentic_ueba never executes containment.
* The Mode A and Entity Graph windows from SKILL.md: Mode A scores the last
  complete UTC day D (`[D, D+1)`), and Entity Graph joins start at D-2 with each
  event stage pinned to D.
* The raw 30-day MAD / quantile baseline window `[D-29, D+1)`, as computed by
  `secops-risk-metrics-multistage/scripts/ueba_hybrid_engine.py`.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
import importlib.util
from pathlib import Path
import re
import sys
import threading
from types import ModuleType
from typing import Any, Dict, Optional, Tuple

from src.config import get_skills_root

RISK_METRICS_SKILL = "secops-risk-metrics-multistage"
STATS_HUNTER_SKILL = "secops-statistical-hunter"

# Serializes by-path loading of stats-hunter scripts across worker threads.
_LOAD_LOCK = threading.RLock()


def _load_module(skill: str, rel_path: str, module_name: str) -> ModuleType:
  """Loads a skill script.

  Risk-metrics scripts import each other as the `scripts` package, so they are
  imported as `scripts.<name>` with the skill root on sys.path, exactly as
  PipelineRunner._ensure_skill_path() does. Stats-hunter scripts load by path
  under a private module name, so the two skills' `scripts` directories never
  collide; the risk-metrics root and its shared `scripts.ueba_constants` are
  loaded first, because the stats-hunter builder imports `scripts.ueba_constants`
  (byte-identical in both skills) and must not depend on import order.
  """
  root = get_skills_root() / skill
  path = root / rel_path
  if not path.is_file():
    raise FileNotFoundError(f"Harness source not found: {path}")
  if skill == RISK_METRICS_SKILL:
    if str(root) not in sys.path:
      sys.path.insert(0, str(root))
    module = importlib.import_module("scripts." + Path(rel_path).stem)
    if Path(module.__file__).resolve() != path.resolve():
      raise ImportError(
          f"'scripts' resolved to {module.__file__}, not {path}; another skill's scripts "
          "directory is ahead of secops-risk-metrics-multistage on sys.path.")
    return module
  constants()
  with _LOAD_LOCK:
    if module_name in sys.modules:
      return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
      raise ImportError(f"Cannot load harness source {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
      spec.loader.exec_module(module)
    except Exception:
      sys.modules.pop(module_name, None)
      raise
    return module


def _private_module_name(skill: str, rel_path: str) -> str:
  """`_harness_<skill>__<path without .py>`, every non-identifier character replaced by `_`."""
  return "_harness_" + re.sub(r"\W", "_", f"{skill}__{Path(rel_path).with_suffix('').as_posix()}")


def skill_module(skill: str, rel_path: str) -> ModuleType:
  """A skill script, e.g. `skill_module(STATS_HUNTER_SKILL, "scripts/multistage_query_builder.py")`.

  Stable access: every call returns the same module object. Risk-metrics scripts are the
  `scripts.<name>` package modules; stats-hunter scripts load by path under a private name derived
  from skill + path, after the risk-metrics root, so their loading never depends on import order.
  """
  rel = Path(rel_path)
  if rel.is_absolute() or ".." in rel.parts:
    raise ValueError(f"skill_module expects a path inside the skill, got {rel_path!r}")
  return _load_module(skill, rel.as_posix(), _private_module_name(skill, rel.as_posix()))


@lru_cache(maxsize=None)
def constants() -> ModuleType:
  """The canonical shared constants module (`scripts/ueba_constants.py`)."""
  return _load_module(RISK_METRICS_SKILL, "scripts/ueba_constants.py", "_harness_ueba_constants")


# ---------------------------------------------------------------------------
# Calibrated Risk Index (CRI)
# ---------------------------------------------------------------------------


def cri_bands() -> Tuple[Tuple[int, int, str, str, str], ...]:
  """`(low, high, code, label, emoji)` bands, straight from the skill."""
  return constants().CRI_BANDS


def calculate_cri(score: Any, baseline_threshold: Optional[float] = None) -> Optional[int]:
  """CRI 0..100 from a Z / Z-equivalent score; 0 for Z <= 0; None on missing data."""
  if baseline_threshold is None:
    return constants().calculate_cri(score)
  return constants().calculate_cri(score, baseline_threshold)


def coerce_cri(cri: Any) -> Optional[int]:
  """Clamps a CRI to 0..100, or None when missing or invalid."""
  return constants().coerce_cri_int(cri)


def format_cri(cri: Any) -> str:
  """'0'..'100', or 'N/A'."""
  return constants().format_cri(cri)


def cri_band(cri: Any) -> Tuple[str, str, str]:
  """`(code, label, emoji)`; code is INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL or N/A."""
  return constants().get_cri_band_info(cri)


# Band code -> agentic_ueba verdict vocabulary.
BAND_VERDICTS: Dict[str, str] = {
    "CRITICAL": "CRITICAL_OUTLIER",
    "HIGH": "HIGH_OUTLIER",
    "MEDIUM": "MEDIUM_OUTLIER",
    "LOW": "LOW_OUTLIER",
    "INFORMATIONAL": "NOMINAL_BASELINE",
    "N/A": "NOT_EVALUATED",
}

# Band code -> (response kind, guidance). From calibrated-risk-index-guide.md Tiers 1-5.
BAND_RESPONSES: Dict[str, Tuple[str, str]] = {
    "CRITICAL": ("CONTAIN", "Tier 5 Critical Outlier: high-priority incident response escalation; isolate "
                            "the host or suspend credentials if paired with suspicious command-line artifacts."),
    "HIGH": ("INVESTIGATE", "Tier 4 High Threat: immediate analyst intervention; inspect process execution "
                            "lineage and network destinations."),
    "MEDIUM": ("INVESTIGATE", "Tier 3 Medium Outlier: open a Tier 1 SOC investigation; cross-reference peers "
                              "and check for secondary tool execution."),
    "LOW": ("MONITOR", "Tier 2 Low Drift: track longitudinally (CUSUM); do not page analysts."),
    "INFORMATIONAL": ("MONITOR", "Tier 1 Nominal: suppress; no investigation required."),
    "N/A": ("MONITOR", "Not evaluated: missing data or error; no escalation."),
}

RECOMMENDATION_NOTE = "Recommendation only: agentic_ueba does not execute containment."


def verdict_for(cri: Any) -> str:
  """agentic_ueba verdict for a CRI value."""
  return BAND_VERDICTS[cri_band(cri)[0]]


def response_kind(cri: Any) -> str:
  """CONTAIN, INVESTIGATE or MONITOR: the response kind of the CRI's band (BAND_RESPONSES)."""
  return BAND_RESPONSES[cri_band(cri)[0]][0]


def recommended_action(cri: Any, containment_action: str = "ISOLATE_HOST") -> str:
  """Recommended action for a CRI value.

  Critical returns the caller's domain-specific containment recommendation
  (e.g. ISOLATE_HOST, LOCK_ACCOUNT, REVOKE_IAM_ROLES, THROTTLE_EGRESS);
  High and Medium return INVESTIGATE; Low, Nominal and N/A return MONITOR.
  """
  kind = response_kind(cri)
  return containment_action if kind == "CONTAIN" else kind


def action_guidance(cri: Any) -> str:
  """Human-readable guidance for the CRI's tier, with the recommendation-only note."""
  return f"{BAND_RESPONSES[cri_band(cri)[0]][1]} {RECOMMENDATION_NOTE}"


# ---------------------------------------------------------------------------
# Thresholds and caps
# ---------------------------------------------------------------------------


def loopback_thresholds() -> Tuple[int, float]:
  """`(min_distinct_hits, sum_z_sq_threshold)` for the Wave 3 capstone."""
  c = constants()
  return c.LOOPBACK_MIN_DISTINCT_HITS, c.LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD


def writeback_cri_threshold() -> int:
  """Minimum CRI for UDM write-back of a finding."""
  return constants().WRITEBACK_CRI_THRESHOLD


def min_baseline_days() -> int:
  """Active-day maturity gate for a 30-day baseline."""
  return constants().DEFAULT_MIN_BASELINE_DAYS


def mode_caps() -> Dict[str, int]:
  """Mode B / Mode C window caps in days."""
  c = constants()
  return {
      "mode_b_macro_days": c.MAX_MODE_B_DAYS_MACRO,
      "mode_b_cusum_macro_days": c.MAX_CUSUM_MODE_B_DAYS_MACRO,
      "mode_c_macro_days": c.MAX_MODE_C_DAYS_MACRO,
      "mode_b_micro_days": c.MAX_MODE_B_DAYS_MICRO,
  }


# ---------------------------------------------------------------------------
# Retired models
# ---------------------------------------------------------------------------


def _norm(name: Any) -> str:
  text = str(getattr(name, "value", name)).strip()
  if text.lower().endswith(".yl2"):
    text = text[:-4]
  return text.upper()


# Pipeline templates are named <model>_<n>stage.yl2.
_STAGE_SUFFIX_RE = re.compile(r"_\d+STAGE$")


@lru_cache(maxsize=None)
def retired_models() -> Dict[str, str]:
  """Normalized model / archetype / pipeline name -> retirement message, from both skills."""
  out: Dict[str, str] = {}
  pv = skill_module(RISK_METRICS_SKILL, "scripts/preflight_validator.py")
  for registry in (pv.RETIRED_STATISTICAL_MODELS, pv.RETIRED_PIPELINE_ARCHITECTURES):
    for key, msg in registry.items():
      out[_norm(key)] = msg
  mqb = skill_module(STATS_HUNTER_SKILL, "scripts/multistage_query_builder.py")
  for key, msg in mqb.RETIRED_ARCHETYPES.items():
    out[_norm(key)] = msg
  hybrid = skill_module(RISK_METRICS_SKILL, "scripts/ueba_hybrid_engine.py")
  for key, replacement in hybrid.RETIRED_MODEL_ALIASES.items():
    out[_norm(key)] = f"Statistical model '{key}' is retired: use {replacement}."
  return out


def retirement_message(name: Any) -> Optional[str]:
  """The skill's retirement message for a model / template name, or None if active.

  A name missing from the registries is retried without a trailing `_<N>STAGE` suffix, so the
  template of a retired model (`impossible_travel_geo_velocity_2stage.yl2`) is retired too. The
  fallback applies only on a miss: an exact entry (e.g. CIRCADIAN_VON_MISES_2STAGE) keeps its own
  message, and an active model's template stays active.
  """
  registry = retired_models()
  key = _norm(name)
  if key in registry:
    return registry[key]
  base = _STAGE_SUFFIX_RE.sub("", key)
  return registry.get(base) if base != key else None


def is_retired(name: Any) -> bool:
  return retirement_message(name) is not None


def assert_not_retired(name: Any) -> None:
  """Raises ValueError with the skill's own message if `name` is retired."""
  msg = retirement_message(name)
  if msg:
    raise ValueError(msg)


# ---------------------------------------------------------------------------
# Time windows (SKILL.md rules)
# ---------------------------------------------------------------------------


def _iso_midnight(day: date) -> str:
  return f"{day.isoformat()}T00:00:00Z"


def mode_a_day(now: Optional[datetime] = None) -> date:
  """Mode A scored day: the last complete UTC day."""
  now = now or datetime.now(timezone.utc)
  return (now.astimezone(timezone.utc) - timedelta(days=1)).date()


def mode_a_window(day: Optional[date] = None) -> Tuple[str, str]:
  """`(startTime, endTime)` = `[D, D+1)` in UTC."""
  day = day or mode_a_day()
  return _iso_midnight(day), _iso_midnight(day + timedelta(days=1))


def ecg_window(day: Optional[date] = None) -> Tuple[str, str]:
  """Entity Graph join window for Mode A: `[D-2, D+1)`; pin event stages with event_day_pin(D)."""
  day = day or mode_a_day()
  return _iso_midnight(day - timedelta(days=2)), _iso_midnight(day + timedelta(days=1))


# Days of raw daily rows in a Mode A MAD / quantile baseline (ueba_hybrid_engine, see raw_baseline_window).
_RAW_BASELINE_DAYS = 30


def raw_baseline_window(day: Optional[date] = None) -> Tuple[str, str]:
  """Raw 30-day MAD / quantile baseline window for Mode A: `[D-29, D+1)` in UTC.

  The window's daily rows are the empirical series and `$in_scoring_window` gates scoring to D.
  Verified against `secops-risk-metrics-multistage/scripts/ueba_hybrid_engine.py`
  `_compute_execution_windows`: in Mode A, StatisticalModel.MAD and QUANTILE_IQR_SKEW start at
  `scored_day - timedelta(days=29)` (00:00:00Z) and end at the scored day + 1 day (00:00:00Z).
  """
  day = day or mode_a_day()
  return _iso_midnight(day - timedelta(days=_RAW_BASELINE_DAYS - 1)), _iso_midnight(day + timedelta(days=1))


def event_day_pin(day: Optional[date] = None) -> str:
  """Event-stage filter that pins an Entity Graph hunt to the scored day."""
  day = day or mode_a_day()
  return f'timestamp.get_date(metadata.event_timestamp.seconds) = "{day.isoformat()}"'

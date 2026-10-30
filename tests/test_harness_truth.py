# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek
"""Tests for src/harness_truth.py: agentic_ueba reads harness truth from the skills."""

from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from src import harness_truth as ht
from src.config import get_skills_root

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_constants_are_loaded_from_the_canonical_skill():
  mod = ht.constants()
  expected = get_skills_root() / ht.RISK_METRICS_SKILL / "scripts" / "ueba_constants.py"
  assert Path(mod.__file__).resolve() == expected.resolve()
  # Nothing is re-declared locally: the bands are the skill's own object.
  assert ht.cri_bands() is mod.CRI_BANDS


@pytest.mark.parametrize(
    "cri,code",
    [(0, "INFORMATIONAL"), (25, "INFORMATIONAL"), (26, "LOW"), (45, "LOW"), (46, "MEDIUM"),
     (69, "MEDIUM"), (70, "HIGH"), (89, "HIGH"), (90, "CRITICAL"), (100, "CRITICAL"),
     (None, "N/A"), ("nan", "N/A")],
)
def test_cri_band_boundaries_follow_the_skill(cri, code):
  assert ht.cri_band(cri)[0] == code


def test_calculate_cri_zero_floor_and_missing_data():
  assert ht.calculate_cri(-2.0) == 0
  assert ht.calculate_cri(0.0) == 0
  assert ht.calculate_cri(3.0) == 50  # 3.0 sigma alertable anchor
  assert ht.calculate_cri(None) is None
  assert ht.format_cri(None) == "N/A"


@pytest.mark.parametrize(
    "cri,verdict",
    [(95, "CRITICAL_OUTLIER"), (75, "HIGH_OUTLIER"), (50, "MEDIUM_OUTLIER"), (30, "LOW_OUTLIER"),
     (10, "NOMINAL_BASELINE"), (None, "NOT_EVALUATED")],
)
def test_verdict_for_maps_bands_to_agentic_verdicts(cri, verdict):
  assert ht.verdict_for(cri) == verdict


def test_recommended_action_follows_cri_guide_tiers():
  # Tier 5 (Critical): containment recommendation, domain-specific action kept by the caller.
  assert ht.recommended_action(92, containment_action="LOCK_ACCOUNT") == "LOCK_ACCOUNT"
  assert ht.recommended_action(92) == "ISOLATE_HOST"
  # Tier 4 (High) and Tier 3 (Medium): analyst investigation, not containment.
  assert ht.recommended_action(80, containment_action="LOCK_ACCOUNT") == "INVESTIGATE"
  assert ht.recommended_action(50) == "INVESTIGATE"
  # Tier 2 (Low) and Tier 1 (Nominal): monitor only.
  assert ht.recommended_action(40) == "MONITOR"
  assert ht.recommended_action(0) == "MONITOR"
  # Missing data never escalates.
  assert ht.recommended_action(None) == "MONITOR"
  assert "recommendation" in ht.action_guidance(92).lower()


@pytest.mark.parametrize(
    "cri,kind",
    [(100, "CONTAIN"), (90, "CONTAIN"), (89, "INVESTIGATE"), (70, "INVESTIGATE"), (69, "INVESTIGATE"),
     (46, "INVESTIGATE"), (45, "MONITOR"), (26, "MONITOR"), (0, "MONITOR"), (None, "MONITOR"), ("nan", "MONITOR")],
)
def test_response_kind_follows_the_band_responses(cri, kind):
  assert ht.response_kind(cri) == kind
  assert ht.response_kind(cri) == ht.BAND_RESPONSES[ht.cri_band(cri)[0]][0]
  # The recommended action is the caller's containment action exactly when the kind is CONTAIN.
  assert (ht.recommended_action(cri, containment_action="LOCK_ACCOUNT") == "LOCK_ACCOUNT") is (kind == "CONTAIN")


@pytest.mark.parametrize(
    "name",
    ["CIRCADIAN_VON_MISES", "circadian_von_mises_2stage.yl2", "HOURLY_TEMPORAL_ZSCORE",
     "PIECEWISE_CRI", "IMPOSSIBLE_TRAVEL_GEO_VELOCITY", "impossible_travel", "ASYMMETRIC_Z",
     "HYBRID_METRIC_ORTHOGONAL_SPACE_2STAGE"],
)
def test_retired_models_come_from_skill_registries(name):
  assert ht.is_retired(name)
  msg = ht.retirement_message(name)
  assert msg and "retired" in msg.lower()
  with pytest.raises(ValueError):
    ht.assert_not_retired(name)


@pytest.mark.parametrize("name", ["STANDARD_Z_SCORE", "HOUR_OF_DAY_PROFILE", "C2_BEACONING_JITTER"])
def test_active_models_are_not_retired(name):
  assert not ht.is_retired(name)
  ht.assert_not_retired(name)


@pytest.mark.parametrize(
    "name,model",
    [("impossible_travel_geo_velocity_2stage.yl2", "IMPOSSIBLE_TRAVEL_GEO_VELOCITY"),
     ("IMPOSSIBLE_TRAVEL_GEO_VELOCITY_2STAGE", "IMPOSSIBLE_TRAVEL_GEO_VELOCITY"),
     ("hourly_temporal_zscore_2stage.yl2", "HOURLY_TEMPORAL_ZSCORE"),
     ("piecewise_cri_3stage", "PIECEWISE_CRI")],
)
def test_retired_lookup_falls_back_to_the_model_without_its_stage_suffix(name, model):
  # Pipeline templates are named <model>_<n>stage.yl2: a retired model's template is retired too.
  assert ht.is_retired(name)
  assert ht.retirement_message(name) == ht.retirement_message(model)
  with pytest.raises(ValueError):
    ht.assert_not_retired(name)


def test_stage_suffix_fallback_never_overrides_an_exact_registry_entry():
  # The pipeline architecture has its own retirement message; the fallback applies only on a miss.
  exact = ht.retired_models()["CIRCADIAN_VON_MISES_2STAGE"]
  assert ht.retirement_message("circadian_von_mises_2stage.yl2") == exact
  assert exact != ht.retirement_message("CIRCADIAN_VON_MISES")


@pytest.mark.parametrize(
    "name", ["standard_z_score_2stage", "standard_z_score_2stage.yl2", "HOUR_OF_DAY_PROFILE",
             "mad_robust_z_4stage.yl2", "dual_sector_fusion_3stage.yl2"],
)
def test_stage_suffix_fallback_never_retires_an_active_template(name):
  assert not ht.is_retired(name)
  ht.assert_not_retired(name)


def test_no_skill_template_or_active_model_pipeline_becomes_retired():
  root = get_skills_root()
  templates = [p.name for skill in (ht.RISK_METRICS_SKILL, ht.STATS_HUNTER_SKILL)
               for p in (root / skill / "templates").rglob("*.yl2")]
  assert len(templates) > 50
  assert [n for n in templates if ht.is_retired(n)] == []
  builder = ht.skill_module(ht.STATS_HUNTER_SKILL, "scripts/multistage_query_builder.py")
  hybrid = ht.skill_module(ht.RISK_METRICS_SKILL, "scripts/ueba_hybrid_engine.py")
  active = [m.name for enum in (builder.ModelArchetype, hybrid.StatisticalModel) for m in enum
            if not ht.is_retired(m.name)]
  assert len(active) > 30
  assert [m for m in active if ht.is_retired(f"{m.lower()}_2stage.yl2")] == []


def test_loopback_and_writeback_thresholds_come_from_constants():
  c = ht.constants()
  assert ht.loopback_thresholds() == (c.LOOPBACK_MIN_DISTINCT_HITS, c.LOOPBACK_COMPOSITE_SUM_Z_SQ_THRESHOLD)
  assert ht.loopback_thresholds() == (2, 25.0)
  assert ht.writeback_cri_threshold() == c.WRITEBACK_CRI_THRESHOLD
  assert ht.min_baseline_days() == c.DEFAULT_MIN_BASELINE_DAYS == 7


def test_mode_a_is_the_last_complete_utc_day():
  now = datetime(2026, 10, 30, 0, 30, tzinfo=timezone.utc)
  assert ht.mode_a_day(now) == date(2026, 10, 29)
  assert ht.mode_a_window(date(2026, 10, 29)) == ("2026-10-29T00:00:00Z", "2026-10-30T00:00:00Z")


def test_entity_graph_window_starts_two_days_back_and_pins_event_day():
  assert ht.ecg_window(date(2026, 10, 29)) == ("2026-10-27T00:00:00Z", "2026-10-30T00:00:00Z")
  assert ht.event_day_pin(date(2026, 10, 29)) == (
      'timestamp.get_date(metadata.event_timestamp.seconds) = "2026-10-29"')


def _utc(iso: str) -> datetime:
  return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def test_raw_baseline_window_is_the_30_day_window_ending_with_the_scored_day():
  start, end = ht.raw_baseline_window(date(2026, 10, 29))
  assert (start, end) == ("2026-09-30T00:00:00Z", "2026-10-30T00:00:00Z")
  assert _utc(end) - _utc(start) == timedelta(days=30)
  # D is the last day of the raw baseline: the window ends where the Mode A window ends.
  assert end == ht.mode_a_window(date(2026, 10, 29))[1]
  assert ht.raw_baseline_window() == ht.raw_baseline_window(ht.mode_a_day())


@pytest.mark.parametrize("model", ["MAD", "QUANTILE_IQR_SKEW"])
@pytest.mark.parametrize("day", [date(2026, 10, 29), date(2026, 3, 1), date(2024, 3, 1), date(2027, 1, 1)])
def test_raw_baseline_window_matches_the_risk_metrics_hybrid_engine(model, day):
  # The skill's own Mode A window for raw MAD / quantile baselines (scored day gated by $in_scoring_window).
  hybrid = ht.skill_module(ht.RISK_METRICS_SKILL, "scripts/ueba_hybrid_engine.py")
  windows = hybrid._compute_execution_windows(  # pylint: disable=protected-access
      "", mode="A", statistical_model=hybrid.StatisticalModel[model], target_date=day.isoformat())
  assert ht.raw_baseline_window(day) == (windows["start_time"], windows["end_time"])


def test_mode_caps_come_from_constants():
  c = ht.constants()
  assert ht.mode_caps() == {
      "mode_b_macro_days": c.MAX_MODE_B_DAYS_MACRO,
      "mode_b_cusum_macro_days": c.MAX_CUSUM_MODE_B_DAYS_MACRO,
      "mode_c_macro_days": c.MAX_MODE_C_DAYS_MACRO,
      "mode_b_micro_days": c.MAX_MODE_B_DAYS_MICRO,
  }


def test_skill_module_loads_risk_metrics_scripts_as_the_scripts_package():
  module = ht.skill_module(ht.RISK_METRICS_SKILL, "scripts/submission_tests.py")
  expected = get_skills_root() / ht.RISK_METRICS_SKILL / "scripts" / "submission_tests.py"
  assert Path(module.__file__).resolve() == expected.resolve()
  assert module is sys.modules["scripts.submission_tests"]
  assert ht.skill_module(ht.RISK_METRICS_SKILL, "scripts/ueba_constants.py") is ht.constants()


def test_skill_module_loads_stats_hunter_scripts_by_path_under_a_private_name():
  builder = ht.skill_module(ht.STATS_HUNTER_SKILL, "scripts/multistage_query_builder.py")
  expected = get_skills_root() / ht.STATS_HUNTER_SKILL / "scripts" / "multistage_query_builder.py"
  assert Path(builder.__file__).resolve() == expected.resolve()
  assert builder.__name__.startswith("_harness_") and not builder.__name__.startswith("scripts")
  assert ht.skill_module(ht.STATS_HUNTER_SKILL, "scripts/multistage_query_builder.py") is builder
  # The builder imports the shared ueba_constants as `scripts.ueba_constants`: the risk-metrics copy.
  assert builder.format_cri is ht.constants().format_cri
  # The private name is derived from skill + path: the stats-hunter copy of ueba_constants is its own module.
  sh_constants = ht.skill_module(ht.STATS_HUNTER_SKILL, "scripts/ueba_constants.py")
  assert sh_constants is not ht.constants()
  assert sh_constants.__name__ not in (builder.__name__, ht.constants().__name__)
  assert sh_constants.CRI_BANDS == ht.cri_bands()


def test_skill_module_raises_for_a_missing_script():
  with pytest.raises(FileNotFoundError):
    ht.skill_module(ht.STATS_HUNTER_SKILL, "scripts/no_such_script.py")


def test_stats_hunter_scripts_load_first_in_a_fresh_interpreter():
  # Loading must not depend on import order: a stats-hunter script loaded before any risk-metrics
  # module still resolves its `scripts.ueba_constants` import to the risk-metrics copy.
  code = textwrap.dedent("""
      import sys
      from src import harness_truth as ht
      builder = ht.skill_module(ht.STATS_HUNTER_SKILL, "scripts/multistage_query_builder.py")
      assert sys.modules["scripts.ueba_constants"] is ht.constants()
      assert builder.format_cri is ht.constants().format_cri
      ht.skill_module(ht.RISK_METRICS_SKILL, "scripts/submission_tests.py")
      print("LOADED")
  """)
  proc = subprocess.run(
      [sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, check=False)
  assert proc.returncode == 0, proc.stderr
  assert proc.stdout.strip().endswith("LOADED")

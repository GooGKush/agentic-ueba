# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""CaseWallCardFormatter renders the harness CRI bands from src/harness_truth.py, never its own ladder."""

import pytest

from src import harness_truth as ht
from src.formatters.case_wall_card import CaseWallCardFormatter

# Every harness band edge (26/46/70/90) plus the edges of the retired 80/60/40 ladder.
BOUNDARIES = [0, 25, 26, 39, 40, 45, 46, 59, 60, 69, 70, 79, 80, 88, 89, 90, 100]
MISSING = [None, "N/A", float("nan")]


def _card(cri, is_outlier=True, **kwargs):
  return CaseWallCardFormatter.format_card(
      target_entity="alice", entity_type="USER", model_name="STANDARD_Z_SCORE",
      calibrated_risk_index=cri, is_outlier=is_outlier, rows_count=12, **kwargs,
  )


@pytest.mark.parametrize("cri", BOUNDARIES)
def test_risk_bar_shows_the_harness_band_and_verdict(cri):
  bar = CaseWallCardFormatter.render_risk_bar(cri)
  _, label, emoji = ht.cri_band(cri)
  assert bar.startswith(f"`{ht.format_cri(cri)}/100`")
  assert f"{emoji} **{label.upper()}**" in bar
  assert f"`{ht.verdict_for(cri)}`" in bar
  assert bar.count("█") + bar.count("░") == 10


@pytest.mark.parametrize("missing", MISSING)
def test_missing_cri_renders_na_never_a_nominal_zero(missing):
  bar = CaseWallCardFormatter.render_risk_bar(missing)
  assert bar.startswith("`N/A`") and f"`{ht.verdict_for(None)}`" in bar
  assert "0/100" not in bar and "NOMINAL" not in bar.upper()
  card = _card(missing, is_outlier=False)
  assert "N/A" in card and ht.action_guidance(None) in card
  assert "0/100" not in card and "NOMINAL" not in card.upper()


@pytest.mark.parametrize("cri", BOUNDARIES + MISSING)
def test_case_risk_tags_follow_the_harness_bands(cri):
  tags = CaseWallCardFormatter.build_case_tags(calibrated_risk_index=cri, primary_vector="Egress")
  expected = {"CRITICAL_OUTLIER": ["RISK:CRITICAL"], "HIGH_OUTLIER": ["RISK:HIGH"]}.get(ht.verdict_for(cri), [])
  # A High / Critical finding carries its common vector; lower bands and N/A carry no tag by themselves.
  assert tags == (expected + ["VECTOR:EGRESS"] if expected else [])


def test_cri_88_is_a_high_finding_and_90_is_critical():
  assert CaseWallCardFormatter.build_case_tags(88.0, primary_vector="Workspace", second_order_ran=True) == [
      "RISK:HIGH", "VECTOR:WORKSPACE", "SECOND_ORDER_HUNT"]
  assert CaseWallCardFormatter.build_case_tags(90.0, primary_vector="Workspace") == ["RISK:CRITICAL", "VECTOR:WORKSPACE"]
  # Medium (46-69) is no RISK finding; an outlier or a second-order hunt still tags its vector.
  assert CaseWallCardFormatter.build_case_tags(68.0, primary_vector="Auth", is_outlier=True) == ["VECTOR:AUTH"]
  assert CaseWallCardFormatter.build_case_tags(None, primary_vector="Egress", second_order_ran=True) == [
      "VECTOR:EGRESS", "SECOND_ORDER_HUNT"]


@pytest.mark.parametrize("cri,is_outlier", [(95, True), (75, True), (50, True), (30, False), (10, False)])
def test_card_guidance_follows_the_harness_action_mapping(cri, is_outlier):
  card = _card(cri, is_outlier=is_outlier)
  assert CaseWallCardFormatter.render_risk_bar(cri) in card
  assert f"CRI {ht.format_cri(cri)}/100" in card and f"`{ht.verdict_for(cri)}`" in card
  # Tier guidance with the recommendation-only note, not a blanket containment instruction.
  assert ht.action_guidance(cri) in card
  assert "containment playbooks" not in card


def test_tags_line_makes_no_band_claim_without_tags():
  assert CaseWallCardFormatter.render_tags_line([]) == "`NONE`"
  assert "**Case Triage Tags**: `NONE`" in _card(None, is_outlier=False)

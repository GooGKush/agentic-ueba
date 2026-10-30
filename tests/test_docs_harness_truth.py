# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""README.md and ARCHITECTURE.md state the harness truth that src/harness_truth.py serves at runtime.

Expected values are read from harness_truth (and through it from the skills), never restated here.
"""

import json
import re
from pathlib import Path

import pytest

from src import harness_truth as ht

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = {name: (REPO_ROOT / name).read_text(encoding="utf-8") for name in ("README.md", "ARCHITECTURE.md")}
DOC_NAMES = sorted(DOCS)


def _balanced():
  return ht.constants().resolve_sensitivity_thresholds("BALANCED")[1]


@pytest.mark.parametrize("doc", DOC_NAMES)
def test_docs_name_harness_truth_as_the_single_runtime_source(doc):
  assert "`src/harness_truth.py`" in DOCS[doc]
  assert "single runtime source of harness truth" in DOCS[doc]


@pytest.mark.parametrize("doc", DOC_NAMES)
def test_docs_state_the_harness_cri_formula_bands_and_mapping(doc):
  text = DOCS[doc]
  assert "zero floor" in text and "`N/A`" in text
  for low, high, _, label, _ in ht.cri_bands():
    assert f"`{low}–{high}` {label}" in text, (low, high, label)
  for verdict in ht.BAND_VERDICTS.values():
    assert f"`{verdict}`" in text, verdict
  assert "recommendations only" in text


def test_readme_triage_example_uses_the_harness_verdict_and_action():
  from src.autonomous_hunter import GENERIC_CONTAINMENT_ACTION  # the triad pivot's containment recommendation

  block = DOCS["README.md"].split("**Response Structure (`JITHuntResponse`)**:", 1)[1].split("```json", 1)[1]
  triage = json.loads(block.split("```", 1)[0])["triage"]
  cri = triage["calibrated_risk_index"]
  assert triage["verdict"] == ht.verdict_for(cri)
  assert triage["recommended_action"] == ht.recommended_action(cri, containment_action=GENERIC_CONTAINMENT_ACTION)


@pytest.mark.parametrize("doc", DOC_NAMES)
def test_docs_state_the_active_archetype_count(doc):
  builder = ht.skill_module(ht.STATS_HUNTER_SKILL, "scripts/multistage_query_builder.py")
  active = [a.name for a in builder.ModelArchetype if not ht.is_retired(a.name)]
  text = DOCS[doc]
  stated = re.findall(r"\b(\d+) [Aa]ctive (?:canonical raw UDM |`secops-statistical-hunter` )?[Aa]rchetypes", text)
  assert stated and {int(n) for n in stated} == {len(active)}
  # No archetype count that does not say it counts the active ones.
  assert re.findall(r"\b(\d+) (?:canonical )?(?:raw UDM )?(?:`secops-statistical-hunter` )?[Aa]rchetypes\b", text) == []


@pytest.mark.parametrize("doc", DOC_NAMES)
def test_docs_never_list_a_retired_model_as_active(doc):
  for line in DOCS[doc].splitlines():
    for name in ht.retired_models():
      if f"`{name}`" in line:
        assert "retired" in line.lower(), (name, line)
    assert "geodesic impossible travel" not in line.lower() or "retired" in line.lower(), line


def test_readme_marks_the_retired_mcp_tools_retired():
  rows = {line.split("|")[2].strip(): line for line in DOCS["README.md"].splitlines() if line.startswith("| | `hunt_")}
  for tool, model in (("`hunt_circadian_von_mises`", "CIRCADIAN_VON_MISES"),
                      ("`hunt_impossible_travel`", "IMPOSSIBLE_TRAVEL_GEO_VELOCITY")):
    assert ht.is_retired(model)
    assert "**Retired**" in rows[tool] and f"`{model}`" in rows[tool] and "`NOT_EVALUATED`" in rows[tool]


@pytest.mark.parametrize("doc", DOC_NAMES)
def test_docs_state_the_mode_a_entity_graph_window(doc):
  text = DOCS[doc]
  assert "`D-2 00:00:00Z`" in text and "`D+1 00:00:00Z`" in text and "event_day_pin" in text
  assert "back `48h`" not in text
  assert "today's UTC bucket" not in text  # Mode A scores the last complete UTC day D


def test_architecture_states_the_balanced_fusion_gate():
  assert f"`fusion_threshold_sq = {_balanced()['fusion_threshold_sq']}`" in DOCS["ARCHITECTURE.md"]
  assert "`fusion_threshold_sq = 9.0`" not in DOCS["ARCHITECTURE.md"]


@pytest.mark.parametrize("doc", DOC_NAMES)
def test_docs_state_the_band_escalation_dedup(doc):
  assert "+2.0" not in DOCS[doc]
  assert "higher harness CRI band" in DOCS[doc]


def test_readme_fleet_spike_threshold_defaults_to_the_harness_tier():
  rows = {line.split("|")[1].strip(): line for line in DOCS["README.md"].splitlines() if line.startswith("| `FLEET_360_")}
  assert f"`{_balanced()['anomaly_threshold']}` (harness BALANCED `anomaly_threshold`)" in rows["`FLEET_360_SPIKE_THRESHOLD_Z`"]

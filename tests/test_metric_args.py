"""Guards the secops-risk-metrics-multistage v1.8.2 metric-argument contract.

Every metrics.*(...) filter argument must be a direct UDM field path
(<field>: <field>), never a $placeholder or quoted literal, so baselines do not
zero out when a query is pasted into the SecOps UI with Case Sensitivity Off.
"""
import asyncio
import re

from src.risk_metrics_engine import RiskMetricsEngine

METRIC_CALL = re.compile(r"metrics\.[a-z_]+\((.*?)\)\)", re.DOTALL)
BAD_ARG = re.compile(r"[a-z_.]+:\s*(\$[a-z_]+|\"[^\"]*\")")
OUTCOME_VAR = re.compile(r"^\s*\$([a-zA-Z0-9_]+)\s*=", re.MULTILINE)


def _render_all():
  eng = RiskMetricsEngine()
  captured = []

  async def fake_exec(session, query, *args, **kwargs):
    captured.append(query)
    return {}

  eng.runner.execute_query_via_mcp = fake_exec

  async def main():
    await eng.run_360_behavioral_radar(None, "user.a", entity_type="USER")
    await eng.run_360_behavioral_radar(None, "host-a", entity_type="HOST")
    await eng.run_cloud_crud_surge(None, "user.a")

  asyncio.run(main())
  captured.extend(eng.build_fleet_360_sector_queries(entity_type="USER").values())
  captured.extend(eng.build_fleet_360_sector_queries(entity_type="ASSET").values())
  captured.append(eng._render_rare_destination_ecg_query("dns_queries_total"))
  captured.append(eng._render_rare_destination_ecg_query("network_bytes_outbound"))
  captured.append(eng._render_fusion_rare_destination_query())
  return captured


def test_no_placeholder_or_literal_args_inside_metrics_calls():
  queries = _render_all()
  assert queries
  for q in queries:
    code = re.sub(r"//[^\n]*", "", q)
    for call in METRIC_CALL.findall(code):
      bad = [m.group(0) for m in BAD_ARG.finditer(call)]
      assert not bad, f"metrics.* call has non-field-path args {bad}:\n{q}"


def test_cloud_crud_outcomes_within_compiler_limit():
  eng = RiskMetricsEngine()
  captured = []

  async def fake_exec(session, query, *args, **kwargs):
    captured.append(query)
    return {}

  eng.runner.execute_query_via_mcp = fake_exec
  asyncio.run(eng.run_cloud_crud_surge(None, "user.a"))
  query = captured[0]
  stage_body, root = query.split("\n}\n", 1)
  stage_outcome = stage_body.split("outcome:", 1)[1]
  root_outcome = root.split("outcome:", 1)[1].split("order:", 1)[0]
  assert len(OUTCOME_VAR.findall(stage_outcome)) <= 20
  assert len(OUTCOME_VAR.findall(root_outcome)) <= 20
  for fam in ("resource_read_total", "resource_written_total",
              "resource_deletion_total", "resource_creation_total"):
    assert f"metrics.{fam}(" in query

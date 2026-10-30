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


def _outcome_blocks(query):
  """Every outcome: block (each named stage and the root) as text, comments removed.

  The canonical Cloud CRUD sector (templates/radar_360/user_2_cloud_risk.yl2) has two stages plus a
  root, so the 20-variable limit is checked per block rather than on a single stage/root split.
  """
  code = "\n".join(re.sub(r"//[^\n]*", "", ln) for ln in query.splitlines())
  blocks = []
  for m in re.finditer(r"^\s*outcome:\s*\n", code, re.M):
    body = []
    for line in code[m.end():].splitlines():
      if re.match(r"^\s*(condition|order|limit|match|outcome):", line) or line.strip().startswith("}") \
          or re.match(r"^\s*stage\s+\w+", line):
        break
      body.append(line)
    blocks.append("\n".join(body))
  return blocks


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
    await eng.run_workspace_triad(None, "user.a")
    await eng.run_alert_surge(None, "host-a", entity_type="ASSET")
    await eng.run_alert_surge(None, "user.a", entity_type="USER")
    await eng.run_failure_ratio_surge(None, "user.a", fail_metric="http_queries_fail")
    await eng.run_failure_ratio_surge(None, "user.a", fail_metric="auth_attempts_fail")
    for mode in ("fail", "success", "total"):
      await eng.run_cloud_repository_scope(None, "user.a", outcome_mode=mode)
    for kc in (
        "CREDENTIAL_ACCESS_TO_EXECUTION",
        "INITIAL_ACCESS_TO_DISCOVERY",
        "EXECUTION_TO_C2_DNS",
        "EXECUTION_TO_EXFILTRATION",
        "CREDENTIAL_ACCESS_TO_LATERAL_MOVEMENT",
        "CLOUD_DISCOVERY_TO_COLLECTION",
        "DEFENSE_EVASION_ALERT_TO_EXFILTRATION",
        "C2_BEACON_TO_RARE_DESTINATION_EXFIL",
    ):
      await eng.run_killchain_archetype(None, "user.a", archetype=kc)
    for m_name, m_metric in (
        ("MAD", "network_bytes_outbound"),
        ("TWO_PART_HURDLE", "workspace_total_download_actions"),
        ("RELATIVE_DEVIATION", "http_queries_total"),
        ("HTTP_ERROR_RATIO_SURGE_2STAGE", "http_queries_fail"),
        ("HTTP_TARGET_SURGE_2STAGE", "http_queries_total"),
        ("HYBRID_METRIC_HTTP_UA_PREVALENCE_2STAGE", "http_queries_total"),
    ):
      await eng.run_dynamic_metric_pipeline(None, "user.a", target_metric=m_metric, model_name=m_name)

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
  blocks = _outcome_blocks(query)
  assert len(blocks) >= 2
  for block in blocks:
    assert len(OUTCOME_VAR.findall(block)) <= 20
  assert "if(if(" not in query
  for fam in ("resource_read_total", "resource_written_total",
              "resource_deletion_total", "resource_creation_total"):
    assert f"metrics.{fam}(" in query


def test_360_radar_cloud_spoke_4family_and_outcome_limits():
  eng = RiskMetricsEngine()
  captured = []

  async def fake_exec(session, query, *args, **kwargs):
    captured.append(query)
    return {}

  eng.runner.execute_query_via_mcp = fake_exec
  asyncio.run(eng.run_360_behavioral_radar(None, "user.a", entity_type="USER"))
  user_cloud_q = [q for q in captured if "stage cloud_risk" in q][0]
  fleet_cloud_q = eng.build_fleet_360_sector_queries(entity_type="USER")["Cloud"]

  for q in (user_cloud_q, fleet_cloud_q):
    blocks = _outcome_blocks(q)
    assert len(blocks) >= 2
    for block in blocks:
      assert len(OUTCOME_VAR.findall(block)) <= 20
    assert "if(if(" not in q
    for fam in ("resource_read_total", "resource_written_total",
                "resource_deletion_total", "resource_creation_total"):
      assert f"metrics.{fam}(" in q


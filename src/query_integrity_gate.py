# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Pre-Dispatch and Post-Execution Query Integrity Gate for Agentic UEBA.

Ensures that composed YARA-L 2.0 queries are syntactically valid, free of
unresolved template placeholders, properly scoped to target entities, and
that Chronicle backend API/compiler errors never silently degrade into 0-row
clean hunt results.

Pre-dispatch platform rules come from the remediated UEBA harness at runtime
(`src.harness_truth` and the skills' own query validators), never from copies:

* bare `sqrt(` (use `math.sqrt`), more than 20 outcome variables per outcome
  block and `if()` without an else branch:
  `secops-statistical-hunter/scripts/multistage_query_builder.py`
  `validate_multistage_syntax`, loaded through `harness_truth.skill_module`;
* compound arithmetic inside either `if()` branch (the multiplicative gate
  `if(c, 1.0, 0.0) * (a - b) / d` stays legal), stage references, `$stage.field`
  in `match:`, literal `/ 0`, ternaries and the ECG prevalence invariant:
  `secops-risk-metrics-multistage/scripts/submission_tests.py`;
* retired models and templates, including in-query CRI ladders (retired
  `PIECEWISE_CRI`): `harness_truth.retirement_message`.
"""

import re
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Tuple

from src import harness_truth


class QueryValidationError(ValueError):
  """Raised when a query fails pre-dispatch QA validation before API execution."""

  def __init__(self, errors: List[str], query: str = ""):
    self.errors = list(errors)
    self.query = query
    super().__init__(f"Pre-dispatch query validation failed ({len(errors)} error(s)): {'; '.join(errors)}")


class ChronicleBackendQueryError(RuntimeError):
  """Raised when the Chronicle backend rejects or fails a query on execution."""

  def __init__(self, errors: List[str], raw_response: Any = None):
    self.errors = list(errors)
    self.raw_response = raw_response
    super().__init__(f"Chronicle backend query error ({len(errors)} issue(s)): {'; '.join(errors)}")


class QueryIntegrityGate:
  """Pre-Dispatch and Post-Execution QA Gate for multi-stage YARA-L queries."""

  BACKEND_ERROR_SIGNATURES: Tuple[str, ...] = (
      "Request contains an invalid argument",
      "INVALID_ARGUMENT",
      "FAILED_PRECONDITION",
      "syntax error",
      "compilation error",
      "semantic error",
      "parsing:",
      "semantic analysis:",
      "400 Client Error",
      "Internal error encountered",
      "com.google.chronicle",
  )

  # Any `{{ ... }}` slot left by template rendering, whatever its spacing or content.
  _UNRESOLVED_SLOT_RE = re.compile(r"\{\{[^{}\n]*\}\}")

  # Methodology header lines that name the model, architecture or template a query was built from.
  _MODEL_HEADER_RE = re.compile(
      r"//[ \t]*(?:Statistical[ \t]+Model|Models?(?:[ \t]+Supported)?|ARCHITECTURE|Template|Pipeline)[ \t]*:[ \t]*([^\n]*)",
      re.IGNORECASE,
  )
  _NAME_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.yl2)?")
  _TEMPLATE_FILE_RE = re.compile(r"\b[A-Za-z0-9_]+\.yl2\b")

  _OUTCOME_BLOCK_RE = re.compile(
      r"\boutcome\s*:(.*?)(?=\n[ \t]*(?:condition|order|match|limit|outcome)\s*:|\}|\Z)", re.DOTALL
  )
  _ASSIGNMENT_RE = re.compile(r"^[ \t]*\$([A-Za-z_]\w*)[ \t]*=(?!=)[ \t]*(.+?)[ \t]*$", re.MULTILINE)
  _CRI_NAME_RE = re.compile(r"(?:^|_)cri(?:_|$)|calibrated_risk", re.IGNORECASE)
  _BARE_REFERENCE_RE = re.compile(r"[$\w.\[\]]+")
  _AGGREGATE_CALL_RE = re.compile(r"(?:max|min|sum|avg|array_distinct|count_distinct)\s*\(")
  _COMPUTATION_RE = re.compile(r"\bif\s*\(|[-+*/]")

  @staticmethod
  def normalize_yaral(query: str) -> str:
    """Strips comments and normalizes whitespace for concordance checks."""
    if not query:
      return ""
    no_line = re.sub(r"//[^\n]*", "", query)
    no_block = re.sub(r"/\*.*?\*/", "", no_line, flags=re.DOTALL)
    return " ".join(no_block.split())

  # ---------------------------------------------------------------------------
  # Harness validators (loaded from the skills at runtime)
  # ---------------------------------------------------------------------------

  @classmethod
  def stats_hunter_query_builder(cls) -> ModuleType:
    """`secops-statistical-hunter/scripts/multistage_query_builder.py` (harness_truth.skill_module).

    skill_module loads the risk-metrics skill first, so the builder's `scripts.ueba_constants` import
    resolves to the byte-identical shared module.
    """
    return harness_truth.skill_module(harness_truth.STATS_HUNTER_SKILL, "scripts/multistage_query_builder.py")

  @classmethod
  def risk_metrics_submission_tests(cls) -> ModuleType:
    """`secops-risk-metrics-multistage/scripts/submission_tests.py` (query checks and if() helpers)."""
    return harness_truth.skill_module(harness_truth.RISK_METRICS_SKILL, "scripts/submission_tests.py")

  @staticmethod
  def _code_for_validators(query: str) -> str:
    """Blanks block comments and string, backtick and regex literals, keeping line structure.

    The skills' validators are line- and brace-based; literal contents such as regex
    quantifiers (`{8}`) or a quoted `sqrt(` must not be read as code.
    """
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), query, flags=re.DOTALL)
    text = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)
    text = re.sub(r"`[^`\n]*`", "``", text)
    return re.sub(r"((?:^|[=(,~])[ \t]*)/(?:\\.|[^/\\\n])+/", r'\1""', text, flags=re.MULTILINE)

  @classmethod
  def platform_rule_errors(cls, query: str) -> List[str]:
    """Harness platform-rule violations for a composed query (empty when it complies).

    Fails closed: if the skills' validators cannot be loaded or raise, the query is reported
    as unverifiable (HARNESS_VALIDATORS_UNAVAILABLE) rather than dispatched.
    """
    try:
      return cls._evaluate_platform_rules(query)
    except Exception as harness_err:  # Never dispatch a query the harness could not verify.
      return [
          "HARNESS_VALIDATORS_UNAVAILABLE: The skills' query validators could not verify this query "
          f"({type(harness_err).__name__}: {harness_err}); refusing to dispatch an unverified query."
      ]

  @classmethod
  def _evaluate_platform_rules(cls, query: str) -> List[str]:
    builder = cls.stats_hunter_query_builder()
    submission = cls.risk_metrics_submission_tests()
    code = cls._code_for_validators(query)
    errors: List[str] = []

    # Stats-hunter validator: only the platform rules (its other checks are heuristics the
    # risk-metrics runbooks deliberately violate, e.g. in-stage outcome chaining).
    for err in builder.validate_multistage_syntax(code):
      if "(INVALID_SQRT_FUNCTION)" in err:
        errors.append(f"BARE_SQRT_FUNCTION: {err}")
      elif err.startswith("OUTCOME LIMIT EXCEEDED"):
        errors.append(f"OUTCOME_VARIABLE_LIMIT_EXCEEDED: {err}")
      elif err.startswith("INVALID_IF_CONDITIONAL") and "else-clause" in err:
        errors.append(err)

    # Risk-metrics helpers: both if() branches must be placeholders, fields or constants.
    for call, args in submission.iter_if_calls(code):
      if len(args) >= 3 and any(submission.if_branch_has_compound_arithmetic(branch) for branch in args[1:3]):
        errors.append(
            "COMPOUND_ARITHMETIC_IN_IF_BRANCH: if() branches accept only placeholders, fields and constants; "
            "precompute each branch into its own outcome variable (the multiplicative gate "
            f"if(c, 1.0, 0.0) * (a - b) / d is valid): {' '.join(call.split())}"
        )

    for check in (
        submission.check_stage_references,
        submission.check_root_match_stage_prefix,
        submission.check_outcome_conditionals_and_divisions,
    ):
      errors.extend(check(code))
    # The ECG invariant reads string literals ("DERIVED_CONTEXT"), so it gets the raw query.
    errors.extend(submission.check_ecg_invariants(query))

    errors.extend(cls.retired_model_errors(query))
    errors.extend(cls.in_query_cri_errors(query))
    return errors

  @classmethod
  def retired_model_errors(cls, query: str) -> List[str]:
    """Retired models / templates named in methodology headers or `.yl2` references.

    harness_truth.retirement_message also resolves `<model>_<n>stage.yl2` template names to their model.
    """
    tokens = set(cls._TEMPLATE_FILE_RE.findall(query))
    for header in cls._MODEL_HEADER_RE.finditer(query):
      tokens.update(cls._NAME_TOKEN_RE.findall(header.group(1)))

    errors: List[str] = []
    for token in sorted(tokens):
      if "_" not in token:
        continue
      message = harness_truth.retirement_message(token)
      if message:
        errors.append(f"RETIRED_MODEL_OR_TEMPLATE ({token}): {message}")
    return errors

  @classmethod
  def _is_cri_projection(cls, rhs: str) -> bool:
    """True when an outcome only projects an existing CRI value (e.g. max(security_result.risk_score))."""
    if cls._BARE_REFERENCE_RE.fullmatch(rhs):
      return True
    return bool(cls._AGGREGATE_CALL_RE.match(rhs)) and not cls._COMPUTATION_RE.search(rhs)

  @classmethod
  def in_query_cri_errors(cls, query: str) -> List[str]:
    """Outcome variables that compute a CRI in-query (step ladders or sigmoids): retired PIECEWISE_CRI."""
    code = re.sub(r"//[^\n]*", "", cls._code_for_validators(query))
    retired = harness_truth.retirement_message("PIECEWISE_CRI") or ""
    errors: List[str] = []
    for block in cls._OUTCOME_BLOCK_RE.findall(code):
      for assignment in cls._ASSIGNMENT_RE.finditer(block):
        name, rhs = assignment.group(1), assignment.group(2).strip()
        if cls._CRI_NAME_RE.search(name) and not cls._is_cri_projection(rhs):
          errors.append(
              f"IN_QUERY_CRI_COMPUTATION (${name}): CRI is computed in Python from the scored Z, never "
              f"inside the query. {retired}".rstrip()
          )
    return errors

  # ---------------------------------------------------------------------------
  # Pre-dispatch and post-execution gates
  # ---------------------------------------------------------------------------

  @classmethod
  def verify_pre_dispatch(
      cls,
      query: str,
      expected_entity: Optional[str] = None,
      expected_preflight_query: Optional[str] = None,
      ast_validator_fn: Optional[Callable[[str], List[str]]] = None,
      raise_on_error: bool = True,
  ) -> Dict[str, Any]:
    """Validates a composed YARA-L query BEFORE sending it to Chronicle OneMCP."""
    errors: List[str] = []
    if not query or not query.strip():
      errors.append("EMPTY_QUERY: Cannot dispatch an empty query string to udm_search.")
      if raise_on_error:
        raise QueryValidationError(errors, query=query)
      return {"valid": False, "passed": False, "errors": errors}

    unresolved = cls._UNRESOLVED_SLOT_RE.findall(query)
    if unresolved:
      errors.append(
          f"UNRESOLVED_TEMPLATE_PLACEHOLDERS: Query contains unresolved slot(s): {sorted(set(unresolved))}"
      )

    errors.extend(cls.platform_rule_errors(query))

    if ast_validator_fn is not None:
      ast_errors = [
          e for e in ast_validator_fn(query) if not e.startswith("MISSING_GOAL_HEADER")
      ]
      errors.extend(ast_errors)

    # Check bare Data Table equality or `in` membership without column specification
    code_no_comments = re.sub(r"//[^\n]*", "", query)
    code_no_comments = re.sub(r"/\*.*?\*/", "", code_no_comments, flags=re.DOTALL)
    code_no_literals = re.sub(r'"(?:\\.|[^"\\])*"', '""', code_no_comments)
    for m_dt in re.finditer(r"(?:=|\bin)\s*%([a-zA-Z0-9_]+)(?![.\w])", code_no_literals):
      errors.append(
          f"INVALID_DATA_TABLE_COLUMN_SYNTAX: Data Table reference '%{m_dt.group(1)}' must specify a column (e.g., '%{m_dt.group(1)}.column_name')."
      )

    if expected_entity and expected_entity.strip().lower() not in (
        "",
        "fleet",
        "all",
        "enterprise",
        "unknown",
        "unknown_entity",
        "target_entity",
        "*",
    ):
      ent = expected_entity.strip()
      if ent.lower() not in query.lower():
        errors.append(
            f"MISSING_ENTITY_FILTER (UNSCOPED_ENTITY_QUERY): Expected target entity '{ent}' is not bound in the query predicates."
        )

    if expected_preflight_query:
      norm_pre = cls.normalize_yaral(expected_preflight_query)
      norm_cur = cls.normalize_yaral(query)
      if norm_pre != norm_cur:
        errors.append(
            "PREFLIGHT_QUERY_MUTATION (PREFLIGHT_EXECUTION_DRIFT): Dispatched query drifted from pre-flight preview query."
        )

    valid = len(errors) == 0
    if not valid and raise_on_error:
      raise QueryValidationError(errors, query=query)
    return {"valid": valid, "passed": valid, "errors": errors}

  validate_preflight_query = verify_pre_dispatch

  @classmethod
  def verify_backend_response(
      cls,
      dispatched_query: str,
      raw_response: Any,
      raw_text: str = "",
      is_error_flag: bool = False,
      raise_on_error: bool = True,
  ) -> Dict[str, Any]:
    """Inspects raw udm_search responses so backend/compiler errors never masquerade as 0-row clean hunts."""
    errors: List[str] = []
    if is_error_flag:
      errors.append("MCP_TOOL_ERROR_FLAG: udm_search returned isError=True.")

    combined_text = raw_text or ""
    if isinstance(raw_response, dict):
      if raw_response.get("error"):
        errors.append(f"CHRONICLE_API_ERROR_FIELD: {raw_response.get('error')}")
      if "raw_text" in raw_response and isinstance(raw_response["raw_text"], str):
        combined_text = f"{combined_text}\n{raw_response['raw_text']}"
      exec_q = raw_response.get("executed_query")
      if exec_q and dispatched_query:
        if cls.normalize_yaral(exec_q) != cls.normalize_yaral(dispatched_query):
          errors.append(
              "POST_EXECUTION_QUERY_DRIFT: Executed query reported in response does not match dispatched query."
          )
    elif isinstance(raw_response, str):
      combined_text = f"{combined_text}\n{raw_response}"

    for sig in cls.BACKEND_ERROR_SIGNATURES:
      if sig.lower() in combined_text.lower():
        snippet = " ".join(combined_text.split())[:280]
        errors.append(f"CHRONICLE_BACKEND_QUERY_ERROR: Backend rejected query ({sig}): {snippet}")
        break

    valid = len(errors) == 0
    if not valid and raise_on_error:
      raise ChronicleBackendQueryError(errors, raw_response=raw_response)
    return {"valid": valid, "passed": valid, "errors": errors}

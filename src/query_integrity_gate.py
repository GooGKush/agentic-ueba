# Copyright 2026 Google LLC. All Rights Reserved.
# Author: Greg Kushmerek

"""Pre-Dispatch and Post-Execution Query Integrity Gate for Agentic UEBA.

Ensures that composed YARA-L 2.0 queries are syntactically valid, free of
unresolved template placeholders, properly scoped to target entities, and
that Chronicle backend API/compiler errors never silently degrade into 0-row
clean hunt results.
"""

import re
from typing import Any, Callable, Dict, List, Optional, Tuple


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

  @staticmethod
  def normalize_yaral(query: str) -> str:
    """Strips comments and normalizes whitespace for concordance checks."""
    if not query:
      return ""
    no_line = re.sub(r"//[^\n]*", "", query)
    no_block = re.sub(r"/\*.*?\*/", "", no_line, flags=re.DOTALL)
    return " ".join(no_block.split())

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

    unresolved = re.findall(r"\{\{[a-zA-Z0-9_]+\}\}", query)
    if unresolved:
      errors.append(
          f"UNRESOLVED_TEMPLATE_PLACEHOLDERS: Query contains unresolved slot(s): {sorted(set(unresolved))}"
      )

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

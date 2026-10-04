"""Regression tests for high-impact authorization and bounded queries."""
import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _tree(path: str):
    return ast.parse((ROOT / path).read_text(encoding="utf-8"))


def test_user_deletion_requires_step_up_role():
    tree = _tree("backend/routers/users.py")
    functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "delete_user"]
    assert len(functions) == 1
    source = ast.get_source_segment((ROOT / "backend/routers/users.py").read_text(encoding="utf-8"), functions[0]) or ""
    assert 'Depends(require_step_up_role("owner", "admin"))' in source


def test_threat_and_audit_query_limits_are_bounded():
    threats = (ROOT / "backend/routers/threats.py").read_text(encoding="utf-8")
    resources = (ROOT / "backend/routers/resources.py").read_text(encoding="utf-8")
    assert 'limit: int = Query(50, ge=1, le=100)' in threats
    assert 'limit: int = Query(100, ge=1, le=200)' in resources

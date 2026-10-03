"""Guards for roadmap Phase 6: the agent's tools must stay read-only and small."""
import ast
from pathlib import Path

from app.agent.tools import TOOLS

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_TOOLS = {"get_alert_summary", "query_events", "enrich_ip", "get_related_alerts", "lookup_mitre",
                  "finalize_incident"}


def test_tool_whitelist_is_exact():
    """Adding a tool must be a deliberate act: this test fails until you update it on purpose."""
    assert {t["function"]["name"] for t in TOOLS} == EXPECTED_TOOLS


def test_tools_module_cannot_touch_files_processes_or_sockets():
    tree = ast.parse((ROOT / "app" / "agent" / "tools.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"typing", "app"}, imported
    calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert not calls & {"open", "exec", "eval", "compile", "__import__", "getattr", "setattr"}, calls


def test_only_the_enrichment_module_may_use_the_network():
    """enrich/ip.py is the single place allowed to import httpx, and only when ENRICH_ONLINE=1."""
    offenders = []
    for path in (ROOT / "app").rglob("*.py"):
        if "httpx" in path.read_text() and path.name != "ip.py":
            offenders.append(path.name)
    assert offenders == []

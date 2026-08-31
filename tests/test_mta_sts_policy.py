"""MTA-STS: parse the permitted MX set, and grade the policy's own certificate.

WHY THIS EXISTS. `mta_sts_mode` is captured from the policy file at
https://mta-sts.<domain>/.well-known/mta-sts.txt, and that fetch used to pass
`ssl=False` — "to avoid cert failures". RFC 8461 §3.3 requires the policy be fetched over
a **validated** HTTPS connection: a policy served behind an expired, self-signed or
wrong-name certificate is not a policy, and a conforming sender discards it. So the column
counted domains whose MTA-STS no sender would honour — populated, and answering a
different question than its name implies.

`tls_ok` makes that falsifiable, and the `mx:` set makes the other half checkable: a
domain in `enforce` whose policy omits its own MX has its mail REFUSED by conforming
senders. Both come out of the fetch that already happens; neither adds a request.

`test_tls_failure_does_not_lose_the_mode` and `test_no_retry_on_a_plain_failure` are the
load-bearing pair — the first says grading the cert must not cost existing coverage, the
second says it must not cost an extra request on the common failure.

Run: pytest tests/test_mta_sts_policy.py
"""
from __future__ import annotations

import ast
import asyncio
import re
import ssl
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = (REPO / "dns_module" / "policy.py").read_text(encoding="utf-8")


def _lift(names, ns):
    """Exec selected top-level nodes out of policy.py.

    Importing the module pulls aiohttp; the parsing under test needs only `re`. Same
    approach as tests/test_probe_off_is_null.py so this runs in a lean CI env.
    """
    tree = ast.parse(SRC)
    want = set(names)
    out = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in want:
                    out.append(node)
    exec(compile(ast.Module(out, []), "<policy>", "exec"), ns)
    return ns


_NS = _lift(["MTASTS_MODE_RE", "MTASTS_MAXAGE_RE", "MTASTS_MX_RE"], {"re": re})
MX_RE = _NS["MTASTS_MX_RE"]
MODE_RE = _NS["MTASTS_MODE_RE"]

POLICY = """version: STSv1
mode: enforce
mx: mx1.example.com
mx: mx2.example.com
mx: *.mail.example.net
max_age: 604800
"""


def _mx(text):
    return [m.group("mx").strip().rstrip(".").lower() for m in MX_RE.finditer(text)]


# ------------------------------------------------------------------ the mx: parse
def test_every_mx_line_is_captured():
    """findall, not search — a policy names one host per line and they all bind."""
    assert _mx(POLICY) == ["mx1.example.com", "mx2.example.com", "*.mail.example.net"]


def test_wildcard_hosts_survive_intact():
    """RFC 8461 §3.2 permits `*.example.net`; dropping the star would silently narrow it."""
    assert "*.mail.example.net" in _mx(POLICY)


def test_mx_is_normalised_for_comparison():
    """Lowercased and dot-stripped, so it compares directly against resolver output."""
    assert _mx("mx: MX1.Example.COM.\n") == ["mx1.example.com"]


def test_a_policy_without_mx_yields_empty_not_error():
    assert _mx("version: STSv1\nmode: testing\nmax_age: 86400\n") == []


def test_mx_regex_does_not_match_max_age_or_mode():
    """`mx` must anchor to its own line — a sloppy pattern eats `max_age:` too."""
    assert _mx("max_age: 604800\nmode: enforce\n") == []


# --------------------------------------------------------------- the fetch semantics
class _FakeResp:
    def __init__(self, status=200, text=POLICY):
        self.status, self._t = status, text

    async def text(self):
        return self._t

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _run_fetch(monkeypatch, behaviour):
    """Drive the real fetch_mta_sts_policy_http with aiohttp stubbed.

    `behaviour(verify)` either returns a response or raises, so a test can say "verified
    fails with a cert error, unverified succeeds" and assert on the call log.
    """
    import types as _t
    import sys

    calls = []
    fake = _t.ModuleType("aiohttp")

    class _Session:
        def __init__(self, **kw):
            self._verify = kw["connector"]._verify

        def get(self, url, **kw):
            calls.append(self._verify)
            return behaviour(self._verify)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class _Conn:
        def __init__(self, **kw):
            self._verify = kw.get("ssl") is not False

    fake.ClientTimeout = lambda **kw: None
    fake.TCPConnector = _Conn
    fake.ThreadedResolver = lambda: None
    fake.ClientSession = _Session
    fake.ClientConnectorCertificateError = type("CCE", (Exception,), {})
    fake.ClientConnectorSSLError = type("CCS", (Exception,), {})
    monkeypatch.setitem(sys.modules, "aiohttp", fake)

    ns = {"re": re, "aiohttp": fake, "_ssl": ssl, "Optional": object,
          "Any": object, "Dict": dict}
    tree = ast.parse(SRC)
    nodes = [n for n in tree.body
             if (isinstance(n, ast.Assign)
                 and any(getattr(t, "id", "").startswith(("MTASTS_", "_TLS_"))
                         for t in n.targets))
             or (isinstance(n, ast.AsyncFunctionDef)
                 and n.name == "fetch_mta_sts_policy_http")]
    exec(compile(ast.Module(nodes, []), "<policy>", "exec"), ns)
    return asyncio.run(ns["fetch_mta_sts_policy_http"]("example.com")), calls


def test_verified_fetch_is_graded_ok(monkeypatch):
    res, calls = _run_fetch(monkeypatch, lambda verify: _FakeResp())
    assert res["tls_ok"] is True
    assert res["mode"] == "enforce"
    assert res["mx"][0] == "mx1.example.com"
    assert calls == [True], "a clean fetch must cost exactly one request"


def test_tls_failure_does_not_lose_the_mode(monkeypatch):
    """A bad cert downgrades the GRADE, it does not blank the data.

    Turning verification on must not cost existing mta_sts_mode coverage — otherwise the
    honest fix reads as a regression and gets reverted.
    """
    import sys

    def behaviour(verify):
        if verify:
            raise sys.modules["aiohttp"].ClientConnectorCertificateError()
        return _FakeResp()

    res, calls = _run_fetch(monkeypatch, behaviour)
    assert res["tls_ok"] is False, "policy is served but not RFC-valid"
    assert res["mode"] == "enforce", "mode still parsed from the unverified body"
    assert calls == [True, False]


def test_no_retry_on_a_plain_failure(monkeypatch):
    """A timeout means there is no policy to grade — retrying doubles the common failure."""
    def behaviour(verify):
        raise TimeoutError("no route")

    res, calls = _run_fetch(monkeypatch, behaviour)
    assert res["tls_ok"] is None
    assert res["mode"] == ""
    assert calls == [True], "must not retry when the failure was not about the certificate"


def test_missing_policy_is_none_not_false(monkeypatch):
    """404 is "no policy", which is a different fact from "policy with a bad cert"."""
    res, calls = _run_fetch(monkeypatch, lambda verify: _FakeResp(status=404))
    assert res["tls_ok"] is None
    assert res["mx"] == []


def test_row_builder_emits_both_new_fields():
    """Producer and row builder must not drift — the defect class this repo keeps hitting."""
    bp = ast.parse((REPO / "dns_module" / "batch_processor.py").read_text(encoding="utf-8"))
    keys = {k.value for n in ast.walk(bp) if isinstance(n, ast.Dict)
            for k in n.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    assert "mta_sts_mx" in keys
    assert "mta_sts_policy_tls_ok" in keys
    # ...and in the Arrow schema, or they never reach the parquet.
    fields = {n.args[0].value for n in ast.walk(bp)
              if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "field"
              and n.args and isinstance(n.args[0], ast.Constant)}
    assert {"mta_sts_mx", "mta_sts_policy_tls_ok"} <= fields

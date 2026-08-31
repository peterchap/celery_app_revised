"""`www` shipped a Python repr while its three real columns sat empty beside it.

WHY THIS EXISTS. `_check_sub` returns {'A': [...], 'AAAA': [...]} and `fetch_domain` stored
that dict whole under `records['www']`, while `_dnsrecord_to_expanded_row` read `www_a`,
`www_int` and `www_ptr` — keys nothing ever set. Measured 2026-08-27 over 44,640 bronze
rows: `www` **87.61% populated** with `"{'A': ['188.114.97.3'], ...}"` in a VARCHAR, and
`www_a` / `www_int` / `www_ptr` at **0.000%** with their data inside that string.

This is a third defect class beyond the two the alert column review names. The empty-string
trap is caught by `nullif(trim(x),'')`; the populated-constant trap is caught by checking
distinct values. **A stringified dict defeats both** — `IS NOT NULL` passes, `trim() <> ''`
passes, there are millions of distinct values, and the column still answers nothing.

`test_repr_never_ships` is the load-bearing one: it fails if the dict is ever assigned to
the bare key again, which is what the original defect was.

Run: pytest tests/test_www_unpack.py
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Dict, Optional

REPO = Path(__file__).resolve().parents[1]


def _lift(module_name: str, func_name: str, ns: dict):
    """Exec one top-level function out of a module that cannot be imported standalone.

    dns_fetcher.py pulls loguru, tldextract, lmdb and aiolimiter at import; the function
    under test needs none of them. Same trick as tests/test_probe_off_is_null.py — lift
    just the AST node, so this runs in a lean CI env rather than skipping.
    """
    import ast

    src = (REPO / "dns_module" / f"{module_name}.py").read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            exec(compile(ast.Module([node], []), f"<{module_name}>", "exec"), ns)
            return ns[func_name]
    raise AssertionError(f"{func_name} not found in {module_name}.py")


# ip_to_int lifted from its real source too, rather than reimplemented here — a local copy
# would let the two drift and this test would keep passing against the wrong arithmetic.
_NS: dict = {"Dict": Dict, "Any": Any, "Optional": Optional}
_NS["ip_to_int"] = _lift("dns_utils", "ip_to_int", dict(_NS, ipaddress=ipaddress))
unpack = _lift("dns_fetcher", "unpack_host_record", _NS)


def test_a_list_lands_in_prefix_a():
    r: dict = {}
    unpack(r, "www", "www.example.com", {"A": ["203.0.113.10", "203.0.113.11"]})
    assert r["www_a"] == ["203.0.113.10", "203.0.113.11"]


def test_int_is_the_first_address():
    r: dict = {}
    unpack(r, "www", "www.example.com", {"A": ["1.2.3.4", "5.6.7.8"]})
    # 1.2.3.4 -> 16909060
    assert r["www_int"] == 16909060


def test_repr_never_ships():
    """The defect itself. The bare column must be the hostname, never the dict."""
    r: dict = {}
    sub = {"A": ["188.114.97.3"], "AAAA": ["2a06:98c1:3120::3"]}
    unpack(r, "www", "www.example.com", sub)
    assert r["www"] == "www.example.com"
    assert r["www"] is not sub
    assert "{" not in str(r["www"]) and "'A'" not in str(r["www"])


def test_ptr_is_read_from_the_map_not_resolved():
    """PTR comes from ptr_map — the apex/mx/ns reverse lookups already made."""
    r: dict = {}
    unpack(r, "www", "www.example.com", {"A": ["1.2.3.4"]}, {"1.2.3.4": "host.cdn.net"})
    assert r["www_ptr"] == "host.cdn.net"


def test_ptr_absent_when_the_map_misses():
    """A www host on its own IP costs nothing extra — the field is simply empty.

    Filling it would mean a reverse lookup per domain across 402M rows, which is exactly
    the trade this whole workstream refuses.
    """
    r: dict = {}
    unpack(r, "www", "www.example.com", {"A": ["9.9.9.9"]}, {"1.2.3.4": "host.cdn.net"})
    assert "www_ptr" not in r


def test_no_addresses_writes_nothing():
    """A host that did not resolve must leave every field unset, not set them empty.

    Same invariant as the probe-off-must-be-null branch: "we did not find one" and "there
    is none" are different answers and only one of them is a measurement.
    """
    r: dict = {}
    unpack(r, "www", "www.example.com", {"AAAA": ["2606:4700::1111"]})
    assert r == {}
    unpack(r, "www", "www.example.com", {})
    assert r == {}


def test_mail_uses_the_same_path():
    r: dict = {}
    unpack(r, "mail", "mail.example.com", {"A": ["1.2.3.4"]}, {"1.2.3.4": "mx.example.net"})
    assert (r["mail"], r["mail_a"], r["mail_int"], r["mail_ptr"]) == (
        "mail.example.com", ["1.2.3.4"], 16909060, "mx.example.net")


def test_survives_a_junk_address():
    """A bad first address must not lose the whole record — int is skipped, rest stands."""
    r: dict = {}
    unpack(r, "www", "www.example.com", {"A": ["not-an-ip"]})
    assert r["www_a"] == ["not-an-ip"]
    assert r["www"] == "www.example.com"


def test_row_builder_reads_what_this_writes():
    """End-to-end against the real row builder, so the two halves cannot drift apart.

    The original bug was exactly a mismatch between the keys the producer set and the keys
    the row builder read, so asserting them together is the point.
    """
    import ast

    src = (REPO / "dns_module" / "batch_processor.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "_dnsrecord_to_expanded_row")
    keys = {k.value for node in ast.walk(fn) if isinstance(node, ast.Dict)
            for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    for f in ("www", "www_a", "www_int", "www_ptr", "mail_a", "mail_int", "mail_ptr"):
        assert f in keys, f"{f} is no longer emitted by the row builder"

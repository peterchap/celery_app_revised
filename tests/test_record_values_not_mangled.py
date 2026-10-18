r"""CAA, NAPTR and SRV shipped with every space, quote and punctuation mark stripped.

WHY THIS EXISTS. `DNSFetcher.fetch_records()` built the `caa`, `naptr` and `srv` columns
with `list_to_string()`, which runs every item through `to_ascii_hostname()` — the
*hostname* normalizer. It splits on ".", IDNA-encodes each label, and on InvalidCodepoint
falls back to `re.sub(r"[^A-Za-z0-9\-]", "", lbl)`. A record value is not a hostname, so
spaces, quotes, "@", ":", "+", "!" and "$" were all erased and the remains re-split on
dots. Measured on the branch before the fix:

    '0 issue "letsencrypt.org"'                -> '0issueletsencrypt.org'
    '0 iodef "mailto:abuse@example.com"'       -> '0iodefmailtoabuseexample.com'
    '10 100 "" "E2U+sip" "!^.*$!sip:info@..."' -> '10100e2usip.sipinfoexample.com'
    '10 5 5269 xmpp-server.example.com.'       -> '1055269xmpp-server.example.com'

Same defect class as the IPv6 colon stripping (tests/test_ipv6_not_mangled.py): one
normalizer, applied to values it was never written for. The SRV case is the sharpest —
`10 5 5269` fuses into `1055269`, and nothing can tell that back from `1 05 5269` or
`105 5 269`, so priority, weight and port are gone, not merely reformatted.

`caa` is the load-bearing one. centralake's `ingest_gold_dns_wide.py` reads it —
`CASE WHEN b.caa <> '' THEN [b.caa] END AS caa_records` — and it is the **only** route
from the collector into `gold.dns_wide.caa_records`; the struct columns bronze carries
beside it are not read there at all. `naptr` and `srv` have no reader in centralake today
but sit in the bronze Parquet schema, so they are fixed rather than dropped: both are
also written by the bulk path, and two producers of one column must not disagree about
its format.

`test_the_exact_reported_manglings_are_gone` is the load-bearing one: it fails if a record
value is ever fed back through the hostname normalizer.

Run: pytest tests/test_record_values_not_mangled.py
"""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_dns_utils():
    """Import dns_utils by path, skipping dns_module/__init__.py.

    That __init__ pulls dns_lookup -> lmdb, which the functions under test do not need;
    loading the file directly keeps this runnable in a lean CI env rather than skipping.
    Same motivation as the AST lift in tests/test_www_unpack.py.
    """
    spec = importlib.util.spec_from_file_location(
        "_dns_utils_under_test", REPO / "dns_module" / "dns_utils.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_u = _load_dns_utils()
records_to_string = _u.records_to_string
list_to_string = _u.list_to_string

CAA = [
    '0 issue "letsencrypt.org"',
    '0 issuewild ";"',
    '0 iodef "mailto:abuse@example.com"',
    '128 issue "digicert.com; cansignhttpexchanges=yes"',
]
NAPTR = [
    '10 100 "" "E2U+sip" "!^.*$!sip:info@example.com!" .',
    '100 10 "S" "SIP+D2U" "" _sip._udp.example.com.',
]
SRV = [
    '10 5 5269 xmpp-server.example.com.',
    '0 1 443 sipdir.online.lync.com.',
]


@pytest.mark.parametrize("value", CAA + NAPTR + SRV)
def test_a_record_value_survives_the_column(value: str) -> None:
    """The regression itself: one value in, the same text back out."""
    assert records_to_string([value]) == value


def test_the_exact_reported_manglings_are_gone() -> None:
    """The four values from the report, each against what actually shipped."""
    assert records_to_string(['0 issue "letsencrypt.org"']) != "0issueletsencrypt.org"
    assert records_to_string(['0 iodef "mailto:abuse@example.com"']) != (
        "0iodefmailtoabuseexample.com")
    assert records_to_string(['10 5 5269 xmpp-server.example.com.']) != (
        "1055269xmpp-server.example.com")
    # And the hostname joiner is still the thing that did it, so the test keeps meaning
    # something if someone re-points the column at it.
    assert list_to_string(['0 issue "letsencrypt.org"']) == "0issueletsencrypt.org"


@pytest.mark.parametrize("value", CAA)
def test_caa_fields_are_still_recoverable(value: str) -> None:
    """flags / tag / value must still be three readable things, not one fused token.

    This is the shape centralake's ingest_gold_dns_wide.py hands to gold.dns_wide as
    caa_records, and the only route the collector has into that column.
    """
    flags, tag, rest = records_to_string([value]).split(" ", 2)
    assert flags.isdigit()
    assert tag in {"issue", "issuewild", "iodef", "contactemail", "contactphone"}
    assert rest.startswith('"') and rest.endswith('"')


@pytest.mark.parametrize("value", SRV)
def test_srv_triple_does_not_fuse(value: str) -> None:
    """priority, weight and port were run together into one integer and lost."""
    priority, weight, port, target = records_to_string([value]).split(" ")
    assert (priority.isdigit(), weight.isdigit(), port.isdigit()) == (True, True, True)
    assert int(port) in {5269, 443}
    assert target.endswith(".")


def test_naptr_keeps_its_quoting_and_its_regexp() -> None:
    """The regexp field is the whole point of a NAPTR and is nothing but punctuation."""
    out = records_to_string(['10 100 "" "E2U+sip" "!^.*$!sip:info@example.com!" .'])
    assert '"E2U+sip"' in out
    assert '"!^.*$!sip:info@example.com!"' in out
    assert '""' in out  # the empty flags field must survive as an empty field


def test_multiple_records_stay_separable() -> None:
    """The "|" separator must round-trip a whole RRset, spaces and commas included."""
    assert records_to_string(CAA).split("|") == CAA
    assert records_to_string(NAPTR).split("|") == NAPTR


def test_separator_matches_the_bulk_producer() -> None:
    """Both paths write bronze `caa`; they must agree on the separator.

    batch_processor._join_list() is lifted rather than reimplemented — a local copy would
    let the two drift and this test would keep passing against the wrong format.
    """
    src = (REPO / "dns_module" / "batch_processor.py").read_text(encoding="utf-8")
    node = next(n for n in ast.parse(src).body
                if isinstance(n, ast.FunctionDef) and n.name == "_join_list")
    ns: dict = {"Any": object}
    exec(compile(ast.Module([node], []), "<batch_processor>", "exec"), ns)
    assert ns["_join_list"](CAA) == records_to_string(CAA)
    assert ns["_join_list"](SRV) == records_to_string(SRV)


def test_empties_and_junk_do_not_produce_phantom_records() -> None:
    """A None or a blank must drop out, not become an empty record in the RRset."""
    assert records_to_string([]) == ""
    assert records_to_string([None, "", "   "]) == ""
    assert records_to_string(['0 issue "x.org"', None, "  "]) == '0 issue "x.org"'
    assert records_to_string(["  0 issue \"x.org\"  "]) == '0 issue "x.org"'


def test_the_column_writers_use_this_joiner() -> None:
    """Pin the three call sites, so the fix cannot be quietly reverted at the source.

    The defect was a wrong function name at one keyword argument; asserting the argument
    and not just the helper is what makes this test cover it.
    """
    src = (REPO / "dns_module" / "dns_fetcher.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "DNSRecords"]
    assert calls, "DNSRecords(...) is no longer constructed in dns_fetcher.py"
    seen = set()
    for call in calls:
        for kw in call.keywords:
            if kw.arg not in ("caa", "naptr", "srv"):
                continue
            flat = ast.dump(kw.value)
            assert "records_to_string" in flat, f"{kw.arg}= no longer uses records_to_string"
            assert "list_to_string" not in flat, f"{kw.arg}= is back on the hostname joiner"
            seen.add(kw.arg)
    assert seen == {"caa", "naptr", "srv"}

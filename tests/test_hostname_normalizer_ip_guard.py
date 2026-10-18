r"""The hostname normalizer itself could still destroy an IP; now it cannot.

WHY THIS EXISTS. `ip_list_to_string()` (1.6.1, commit 910c452) keeps the `a` and `aaaa`
columns away from `to_ascii_hostname()`, which fixed the reported defect: IPv6 addresses
reaching reports as `2602ff1690117b01`. It fixed the two call sites, not the mechanism.
`to_ascii_hostname()` still split on ".", IDNA-encoded each label, and on InvalidCodepoint
fell back to `re.sub(r"[^A-Za-z0-9\-]", "", lbl)` — so the *next* caller to hand it an
address, in any column, would have been corrupted the same silent way.

The guard closes that: an IP literal is returned canonically instead of entering the IDNA
path. This is defence in depth behind `ip_list_to_string()`, not a replacement for it —
that function is still what the IP columns should call, because it says so at the call
site and canonicalizes a whole list.

`test_the_normalizer_itself_is_safe_now` is the load-bearing one: it fails if the IDNA
path is ever reachable with an IP again.

Run: pytest tests/test_hostname_normalizer_ip_guard.py
"""
from __future__ import annotations

import importlib.util
import ipaddress
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_dns_utils():
    """Import dns_utils by path, skipping dns_module/__init__.py.

    That __init__ pulls dns_lookup -> lmdb, which this needs none of; loading the file
    directly keeps this runnable in a lean CI env rather than skipping. Same motivation
    as the AST lift in tests/test_www_unpack.py.
    """
    spec = importlib.util.spec_from_file_location(
        "_dns_utils_under_test", REPO / "dns_module" / "dns_utils.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_u = _load_dns_utils()
normalize_ip = _u.normalize_ip
to_ascii_hostname = _u.to_ascii_hostname

# The address from the original report, plus forms that exercise `::` elision and the
# single-zero groups the LDH fallback erased without trace.
IPV6 = [
    "2602:ff16:9:0:1:17b:0:1",
    "2a06:98c1:3120::3",
    "2606:4700::1111",
    "2001:db8:0:0:0:0:0:1",
]
IPV4 = ["192.0.2.1", "188.114.97.3", "1.2.3.4"]


@pytest.mark.parametrize("ip", IPV6 + IPV4)
def test_the_normalizer_itself_is_safe_now(ip: str) -> None:
    """Hand to_ascii_hostname an address directly: it must come back as that address."""
    out = to_ascii_hostname(ip)
    assert ipaddress.ip_address(out) == ipaddress.ip_address(ip)


def test_the_exact_reported_mangling_cannot_recur() -> None:
    assert to_ascii_hostname("2602:ff16:9:0:1:17b:0:1") != "2602ff1690117b01"


def test_normalize_ip_agrees_with_hash_ip() -> None:
    """hash_ip() keys on .compressed; anything canonicalizing IPs must match it."""
    assert normalize_ip("2001:DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert normalize_ip("[2606:4700::1111]") == "2606:4700::1111"
    assert normalize_ip("example.com") == ""
    assert normalize_ip("not-an-ip") == ""
    assert normalize_ip("") == ""
    assert normalize_ip(None) == ""


def test_ipv4_is_untouched_by_the_guard() -> None:
    """IPv4 always survived IDNA unchanged; the guard must not alter that output."""
    for ip in IPV4:
        assert to_ascii_hostname(ip) == ip


def test_hostnames_still_normalize() -> None:
    """The guard must not shadow the hostname path it sits in front of."""
    assert to_ascii_hostname("WWW.Example.COM.") == "www.example.com"
    assert to_ascii_hostname("München.de") == "xn--mnchen-3ya.de"
    assert to_ascii_hostname("mail.example.co.uk") == "mail.example.co.uk"
    assert to_ascii_hostname(None) == ""
    assert to_ascii_hostname("") == ""


def test_a_hostname_that_merely_looks_numeric_is_not_an_ip() -> None:
    """Leading zeros make it not an address; it must take the hostname path."""
    assert to_ascii_hostname("01.2.3.4") == "01.2.3.4"
    assert to_ascii_hostname("1.2.3.4.5") == "1.2.3.4.5"

"""Regression tests for dns_module's SMTP-220 banner parser.

WHY THIS EXISTS. Until 2026-08-20 `ROBUST_BANNER_REGEX` required `220` followed by
WHITESPACE, so RFC 5321's multiline greeting form `220-host ...` never matched:
parse_smtp_banner returned (None, None), the banner was discarded, and
infer_mbp_from_banner had nothing to work with. Exim and cPanel hosts greet that way
routinely, so this silently dropped a whole class of servers from mail-provider inference.
It had no test, which is why it lasted.

The banner path this guards is live on every DNS slave: dns_fetcher.py:2211 calls
parse_smtp_banner and feeds infer_mbp_from_banner directly from it.

⚠️ THIS PACKAGE IS CONSUMED BY TAG. Downstream pins
`datazag-dns-module @ git+ssh://…/celery_app_revised.git@dns-module-v<N>`, so a fix on
master reaches nothing until pyproject.toml's version is bumped and a new
`dns-module-v*` tag is cut. Landing a parser change here is half the job.

Run: pytest tests/test_smtp_banner_parse.py
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_dns_utils():
    """Load dns_utils.py directly. Importing `dns_module` as a package pulls in the fetcher's
    heavy async dependencies, which a regex test has no business requiring."""
    spec = importlib.util.spec_from_file_location(
        "_dns_utils_under_test", REPO / "dns_module" / "dns_utils.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


try:
    _U = _load_dns_utils()
except Exception as exc:                                   # pragma: no cover
    pytest.skip(f"cannot load dns_module.dns_utils: {exc}", allow_module_level=True)

parse_smtp_banner = _U.parse_smtp_banner
infer_mbp_from_banner = _U.infer_mbp_from_banner


# ── the defect this file exists for ──────────────────────────────────────────────────────

@pytest.mark.parametrize("banner,expected", [
    ("220-out.example.com ESMTP",                     ("out.example.com", "")),
    # Hostname hyphens must survive — only the FIRST hyphen is the continuation marker.
    ("220-vps-7ac26990.vps.ovh.us ESMTP Exim 4.98.2", ("vps-7ac26990.vps.ovh.us", "Exim 4.98.2")),
    ("220-mx.google.com ESMTP gsmtp",                 ("mx.google.com", "gsmtp")),
    ("220-mail.example.org ESMTP Postfix",            ("mail.example.org", "Postfix")),
])
def test_multiline_220_greeting_is_parsed(banner, expected):
    assert parse_smtp_banner(banner) == expected


@pytest.mark.parametrize("banner,expected", [
    ("220 mail.foo.com ESMTP Postfix",          ("mail.foo.com", "Postfix")),
    ("220 mx.google.com ESMTP gv21... - gsmtp", ("mx.google.com", "gv21... - gsmtp")),
    ("220 hostonly.example",                    ("hostonly.example", "")),
    ("220 host.example SMTP Exim",              ("host.example", "Exim")),
])
def test_single_line_greeting_still_parses(banner, expected):
    """The widening must not regress the form that already worked."""
    assert parse_smtp_banner(banner) == expected


@pytest.mark.parametrize("banner", [
    "",
    None,
    "550 not a banner",
    "220-",                       # continuation marker with no host
    "220 - host.example ESMTP",   # detached hyphen is not a continuation marker
    "2205551212 nonsense",        # `220` must be followed by the separator, not more digits
    "220x.example ESMTP",
])
def test_non_banners_and_false_positives_return_none(banner):
    """Guards the widening from drifting into `220\\S*`, which would swallow any reply code
    that merely begins with 220."""
    assert parse_smtp_banner(banner) == (None, None)


# ── the consumer that motivated the fix ──────────────────────────────────────────────────

@pytest.mark.parametrize("banner,expected", [
    ("220-mx.google.com ESMTP gsmtp",        ("Google Workspace", "EnterpriseMail")),
    ("220-mx1.pphosted.com ESMTP Proofpoint", ("Proofpoint", "SEG")),
    ("220-mail.example.com ESMTP mimecast",  ("Mimecast", "SEG")),
])
def test_provider_inference_now_reaches_multiline_hosts(banner, expected):
    """The point of the fix, end to end. These hosts inferred NOTHING before, because the
    banner never parsed — _BANNER_MAP always had the rules, it just never saw the text."""
    host, details = parse_smtp_banner(banner)
    assert infer_mbp_from_banner(host, details) == expected


def test_unmapped_provider_still_yields_none():
    """_BANNER_MAP is deliberately a small set of high-precision hints; the big rules live in
    provider tables. An Exim banner parsing correctly but mapping to nothing is expected —
    the gain from the fix is that banner_host/banner_details are populated at all."""
    host, details = parse_smtp_banner("220-vps-7ac26990.vps.ovh.us ESMTP Exim 4.98.2")
    assert (host, details) == ("vps-7ac26990.vps.ovh.us", "Exim 4.98.2")
    assert infer_mbp_from_banner(host, details) == (None, None)

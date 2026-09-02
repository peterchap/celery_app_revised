"""Tests for dns_module.banner_rules — the banner fingerprints promoted out of tests/.

WHY THIS EXISTS. Until 2026-09-01 these rules lived in `dnsproject/tests/smtp_banner.py`,
where no pipeline could import them, and their only guard was a bare function called
`test_no_risk_bias_on_software_only_rule` defined *inside the module under test* — which
pytest collected only by accident of the filename. Promoting the rules without promoting
their invariants would have moved the code and left the protection behind.

Run: pytest tests/test_banner_rules.py
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load():
    """Load banner_rules directly by path. dns_module/__init__.py imports dns_lookup, which
    pulls dnspython and friends; this module needs only `re`, and a regex test should not
    require the collection stack to be installed."""
    spec = importlib.util.spec_from_file_location(
        "_banner_rules_under_test", REPO / "dns_module" / "banner_rules.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


br = _load()


# ── the operator/software split, which is the point of the module ────────────────────────

@pytest.mark.parametrize("host,details,expected", [
    ("mx.google.com", "gv21... - gsmtp",              ("Google Workspace", "enterprise", 95, None)),
    ("contoso-co-uk.mail.protection.outlook.com", "", ("Microsoft 365 (EOP)", "enterprise", 95, None)),
    ("mx1.pphosted.com", "Proofpoint",                ("Proofpoint", "seg", 95, None)),
])
def test_operator_banners_carry_no_software(host, details, expected):
    """An OPERATOR banner names a company and carries no software, so mta_software is None."""
    assert br.fingerprint_provider(host, details) == expected


@pytest.mark.parametrize("host,details,software", [
    ("mail.example.org", "Postfix",   "Postfix"),
    ("anything.at.all", "postfix",    "Postfix"),
    ("mail.example.org", "Exim 4.98", "Exim"),
    ("mail.example.org", "OpenSMTPD", "OpenSMTPD"),
])
def test_oss_mta_software_is_not_a_provider(host, details, software):
    """Software has no operator, country or commercial relationship, so `provider` is None
    and `mta_software` carries the answer. This is the category error the 2026-08-23 split
    exists to fix; asserting it here is what stops it being un-fixed."""
    provider, category, _conf, mta = br.fingerprint_provider(host, details)
    assert provider is None
    assert mta == software
    assert category == "self_hosted"


def test_no_risk_bias_on_software_only_rule():
    """A software-only rule must never carry a risk/reputation weight.

    Promoted from a bare function inside the old module — where it was collected only because
    the file happened to start with `test_`. Two operators of the same MTA have opposite
    sending practices; the software is identical in both."""
    for rule in br.PROVIDER_RULES:
        if rule.get("software") and not rule.get("name"):
            for banned in ("risk_bias", "reputation", "risk", "trust"):
                assert banned not in rule, (
                    f"software-only rule {rule['software']!r} carries {banned!r}. MTA "
                    "software is a descriptor; sending behaviour is a property of the sender."
                )
            assert rule.get("name") is None, (
                f"{rule['software']!r} must not be filed as a provider — software has no "
                "operator, country or commercial relationship."
            )


# ── taxonomy reconciliation with the lake ────────────────────────────────────────────────

# The VALID set from dnsproject's scripts/build_mbp_category_map.py, materialised as
# ref.mbp_category_map. Duplicated here deliberately: this test's job is to fail when the two
# vocabularies drift, which it cannot do if it imports the value it is checking against.
LAKE_VALID_MBP_CATEGORIES = {
    "Mailbox Provider", "Hosting Mailbox", "Security Gateway",
    "Transactional", "Self-hosted MTA", "Parking", "unknown",
}
# `Parking` added 2026-09-02 (dnsproject: mbp_category adds Parking). Nothing here emits it —
# a banner cannot tell you a domain is parked — so no rule or mapping changes. It is mirrored
# only so this constant stays a faithful copy of the lake's VALID set, which is the one job it
# has: the assertions below are subset checks, so an incomplete mirror fails to catch drift
# rather than failing loudly.


def test_every_rule_category_maps_to_a_valid_lake_category():
    """Every category these rules can emit must translate into the curated taxonomy. A rule
    category with no mapping would write a value `ref.mbp_category_map` rejects."""
    emitted = {r["category"] for r in br.PROVIDER_RULES} | {"unknown"}
    for cat in emitted:
        mapped = br.mbp_category_for(cat)
        assert mapped in LAKE_VALID_MBP_CATEGORIES, f"{cat!r} -> {mapped!r} is not a lake category"


def test_mapping_has_no_entries_the_lake_would_reject():
    assert set(br.MBP_CATEGORY.values()) <= LAKE_VALID_MBP_CATEGORIES


def test_unrecognised_category_degrades_to_unknown_rather_than_raising():
    """A banner classifier must not be able to halt a corpus sweep."""
    assert br.mbp_category_for("something-nobody-defined") == "unknown"
    assert br.mbp_category_for("") == "unknown"
    assert br.mbp_category_for(None) == "unknown"


def test_hosting_mailbox_is_not_claimed_by_rules():
    """PINS A SCOPE DECISION, and it is the important test in this file.

    `Hosting Mailbox` is the LARGEST class in the real corpus — Bluehost, HostGator, Sakura
    and the rest dominate the vanity-MX residue — and no rule here can produce it, because
    identifying a hosting company is a CATALOGUE lookup, not a banner pattern.

    Measured 2026-09-01 over a 2,500-host vanity-MX probe: this rule list attributed 0
    operators where announced-hostname -> registered-domain -> ref.provider_catalog
    attributed 87.7%. The correct response to that gap is curation in the catalogue, NOT
    pasting 570 hosting providers into this file, where only a release could change them.

    If this test fails because someone added a hosting rule, that is the conversation to
    have — not a line to delete."""
    assert "Hosting Mailbox" not in br.MBP_CATEGORY.values()
    assert not any(r["category"] == "hosting" for r in br.PROVIDER_RULES)


# ── ordering and shape invariants ────────────────────────────────────────────────────────

def test_operator_rules_precede_the_catch_all_software_rules():
    """FIRST MATCH WINS, and the OSS-MTA rules match `host = .*`. If one were ordered above
    an operator rule it would swallow every banner that happens to name its software."""
    first_catch_all = next(
        (i for i, r in enumerate(br.PROVIDER_RULES) if r.get("host") == r".*"), len(br.PROVIDER_RULES))
    last_named = max(i for i, r in enumerate(br.PROVIDER_RULES) if r.get("name"))
    assert last_named < first_catch_all


def test_every_rule_is_exactly_one_of_operator_or_software():
    for rule in br.PROVIDER_RULES:
        assert bool(rule.get("name")) != bool(rule.get("software")), (
            f"rule {rule!r} must be an operator OR software, never both and never neither"
        )


def test_unmatched_banner_returns_none_not_a_sentinel_string():
    """Changed on promotion. `"Unknown"` as a provider is indistinguishable from a real
    operator of that name once written to a column; None is what this estate treats as
    absent. `category` stays the STRING "unknown" — that is a real taxonomy value."""
    provider, category, conf, mta = br.fingerprint_provider("no.match.example", "nothing here")
    assert provider is None
    assert mta is None
    assert category == "unknown"
    assert conf == 0


def test_case_insensitive_rules_are_reachable():
    """REGRESSION, found by promoting the rules. `fingerprint_provider` lower-cases both
    inputs and the patterns were matched with no flags, so the OpenSMTPD rule
    (`r"\bOpenSMTPD\b"`) could never match `"opensmtpd"` — it was unreachable from the day it
    was written, and the old suite never asserted it.

    Kept as its own test rather than folded into the parametrized one above so that the
    failure names the cause if the flag is ever dropped again."""
    for details, expected in [("OpenSMTPD", "OpenSMTPD"), ("opensmtpd", "OpenSMTPD"),
                              ("OPENSMTPD 7.4", "OpenSMTPD"), ("PostFix", "Postfix")]:
        _p, _c, _conf, mta = br.fingerprint_provider("mail.example.org", details)
        assert mta == expected, f"{details!r} should fingerprint as {expected}"

"""SMTP banner fingerprinting — operator vs software, as two separate facts.

PROMOTED 2026-09-01 from `dnsproject/tests/smtp_banner.py`, where this logic had been living
since the 2026-08-23 provider/software split. It was the most correct banner classifier in
the estate and **no pipeline could import it**, because it sat in a test file. That is the
whole reason for this module.

⚠️ WHY IT ENDED UP IN tests/ — worth knowing before "tidying" it back.
`dnsproject`'s dev venv has no `datazag-dns-module` installed, and an orphaned
`dnsproject/dns_module/` directory (containing only `__pycache__`) shadows the real package
as a namespace package, so `from dns_module.dns_utils import ...` raises ModuleNotFoundError
there. Vendoring the logic into `tests/` was the only way to test it locally. So the copy in
dnsproject CANNOT simply be deleted in favour of this module until that environment is fixed
— see the PR that added this file.

────────────────────────────────────────────────────────────────────────────────────────────
🚨 WHAT THIS MODULE IS FOR, AND WHAT IT IS NOT FOR

These rules match BANNER TEXT — the greeting a server prints. They are good at software
(`Postfix`, `Exim`) and at a handful of operators whose banners are idiomatic (`gsmtp`,
`pphosted.com`).

**They are NOT the way to identify an operator at scale, and the numbers say so plainly.**
Measured 2026-09-01 over a 2,500-host probe of vanity MX hosts (see the C1/C2 readiness
assessment in the datazag-pipeline hub, §7):

    this rule list                        ->   0 hosts attributed to an operator   (0.0%)
    announced-hostname -> registered-domain -> 1,438 of 1,639 answered            (87.7%)

Zero versus 87.7% **on identical bytes**. Two reasons, and both are structural rather than a
missing-rules problem:

  1. The list contains NO hosting companies. Bluehost, XServer, HostGator, Sakura,
     HostEurope — 570 distinct operators in that probe, of which only 32 are in
     `ref.provider_catalog` — cannot match by construction.
  2. `Exim` and `Postfix` are what cPanel and Plesk run. Reading them as the answer to
     *"who operates this mailbox"* is the category error the split below exists to fix.

🔑 **So the operator axis belongs in DATA, not in this file.** `ref.provider_catalog` is the
operator catalogue and it is curated; the long tail of hosting companies goes there, not into
a hardcoded Python list that only a release can change. **Do not "fix" the 0% by pasting 570
hosting providers in here.** The intended pipeline is:

    banner -> parse_smtp_banner()      -> announced hostname + details
           -> announced hostname       -> registered domain -> ref.provider_catalog  [OPERATOR]
           -> details/host             -> fingerprint_provider()                     [SOFTWARE]

This module owns the second line. The catalogue owns the first.
────────────────────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# Bumped when the rules or the taxonomy mapping change, so a consumer can tell which
# vocabulary a stored value came from.
BANNER_RULES_VERSION = "2026.09.01"

# ── Provider / software fingerprints ─────────────────────────────────────────────────────
# Order matters: FIRST MATCH WINS. Operators are listed before the generic OSS-MTA rules,
# whose `host` is `.*` and would otherwise swallow an operator whose banner also names its
# software (Google's greeting says `gsmtp`, not `postfix`, but plenty of others do both).
PROVIDER_RULES: List[Dict[str, Any]] = [
    # Enterprise suites
    {"name": "Google Workspace", "category": "enterprise", "confidence": 95,
     "host": r"(?:^|\.)google\.com$", "details": r"\bgsmtp\b"},
    {"name": "Microsoft 365 (EOP)", "category": "enterprise", "confidence": 95,
     "host": r"(?:mail\.|.*\.)protection\.outlook\.com$", "details": r""},
    {"name": "Microsoft 365 (Outlook)", "category": "enterprise", "confidence": 85,
     "host": r"(?:^|\.)outlook\.com$", "details": r""},

    # SEG (Secure Email Gateway)
    {"name": "Proofpoint", "category": "seg", "confidence": 95,
     "host": r"(?:^|\.)pphosted\.com$", "details": r"\bproofpoint\b"},
    {"name": "Mimecast", "category": "seg", "confidence": 95,
     "host": r"(?:^|\.)mimecast\.com$", "details": r"\bmimecast\b"},
    {"name": "Cisco IronPort", "category": "seg", "confidence": 90,
     "host": r"(?:^|\.)secureserver\.net$|(?:^|\.)iphmx\.com$", "details": r"\b(ironport|cisco)\b"},
    {"name": "Barracuda", "category": "seg", "confidence": 90,
     "host": r"(?:^|\.)barracudanetworks\.com$", "details": r"\bbarracuda\b"},

    # ESP / transactionals
    {"name": "SendGrid", "category": "esp", "confidence": 85,
     "host": r"(?:^|\.)sendgrid\.net$", "details": r"\bsendgrid\b"},
    {"name": "Mailgun", "category": "esp", "confidence": 85,
     "host": r"(?:^|\.)mailgun\.net$", "details": r"\b(mailgun|mxmg)\b"},
    {"name": "Amazon SES", "category": "esp", "confidence": 80,
     "host": r"(?:^|\.)amazonses\.com$", "details": r"(?:Amazon SES|ESMTPSA)?"},
    {"name": "SparkPost", "category": "esp", "confidence": 80,
     "host": r"(?:^|\.)sparkpostmail\.com$", "details": r"\bsparkpost\b"},

    # Other enterprise mail
    {"name": "Zoho Mail", "category": "enterprise", "confidence": 85,
     "host": r"(?:^|\.)zoho\.com$", "details": r"\bzoho\b"},

    # OSS MTAs (often self-hosted). `software`, never `name` — see fingerprint_provider().
    {"software": "Postfix", "category": "self_hosted", "confidence": 70,
     "host": r".*", "details": r"\bpostfix\b"},
    {"software": "Exim", "category": "self_hosted", "confidence": 70,
     "host": r".*", "details": r"\bexim\b"},
    {"software": "Haraka", "category": "self_hosted", "confidence": 70,
     "host": r".*", "details": r"\bharaka\b"},
    {"software": "OpenSMTPD", "category": "self_hosted", "confidence": 70,
     "host": r".*", "details": r"\bOpenSMTPD\b"},
]

# ── Taxonomy reconciliation ──────────────────────────────────────────────────────────────
# These rules speak `enterprise/seg/esp/self_hosted`. The lake's curated taxonomy — the
# `VALID` set in dnsproject's scripts/build_mbp_category_map.py, materialised as
# `ref.mbp_category_map` — speaks a different vocabulary. Anything writing a banner result
# next to `mbp_category` must translate, and translating in one named place beats each
# consumer inventing its own mapping.
#
# ⚠️ `Hosting Mailbox` is deliberately absent from the right-hand side. It is the single
# LARGEST class in the real corpus (Bluehost, HostGator, Sakura … dominate the vanity-MX
# residue) and NO rule here can produce it — because identifying a hosting company is a
# catalogue lookup, not a banner pattern. Its absence is a fact about this module's scope,
# not an oversight, and `test_hosting_mailbox_is_not_claimed_by_rules` pins it.
MBP_CATEGORY: Dict[str, str] = {
    "enterprise":  "Mailbox Provider",
    "seg":         "Security Gateway",
    "esp":         "Transactional",
    "self_hosted": "Self-hosted MTA",
    "unknown":     "unknown",
}


def mbp_category_for(rule_category: str) -> str:
    """Translate a rule `category` into the lake's `mbp_category` vocabulary.

    Unrecognised input maps to `unknown` rather than raising: a banner classifier should not
    be able to halt a corpus sweep, and `unknown` is an honest answer that the taxonomy
    already admits.
    """
    return MBP_CATEGORY.get((rule_category or "").strip().lower(), "unknown")


def fingerprint_provider(host: str, details: str) -> Tuple[Optional[str], str, int, Optional[str]]:
    """Return (provider, category, confidence, mta_software).

    🚨 TWO FIELDS, NOT ONE (split 2026-08-23). A banner can name an OPERATOR (Google,
    Proofpoint, Namecheap) or it can name SOFTWARE (Postfix, Exim, Haraka, OpenSMTPD), and
    those are different kinds of fact:

      provider      an operator — has a company, a country, a commercial relationship, and a
                    policy. None when the banner names only software.
      mta_software  what program answered. None when the banner names only an operator.

    Until this split, `Postfix` and `Exim` were returned as `name` and landed in
    `mx_banner_provider` beside `Google` and `Proofpoint`. That is a category error: Postfix
    is software with no operator, no country and no commercial relationship, so the provider
    field answered a different question depending on the row.

    🚨 NO POLICY, REPUTATION OR RISK VALUE MAY BE DERIVED FROM `mta_software`. Two operators
    of the same MTA have opposite sending practices; the software is identical in both.
    Deriving reputation from it would be the `deliverability_score` mistake again —
    attributing a *sender's* behaviour to a fact about *infrastructure*. Enforced by
    `test_no_risk_bias_on_software_only_rule` in tests/test_banner_rules.py.

    ⚠️ Direction limits this axis: KumoMTA and PowerMTA are *sending* MTAs and the corpus
    observes the *receiving* side, so they are rare here. Rare, not absent — `mymailsystem.com`
    answers `220 send KumoMTA` on an MX serving 46,295 domains (measured 2026-08-23), which is
    why the taxonomy admits them rather than excluding them by rule.

    ⚠️ CHANGED ON PROMOTION: an unmatched banner now returns `None` for provider, not the
    string `"Unknown"`. A sentinel string is indistinguishable from a real operator named
    Unknown once it has been written to a column, and `None`/NULL is what every consumer of
    this estate already treats as absent. `category` still returns the string `"unknown"`,
    which is a legitimate VALUE in the curated taxonomy rather than a sentinel.
    """
    h = (host or "").lower()
    d = (details or "").lower()
    for rule in PROVIDER_RULES:
        # 🚨 `re.IGNORECASE` ADDED ON PROMOTION 2026-09-01, and it fixes a DEAD RULE.
        # Both inputs are lower-cased above, and the patterns were matched with no flags —
        # so `{"software": "OpenSMTPD", "details": r"\bOpenSMTPD\b"}` could never fire against
        # `"opensmtpd"`. It had been unreachable since the rule was written, and the old suite
        # never asserted it (it tested the PARSER on an OpenSMTPD banner, which is a different
        # function, and mentioned the rule only in a comment).
        # Verified a no-op for every other rule: all remaining patterns are already lower-case,
        # and Amazon SES's `(?:Amazon SES|ESMTPSA)?` is an optional group that matches the empty
        # string either way. So this changes exactly one rule — the broken one.
        host_ok = re.search(rule["host"], h, re.IGNORECASE) is not None if rule.get("host") else True
        detl_ok = re.search(rule["details"], d, re.IGNORECASE) is not None if rule.get("details") else True
        if host_ok and detl_ok:
            return (
                rule.get("name"),
                rule["category"],
                int(rule["confidence"]),
                rule.get("software"),
            )
    return None, "unknown", 0, None

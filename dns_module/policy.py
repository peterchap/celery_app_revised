"""
dns_module/policy.py

Policy-related helpers: detect MTA-STS presence, fetch mta-sts policy over HTTPS,
and extract TLS-RPT rua from _smtp._tls TXT.

Public API:
- async detect_mta_sts(regdom: str, lookup, fetch_policy: bool = False, http_timeout: float = 2.5)
    -> dict(has_mta_sts: bool, raw_txt: str, mode: str, max_age: Optional[int], id: Optional[str], policy_text: Optional[str])

- async fetch_tlsrpt_rua(regdom: str, lookup) -> str

Notes:
- `lookup` should offer async method `resolve_txt_joined(name)` returning joined TXT string.
  You can pass an instance of DNSLookup or any object with that method.
- HTTP fetch of the mta-sts policy (/.well-known/mta-sts.txt) is optional and bounded by timeout.
"""
from __future__ import annotations
import re
import ssl as _ssl
import aiohttp
from typing import Optional, Any, Dict

# Only these justify the unverified retry. A timeout or a refused connection means there
# is no policy to grade, so retrying would double the cost of the common failure for no
# extra fact. Built defensively because aiohttp has moved these around between versions.
_TLS_ERRORS = tuple(
    e for e in (
        getattr(aiohttp, "ClientConnectorCertificateError", None),
        getattr(aiohttp, "ClientConnectorSSLError", None),
        _ssl.SSLError,
        _ssl.CertificateError,
    ) if isinstance(e, type)
)

MTASTS_TXT_RE = re.compile(r"v\s*=\s*(?:stsv1|mta[-_]?sts)", re.I)
MTASTS_ID_RE = re.compile(r"^v\s*=\s*mta-sts:\s*id=(?P<id>[^;\s]+)", re.I)
MTASTS_MODE_RE = re.compile(r"(?mi)^mode\s*:\s*(?P<mode>\S+)")
MTASTS_MAXAGE_RE = re.compile(r"(?mi)^max_age\s*:\s*(?P<max>\d+)")
# RFC 8461 §3.2: one `mx:` line per permitted host, wildcards allowed (`*.example.net`).
# The policy may repeat it, so this is findall, not search.
MTASTS_MX_RE = re.compile(r"(?mi)^mx\s*:\s*(?P<mx>\S+)")
TLSRPT_RE = re.compile(r"^v=tlsrpt1;\s*rua=([^;]+)", re.I)


async def detect_mta_sts(
    regdom: str,
    lookup: Any,
    fetch_policy: bool = False,
    http_timeout: float = 2.5,
) -> Dict[str, Optional[Any]]:
    """
    Detect presence of MTA-STS via TXT record and optionally fetch the HTTP policy.

    Returns a dict:
      {
        "has_mta_sts": bool,
        "raw_txt": str,
        "mode": str or "",
        "max_age": int or None,
        "id": str or None,
        "policy_text": str or None
      }
    """
    raw_txt = ""
    mode = ""
    max_age = None
    sts_id = None
    policy_text = None
    has_mta = False

    try:
        raw_txt = await lookup.resolve_txt_joined(f"_mta-sts.{regdom}")
    except Exception:
        raw_txt = ""

    if raw_txt:
        if MTASTS_TXT_RE.search(raw_txt):
            has_mta = True
        m_id = MTASTS_ID_RE.search(raw_txt)
        if m_id:
            sts_id = m_id.group("id")

    # Optionally fetch the HTTPS policy file if TXT exists or fetch_policy True
    if fetch_policy and regdom:
        url = f"https://mta-sts.{regdom}/.well-known/mta-sts.txt"
        try:
            timeout = aiohttp.ClientTimeout(total=http_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as s:
                async with s.get(url, allow_redirects=True, ssl=False) as r:  # allow ssl False to avoid cert failures
                    if r.status == 200:
                        txt = await r.text()
                        policy_text = txt
                        # parse mode and max_age heuristically from policy body
                        m_mode = MTASTS_MODE_RE.search(txt)
                        if m_mode:
                            mode = m_mode.group("mode").strip().lower()
                        m_max = MTASTS_MAXAGE_RE.search(txt)
                        if m_max:
                            try:
                                max_age = int(m_max.group("max"))
                            except Exception:
                                max_age = None
        except Exception:
            # swallow network errors and return what we have
            policy_text = None

    return {
        "has_mta_sts": bool(has_mta),
        "raw_txt": raw_txt or "",
        "mode": mode or "",
        "max_age": max_age,
        "id": sts_id or None,
        "policy_text": policy_text,
    }


async def fetch_tlsrpt_rua(regdom: str, lookup: Any) -> str:
    """
    Read the _smtp._tls TXT and return the raw rua string (or empty string).
    """
    try:
        raw = await lookup.resolve_txt_joined(f"_smtp._tls.{regdom}")
    except Exception:
        return ""
    if not raw:
        return ""
    m = TLSRPT_RE.search(raw)
    return m.group(1).strip() if m else raw

async def fetch_mta_sts_policy_http(
    regdom: str,
    http_timeout: float = 2.5,
) -> Dict[str, Optional[Any]]:
    """
    Fetch + parse https://mta-sts.<regdom>/.well-known/mta-sts.txt only.

    Standalone variant of the policy fetch inside detect_mta_sts, with no DNS
    `lookup` dependency — for the batch path, which already holds the _mta-sts
    TXT record and only needs the HTTPS policy body (mode / max_age). Call it
    ONLY when the TXT exists (<1% of domains), so the single bounded HTTPS GET
    never weighs on corpus throughput.

    Returns {"mode", "max_age", "mx", "tls_ok", "policy_text"}.

    `tls_ok` is the falsifiable half and the reason this is worth more than the TXT
    record. RFC 8461 §3.3 requires the policy be fetched over a **validated** HTTPS
    connection: a policy served behind an expired, self-signed or wrong-name certificate
    is not a policy at all, and a conforming sender discards it. This used to pass
    `ssl=False` — "to avoid cert failures" — so `mta_sts_mode` counted domains whose
    policy no conforming sender would honour. Populated, and answering a different
    question than its name implies.

      True  — fetched with certificate verification. The policy is usable.
      False — verification failed but the file is served; the domain believes it has
              MTA-STS and, per spec, it does not. This is the finding.
      None  — no policy retrieved at all (404, timeout, no such host).

    The unverified retry fires ONLY on a TLS error, so the ordinary success path and the
    ordinary failure path both stay at one request. `mode`/`max_age` are still parsed from
    an unverified body, so existing coverage does not regress — `tls_ok` is what tells you
    whether to trust them.
    """
    mode = ""
    max_age = None
    mx: list = []
    tls_ok = None
    policy_text = None
    empty = {"mode": mode, "max_age": max_age, "mx": mx,
             "tls_ok": tls_ok, "policy_text": policy_text}
    if not regdom:
        return empty
    url = f"https://mta-sts.{regdom}/.well-known/mta-sts.txt"

    async def _get(verify: bool) -> Optional[str]:
        timeout = aiohttp.ClientTimeout(total=http_timeout)
        # ThreadedResolver = OS getaddrinfo (local Unbound on the slaves). The
        # default aiodns/c-ares resolver fails on some hosts ("Could not contact
        # DNS servers") and would silently blank mta_sts_mode.
        conn = aiohttp.TCPConnector(resolver=aiohttp.ThreadedResolver(),
                                    ssl=None if verify else False)
        async with aiohttp.ClientSession(timeout=timeout, connector=conn) as s:
            async with s.get(url, allow_redirects=True) as r:
                if r.status == 200:
                    return await r.text()
        return None

    try:
        policy_text = await _get(verify=True)
        if policy_text is not None:
            tls_ok = True
    except _TLS_ERRORS:
        # Certificate rejected. Re-fetch unverified purely to establish that a policy IS
        # published — so the row can say "claims MTA-STS, policy not RFC-valid" rather
        # than being indistinguishable from a domain with no policy at all.
        try:
            policy_text = await _get(verify=False)
            if policy_text is not None:
                tls_ok = False
        except Exception:
            policy_text = None
    except Exception:
        policy_text = None

    if policy_text:
        m_mode = MTASTS_MODE_RE.search(policy_text)
        if m_mode:
            mode = m_mode.group("mode").strip().lower()
        m_max = MTASTS_MAXAGE_RE.search(policy_text)
        if m_max:
            try:
                max_age = int(m_max.group("max"))
            except Exception:
                max_age = None
        # Lowercased and dot-stripped so it compares directly against the MX hostnames
        # the resolver returns, without every consumer redoing the normalisation.
        mx = [m.group("mx").strip().rstrip(".").lower()
              for m in MTASTS_MX_RE.finditer(policy_text)]

    return {"mode": mode, "max_age": max_age, "mx": mx,
            "tls_ok": tls_ok, "policy_text": policy_text}

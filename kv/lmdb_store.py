# kv/lmdb_store.py
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import zlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import lmdb

DEFAULT_FIELDS = ("ns", "a", "mx_regdom", "registered_domain", "mx_ips")

logger = logging.getLogger("kv.lmdb_store")

# Module-level env cache: (normalised_path, readonly) → (env, refcount, lock)
_ENV_CACHE: Dict[Tuple[str, bool], Tuple[lmdb.Environment, int, threading.Lock]] = {}
_ENV_CACHE_LOCK = threading.Lock()

_DEFAULT_MAX_READERS = 64
_DEFAULT_MAP_SIZE    = 1 << 30   # 1 GiB

# v2 value prefix — distinguishes new JSON values from v1 raw sha1 hex
_V2_PREFIX = b"v2:"


# ── Helpers ───────────────────────────────────────────────────────────────────

def sha1_hex(data: bytes) -> bytes:
    return hashlib.sha1(data).hexdigest().encode("ascii")


def _normalise_path(path: str | Path) -> str:
    p = Path(path)
    try:
        return str(p.resolve())
    except OSError:
        return str(p.absolute())


def _open_env(
    path: str,
    readonly: bool,
    max_readers: int = _DEFAULT_MAX_READERS,
    map_size:    int = _DEFAULT_MAP_SIZE,
) -> lmdb.Environment:
    norm_path = _normalise_path(path)
    key = (norm_path, bool(readonly))

    with _ENV_CACHE_LOCK:
        entry = _ENV_CACHE.get(key)
        if entry:
            env, refcnt, lock = entry
            _ENV_CACHE[key] = (env, refcnt + 1, lock)
            return env

        if not readonly:
            Path(norm_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            env = lmdb.open(
                norm_path,
                subdir=Path(norm_path).is_dir(),
                readonly=readonly,
                lock=not readonly,
                max_readers=max(1, int(max_readers)),
                map_size=map_size,
                readahead=True,
            )
        except lmdb.Error as exc:
            if "already open" in str(exc).lower():
                for (cached_path, cached_ro), (env, refcnt, lock) in _ENV_CACHE.items():
                    if cached_path == norm_path:
                        _ENV_CACHE[(cached_path, cached_ro)] = (env, refcnt + 1, lock)
                        return env
            raise

        _ENV_CACHE[key] = (env, 1, threading.Lock())
        return env


def _close_env(path: str, readonly: bool) -> None:
    norm_path = _normalise_path(path)
    key = (norm_path, bool(readonly))

    with _ENV_CACHE_LOCK:
        entry = _ENV_CACHE.get(key)
        if not entry:
            return
        env, refcnt, lock = entry
        refcnt -= 1
        if refcnt <= 0:
            del _ENV_CACHE[key]
            try:
                with lock:
                    env.close()
            except Exception:
                logger.exception("error closing lmdb env %s", norm_path)
        else:
            _ENV_CACHE[key] = (env, refcnt, lock)


# ── Value encoding ────────────────────────────────────────────────────────────

def _encode_record(record: Dict) -> bytes:
    """Encode a v2 record dict → b'v2:' + zlib(JSON)."""
    payload = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return _V2_PREFIX + zlib.compress(payload)


def _decode_raw(raw: bytes) -> Optional[Dict]:
    """
    Decode a stored value regardless of format version.

    v1  raw 40-byte sha1 hex ascii → minimal dict, empty record lists, _v1=True
    v2  b'v2:' + zlib(JSON)        → full record dict
    """
    if not raw:
        return None

    if raw[:3] == _V2_PREFIX:
        try:
            return json.loads(zlib.decompress(raw[3:]).decode("utf-8"))
        except Exception:
            logger.warning("failed to decode v2 lmdb value len=%d", len(raw))
            return None

    # v1: raw sha1 hex
    return {
        "sig":          raw.decode("ascii", "ignore"),
        "is_active":    True,
        "last_seen_ts": 0,
        "ns":  [], "a":  [], "mx":  [], "cname": [], "ptr": [],
        "prev_ns": None, "prev_a": None, "prev_mx": None,
        "ns_changed_ts": None, "a_changed_ts": None, "mx_changed_ts": None,
        "mx_regdom": "",
        "_v1": True,
    }


class LMDBActivity:
    """
    Per-domain DNS state store.

    v1 schema (legacy) : key=domain_bytes  value=sha1_hex_bytes
    v2 schema (current): key=domain_bytes  value=b'v2:' + zlib(JSON)

    JSON record fields
    ------------------
    sig            str        sha1 hex of the DNS fingerprint
    is_active      bool
    last_seen_ts   int        unix timestamp of last resolution
    ns             list[str]  sorted nameservers
    a              list[str]  sorted A records
    mx             list[str]  sorted MX hosts
    cname          list[str]
    ptr            list[str]
    mx_regdom      str        registrable domain of first MX host
    prev_ns        list|null  previous ns values (on last change)
    prev_a         list|null
    prev_mx        list|null
    ns_changed_ts  int|null   unix timestamp of last NS change
    a_changed_ts   int|null
    mx_changed_ts  int|null

    Workers  → readonly=True,  use get_sig() / batch_get_sig()
    Master   → readonly=False, use set_record() / upsert_from_delta()
    """

    def __init__(
        self,
        path:        str | Path,
        readonly:    bool = True,
        max_readers: Optional[int] = None,
        map_size:    Optional[int] = None,
    ) -> None:
        self.path        = _normalise_path(path)
        self.readonly    = bool(readonly)
        self.max_readers = max_readers or _DEFAULT_MAX_READERS
        self.map_size    = map_size    or _DEFAULT_MAP_SIZE
        self.env         = _open_env(
            self.path, self.readonly,
            max_readers=self.max_readers,
            map_size=self.map_size,
        )
        self.db      = None   # unnamed db
        self._closed = False

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _b(x: Any) -> bytes:
        if isinstance(x, bytes):  return x
        if isinstance(x, str):    return x.encode("utf-8", "ignore")
        return str(x).encode("utf-8", "ignore")

    @staticmethod
    def _norm(v: Any) -> Any:
        if v is None:        return ""
        if isinstance(v, str): return v.strip().lower()
        return v

    # ── Signature computation (unchanged — callers depend on these) ───────────

    @classmethod
    def compute_signature_dict(
        cls,
        record: Dict[str, Any],
        fields: Iterable[str] = DEFAULT_FIELDS,
    ) -> bytes:
        payload = {f: cls._norm(record.get(f)) for f in fields}
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return sha1_hex(blob)

    @classmethod
    def compute_signature_values(
        cls,
        *,
        ns:                str,
        a:                 str,
        mx_regdom:         str,
        registered_domain: str,
        mx_ips:            str,
    ) -> bytes:
        payload = {
            "ns":                cls._norm(ns),
            "a":                 cls._norm(a),
            "mx_regdom":         cls._norm(mx_regdom),
            "registered_domain": cls._norm(registered_domain),
            "mx_ips":            cls._norm(mx_ips),
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return sha1_hex(blob)

    @classmethod
    def signature_from_arrow_row(cls, row: Dict[str, Any]) -> bytes:
        mx_regdom = (
            row.get("mx_regdom_norm")
            or row.get("mx_domain")
            or row.get("mail_mx_domain")
            or ""
        )
        return cls.compute_signature_dict({
            "ns":                row.get("ns", ""),
            "a":                 row.get("a", ""),
            "mx_regdom":         mx_regdom,
            "registered_domain": row.get("registered_domain") or row.get("domain") or "",
        })

    # ── Read ──────────────────────────────────────────────────────────────────

    def get_sig(self, domain: str) -> Optional[Dict]:
        """
        Return stored state dict for a domain, or None if unseen.

        Always contains: sig, is_active, ns, a, mx, cname, ptr, last_seen_ts.
        v1 records have _v1=True and empty record lists.
        """
        with self.env.begin(db=self.db, write=False) as txn:
            raw = txn.get(self._b(domain))
            return _decode_raw(bytes(raw)) if raw is not None else None

    def batch_get_sig(self, domains: List[str]) -> Dict[str, Optional[Dict]]:
        """
        Read state for many domains in a single LMDB transaction.
        Significantly faster than N individual get_sig() calls for large batches.
        Returns {domain: state_dict | None}.
        """
        result: Dict[str, Optional[Dict]] = {}
        with self.env.begin(db=self.db, write=False) as txn:
            for domain in domains:
                raw = txn.get(self._b(domain))
                result[domain] = _decode_raw(bytes(raw)) if raw is not None else None
        return result

    # ── Write (master only) ───────────────────────────────────────────────────

    def set_sig(self, domain: str, sig: bytes) -> None:
        """
        Legacy write — stores raw v1 sha1 bytes.
        Kept for backward compat with any existing master code.
        Prefer set_record() for all new writes.
        """
        if self.readonly:
            return
        with self.env.begin(db=self.db, write=True) as txn:
            txn.put(self._b(domain), sig)

    def set_record(
        self,
        domain:    str,
        sig:       bytes | str,
        ns:        List[str],
        a:         List[str],
        mx:        List[str],
        cname:     List[str],
        ptr:       List[str],
        mx_regdom: str  = "",
        is_active: bool = True,
    ) -> None:
        """
        Write a full v2 record for a domain.
        Automatically carries forward prev_* and *_changed_ts from stored state.
        Called by the master when applying a delta.
        """
        if self.readonly:
            return

        now      = int(time.time())
        existing = self.get_sig(domain)

        # Carry forward change-history fields
        ns_changed_ts = mx_changed_ts = a_changed_ts = None
        prev_ns = prev_a = prev_mx = None

        if existing and not existing.get("_v1"):
            # Detect per-record changes and update timestamps
            if sorted(existing.get("ns") or []) != sorted(ns):
                prev_ns       = existing.get("ns")
                ns_changed_ts = now
            else:
                prev_ns       = existing.get("prev_ns")
                ns_changed_ts = existing.get("ns_changed_ts")

            if sorted(existing.get("a") or []) != sorted(a):
                prev_a       = existing.get("a")
                a_changed_ts = now
            else:
                prev_a       = existing.get("prev_a")
                a_changed_ts = existing.get("a_changed_ts")

            if sorted(existing.get("mx") or []) != sorted(mx):
                prev_mx       = existing.get("mx")
                mx_changed_ts = now
            else:
                prev_mx       = existing.get("prev_mx")
                mx_changed_ts = existing.get("mx_changed_ts")

        sig_str = sig.decode("ascii", "ignore") if isinstance(sig, bytes) else sig

        record = {
            "sig":           sig_str,
            "is_active":     is_active,
            "last_seen_ts":  now,
            "ns":            sorted(ns),
            "a":             sorted(a),
            "mx":            sorted(mx),
            "cname":         sorted(cname),
            "ptr":           sorted(ptr),
            "mx_regdom":     mx_regdom,
            "prev_ns":       prev_ns,
            "prev_a":        prev_a,
            "prev_mx":       prev_mx,
            "ns_changed_ts": ns_changed_ts,
            "a_changed_ts":  a_changed_ts,
            "mx_changed_ts": mx_changed_ts,
        }

        with self.env.begin(db=self.db, write=True) as txn:
            txn.put(self._b(domain), _encode_record(record))

    def upsert_from_delta(self, delta: Dict[str, Any]) -> None:
        """
        Apply a delta dict (as produced by change_tracker) to the store.
        Convenience wrapper around set_record() for master delta consumers.
        """
        def _jload(s: Any) -> List[str]:
            if not s:
                return []
            if isinstance(s, list):
                return s
            try:
                v = json.loads(s)
                return v if isinstance(v, list) else [str(v)]
            except Exception:
                return []

        sig = delta.get("dns_sig", b"")
        if isinstance(sig, str):
            sig = sig.encode("ascii", "ignore")

        self.set_record(
            domain    = str(delta.get("domain", "")).lower(),
            sig       = sig,
            ns        = _jload(delta.get("ns",    "[]")),
            a         = _jload(delta.get("a",     "[]")),
            mx        = _jload(delta.get("mx",    "[]")),
            cname     = _jload(delta.get("cname", "[]")),
            ptr       = _jload(delta.get("ptr",   "[]")),
            mx_regdom = str(delta.get("mx_regdom", "")),
            is_active = str(delta.get("is_active", "true")).lower() == "true",
        )

    # ── Misc ──────────────────────────────────────────────────────────────────

    def changed(self, domain: str, new_sig: bytes) -> bool:
        """Hash-only change check — kept for backward compat."""
        existing = self.get_sig(domain)
        if existing is None:
            return True
        stored = existing.get("sig", "")
        new_str = new_sig.decode("ascii", "ignore") if isinstance(new_sig, bytes) else new_sig
        return stored != new_str

    def begin(self, write: bool = False, **kwargs):
        return self.env.begin(write=write, **kwargs)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        if self._closed:
            return
        _close_env(self.path, self.readonly)
        self._closed = True

    def __enter__(self) -> "LMDBActivity":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        try:
            self.close()
        except Exception:
            pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

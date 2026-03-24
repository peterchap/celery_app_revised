# kv/lmdb_store.py
from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

import lmdb

DEFAULT_FIELDS = ("ns", "a", "mx_regdom", "registered_domain", "mx_ips")

logger = logging.getLogger("kv.lmdb_store")

# Module-level cache: key -> (env, refcount, lock)
# Key is (normalised_path, readonly)
_ENV_CACHE: Dict[Tuple[str, bool], Tuple[lmdb.Environment, int, threading.Lock]] = {}
_ENV_CACHE_LOCK = threading.Lock()

_DEFAULT_MAX_READERS = 64
_DEFAULT_MAP_SIZE = 1 << 30  # 1 GiB


def sha1_hex(data: bytes) -> bytes:
    return hashlib.sha1(data).hexdigest().encode("ascii")


def _normalise_path(path: str | Path) -> str:
    """Resolve symlinks and normalise path to avoid cache misses."""
    p = Path(path)
    try:
        return str(p.resolve())
    except OSError:
        # Path may not exist yet (writable env being created)
        return str(p.absolute())


def _open_env(
    path: str,
    readonly: bool,
    max_readers: int = _DEFAULT_MAX_READERS,
    map_size: int = _DEFAULT_MAP_SIZE,
) -> lmdb.Environment:
    """
    Open (or reuse) an lmdb.Environment for the given path+mode.
    Uses the module-level _ENV_CACHE to avoid repeated opens which consume fds.
    Path is normalised before caching to prevent symlink/trailing-slash misses.
    """
    norm_path = _normalise_path(path)
    key = (norm_path, bool(readonly))

    with _ENV_CACHE_LOCK:
        entry = _ENV_CACHE.get(key)
        if entry:
            env, refcnt, lock = entry
            _ENV_CACHE[key] = (env, refcnt + 1, lock)
            logger.debug("reused lmdb env %s readonly=%s ref=%d", norm_path, readonly, refcnt + 1)
            return env

        # Ensure parent dir exists for writable envs
        if not readonly:
            Path(norm_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            env = lmdb.open(
                norm_path,
                subdir=Path(norm_path).is_dir(),
                readonly=readonly,
                lock=not readonly,   # no file locking needed for readonly opens (safe on NFS)
                max_readers=max(1, int(max_readers)),
                map_size=map_size,
                readahead=True,
            )
        except lmdb.Error as exc:
            if "already open" in str(exc).lower():
                # Another code path opened this env under a different key (e.g. un-normalised path).
                # Scan the cache for any entry sharing the same resolved path and reuse it.
                for (cached_path, cached_ro), (env, refcnt, lock) in _ENV_CACHE.items():
                    if cached_path == norm_path:
                        _ENV_CACHE[(cached_path, cached_ro)] = (env, refcnt + 1, lock)
                        logger.warning(
                            "lmdb env %s already open (cached as readonly=%s), reusing", norm_path, cached_ro
                        )
                        return env
            raise

        _ENV_CACHE[key] = (env, 1, threading.Lock())
        logger.debug("opened lmdb env %s readonly=%s ref=1", norm_path, readonly)
        return env


def _close_env(path: str, readonly: bool) -> None:
    norm_path = _normalise_path(path)
    key = (norm_path, bool(readonly))

    with _ENV_CACHE_LOCK:
        entry = _ENV_CACHE.get(key)
        if not entry:
            logger.debug("close_env called but no cache entry for %s readonly=%s", norm_path, readonly)
            return

        env, refcnt, lock = entry
        refcnt -= 1
        if refcnt <= 0:
            del _ENV_CACHE[key]
            try:
                with lock:
                    env.close()
                logger.debug("closed lmdb env %s readonly=%s", norm_path, readonly)
            except Exception:
                logger.exception("error closing lmdb env %s readonly=%s", norm_path, readonly)
        else:
            _ENV_CACHE[key] = (env, refcnt, lock)
            logger.debug("decremented refcount for lmdb env %s readonly=%s ref=%d", norm_path, readonly, refcnt)


class LMDBActivity:
    """
    Read-only (workers) or read-write (master) LMDB store of per-domain signatures.

    - Key:   domain (bytes, utf-8)
    - Value: sha1 hex digest (bytes)

    Reuses environment objects process-wide to avoid exhausting file descriptors.
    Use as a context manager or call .close() when done.

    Workers should always open with readonly=True (the default).
    The master is the only process that should open with readonly=False.
    """

    def __init__(
        self,
        path: str | Path,
        readonly: bool = True,
        max_readers: Optional[int] = None,
        map_size: Optional[int] = None,
    ) -> None:
        self.path = _normalise_path(path)
        self.readonly = bool(readonly)
        self.max_readers = max_readers or _DEFAULT_MAX_READERS
        self.map_size = map_size or _DEFAULT_MAP_SIZE
        self.env: lmdb.Environment = _open_env(
            self.path, self.readonly, max_readers=self.max_readers, map_size=self.map_size
        )
        self.db = None  # unnamed db
        self._closed = False
        logger.debug("LMDBActivity.__init__ path=%s readonly=%s", self.path, self.readonly)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _b(x: Any) -> bytes:
        if isinstance(x, bytes):
            return x
        if isinstance(x, str):
            return x.encode("utf-8", "ignore")
        return str(x).encode("utf-8", "ignore")

    @staticmethod
    def _norm(v: Any) -> Any:
        if v is None:
            return ""
        if isinstance(v, str):
            return v.strip().lower()
        return v

    # ------------------------------------------------------------------ #
    # Signature computation
    # ------------------------------------------------------------------ #

    @classmethod
    def compute_signature_dict(
        cls, record: Dict[str, Any], fields: Iterable[str] = DEFAULT_FIELDS
    ) -> bytes:
        payload = {f: cls._norm(record.get(f)) for f in fields}
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return sha1_hex(blob)

    @classmethod
    def compute_signature_values(
        cls,
        *,
        ns: str,
        a: str,
        mx_regdom: str,
        registered_domain: str,
        mx_ips: str,
    ) -> bytes:
        payload = {
            "ns": cls._norm(ns),
            "a": cls._norm(a),
            "mx_regdom": cls._norm(mx_regdom),
            "registered_domain": cls._norm(registered_domain),
            "mx_ips": cls._norm(mx_ips),
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
        data = {
            "ns": row.get("ns", ""),
            "a": row.get("a", ""),
            "mx_regdom": mx_regdom,
            "registered_domain": row.get("registered_domain") or row.get("domain") or "",
        }
        return cls.compute_signature_dict(data)

    # ------------------------------------------------------------------ #
    # Get / set / changed
    # ------------------------------------------------------------------ #

    def get_sig(self, domain: str) -> Optional[bytes]:
        with self.env.begin(db=self.db, write=False) as txn:
            res = txn.get(self._b(domain))
            if res is None:
                return None
            return bytes(res)

    def set_sig(self, domain: str, sig: bytes) -> None:
        if self.readonly:
            # Workers never write — master owns all writes
            return
        with self.env.begin(db=self.db, write=True) as txn:
            txn.put(self._b(domain), sig)

    def changed(self, domain: str, new_sig: bytes) -> bool:
        return self.get_sig(domain) != new_sig

    def begin(self, write: bool = False, **kwargs):
        """Convenience: return an LMDB transaction (context manager)."""
        return self.env.begin(write=write, **kwargs)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def close(self) -> None:
        """Release this instance's reference to the shared environment."""
        if self._closed:
            return
        _close_env(self.path, self.readonly)
        self._closed = True
        logger.debug("LMDBActivity.close path=%s readonly=%s", self.path, self.readonly)

    def __enter__(self) -> LMDBActivity:
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

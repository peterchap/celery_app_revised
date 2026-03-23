# kv/lmdb_store.py
from __future__ import annotations
import lmdb
import hashlib
import json
import threading
import os
import logging
from typing import Optional, Iterable, Dict, Any, Tuple

DEFAULT_FIELDS = ("ns", "a", "mx_regdom", "registered_domain", "mx_ips")

logger = logging.getLogger("kv.lmdb_store")

# Module-level cache: key -> (env, refcount, lock)
# Key is (path, readonly)
_ENV_CACHE: Dict[Tuple[str, bool], Tuple[lmdb.Environment, int, threading.Lock]] = {}
_ENV_CACHE_LOCK = threading.Lock()

# Tune these for your environment. Keep max_readers modest to limit internal structures
_DEFAULT_MAX_READERS = 64
_DEFAULT_MAP_SIZE = 1 << 30  # 1GiB default map size (adjust if needed)


def sha1_hex(data: bytes) -> bytes:
    return hashlib.sha1(data).hexdigest().encode("ascii")


def _open_env(path: str, readonly: bool, max_readers: int = _DEFAULT_MAX_READERS, map_size: int = _DEFAULT_MAP_SIZE) -> lmdb.Environment:
    """
    Open (or reuse) an lmdb.Environment for the given path+mode.
    Uses the module-level _ENV_CACHE to avoid repeated opens which consume fds.
    """
    key = (path, bool(readonly))
    with _ENV_CACHE_LOCK:
        entry = _ENV_CACHE.get(key)
        if entry:
            env, refcnt, lock = entry
            _ENV_CACHE[key] = (env, refcnt + 1, lock)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("reused lmdb env %s readonly=%s ref=%d", path, readonly, refcnt + 1)
            return env

        # Ensure parent dir exists for writable envs
        if not readonly:
            parent = os.path.dirname(path)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)

        lock_flag = not readonly

        env = lmdb.open(
            path,
            subdir=os.path.isdir(path) or False,
            readonly=readonly,
            lock=lock_flag,
            max_readers=max(1, int(max_readers)),
            map_size=map_size,
            readahead=True,
        )
        _ENV_CACHE[key] = (env, 1, threading.Lock())
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("opened lmdb env %s readonly=%s ref=1", path, readonly)
        return env


def _close_env(path: str, readonly: bool):
    key = (path, bool(readonly))
    with _ENV_CACHE_LOCK:
        entry = _ENV_CACHE.get(key)
        if not entry:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("close_env called but no cache entry for %s readonly=%s", path, readonly)
            return
        env, refcnt, lock = entry
        refcnt -= 1
        if refcnt <= 0:
            # remove from cache and close
            del _ENV_CACHE[key]
            try:
                # close under the per-entry lock to avoid races
                with lock:
                    env.close()
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("closed lmdb env %s readonly=%s", path, readonly)
            except Exception:
                logger.exception("error closing lmdb env %s readonly=%s", path, readonly)
        else:
            _ENV_CACHE[key] = (env, refcnt, lock)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("decremented refcount for lmdb env %s readonly=%s ref=%d", path, readonly, refcnt)


class LMDBActivity:
    """
    Read-only (slaves) or read-write (master) LMDB store of per-domain signatures.

    - Key: domain (bytes, utf-8)
    - Value: sha1 hex digest (bytes)

    This wrapper reuses environment objects process-wide to avoid exhausting file descriptors.
    Use as a context manager or call .close() when done.
    """

    def __init__(self, path: str, readonly: bool = True, max_readers: Optional[int] = None, map_size: Optional[int] = None):
        """
        Note: defaults for max_readers and map_size come from module constants if not supplied.
        """
        self.path = path
        self.readonly = bool(readonly)
        self.max_readers = max_readers or _DEFAULT_MAX_READERS
        self.map_size = map_size or _DEFAULT_MAP_SIZE
        # Acquire (and possibly create) the shared env from the cache
        self.env: lmdb.Environment = _open_env(self.path, self.readonly, max_readers=self.max_readers, map_size=self.map_size)
        self.db = None  # unnamed db
        self._closed = False
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("LMDBActivity.__init__ path=%s readonly=%s", path, readonly)

    @staticmethod
    def _b(x: Any) -> bytes:
        if isinstance(x, bytes):
            return x
        if isinstance(x, str):
            return x.encode("utf-8", "ignore")
        return str(x).encode("utf-8", "ignore")

    # ---------- signature computation helpers ----------

    @staticmethod
    def _norm(v: Any) -> Any:
        if v is None:
            return ""
        if isinstance(v, str):
            return v.strip().lower()
        return v

    @classmethod
    def compute_signature_dict(cls, record: Dict[str, Any], fields: Iterable[str] = DEFAULT_FIELDS) -> bytes:
        # Normalize and serialize a small tuple of decisive fields, then sha1
        payload = {f: cls._norm(record.get(f)) for f in fields}
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return sha1_hex(blob)

    @classmethod
    def compute_signature_values(cls, *, ns: str, a: str, mx_regdom: str, registered_domain: str, mx_ips: str) -> bytes:
        payload = {
            "ns": cls._norm(ns),
            "a": cls._norm(a),
            "mx_regdom": cls._norm(mx_regdom),
            "registered_domain": cls._norm(registered_domain),
            "mx_ips": cls._norm(mx_ips),
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return sha1_hex(blob)

    # ---------- get / set / changed ----------

    def get_sig(self, domain: str) -> Optional[bytes]:
        with self.env.begin(db=self.db, write=False) as txn:
            res = txn.get(self._b(domain))
            if res is None:
                return None
            # Ensure buffer-like results (memoryview/bytearray/etc.) are converted to bytes
            return bytes(res)

    def set_sig(self, domain: str, sig: bytes) -> None:
        if self.readonly:
            # On slaves we never write
            return
        with self.env.begin(db=self.db, write=True) as txn:
            txn.put(self._b(domain), sig)

    def changed(self, domain: str, new_sig: bytes) -> bool:
        prev = self.get_sig(domain)
        return (prev != new_sig)

    def begin(self, write: bool = False, **kwargs):
        """
        Convenience: return an LMDB transaction (context manager).
        """
        return self.env.begin(write=write, **kwargs)

    def close(self):
        """Release this user's reference to the shared environment. Environment closed when last user calls close()."""
        if self._closed:
            return
        _close_env(self.path, self.readonly)
        self._closed = True
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("LMDBActivity.close path=%s readonly=%s", self.path, self.readonly)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.close()
        except Exception:
            pass

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # Convenience: from pyarrow row (dict-like)
    @classmethod
    def signature_from_arrow_row(cls, row: Dict[str, Any]) -> bytes:
        # Flexible: try multiple source columns for MX regdom
        mx_regdom = row.get("mx_regdom_norm") or row.get("mx_domain") or row.get("mail_mx_domain") or ""
        data = {
            "ns": row.get("ns", ""),
            "a": row.get("a", ""),
            "mx_regdom": mx_regdom,
            "registered_domain": row.get("registered_domain") or row.get("domain") or "",
        }
        return cls.compute_signature_dict(data)

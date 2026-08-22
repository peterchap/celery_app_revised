"""Regression tests for the "a probe that did not run must report NULL" invariant.

WHY THIS EXISTS. `has_security_txt` was initialised to `False` before the
`run_blocking_probes` gate and then coerced with `bool(...)` on the way into Arrow.
Nothing in this repo ever sets `run_blocking_probes=True`, so the probe never ran and
every row shipped `false` — "we did not look" published as "there is none". Measured
2026-08-22 against `gold.dns_wide`: 385,467,247 rows FALSE, **0 TRUE**, out of 395.9M.

The same shape applied to `https_cert_san_count`, which defaulted to `0` — a SAN count
of zero is a measurement, and none had been taken.

This is a defect *class*, not one field: any value behind a feature flag whose "off"
state is a falsy default reports a negative result it never established. These tests pin
the two that were wrong and the helper that keeps `or`-chaining from reintroducing it.

Run: pytest tests/test_probe_off_is_null.py
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load(name: str):
    """Load a single dns_module file by path.

    Importing the package drags in the fetcher's async/pyarrow dependencies, which these
    tests do not need — same approach as tests/test_smtp_banner_parse.py.
    """
    spec = importlib.util.spec_from_file_location(name, REPO / "dns_module" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_func(module_name: str, func_name: str):
    """Exec a single top-level function out of a module that cannot be imported.

    batch_processor.py uses relative imports (`from .entity_hasher import ...`) and pulls
    in pyarrow.flight, so it will not load standalone. The helper under test is pure, so
    lift just its AST node.
    """
    import ast

    src = (REPO / "dns_module" / f"{module_name}.py").read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            ns: dict = {}
            exec(compile(ast.Module([node], []), f"<{module_name}>", "exec"), ns)
            return ns[func_name]
    raise AssertionError(f"{func_name} not found in {module_name}.py")


# --------------------------------------------------------------------------- helper


def test_first_not_none_keeps_falsy_values():
    """False/0/'' are answers. Only None means "no answer"."""
    f = _load_func("batch_processor", "_first_not_none")
    assert f(False, True) is False          # `or` would have returned True
    assert f(0, 7) == 0                     # `or` would have returned 7
    assert f("", "fallback") == ""          # `or` would have returned "fallback"


def test_first_not_none_falls_through_and_bottoms_out_at_none():
    f = _load_func("batch_processor", "_first_not_none")
    assert f(None, "second") == "second"
    assert f(None, None) is None            # NOT False, and NOT ""


# ------------------------------------------------------------------ schema contract


@pytest.mark.parametrize(
    "field_name",
    ["has_security_txt", "security_txt_url", "security_txt_preview", "https_cert_san_count"],
)
def test_probe_gated_fields_are_nullable(field_name):
    """The dataclass must permit None, or "not probed" has nowhere to live."""
    records = _load("dns_records")
    annotation = records.DNSRecords.__dataclass_fields__[field_name].type
    assert type(None) in getattr(annotation, "__args__", ()), (
        f"{field_name} is declared {annotation!r} — a probe behind "
        "run_blocking_probes must be able to report NULL when it did not run"
    )


# ----------------------------------------------------------------- source contract


def test_security_txt_is_not_initialised_falsy_before_the_gate():
    """Guard the exact line that shipped 385M false negatives."""
    src = (REPO / "dns_module" / "dns_fetcher.py").read_text(encoding="utf-8")
    assert 'sec_txt_ok, sec_txt_url, sec_txt_preview = False, "", ""' not in src
    assert src.count("sec_txt_ok, sec_txt_url, sec_txt_preview = None, None, None") == 2


def test_san_count_has_no_zero_default():
    """`else 0` on an unrun probe asserts a certificate has no SANs."""
    src = (REPO / "dns_module" / "dns_fetcher.py").read_text(encoding="utf-8")
    assert 'isinstance(https_san, str) and https_san) else 0' not in src


def test_batch_processor_does_not_coerce_security_txt_to_false():
    """`bool(...)` here is what republished the None as a negative finding."""
    src = (REPO / "dns_module" / "batch_processor.py").read_text(encoding="utf-8")
    assert 'bool(getattr(rec, "has_security_txt"' not in src

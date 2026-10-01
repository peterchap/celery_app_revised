"""The real-time path must read what fetch_domain writes.

fetch_domain stores records lowercase in record.records ('caa', 'txt',
'dnssec', 'tlsrpt_rua', 'has_mta_sts' ...). _fetch_records_inner read 'CAA',
'TXT' and meta['dnssec'], so CAA, TXT and DNSSEC were always empty in every
free, health and estate report (found 2026-10-01 on datazag.com). This pins
the reads to the writer's keys, by source, so a rename on either side fails.
"""
import pathlib
import re

SRC = (pathlib.Path(__file__).resolve().parents[1] / "dns_module" / "dns_fetcher.py").read_text(encoding="utf-8")


def _writes():
    return set(re.findall(r"record\.records\['([a-z_]+)'\]\s*=", SRC))


def test_reader_uses_writer_keys():
    written = _writes()
    for key in ("caa", "txt", "dnssec", "tlsrpt_rua", "has_mta_sts", "mta_sts_txt", "mta_sts_mode"):
        assert key in written, f"fetch_domain no longer writes records['{key}']"
        assert f'recs.get("{key}")' in SRC, f"_fetch_records_inner does not read recs.get('{key}')"


def test_dnssec_not_read_from_meta_only():
    assert 'exp_map["dnskey"] = meta.get("dnssec") or False' not in SRC

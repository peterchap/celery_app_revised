"""A/AAAA lists are joined as addresses, never normalised as hostnames.

list_to_string normalises each item with to_ascii_hostname; an IPv6 address fails IDNA and the
LDH fallback strips its colons, so 2602:ff16:9:0:1:17b:0:1 reached every report as
2602ff1690117b01 (datazag_intelligence, wordtothewise.com, 2026-10-17).
"""
from dns_module.dns_utils import ip_list_to_string, list_to_string


def test_ipv6_keeps_its_colons_in_canonical_form():
    assert ip_list_to_string(["2602:ff16:9:0:1:17b:0:1"]) == "2602:ff16:9:0:1:17b:0:1"
    assert ip_list_to_string(["2001:0DB8:0000:0000:0000:0000:0000:0001"]) == "2001:db8::1"


def test_mixed_and_ipv4_lists():
    assert ip_list_to_string(["192.0.2.1", " 2001:db8::2 ", ""]) == "192.0.2.1,2001:db8::2"


def test_non_addresses_are_kept_as_given():
    assert ip_list_to_string(["not-an-ip"]) == "not-an-ip"
    assert ip_list_to_string([]) == ""


def test_the_hostname_joiner_no_longer_mangles_ipv6_but_is_still_the_wrong_tool():
    """This assertion was inverted when to_ascii_hostname() gained its IP guard.

    It used to pin the mangling -- list_to_string(["2602:ff16:9:0:1:17b:0:1"]) ==
    "2602ff1690117b01" -- as the reason addresses must not go through it. The guard
    removes that failure mode at its source, so the joiner now returns the address
    intact and the old assertion would fail.

    The rule it was defending is unchanged: ip_list_to_string() is what the IP columns
    call. It says so at the call site and it canonicalizes, where this one happens not
    to corrupt. Belt and braces, deliberately.
    """
    assert list_to_string(["2602:ff16:9:0:1:17b:0:1"]) == "2602:ff16:9:0:1:17b:0:1"
    assert ip_list_to_string(["2602:ff16:9:0:1:17b:0:1"]) == "2602:ff16:9:0:1:17b:0:1"

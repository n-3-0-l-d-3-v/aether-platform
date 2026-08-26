"""Canonical serialization and identifier minting.

These tests defend the property everything else rests on: the same meaning
always produces the same bytes, and therefore the same id.
"""

from __future__ import annotations

import pytest

from aether.canonical import (
    CanonicalError,
    bytes_digests,
    canonical_json,
    content_digest,
    file_digests,
    is_id,
    mint_id,
)


def test_key_order_does_not_affect_output():
    left = {"b": 1, "a": [3, 2, {"z": 1, "y": 2}]}
    right = {"a": [3, 2, {"y": 2, "z": 1}]}
    right["b"] = 1
    assert canonical_json(left) == canonical_json(right)


def test_list_order_is_significant():
    assert canonical_json([1, 2]) != canonical_json([2, 1])


def test_integral_floats_collapse_to_ints():
    assert canonical_json({"n": 1.0}) == canonical_json({"n": 1})
    assert content_digest({"n": -0.0}) == content_digest({"n": 0})


def test_floats_round_to_fixed_precision():
    assert canonical_json({"c": 0.1234567891}) == canonical_json({"c": 0.1234567895})


def test_unicode_is_normalized():
    composed = "café"
    decomposed = "café"
    assert canonical_json({"s": composed}) == canonical_json({"s": decomposed})


def test_non_finite_floats_are_rejected():
    with pytest.raises(CanonicalError):
        canonical_json({"n": float("inf")})
    with pytest.raises(CanonicalError):
        canonical_json({"n": float("nan")})


def test_unhashable_types_are_rejected():
    with pytest.raises(CanonicalError):
        canonical_json({"s": {1, 2}})
    with pytest.raises(CanonicalError):
        canonical_json({"o": object()})


def test_non_string_keys_are_rejected():
    with pytest.raises(CanonicalError):
        canonical_json({1: "a"})


def test_mint_id_is_stable_and_prefixed():
    payload = {"kind": "function", "addr": 4096}
    first = mint_id("art", payload)
    assert first == mint_id("art", payload)
    assert is_id(first, "art")
    assert not is_id(first, "clm")
    assert first != mint_id("clm", payload)


def test_mint_id_rejects_bad_prefix():
    with pytest.raises(CanonicalError):
        mint_id("ARTIFACT", {})


def test_is_id_rejects_non_ids():
    assert not is_id("art_short")
    assert not is_id(12345)
    assert not is_id("art_" + "g" * 32)


def test_file_and_bytes_digests_agree(tmp_path):
    payload = b"aether evidence graph"
    path = tmp_path / "blob.bin"
    path.write_bytes(payload)
    assert file_digests(str(path)) == bytes_digests(payload)

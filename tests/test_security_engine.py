"""Tests for the Security Engine and Detection Rules — run against REAL
temp filesystem paths created on disk during the test (real files, real
bytes, real hashlib.sha256; no mocking of I/O)."""
import os
import tempfile
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine
from app.detection_rules import (
    rule_content_hash_mismatch,
    rule_timestamp_or_path_only_difference,
    rule_file_missing_on_one_side,
    rule_size_mismatch,
    rule_low_reproducibility_ratio,
    rule_fully_reproducible,
    ALL_RULES,
)


# ----------------------------------------------------------------------
# Rule-level unit tests with synthetic context dicts
# ----------------------------------------------------------------------

def test_rule_content_hash_mismatch_fires_on_diff():
    ctx = {"side": "both", "hash_a": "aaaa", "hash_b": "bbbb", "size_a": 10, "size_b": 10}
    result = rule_content_hash_mismatch("bin/tool", ctx)
    assert result is not None
    assert result["rule_id"] == "BRC-001"


def test_rule_content_hash_mismatch_silent_on_match():
    ctx = {"side": "both", "hash_a": "aaaa", "hash_b": "aaaa", "size_a": 10, "size_b": 10}
    assert rule_content_hash_mismatch("bin/tool", ctx) is None


def test_rule_timestamp_or_path_only_difference_fires():
    ctx = {
        "side": "both", "hash_a": "aaaa", "hash_b": "bbbb",
        "size_a": 10, "size_b": 10, "timestamp_or_path_only_diff": True,
    }
    result = rule_timestamp_or_path_only_difference("bin/tool", ctx)
    assert result is not None
    assert result["rule_id"] == "BRC-002"


def test_rule_timestamp_or_path_only_difference_silent_when_false():
    ctx = {
        "side": "both", "hash_a": "aaaa", "hash_b": "bbbb",
        "size_a": 10, "size_b": 10, "timestamp_or_path_only_diff": False,
    }
    assert rule_timestamp_or_path_only_difference("bin/tool", ctx) is None


def test_rule_file_missing_on_one_side_a_only():
    ctx = {"side": "a_only", "size_a": 100}
    result = rule_file_missing_on_one_side("bin/only_a", ctx)
    assert result is not None
    assert result["rule_id"] == "BRC-003"


def test_rule_file_missing_on_one_side_b_only():
    ctx = {"side": "b_only", "size_b": 100}
    result = rule_file_missing_on_one_side("bin/only_b", ctx)
    assert result is not None
    assert result["rule_id"] == "BRC-003"


def test_rule_size_mismatch_fires_on_diff_size():
    ctx = {"side": "both", "hash_a": "aaaa", "hash_b": "bbbb", "size_a": 10, "size_b": 20}
    result = rule_size_mismatch("bin/tool", ctx)
    assert result is not None
    assert result["rule_id"] == "BRC-004"


def test_rule_size_mismatch_silent_on_same_size():
    ctx = {"side": "both", "hash_a": "aaaa", "hash_b": "bbbb", "size_a": 10, "size_b": 10}
    assert rule_size_mismatch("bin/tool", ctx) is None


def test_rule_low_reproducibility_ratio_fires_below_threshold():
    ctx = {"kind": "summary", "common_files": 10, "identical_files": 5, "missing_count": 0}
    result = rule_low_reproducibility_ratio("<scan-summary>", ctx)
    assert result is not None
    assert result["rule_id"] == "BRC-005"


def test_rule_low_reproducibility_ratio_silent_above_threshold():
    ctx = {"kind": "summary", "common_files": 10, "identical_files": 10, "missing_count": 0}
    assert rule_low_reproducibility_ratio("<scan-summary>", ctx) is None


def test_rule_fully_reproducible_fires_when_all_identical():
    ctx = {"kind": "summary", "common_files": 10, "identical_files": 10, "missing_count": 0}
    result = rule_fully_reproducible("<scan-summary>", ctx)
    assert result is not None
    assert result["rule_id"] == "BRC-006"


def test_rule_fully_reproducible_silent_with_missing_files():
    ctx = {"kind": "summary", "common_files": 10, "identical_files": 10, "missing_count": 1}
    assert rule_fully_reproducible("<scan-summary>", ctx) is None


def test_all_rules_registered():
    assert len(ALL_RULES) == 6


# ----------------------------------------------------------------------
# Engine-level tests with two REAL temp directories on disk
# ----------------------------------------------------------------------

def _mktree():
    a = tempfile.mkdtemp(prefix="brc_a_")
    b = tempfile.mkdtemp(prefix="brc_b_")
    return a, b


def test_identical_files_not_flagged_as_mismatch():
    a, b = _mktree()
    try:
        content = b"#!/bin/sh\necho hello world\n"
        with open(os.path.join(a, "run.sh"), "wb") as f:
            f.write(content)
        with open(os.path.join(b, "run.sh"), "wb") as f:
            f.write(content)

        engine = ScanEngine(a, b, max_depth=4)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BRC-001" not in rule_ids
        assert "BRC-004" not in rule_ids
        assert "BRC-006" in rule_ids  # fully reproducible summary finding
        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(a)
        shutil.rmtree(b)


def test_content_difference_flags_hash_mismatch_and_size_mismatch():
    a, b = _mktree()
    try:
        with open(os.path.join(a, "app.bin"), "wb") as f:
            f.write(b"BUILD-CONTENT-VERSION-ONE" * 5)
        with open(os.path.join(b, "app.bin"), "wb") as f:
            f.write(b"totally-different-payload-bytes")  # different content AND size

        engine = ScanEngine(a, b, max_depth=4)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BRC-001" in rule_ids
        assert "BRC-004" in rule_ids
        assert "BRC-006" not in rule_ids
    finally:
        shutil.rmtree(a)
        shutil.rmtree(b)


def test_missing_file_on_one_side_flagged():
    a, b = _mktree()
    try:
        with open(os.path.join(a, "only_in_a.txt"), "wb") as f:
            f.write(b"present only in build A")
        # Nothing written into b at all.

        engine = ScanEngine(a, b, max_depth=4)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BRC-003" in rule_ids
        missing = [f for f in result["findings"] if f["rule_id"] == "BRC-003"]
        assert missing[0]["file_path"] == "only_in_a.txt"
    finally:
        shutil.rmtree(a)
        shutil.rmtree(b)


def test_timestamp_only_difference_flagged_as_brc002():
    a, b = _mktree()
    try:
        text_a = "BuildInfo: compiled on 2026-01-05 10:22:11 at /home/ci/build/proj\nVERSION=1.0.0\n"
        text_b = "BuildInfo: compiled on 2026-08-17 22:41:03 at /tmp/build-worker-9/proj\nVERSION=1.0.0\n"
        with open(os.path.join(a, "version.txt"), "w") as f:
            f.write(text_a)
        with open(os.path.join(b, "version.txt"), "w") as f:
            f.write(text_b)

        engine = ScanEngine(a, b, max_depth=4)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BRC-001" in rule_ids
        assert "BRC-002" in rule_ids
    finally:
        shutil.rmtree(a)
        shutil.rmtree(b)


def test_low_reproducibility_ratio_summary_finding():
    a, b = _mktree()
    try:
        # 10 files, 5 differ -> 50% identical, below the 90% threshold.
        for i in range(10):
            name = f"file_{i}.txt"
            with open(os.path.join(a, name), "w") as f:
                f.write(f"content-{i}")
            with open(os.path.join(b, name), "w") as f:
                if i % 2 == 0:
                    f.write(f"content-{i}")  # identical
                else:
                    f.write(f"different-content-{i}")  # differs

        engine = ScanEngine(a, b, max_depth=4)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BRC-005" in rule_ids
        assert "BRC-006" not in rule_ids
    finally:
        shutil.rmtree(a)
        shutil.rmtree(b)


def test_files_scanned_counts_union_of_both_sides():
    a, b = _mktree()
    try:
        with open(os.path.join(a, "shared.txt"), "w") as f:
            f.write("same")
        with open(os.path.join(b, "shared.txt"), "w") as f:
            f.write("same")
        with open(os.path.join(a, "only_a.txt"), "w") as f:
            f.write("a")
        with open(os.path.join(b, "only_b.txt"), "w") as f:
            f.write("b")

        engine = ScanEngine(a, b, max_depth=4)
        result = engine.run()
        assert result["files_scanned"] == 3
        assert result["dirs_scanned"] >= 2
    finally:
        shutil.rmtree(a)
        shutil.rmtree(b)


def test_nonexistent_directory_counts_as_error():
    a, b = _mktree()
    try:
        fake = os.path.join(a, "does_not_exist_at_all")
        engine = ScanEngine(fake, b, max_depth=4)
        result = engine.run()
        assert result["errors_count"] >= 1
    finally:
        shutil.rmtree(a)
        shutil.rmtree(b)

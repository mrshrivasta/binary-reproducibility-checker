"""
Detection Rules — Binary Reproducibility Checker
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL per-file comparison context dict — produced by the
Security Engine from two real directory trees (Build A and Build B) that were
actually walked and actually hashed with hashlib.sha256 — and returns a
Finding dict if the condition is met.

Why reproducible builds matter (supply-chain trust): if you cannot rebuild a
binary from its published source and get byte-for-byte identical output, you
cannot independently verify that the binary you were shipped actually
corresponds to that source. Reproducible-builds tooling (Debian, Tor Project,
F-Droid, etc.) exists specifically to close this trust gap. This tool applies
that same real, mechanical comparison to any two build outputs a user
provides — it does not simulate or estimate anything.
"""

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


def rule_content_hash_mismatch(path, ctx):
    """BRC-001: A file exists on BOTH sides but its real sha256 content hash
    differs between Build A and Build B. This is the core non-reproducibility
    signal this tool exists to catch — if hashes differ, the two build
    outputs are provably NOT byte-for-byte identical, so a third party cannot
    use Build B to verify Build A (or vice versa) against published source."""
    if ctx.get("side") != "both":
        return None
    if ctx["hash_a"] == ctx["hash_b"]:
        return None
    return {
        "rule_id": "BRC-001",
        "rule_name": "Content Hash Mismatch Between Builds",
        "severity": SEVERITY_HIGH,
        "description": (
            f"{path} differs between Build A and Build B: sha256(A)="
            f"{ctx['hash_a'][:12]}... vs sha256(B)={ctx['hash_b'][:12]}... "
            f"(sizes: A={ctx['size_a']} bytes, B={ctx['size_b']} bytes). "
            f"This file is NOT reproducible between the two build outputs."
        ),
        "hash_a": ctx["hash_a"],
        "hash_b": ctx["hash_b"],
    }


def rule_timestamp_or_path_only_difference(path, ctx):
    """BRC-002: For a file already flagged as a content-hash mismatch, a real
    heuristic checks whether the difference disappears once date-like and
    path-like substrings are stripped from a decoded text prefix of both
    files. If the stripped content matches, the root cause is very likely an
    embedded build timestamp or absolute build path baked into the binary —
    one of the most common and most fixable causes of non-reproducibility
    (e.g. __DATE__/__TIME__ macros, unstripped debug paths). Reported as a
    distinct, more specific finding than the generic BRC-001 hash mismatch so
    engineers can prioritize this "easy fix" category."""
    if ctx.get("side") != "both":
        return None
    if ctx["hash_a"] == ctx["hash_b"]:
        return None
    if not ctx.get("timestamp_or_path_only_diff"):
        return None
    return {
        "rule_id": "BRC-002",
        "rule_name": "Embedded Timestamp/Path Non-Determinism",
        "severity": SEVERITY_MEDIUM,
        "description": (
            f"{path} differs in content hash, but after stripping date-like "
            f"and path-like substrings from a decoded text prefix of both "
            f"files, the remaining content is identical. The most likely "
            f"root cause is a build timestamp or absolute build path "
            f"embedded in this file (e.g. __DATE__/__TIME__, debug paths, "
            f"build-directory strings) rather than a genuine content change."
        ),
    }


def rule_file_missing_on_one_side(path, ctx):
    """BRC-003: A file present in one build output is absent from the other.
    This is structural non-reproducibility — even before comparing bytes, the
    two builds do not even agree on what files exist, which is a stronger
    signal than a hash mismatch and often points to non-deterministic build
    steps (conditional codegen, timestamps in filenames, flaky packaging)."""
    side = ctx.get("side")
    if side == "a_only":
        return {
            "rule_id": "BRC-003",
            "rule_name": "File Missing On One Side",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{path} exists in Build A ({ctx.get('size_a')} bytes) but is "
                f"MISSING from Build B. The two build outputs do not agree on "
                f"the set of produced files."
            ),
        }
    if side == "b_only":
        return {
            "rule_id": "BRC-003",
            "rule_name": "File Missing On One Side",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{path} exists in Build B ({ctx.get('size_b')} bytes) but is "
                f"MISSING from Build A. The two build outputs do not agree on "
                f"the set of produced files."
            ),
        }
    return None


def rule_size_mismatch(path, ctx):
    """BRC-004: A file present on both sides has a different real byte size
    between Build A and Build B. Reported as a separate, independently
    queryable rule from BRC-001 (hash mismatch) so a preliminary size-only
    signal can be surfaced/filtered even though a size difference always
    implies a hash difference too — size is cheaper to check and often the
    first clue an engineer looks at."""
    if ctx.get("side") != "both":
        return None
    if ctx["size_a"] == ctx["size_b"]:
        return None
    return {
        "rule_id": "BRC-004",
        "rule_name": "File Size Mismatch Between Builds",
        "severity": SEVERITY_LOW,
        "description": (
            f"{path} has a different size in Build A ({ctx['size_a']} bytes) "
            f"than in Build B ({ctx['size_b']} bytes)."
        ),
    }


def rule_low_reproducibility_ratio(path, ctx):
    """BRC-005: Summary rule computed once per scan (path is a synthetic
    marker, not a real file) from the REAL counts accumulated while comparing
    every file: if fewer than 90% of the files common to both builds are
    byte-identical, the overall build is flagged as largely non-reproducible.
    This gives auditors a single top-line number instead of having to count
    per-file findings themselves."""
    if ctx.get("kind") != "summary":
        return None
    total = ctx.get("common_files", 0)
    if total == 0:
        return None
    identical = ctx.get("identical_files", 0)
    ratio = identical / total
    if ratio >= 0.90:
        return None
    return {
        "rule_id": "BRC-005",
        "rule_name": "Low Overall Reproducibility Ratio",
        "severity": SEVERITY_LOW,
        "description": (
            f"Only {identical}/{total} files ({ratio * 100:.1f}%) common to "
            f"both builds are byte-for-byte identical, which is below the "
            f"90% reproducibility threshold. This build is largely "
            f"non-reproducible."
        ),
    }


def rule_fully_reproducible(path, ctx):
    """BRC-006: Summary, informational rule computed once per scan: if every
    single real file compared between Build A and Build B was byte-for-byte
    identical (and no files were missing on either side), report a genuine
    positive "fully reproducible build" finding. A clean result is real,
    useful audit-trail information worth recording, not just an absence of
    findings."""
    if ctx.get("kind") != "summary":
        return None
    total = ctx.get("common_files", 0)
    if total == 0:
        return None
    identical = ctx.get("identical_files", 0)
    missing = ctx.get("missing_count", 0)
    if identical == total and missing == 0:
        return {
            "rule_id": "BRC-006",
            "rule_name": "Fully Reproducible Build",
            "severity": SEVERITY_LOW,
            "description": (
                f"All {total} files compared between Build A and Build B are "
                f"byte-for-byte identical, and no files were missing on "
                f"either side. This build output is fully reproducible."
            ),
        }
    return None


# Per-file rules are applied once per compared relative path.
PER_FILE_RULES = [
    rule_content_hash_mismatch,
    rule_timestamp_or_path_only_difference,
    rule_file_missing_on_one_side,
    rule_size_mismatch,
]

# Summary rules are applied exactly once per scan, after all files are compared.
SUMMARY_RULES = [
    rule_low_reproducibility_ratio,
    rule_fully_reproducible,
]

ALL_RULES = PER_FILE_RULES + SUMMARY_RULES

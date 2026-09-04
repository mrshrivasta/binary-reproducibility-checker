"""
Security Engine — Binary Reproducibility Checker
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Walks TWO real directory trees on the host filesystem ("Build A" and
"Build B" — e.g. two separate build runs of the same software project),
computes a real sha256 + size inventory for every real file found via
hashlib.sha256 over actual file bytes, and produces real findings from a
real comparison of the two inventories. No sample/mock data is ever
generated — every Finding reflects the actual bytes on disk at scan time.

Designed to run unprivileged: paths it cannot read are counted as errors
and skipped, never fabricated.
"""
import hashlib
import os
import re
import time

from app.detection_rules import PER_FILE_RULES, SUMMARY_RULES

DEFAULT_EXCLUDES = {"/proc", "/sys", "/dev", "/run"}

# Bounded prefix of each file read for the BRC-002 text-diff heuristic.
TEXT_HEURISTIC_PREFIX_BYTES = 65536
# Chunk size used while streaming a file into hashlib.
HASH_CHUNK_BYTES = 1024 * 1024

# Real regex patterns used to strip likely date/time and filesystem-path
# substrings out of decoded text before comparing two "different" files —
# if the *stripped* text is identical, the real difference is very likely
# just an embedded build timestamp or build path, not a content change.
_DATE_PATTERNS = [
    re.compile(r"\d{4}-\d{2}-\d{2}"),                     # 2026-08-17
    re.compile(r"\d{4}/\d{2}/\d{2}"),                     # 2026/08/17
    re.compile(r"\d{1,2}:\d{2}:\d{2}"),                   # 14:32:09
    re.compile(
        r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
        r"[a-z]*\s+\d{1,2}\s+\d{4}"
    ),                                                     # Aug 17 2026
    re.compile(
        r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*\s+"
        r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+"
        r"\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}"
    ),                                                     # __DATE__ __TIME__ combined
]
_PATH_PATTERNS = [
    re.compile(r"/(?:home|tmp|var|usr|build|Users)/[^\s'\"]+"),  # unix build paths
    re.compile(r"[A-Za-z]:\\[^\s'\"]+"),                          # windows build paths
]


def _strip_date_and_path_noise(text):
    for pattern in _DATE_PATTERNS:
        text = pattern.sub("<DATE>", text)
    for pattern in _PATH_PATTERNS:
        text = pattern.sub("<PATH>", text)
    return text


class ScanEngine:
    """Compares two REAL directory trees for byte-for-byte reproducibility."""

    def __init__(self, target_path, target_path_b, max_depth=12, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)      # Build A
        self.target_path_b = os.path.abspath(target_path_b)  # Build B
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real, synchronous dual-directory walk + comparison.
        Returns the summary dict shared by every project in this template."""
        start = time.time()

        inventory_a, dirs_a = self._walk_and_hash(self.target_path)
        inventory_b, dirs_b = self._walk_and_hash(self.target_path_b)
        self.dirs_scanned = dirs_a + dirs_b

        self._compare(inventory_a, inventory_b)

        self.files_scanned = len(set(inventory_a) | set(inventory_b))

        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    # ------------------------------------------------------------------
    # Real filesystem walk + real hashing
    # ------------------------------------------------------------------
    def _walk_and_hash(self, root):
        """Real os.walk over `root`, hashing every real regular file found.
        Returns (inventory, dirs_scanned) where inventory maps the file's
        path relative to `root` -> {"sha256": ..., "size": ...}."""
        inventory = {}
        dirs_scanned = 0
        file_count = 0

        if not os.path.isdir(root):
            self.errors_count += 1
            return inventory, dirs_scanned

        for depth_root, dirnames, filenames in os.walk(root):
            if self._is_excluded(depth_root):
                dirnames[:] = []
                continue

            rel_depth = os.path.relpath(depth_root, root)
            depth = 0 if rel_depth == "." else rel_depth.count(os.sep) + 1
            if depth > self.max_depth:
                dirnames[:] = []
                continue

            dirs_scanned += 1

            for name in filenames:
                if file_count >= self.max_files:
                    return inventory, dirs_scanned
                full_path = os.path.join(depth_root, name)
                if self._is_excluded(full_path):
                    continue
                try:
                    if os.path.islink(full_path):
                        continue
                    size = os.path.getsize(full_path)
                    digest = self._hash_file(full_path)
                except (PermissionError, FileNotFoundError, OSError):
                    self.errors_count += 1
                    continue

                rel_path = os.path.relpath(full_path, root)
                inventory[rel_path] = {"sha256": digest, "size": size, "abs_path": full_path}
                file_count += 1

        return inventory, dirs_scanned

    def _hash_file(self, path):
        """Real, streaming sha256 over a real file's actual bytes."""
        hasher = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(HASH_CHUNK_BYTES)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    # ------------------------------------------------------------------
    # Real comparison + rule application
    # ------------------------------------------------------------------
    def _compare(self, inventory_a, inventory_b):
        common_files = 0
        identical_files = 0
        missing_count = 0

        all_paths = sorted(set(inventory_a) | set(inventory_b))
        for rel_path in all_paths:
            a = inventory_a.get(rel_path)
            b = inventory_b.get(rel_path)

            if a and b:
                common_files += 1
                if a["sha256"] == b["sha256"]:
                    identical_files += 1
                ctx = {
                    "side": "both",
                    "hash_a": a["sha256"],
                    "hash_b": b["sha256"],
                    "size_a": a["size"],
                    "size_b": b["size"],
                }
                if a["sha256"] != b["sha256"]:
                    ctx["timestamp_or_path_only_diff"] = self._is_timestamp_or_path_only_diff(
                        a["abs_path"], b["abs_path"]
                    )
                self._apply_rules(PER_FILE_RULES, rel_path, ctx, a, b)
            elif a and not b:
                missing_count += 1
                ctx = {"side": "a_only", "size_a": a["size"]}
                self._apply_rules(PER_FILE_RULES, rel_path, ctx, a, None)
            else:
                missing_count += 1
                ctx = {"side": "b_only", "size_b": b["size"]}
                self._apply_rules(PER_FILE_RULES, rel_path, ctx, None, b)

        summary_ctx = {
            "kind": "summary",
            "common_files": common_files,
            "identical_files": identical_files,
            "missing_count": missing_count,
        }
        self._apply_rules(
            SUMMARY_RULES,
            "<scan-summary>",
            summary_ctx,
            {"sha256": None, "size": None},
            {"sha256": None, "size": None},
        )

    def _is_timestamp_or_path_only_diff(self, path_a, path_b):
        """Real heuristic for BRC-002: real-read a bounded prefix of both
        files, try to decode as text, strip real date/path patterns via
        regex, and see whether the stripped content matches."""
        try:
            with open(path_a, "rb") as fh:
                raw_a = fh.read(TEXT_HEURISTIC_PREFIX_BYTES)
            with open(path_b, "rb") as fh:
                raw_b = fh.read(TEXT_HEURISTIC_PREFIX_BYTES)
        except (PermissionError, FileNotFoundError, OSError):
            self.errors_count += 1
            return False

        try:
            text_a = raw_a.decode("utf-8")
            text_b = raw_b.decode("utf-8")
        except UnicodeDecodeError:
            # Binary content: still try a lossy decode so that a mostly-binary
            # file with a small embedded ASCII timestamp/path string can
            # still be evaluated by the heuristic.
            text_a = raw_a.decode("utf-8", errors="ignore")
            text_b = raw_b.decode("utf-8", errors="ignore")
            if not text_a or not text_b:
                return False

        if text_a == text_b:
            # Already identical prefixes but the full-file hash differed —
            # the difference lies outside the sampled prefix, not a
            # timestamp/path within it.
            return False

        stripped_a = _strip_date_and_path_noise(text_a)
        stripped_b = _strip_date_and_path_noise(text_b)
        return stripped_a == stripped_b

    def _apply_rules(self, rules, rel_path, ctx, a, b):
        for rule in rules:
            try:
                result = rule(rel_path, ctx)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                result["file_path"] = rel_path
                hash_a = (a or {}).get("sha256")
                hash_b = (b or {}).get("sha256")
                prefix_a = hash_a[:8] if hash_a else "missing"
                prefix_b = hash_b[:8] if hash_b else "missing"
                result["permissions_octal"] = f"A:{prefix_a} vs B:{prefix_b}"
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)

"""High-speed file scanner using strict, swap-aware signature matching.

- Builds a Pattern Map from `file_headers.csv` (columns: File name, 50 bytes).
- Scans a directory (or all mounted drives) for files with NO extension and size < 15MB.
  (Can optionally include files WITH extensions via --include-extensions flag)
- Reads only the first 50 bytes of each candidate file.
- Classifies files by matching against the known signatures from the CSV.
- Matching is resilient to adjacent byte swaps (pair-swap).
- Outputs `detected_files.csv` with File Name, File Path, Detected Type.

Designed for forensics triage / bulk signature classification.

Usage (defaults match this workspace):
  python file_scanner.py --scan-root .\\File --pattern-csv file_headers.csv --output detected_files.csv

To scan all available drives (Windows/Linux/macOS) with mounted volumes:
  python file_scanner.py --scan-all-drives --pattern-csv file_headers.csv --output detected_files.csv

To scan ALL files including those with extensions:
  python file_scanner.py --scan-all-drives --pattern-csv file_headers.csv --output detected_files.csv --include-extensions

To see diagnostic info about filtering (extension, size, permissions):
  python file_scanner.py --scan-all-drives --pattern-csv file_headers.csv --output detected_files.csv --verbose

If `tqdm` is installed, a progress bar is shown. If not installed, a simple textual
progress indicator is used.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import sys
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import subprocess


def get_all_drives() -> List[str]:
    """Enumerate all available drives on Windows (fixed + mounted).
    
    Returns a list of drive paths (e.g., ['C:\\', 'D:\\', '/mnt/external', ...])
    On Windows, checks for drive letters A-Z and uses wmic to find all logical disks.
    """
    
    drives = []
    
    # On Windows, enumerate drive letters A-Z
    if sys.platform == "win32":
        try:
            # Use wmic to get all logical disks
            result = subprocess.run(
                ["wmic", "logicaldisk", "get", "name"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and line != 'Name' and ':' in line:
                        drives.append(f"{line}\\")
        except Exception:
            # Fallback: check drive letters A-Z
            for letter in 'CDEFGHIJKLMNOPQRSTUVWXYZ':
                path = f"{letter}:\\"
                if os.path.exists(path):
                    drives.append(path)
    else:
        # On Linux/macOS, check common mount points
        common_mounts = [
            "/mnt",
            "/media",
            "/Volumes",
            "/run/media"
        ]
        for mount_point in common_mounts:
            if os.path.exists(mount_point):
                drives.append(mount_point)
        
        # Also add root if nothing found
        if not drives and os.path.exists("/"):
            drives.append("/")
    
    return drives


def _pair_swap(data: bytes) -> bytes:
    """Swap adjacent bytes: AB CD EF -> BA DC FE.

    This is a common obfuscation / endianness artifact for 16-bit values.
    """

    if len(data) < 2:
        return data
    swapped = bytearray(data)
    limit = len(swapped) - (len(swapped) % 2)
    for i in range(0, limit, 2):
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
    return bytes(swapped)


def _parse_hex_bytes(cell: str) -> Optional[bytes]:
    """Parse the '50 bytes' CSV cell into bytes.

    Expected format: "4d 5a 90 00 ..." (space-separated hex).
    """

    if not cell:
        return None
    cell = cell.strip()
    if not cell:
        return None
    if cell.lower().startswith("error"):
        return None
    # Keep only hex chars/spaces to be tolerant of odd formatting.
    filtered = []
    for ch in cell:
        if ch in "0123456789abcdefABCDEF ":
            filtered.append(ch)
    filtered_str = "".join(filtered).strip()
    if not filtered_str:
        return None
    try:
        return bytes.fromhex(filtered_str)
    except ValueError:
        return None


def _fuzzy_prefix_score(data: bytes, signature: bytes) -> float:
    """Return ratio of matching bytes between data prefix and signature.

    Avoids whole-buffer equality checks; compares byte-by-byte and returns [0,1].
    """

    if not signature:
        return 0.0
    n = min(len(data), len(signature))
    if n == 0:
        return 0.0
    matches = 0
    for i in range(n):
        if data[i] == signature[i]:
            matches += 1
    return matches / float(n)


def _magic_type(sample_50: bytes) -> str:
    """Return a type label based strictly on magic numbers, else "Unknown".

    Swap-aware: also checks an adjacent pair-swapped view.
    """

    # A small set of common magics. We use fuzzy scoring instead of exact equality.
    candidates: List[Tuple[str, bytes, float]] = [
        ("PNG", b"\x89PNG\r\n\x1a\n", 0.875),
        ("ZIP", b"PK\x03\x04", 0.75),
        ("PDF", b"%PDF-", 0.8),
        ("JPEG", b"\xff\xd8\xff", 0.67),
        ("PE/EXE", b"MZ", 1.0),
        ("MP3(ID3)", b"ID3", 1.0),
        ("UTF-8(TEXT,BOM)", b"\xef\xbb\xbf", 1.0),
    ]

    views = (sample_50, _pair_swap(sample_50))
    best_label = "UNKNOWN"
    best_score = 0.0

    for view in views:
        for label, sig, threshold in candidates:
            score = _fuzzy_prefix_score(view, sig)
            if score >= threshold and score > best_score:
                best_label = label
                best_score = score

    if best_label == "UNKNOWN":
        return "Unknown"
    return best_label


@dataclass(frozen=True)
class SignatureMatch:
    label: str
    score: float
    matched: bool


@dataclass(frozen=True)
class _Pattern:
    """Single known signature row from file_headers.csv."""

    name: str
    type_label: str
    bytes50: bytes
    bytes50_swapped: bytes
    denom_idf: float
    denom_idf_swapped: float


def _entropy_norm(byte_counts: Sequence[int], total: int) -> float:
    """Normalized Shannon entropy in [0,1] for a 256-bin distribution."""

    if total <= 0:
        return 0.0
    inv = 1.0 / float(total)
    h = 0.0
    for c in byte_counts:
        if c:
            p = c * inv
            h -= p * math.log(p, 2)
    return h / 8.0  # log2(256) == 8


class SignatureEngine:
    """Parses file_headers.csv and matches ONLY against those known signatures.

    Design goal: avoid false positives.

    Strategy:
    1) Build an entropy-keyed index from discriminative byte positions to quickly
       narrow candidate patterns (avoids brute-force matching).
    2) Score candidates with a swap-aware, weighted similarity across all 50 bytes.
        3) Require a high score threshold.

        Output labeling policy:
        - A file is considered "detected" only if it matches one of the 220 patterns.
        - The returned label is then computed from the file's magic bytes (or "Unknown").
    """

    def __init__(
        self,
        pattern_csv_path: str,
        key_positions: int = 10,
        min_score: float = 0.98,
        min_key_ratio: float = 0.80,
        min_headtail_ratio: float = 0.85,
        head_len: int = 8,
        tail_len: int = 8,
    ) -> None:
        self.pattern_csv_path = pattern_csv_path
        self.key_positions = max(4, int(key_positions))
        self.min_score = float(min_score)
        self.min_key_ratio = float(min_key_ratio)
        self.min_headtail_ratio = float(min_headtail_ratio)

        self._patterns: List[_Pattern] = []
        # IDF-style weights: common bytes contribute little; rare bytes contribute more.
        self._idf_by_pos: List[List[float]] = [[1.0] * 256 for _ in range(50)]
        self._key_pos: List[int] = []
        self._index: Dict[bytes, List[int]] = {}
        self._head_len = max(2, int(head_len))
        self._tail_len = max(2, int(tail_len))
        self._headtail_index: Dict[bytes, List[int]] = {}

        self._load_patterns_and_build_index()

    def _load_patterns_and_build_index(self) -> None:
        # Load patterns
        try:
            with open(self.pattern_csv_path, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    name = (row.get("File name") or row.get("File Name") or row.get("Name") or "").strip()
                    cell = row.get("50 bytes") or row.get("50 Bytes") or row.get("50")
                    if not name or cell is None:
                        continue
                    sample = _parse_hex_bytes(cell)
                    if not sample or len(sample) < 8:
                        continue
                    if len(sample) < 50:
                        sample = sample + b"\x00" * (50 - len(sample))
                    elif len(sample) > 50:
                        sample = sample[:50]
                    type_label = _magic_type(sample)
                    swapped = _pair_swap(sample)
                    self._patterns.append(
                        _Pattern(
                            name=name,
                            type_label=type_label,
                            bytes50=sample,
                            bytes50_swapped=swapped,
                            denom_idf=0.0,
                            denom_idf_swapped=0.0,
                        )
                    )
        except FileNotFoundError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Failed to parse pattern CSV: {exc}") from exc

        if not self._patterns:
            raise RuntimeError("No usable signatures were loaded from file_headers.csv")

        # Compute per-position entropy across patterns to build weights and a key index.
        counts_by_pos: List[List[int]] = [[0] * 256 for _ in range(50)]
        for p in self._patterns:
            b = p.bytes50
            for i in range(50):
                counts_by_pos[i][b[i]] += 1

        total = len(self._patterns)
        entropies = [(_entropy_norm(counts_by_pos[i], total), i) for i in range(50)]
        entropies.sort(reverse=True)

        # Build IDF weights per position and byte value.
        # Use log((N+1)/(df+1)) with a small floor so weights are never zero.
        # This makes ubiquitous bytes (like 0x00 in many patterns) contribute very little.
        idf_by_pos: List[List[float]] = [[0.0] * 256 for _ in range(50)]
        for i in range(50):
            for byte_val in range(256):
                df = counts_by_pos[i][byte_val]
                idf = math.log((total + 1.0) / (df + 1.0))
                idf_by_pos[i][byte_val] = 0.05 + idf
        self._idf_by_pos = idf_by_pos

        # Fill per-pattern denominators for fast normalization.
        updated: List[_Pattern] = []
        for p in self._patterns:
            denom = 0.0
            denom_s = 0.0
            b = p.bytes50
            bs = p.bytes50_swapped
            for i in range(50):
                denom += self._idf_by_pos[i][b[i]]
                denom_s += self._idf_by_pos[i][bs[i]]
            updated.append(
                _Pattern(
                    name=p.name,
                    type_label=p.type_label,
                    bytes50=p.bytes50,
                    bytes50_swapped=p.bytes50_swapped,
                    denom_idf=denom,
                    denom_idf_swapped=denom_s,
                )
            )
        self._patterns = updated

        # Select key positions: highest entropy positions, spaced out, and ensure we
        # cover both the "head" and "tail" regions (per spec).
        head_region = range(0, min(16, 50))
        tail_region = range(max(0, 50 - 16), 50)

        head_quota = max(2, self.key_positions // 3)
        tail_quota = max(2, self.key_positions // 3)

        key_pos: List[int] = []
        head_used = 0
        tail_used = 0
        for _, pos in entropies:
            if len(key_pos) >= self.key_positions:
                break
            if any(abs(pos - p) <= 1 for p in key_pos):
                continue

            in_head = pos in head_region
            in_tail = pos in tail_region

            if in_head and head_used < head_quota:
                key_pos.append(pos)
                head_used += 1
                continue
            if in_tail and tail_used < tail_quota:
                key_pos.append(pos)
                tail_used += 1
                continue

            # Fill remaining slots with best remaining positions.
            if (head_used >= head_quota) and (tail_used >= tail_quota):
                key_pos.append(pos)
        if len(key_pos) < 4:
            key_pos = [0, 1, 2, 3]
        key_pos.sort()
        self._key_pos = key_pos

        # Build index mapping key bytes -> pattern indices. Include both original and swapped views.
        index: Dict[bytes, List[int]] = {}
        headtail_index: Dict[bytes, List[int]] = {}
        for idx, p in enumerate(self._patterns):
            k1 = bytes(p.bytes50[pos] for pos in self._key_pos)
            k2 = bytes(p.bytes50_swapped[pos] for pos in self._key_pos)
            index.setdefault(k1, []).append(idx)
            index.setdefault(k2, []).append(idx)

            head = p.bytes50[: self._head_len]
            tail = p.bytes50[-self._tail_len :]
            head_s = p.bytes50_swapped[: self._head_len]
            tail_s = p.bytes50_swapped[-self._tail_len :]
            ht1 = head + tail
            ht2 = head_s + tail_s
            headtail_index.setdefault(ht1, []).append(idx)
            headtail_index.setdefault(ht2, []).append(idx)
        self._index = index
        self._headtail_index = headtail_index

    def _candidate_indices(self, sample_50: bytes) -> Set[int]:
        if len(sample_50) < 50:
            sample_50 = sample_50 + b"\x00" * (50 - len(sample_50))
        elif len(sample_50) > 50:
            sample_50 = sample_50[:50]

        swapped = _pair_swap(sample_50)

        k1 = bytes(sample_50[pos] for pos in self._key_pos)
        k2 = bytes(swapped[pos] for pos in self._key_pos)

        head = sample_50[: self._head_len]
        tail = sample_50[-self._tail_len :]
        head_s = swapped[: self._head_len]
        tail_s = swapped[-self._tail_len :]
        ht1 = head + tail
        ht2 = head_s + tail_s

        key_candidates: Set[int] = set(self._index.get(k1, [])) | set(self._index.get(k2, []))
        ht_candidates: Set[int] = set(self._headtail_index.get(ht1, [])) | set(self._headtail_index.get(ht2, []))

        if key_candidates and ht_candidates:
            inter = key_candidates & ht_candidates
            return inter if inter else (key_candidates | ht_candidates)
        return key_candidates or ht_candidates

    def _idf_similarity(self, sample: bytes, pattern: bytes, denom: float) -> float:
        """Rare-byte weighted similarity in [0,1]."""

        if len(sample) != 50:
            sample = (sample + b"\x00" * 50)[:50]
        # pattern is already 50
        num = 0.0
        for i in range(50):
            if sample[i] == pattern[i]:
                num += self._idf_by_pos[i][pattern[i]]
        return num / (denom or 1.0)

    def _agreement_ratios(self, sample: bytes, pattern: bytes) -> Tuple[float, float]:
        """Return (key_ratio, headtail_ratio) for a given alignment."""

        key_hits = 0
        for pos in self._key_pos:
            if sample[pos] == pattern[pos]:
                key_hits += 1
        key_ratio = key_hits / float(len(self._key_pos) or 1)

        ht_hits = 0
        ht_total = self._head_len + self._tail_len
        for i in range(self._head_len):
            if sample[i] == pattern[i]:
                ht_hits += 1
        for i in range(50 - self._tail_len, 50):
            if sample[i] == pattern[i]:
                ht_hits += 1
        headtail_ratio = ht_hits / float(ht_total or 1)

        return key_ratio, headtail_ratio

    def match(self, sample_50: bytes) -> SignatureMatch:
        if not sample_50:
            return SignatureMatch("Unknown", 0.0, matched=False)

        if len(sample_50) < 50:
            sample_50 = sample_50 + b"\x00" * (50 - len(sample_50))
        elif len(sample_50) > 50:
            sample_50 = sample_50[:50]

        candidate_set = self._candidate_indices(sample_50)
        if not candidate_set:
            return SignatureMatch("Unknown", 0.0, matched=False)

        s_swapped = _pair_swap(sample_50)

        best_idx = -1
        best = 0.0
        best_key_ratio = 0.0
        best_headtail_ratio = 0.0

        for idx in candidate_set:
            p = self._patterns[idx]
            # Evaluate four swap-aware alignments; keep ratios for the winning alignment.
            score_n = self._idf_similarity(sample_50, p.bytes50, p.denom_idf)
            kr_n, htr_n = self._agreement_ratios(sample_50, p.bytes50)

            score_s = self._idf_similarity(s_swapped, p.bytes50, p.denom_idf)
            kr_s, htr_s = self._agreement_ratios(s_swapped, p.bytes50)

            score_ns = self._idf_similarity(sample_50, p.bytes50_swapped, p.denom_idf_swapped)
            kr_ns, htr_ns = self._agreement_ratios(sample_50, p.bytes50_swapped)

            score_ss = self._idf_similarity(s_swapped, p.bytes50_swapped, p.denom_idf_swapped)
            kr_ss, htr_ss = self._agreement_ratios(s_swapped, p.bytes50_swapped)

            score = score_n
            kr = kr_n
            htr = htr_n
            if score_s > score:
                score, kr, htr = score_s, kr_s, htr_s
            if score_ns > score:
                score, kr, htr = score_ns, kr_ns, htr_ns
            if score_ss > score:
                score, kr, htr = score_ss, kr_ss, htr_ss

            if score > best:
                best = score
                best_idx = idx
                best_key_ratio = kr
                best_headtail_ratio = htr

        if best_idx < 0:
            return SignatureMatch("Unknown", 0.0, matched=False)

        if best < self.min_score:
            return SignatureMatch("Unknown", best, matched=False)

        # Additional guardrails to prevent generic magic-only false positives.
        if best_key_ratio < self.min_key_ratio or best_headtail_ratio < self.min_headtail_ratio:
            return SignatureMatch("Unknown", best, matched=False)

        # Label is based on the *file's* magic bytes, not the pattern row.
        return SignatureMatch(_magic_type(sample_50), best, matched=True)


def iter_candidate_files(
    scan_root: str,
    max_size_bytes: int,
    verbose: bool = False,
    include_extensions: bool = False,
) -> Tuple[Iterable[str], Optional[Dict[str, int]]]:
    """Yield candidate files with optional extension filter, file size < max_size_bytes.
    
    If verbose=True, also returns a dict with filtering statistics.
    Otherwise returns (iterable, None).
    """

    stats = {"total_files": 0, "filtered_extension": 0, "filtered_size": 0, "filtered_other": 0}

    def _iter():
        # os.walk is reasonably fast; use topdown traversal.
        for dirpath, dirnames, filenames in os.walk(scan_root):
            # Avoid hidden/system dirnames in a cheap way.
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]

            for name in filenames:
                stats["total_files"] += 1
                
                # Filter: optionally skip files with extension
                if not include_extensions:
                    _, ext = os.path.splitext(name)
                    if ext:
                        stats["filtered_extension"] += 1
                        continue

                path = os.path.join(dirpath, name)
                try:
                    st = os.stat(path)
                except OSError:
                    stats["filtered_other"] += 1
                    continue

                if st.st_size <= 0 or st.st_size >= max_size_bytes:
                    stats["filtered_size"] += 1
                    continue

                yield path
    
    return _iter(), stats if verbose else None


def _read_first_50(path: str) -> Tuple[str, Optional[bytes], Optional[str]]:
    """Worker: read first 50 bytes; return (path, bytes|None, error|None)."""

    try:
        with open(path, "rb") as f:
            return path, f.read(50), None
    except Exception as exc:
        return path, None, str(exc)


def _tqdm(total: Optional[int]):
    """Return a tqdm-like progress helper (real tqdm if available, else fallback).

    For large directory/drive scans, total is often unknown. tqdm supports
    total=None and will show a live counter without percentage.
    """

    try:
        from tqdm import tqdm  # type: ignore

        return tqdm(
            total=total,
            unit="file",
            smoothing=0.05,
            dynamic_ncols=True,
            mininterval=0.2,
            desc="Scanning",
        )
    except Exception:
        # Minimal fallback with the same .update()/.close() shape.
        class _Fallback:
            def __init__(self, total_: Optional[int]) -> None:
                self.total = total_
                self.n = 0

            def update(self, inc: int = 1) -> None:
                self.n += inc
                # Print every 500 updates to avoid spamming.
                if (self.n % 500) == 0:
                    if self.total and self.total > 0:
                        pct = (100.0 * self.n) / float(self.total)
                        print(f"Processed {self.n}/{self.total} files ({pct:.1f}%)", file=sys.stderr)
                    else:
                        print(f"Processed {self.n} files", file=sys.stderr)

            def close(self) -> None:
                return

        return _Fallback(total)


def scan_and_classify(
    scan_root: str,
    engine: SignatureEngine,
    output_csv_path: str,
    max_size_bytes: int,
    max_workers: int,
    max_pending: int,
    include_nonmatches: bool,
    append_mode: bool = False,
    verbose: bool = False,
    include_extensions: bool = False,
) -> Tuple[int, int, int, Optional[Dict[str, int]]]:
    """Scan scan_root and write output CSV. Returns (total, matched, unknown, stats_dict|None).
    
    If append_mode is True, appends to existing CSV (for multiple drive scans).
    Otherwise, overwrites the CSV file.
    If verbose=True, also returns filtering statistics.
    If include_extensions=True, scans files WITH extensions too (not just extension-less files).
    """

    total = 0
    matched = 0
    nonmatched = 0

    # When scanning a whole drive, pre-counting is expensive; use an open-ended bar.
    progress = _tqdm(None)

    file_mode = "a" if append_mode else "w"
    write_header = not append_mode or not os.path.exists(output_csv_path) or os.path.getsize(output_csv_path) == 0

    with open(output_csv_path, file_mode, newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        if write_header:
            writer.writerow(["File Name", "File Path", "Detected Type"])

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            pending = set()
            update_counter = 0

            def _drain(done_futs) -> None:
                nonlocal total, matched, nonmatched, update_counter
                for fut in done_futs:
                    path, data, err = fut.result()
                    total += 1
                    progress.update(1)
                    update_counter += 1

                    # Update postfix occasionally to keep overhead low.
                    if (update_counter % 250) == 0:
                        try:
                            progress.set_postfix_str(f"matched={matched}")
                        except Exception:
                            pass

                    file_name = os.path.basename(path)
                    if err is not None or data is None:
                        # Not a detectable match (can't read header).
                        nonmatched += 1
                        if include_nonmatches:
                            writer.writerow([file_name, path, "Unknown"])
                        continue

                    m = engine.match(data)
                    if not m.matched:
                        nonmatched += 1
                        if include_nonmatches:
                            writer.writerow([file_name, path, "Unknown"])
                        continue

                    # Matched a known pattern; label by magic or Unknown.
                    matched += 1
                    writer.writerow([file_name, path, m.label])

            candidate_iter, stats = iter_candidate_files(scan_root, max_size_bytes=max_size_bytes, verbose=verbose, include_extensions=include_extensions)
            for path in candidate_iter:
                pending.add(pool.submit(_read_first_50, path))
                if len(pending) >= max_pending:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    _drain(done)

            # Drain remaining
            if pending:
                done, _ = wait(pending)
                _drain(done)

    progress.close()
    return total, matched, nonmatched, stats


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="High-speed signature-based file scanner")
    parser.add_argument("--pattern-csv", default="file_headers.csv", help="Input pattern CSV")
    parser.add_argument("--scan-root", default=os.path.join(".", "File"), help="Directory to scan")
    parser.add_argument("--scan-all-drives", action="store_true", help="Scan all available drives (overrides --scan-root)")
    parser.add_argument("--output", default="detected_files.csv", help="Output CSV path")
    parser.add_argument("--max-mb", type=int, default=15, help="Max file size to scan (MB)")
    parser.add_argument("--workers", type=int, default=0, help="Thread workers (0=auto)")
    parser.add_argument("--key-bytes", type=int, default=10, help="Discriminative key byte count (indexing)")
    parser.add_argument("--min-score", type=float, default=0.98, help="Min similarity score for match")
    parser.add_argument("--min-key-ratio", type=float, default=0.80, help="Min agreement on key bytes (0-1)")
    parser.add_argument("--min-headtail-ratio", type=float, default=0.85, help="Min agreement on head+tail bytes (0-1)")
    parser.add_argument("--max-pending", type=int, default=5000, help="Max in-flight file reads")
    parser.add_argument(
        "--include-nonmatches",
        action="store_true",
        help="Also write non-matching candidates as Unknown rows (debug/noisy; off by default)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed filtering statistics (why files were skipped)",
    )
    parser.add_argument(
        "--include-extensions",
        action="store_true",
        help="Also scan files WITH extensions (default: only scans extension-less files)",
    )

    args = parser.parse_args(argv)

    max_size_bytes = int(args.max_mb) * 1024 * 1024

    if args.workers and args.workers > 0:
        max_workers = int(args.workers)
    else:
        cpu = os.cpu_count() or 4
        max_workers = min(32, cpu * 5)

    try:
        engine = SignatureEngine(
            pattern_csv_path=args.pattern_csv,
            key_positions=args.key_bytes,
            min_score=args.min_score,
            min_key_ratio=args.min_key_ratio,
            min_headtail_ratio=args.min_headtail_ratio,
        )
    except FileNotFoundError:
        print(f"Pattern CSV not found: {args.pattern_csv}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Failed to initialize SignatureEngine: {exc}", file=sys.stderr)
        return 2

    # Determine scan roots
    if args.scan_all_drives:
        scan_roots = get_all_drives()
        print(f"Scanning all available drives: {scan_roots}", file=sys.stderr)
    else:
        scan_roots = [args.scan_root]

    total_all = 0
    matched_all = 0
    nonmatched_all = 0

    # Scan each root
    for idx, scan_root in enumerate(scan_roots):
        if not os.path.exists(scan_root):
            print(f"Skipping {scan_root} (does not exist)", file=sys.stderr)
            continue

        print(f"\nScanning: {os.path.abspath(scan_root)}", file=sys.stderr)
        
        try:
            # Use append mode if this is not the first scan
            append_mode = idx > 0
            total, matched, nonmatched, stats = scan_and_classify(
                scan_root=scan_root,
                engine=engine,
                output_csv_path=args.output,
                max_size_bytes=max_size_bytes,
                max_workers=max_workers,
                max_pending=max(100, int(args.max_pending)),
                include_nonmatches=bool(args.include_nonmatches),
                append_mode=append_mode,
                verbose=args.verbose,
                include_extensions=args.include_extensions,
            )
            total_all += total
            matched_all += matched
            nonmatched_all += nonmatched
            
            if args.verbose and stats:
                print(f"\n  Scan root: {scan_root}", file=sys.stderr)
                print(f"    Total files examined     : {stats.get('total_files', 0):,}", file=sys.stderr)
                print(f"    Filtered (has extension) : {stats.get('filtered_extension', 0):,}", file=sys.stderr)
                print(f"    Filtered (size/access)   : {stats.get('filtered_size', 0):,}", file=sys.stderr)
                print(f"    Filtered (other reasons) : {stats.get('filtered_other', 0):,}", file=sys.stderr)
                print(f"    Scanned (no extension)   : {total:,}", file=sys.stderr)
        except Exception as exc:
            print(f"Error scanning {scan_root}: {exc}", file=sys.stderr)
            continue

    print("\n" + "="*60)
    print("FINAL SCAN SUMMARY")
    print("="*60)
    print(f"  Pattern CSV    : {os.path.abspath(args.pattern_csv)}")
    print(f"  Output CSV     : {os.path.abspath(args.output)}")
    if args.scan_all_drives:
        print(f"  Scanned drives : {', '.join(scan_roots)}")
    else:
        print(f"  Scan root      : {os.path.abspath(args.scan_root)}")
    print(f"  Total scanned  : {total_all}")
    print(f"  Files matched  : {matched_all}")
    print(f"  Unknown files  : {nonmatched_all}")
    print("="*60)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
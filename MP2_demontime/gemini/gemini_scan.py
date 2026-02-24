import os
import sys
import csv
import math
import argparse
import platform
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from collections import defaultdict

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

def swap_bytes(data: bytes) -> bytes:
    """Swaps adjacent bytes (AB CD -> BA DC)."""
    arr = bytearray(data)
    for i in range(0, len(arr) - 1, 2):
        arr[i], arr[i+1] = arr[i+1], arr[i]
    return bytes(arr)

# --- 1. Signature Database & Matching ---
class SignatureDB:
    def __init__(self, csv_path, key_count):
        self.csv_path = csv_path
        self.key_count = key_count
        self.signatures = []
        self.idf_weights = []
        self.key_positions = []
        self.loaded = False

    def load_and_index(self):
        if not os.path.exists(self.csv_path):
            sys.stderr.write(f"Error: Signature CSV '{self.csv_path}' not found.\n")
            return

        doc_frequencies = [defaultdict(int) for _ in range(50)]
        total_sigs = 0

        try:
            with open(self.csv_path, mode='r', encoding='utf-8') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) < 2 or row[0].lower() == 'file name': continue
                    
                    name, hex_str = row[0], row[1]
                    
                    target_size = -1
                    if len(row) >= 3:
                        try:
                            target_size = int(row[2])
                        except ValueError:
                            target_size = -1 

                    try:
                        b_val = bytes.fromhex(hex_str.replace(' ', ''))
                        if len(b_val) < 50: b_val = b_val.ljust(50, b'\x00')
                        b_val = b_val[:50]
                        
                        self.signatures.append((name, b_val, target_size))
                        
                        for i, byte in enumerate(b_val):
                            doc_frequencies[i][byte] += 1
                        total_sigs += 1
                    except ValueError:
                        continue
        except Exception as e:
            sys.stderr.write(f"Error reading CSV: {e}\n")
            return

        if total_sigs == 0: return

        self.idf_weights = []
        pos_entropy = []
        for i in range(50):
            pos_weights = {}
            total_idf_pos = 0
            for byte_val, count in doc_frequencies[i].items():
                w = math.log(total_sigs / (1 + count))
                pos_weights[byte_val] = w
                total_idf_pos += w
            self.idf_weights.append(pos_weights)
            avg_idf = total_idf_pos / max(1, len(doc_frequencies[i]))
            pos_entropy.append((avg_idf, i))

        pos_entropy.sort(reverse=True)
        self.key_positions = [pos for _, pos in pos_entropy[:self.key_count]]
        self.loaded = True

    def calculate_score(self, file_b, sig_b):
        score, total_weight = 0.0, 0.0
        key_matches = 0
        ht_matches = 0
        
        for i in range(50):
            weight = self.idf_weights[i].get(sig_b[i], 1.0)
            total_weight += weight
            
            is_match = (file_b[i] == sig_b[i])
            if is_match:
                score += weight
                if i in self.key_positions: key_matches += 1
                if i < 8 or i >= 42: ht_matches += 1

        sim_score = score / total_weight if total_weight > 0 else 0
        key_ratio = key_matches / max(1, len(self.key_positions))
        ht_ratio = ht_matches / 16.0 

        return sim_score, key_ratio, ht_ratio

    def match(self, file_bytes, file_size, min_score, min_key_ratio, min_ht_ratio, size_margin):
        if len(file_bytes) < 50:
            file_bytes = file_bytes.ljust(50, b'\x00')
        else:
            file_bytes = file_bytes[:50]

        file_swapped = swap_bytes(file_bytes)
        best_label, best_score = "Unknown", 0.0

        for name, sig_b, target_size in self.signatures:
            
            # --- DYNAMIC STRICT MODE FOR LICENSES/TEXT ---
            # If the signature is mostly printable text (>= 40 out of 50 bytes)
            printable_chars = sum(1 for b in sig_b if 32 <= b <= 126 or b in (9, 10, 13))
            is_text_sig = printable_chars >= 40 

            # Force strict rules if it's a text file like a GPL License
            effective_margin = 0 if is_text_sig else size_margin
            effective_min_score = 1.0 if is_text_sig else min_score

            # 1. Size Check
            if target_size >= 0:
                if abs(file_size - target_size) > effective_margin:
                    continue

            # 2. Byte Matching
            sig_swapped = swap_bytes(sig_b)
            
            comparisons = [
                (file_bytes, sig_b),
                (file_bytes, sig_swapped),
                (file_swapped, sig_b),
                (file_swapped, sig_swapped)
            ]

            for fb, sb in comparisons:
                sim, key_r, ht_r = self.calculate_score(fb, sb)
                
                # --- PERFECT MATCH SHORT-CIRCUIT ---
                # If we hit a 100% exact match on bytes and size, lock it in and stop checking!
                if sim == 1.0 and file_size == target_size:
                    return name, 1.0, True

                # Otherwise, keep looking for the single best fuzzy match
                if sim > best_score and sim >= effective_min_score and key_r >= min_key_ratio and ht_r >= min_ht_ratio:
                    best_score = sim
                    best_label = name

        return (best_label, best_score, best_label != "Unknown")

# --- 2. Discovery & Filtering ---
def get_drives():
    drives = []
    sys_os = platform.system()
    if sys_os == 'Windows':
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if os.path.exists(f"{letter}:\\"):
                drives.append(f"{letter}:\\")
    else:
        mount_points = ['/mnt', '/media', '/Volumes', '/run/media']
        for mp in mount_points:
            if os.path.exists(mp):
                for entry in os.listdir(mp):
                    full_path = os.path.join(mp, entry)
                    if os.path.ismount(full_path) or os.path.isdir(full_path):
                        drives.append(full_path)
        drives.append('/') 
    return drives

def process_file(file_path, file_size, db, args):
    try:
        with open(file_path, 'rb') as f:
            header = f.read(50)
            
        if not header:
            return file_path, "Unknown", False

        if db.loaded:
            label, score, matched = db.match(header, file_size, args.min_score, args.min_key_ratio, args.min_headtail_ratio, args.size_margin)
            if matched: return file_path, label, True

        return file_path, "Unknown", False

    except Exception:
        return file_path, "Error", False

# --- 3. Main Controller ---
def main():
    parser = argparse.ArgumentParser(description="High-Performance Forensic File Scanner")
    parser.add_argument("--pattern-csv", default="file_headers.csv", help="Path to signatures CSV")
    parser.add_argument("--scan-root", default="./File", help="Single directory to scan")
    parser.add_argument("--scan-all-drives", action="store_true", help="Scan all detected drives")
    parser.add_argument("--output", default="detected_files.csv", help="Output CSV path")
    parser.add_argument("--max-mb", type=float, default=15.0, help="Max file size in MB")
    parser.add_argument("--workers", type=int, default=0, help="Thread workers (0=auto)")
    parser.add_argument("--key-bytes", type=int, default=10, help="Number of high-entropy key positions")
    parser.add_argument("--min-score", type=float, default=0.90, help="Overall similarity threshold")
    parser.add_argument("--min-key-ratio", type=float, default=0.75, help="Key position agreement ratio")
    parser.add_argument("--min-headtail-ratio", type=float, default=0.75, help="Head/tail agreement ratio")
    parser.add_argument("--size-margin", type=int, default=50, help="Allowed file size variance in bytes (Default: 50)")
    parser.add_argument("--max-pending", type=int, default=5000, help="Max in-flight file reads")
    parser.add_argument("--include-nonmatches", action="store_true", help="Write Unknown files to CSV")
    parser.add_argument("--include-extensions", action="store_true", help="Scan files with extensions")
    parser.add_argument("--exclude-dirs", nargs='+', default=["Cache_Data", "Cache", "Code Cache"], help="List of directory names to skip")
    args = parser.parse_args()

    workers = args.workers if args.workers > 0 else min(32, (os.cpu_count() or 1) * 5)
    max_size_bytes = int(args.max_mb * 1024 * 1024)

    db = SignatureDB(args.pattern_csv, args.key_bytes)
    db.load_and_index()

    if not db.loaded:
        print("Failed to load CSV. Exiting.")
        sys.exit(1)

    targets = get_drives() if args.scan_all_drives else [args.scan_root]
    
    try:
        out_f = open(args.output, 'w', newline='', encoding='utf-8')
        writer = csv.writer(out_f)
        writer.writerow(["File Name", "File Path", "Detected Type"])
    except IOError as e:
        sys.stderr.write(f"Failed to open output file: {e}\n")
        sys.exit(1)

    global_scanned = 0
    global_matched = 0
    global_unknown = 0

    executor = ThreadPoolExecutor(max_workers=workers)
    pbar = tqdm(desc="Scanning", unit="files", dynamic_ncols=True) if HAS_TQDM else None
    
    exclude_set = set(args.exclude_dirs)

    for target in targets:
        if not os.path.exists(target):
            sys.stderr.write(f"Skipping inaccessible target: {target}\n")
            continue

        pending = set()
        
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in exclude_set]
            
            for file in files:
                path = os.path.join(root, file)
                ext = os.path.splitext(file)[1]
                if ext and not args.include_extensions: continue
                
                try:
                    size = os.path.getsize(path)
                    if size == 0 or size > max_size_bytes: continue
                except OSError:
                    continue 

                if len(pending) >= args.max_pending:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for task in done:
                        res_path, label, matched = task.result()
                        global_scanned += 1
                        if matched:
                            global_matched += 1
                            writer.writerow([os.path.basename(res_path), res_path, label])
                        else:
                            global_unknown += 1
                            if args.include_nonmatches:
                                writer.writerow([os.path.basename(res_path), res_path, label])
                        
                        if pbar is not None: 
                            pbar.update(1)
                            pbar.set_postfix({'Matched': global_matched})
                        elif global_scanned % 500 == 0:
                            print(f"Scanned: {global_scanned} | Matched: {global_matched}", end='\r')

                pending.add(executor.submit(process_file, path, size, db, args))

        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for task in done:
                res_path, label, matched = task.result()
                global_scanned += 1
                if matched:
                    global_matched += 1
                    writer.writerow([os.path.basename(res_path), res_path, label])
                else:
                    global_unknown += 1
                    if args.include_nonmatches:
                        writer.writerow([os.path.basename(res_path), res_path, label])
                
                if pbar is not None: 
                    pbar.update(1)
                    pbar.set_postfix({'Matched': global_matched})
                elif global_scanned % 500 == 0:
                    print(f"Scanned: {global_scanned} | Matched: {global_matched}", end='\r')

    if pbar is not None: pbar.close()
    out_f.close()
    executor.shutdown()

    print("\n" + "="*60)
    print("FINAL SCAN SUMMARY")
    print("="*60)
    print(f"  Pattern CSV    : {os.path.abspath(args.pattern_csv)}")
    print(f"  Output CSV     : {os.path.abspath(args.output)}")
    print(f"  Scanned drives : {', '.join(targets)}")
    print(f"  Total scanned  : {global_scanned:,}")
    print(f"  Files matched  : {global_matched:,}")
    print(f"  Unknown files  : {global_unknown:,}")
    print("="*60)

if __name__ == "__main__":
    main()
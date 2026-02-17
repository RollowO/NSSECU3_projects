import os
import csv
import yara
import sys
from tqdm import tqdm

# ================= CONFIGURATION =================
# Scans the entire E:\ drive. Run as Administrator for best results.
TARGET_PATH = 'E:' 

# Directory containing your .yar files
RULES_DIR = '../scanner_rules' 

OUTPUT_CSV = 'gemini_scan_results.csv'
MAX_FILE_SIZE = 100 * 1024 * 1024 # 100MB Limit
SKIP_NO_EXTENSION = False 
# =================================================

def get_first_50_bytes_hex(filepath):
    """Reads the first 50 bytes of a file and returns them as a hex string."""
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(50)
            return chunk.hex()
    except Exception:
        return "READ_ERROR"

def compile_rules(rules_folder):
    """Compiles all .yar files in the directory using filenames as namespaces."""
    if not os.path.exists(rules_folder):
        print(f"[-] Error: Rules directory '{rules_folder}' not found.")
        return None

    filepaths = {}
    print(f"[*] Searching for YARA rules in '{rules_folder}'...")
    
    for root, _, files in os.walk(rules_folder):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                full_path = os.path.join(root, file)
                # Use the filename as the namespace (Rule Source)
                namespace = file 
                filepaths[namespace] = full_path

    if not filepaths:
        print("[-] No .yar files found in the directory.")
        return None

    print(f"[*] Compiling {len(filepaths)} rule files...")
    try:
        rules = yara.compile(filepaths=filepaths, externals={'filename': ''})
        return rules
    except yara.SyntaxError as e:
        print(f"[-] YARA Compilation Error: {e}")
        return None

def scan():
    # 1. Load and Compile
    rules = compile_rules(RULES_DIR)
    if not rules:
        return

    # 2. Fast Discovery Phase
    print(f"[*] Indexing files in {TARGET_PATH}... (This may take time for C:\\)")
    candidate_files = []
    
    try:
        for root, dirs, files in os.walk(TARGET_PATH):
            for file in files:
                file_path = os.path.join(root, file)
                
                if SKIP_NO_EXTENSION and "." not in file:
                    continue
                    
                try:
                    if os.path.islink(file_path):
                        continue

                    f_size = os.path.getsize(file_path)
                    
                    if f_size <= MAX_FILE_SIZE:
                        candidate_files.append((file_path, f_size))
                except (PermissionError, OSError):
                    continue
    except Exception as e:
        print(f"[-] Error during file indexing: {e}")

    print(f"[*] Queueing {len(candidate_files)} files for scanning.")

    # 3. Targeted Scanning Phase
    results = []
    
    if candidate_files:
        pbar = tqdm(total=len(candidate_files), desc="Scanning", unit="file", colour="green")

        for file_path, f_size in candidate_files:
            try:
                matches = rules.match(
                    filepath=file_path, 
                    externals={'filename': os.path.basename(file_path)}
                )
                
                # --- CHANGED LOGIC START ---
                # Only proceed if there is at least one match
                if matches:
                    # Take strictly the first match found (index 0)
                    first_match = matches[0]
                    
                    hex_head = get_first_50_bytes_hex(file_path)
                    
                    results.append({
                        "File Location": os.path.dirname(file_path),
                        "Filename": os.path.basename(file_path),
                        "YARA Rule Hit": first_match.namespace, # The filename of the .yar rule
                        "First 50 Bytes": hex_head
                    })
                # --- CHANGED LOGIC END ---
                    
            except Exception:
                pass
            
            pbar.update(1)
        
        pbar.close()
    else:
        print("[-] No candidates found to scan.")

    # 4. Save Results
    if results:
        # Sort by 'YARA Rule Hit' so similar detections are grouped
        results.sort(key=lambda x: x["YARA Rule Hit"])
        
        try:
            with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ["File Location", "Filename", "YARA Rule Hit", "First 50 Bytes"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
            print(f"\n[+] Success! {len(results)} matches saved to {OUTPUT_CSV}")
        except PermissionError:
            print(f"\n[-] Error: Could not write to {OUTPUT_CSV}. Is the file open?")
    else:
        print("\n[-] No matches found.")

if __name__ == "__main__":
    scan()

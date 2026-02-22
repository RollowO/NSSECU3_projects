import os
import csv
import yara
from tqdm import tqdm  # Ensure this is installed: pip install tqdm

# ================= CONFIGURATION =================
TARGET_PATH = r'E:Program Files\Common Files'
RULES_FILE = 'NONE_License.yar' 
OUTPUT_CSV = 'gemini_scan_results.csv'
MAX_FILE_SIZE = 10 * 1024 * 1024 # 100MB Limit (Adjust as needed)
SKIP_NO_EXTENSION = False # Set to True if you want to skip files without extensions
# =================================================

def scan():
    if not os.path.exists(RULES_FILE):
        print(f"[-] Error: {RULES_FILE} not found.")
        return

    # 1. Load and Compile
    print(f"[*] Loading YARA rules from {RULES_FILE}...")
    try:
        # Define 'filename' as an external string variable so rules utilizing it don't break
        rules = yara.compile(filepath=RULES_FILE, externals={'filename': ''})
    except yara.SyntaxError as e:
        print(f"[-] YARA Compilation Error: {e}")
        return

    # 2. Fast Discovery Phase (Finding candidates)
    print(f"[*] Indexing files in {TARGET_PATH}... (Please wait)")
    candidate_files = []
    total_files_on_disk = 0

    for root, dirs, files in os.walk(TARGET_PATH):
        for file in files:
            total_files_on_disk += 1
            file_path = os.path.join(root, file)
            
            if SKIP_NO_EXTENSION and "." not in file:
                continue
                
            try:
                f_size = os.path.getsize(file_path)
                
                # Only filter by MAX_FILE_SIZE to prevent memory issues with massive files
                if f_size <= MAX_FILE_SIZE:
                    candidate_files.append((file_path, f_size))
            except (PermissionError, OSError):
                # Skip files we cannot read or access
                continue

    print(f"[*] Found {total_files_on_disk} total files.")
    print(f"[*] Queueing {len(candidate_files)} files for scanning (size < {MAX_FILE_SIZE/1024/1024:.2f} MB).")

    # 3. Targeted Scanning Phase
    results = []
    
    if candidate_files:
        pbar = tqdm(total=len(candidate_files), desc="Scanning Files", unit="file", colour="green")

        for file_path, f_size in candidate_files:
            try:
                # Pass the specific filename to the rule engine for this file
                matches = rules.match(
                    filepath=file_path, 
                    externals={'filename': os.path.basename(file_path)} 
                )
                
                if matches:
                    for m in matches:
                        results.append({
                            "File_Path": file_path,
                            "File_Size": f_size,
                            "Rule": m.rule,
                            "Description": m.meta.get('description', '')
                        })
            except Exception as e:
                # Optional: Print error if scanning specifically fails on a file
                # print(f"Error scanning {file_path}: {e}")
                pass
            
            pbar.update(1)
        
        pbar.close()
    else:
        print("[-] No candidates found to scan.")

    # 4. Save Results
    if results:
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["File_Path", "File_Size", "Rule", "Description"])
            writer.writeheader()
            writer.writerows(results)
        print(f"\n[+] Success! {len(results)} matches saved to {OUTPUT_CSV}")
    else:
        print("\n[-] No matches found.")

if __name__ == "__main__":
    scan()

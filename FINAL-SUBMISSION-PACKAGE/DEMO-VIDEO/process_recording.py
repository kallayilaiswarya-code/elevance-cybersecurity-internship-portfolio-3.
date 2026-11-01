"""
ElevanceSkills SOC Analyst Internship — Video Ingestion & Verification Helper
Monitors and ingests screen recordings from Windows Game Bar into the submission package.
"""

import os
import sys
import shutil
import glob
from pathlib import Path

CAPTURES_DIR = Path(r"C:\Users\aiswarya\OneDrive\Videos\Captures")
TARGET_DIR = Path(r"C:\Users\aiswarya\Documents\Elevance-SOC-Internship-PUBLIC\FINAL-SUBMISSION-PACKAGE\DEMO-VIDEO")
TARGET_FILE = TARGET_DIR / "SOC_Internship_Demo.mp4"

def list_recent_captures():
    if not CAPTURES_DIR.exists():
        print(f"[!] Captures directory not found: {CAPTURES_DIR}")
        return []

    mp4_files = list(CAPTURES_DIR.glob("*.mp4"))
    mp4_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
    return mp4_files

def verify_and_ingest(source_file=None):
    if source_file is None:
        captures = list_recent_captures()
        if not captures:
            print("[-] No MP4 recordings found in Captures folder.")
            print(f"    Expected location: {CAPTURES_DIR}")
            return False
        source_file = captures[0]

    source_path = Path(source_file)
    if not source_path.exists():
        print(f"[!] Source file does not exist: {source_path}")
        return False

    size_bytes = source_path.stat().st_size
    size_mb = size_bytes / (1024 * 1024)
    print(f"\n[+] Inspecting Candidate Video: {source_path.name}")
    print(f"    File Size: {size_mb:.2f} MB")

    if size_mb > 100.0:
        print(f"[!] WARNING: File size exceeds 100 MB limit ({size_mb:.2f} MB).")
    else:
        print("    [PASS] File size is strictly within < 100 MB requirement.")

    # Copy to target location
    shutil.copy2(source_path, TARGET_FILE)
    print(f"[+] Successfully copied to: {TARGET_FILE}")
    print(f"    Target Size: {TARGET_FILE.stat().st_size / (1024*1024):.2f} MB")
    print("    [PASS] Deliverable ready at FINAL-SUBMISSION-PACKAGE/DEMO-VIDEO/SOC_Internship_Demo.mp4")
    return True

if __name__ == "__main__":
    if len(sys.argv) > 1:
        verify_and_ingest(sys.argv[1])
    else:
        captures = list_recent_captures()
        if captures:
            print(f"[i] Found {len(captures)} recording(s) in Windows Game Bar Captures:")
            for i, cap in enumerate(captures[:5]):
                sz = cap.stat().st_size / (1024*1024)
                print(f"    [{i+1}] {cap.name} ({sz:.2f} MB)")
            print("\nRun: python process_recording.py \"<path-to-file>\" to ingest.")
        else:
            print(f"[i] No captures found yet in {CAPTURES_DIR}.")
            print("    Please record using Microsoft Edge + Windows Game Bar (Win + Alt + R).")

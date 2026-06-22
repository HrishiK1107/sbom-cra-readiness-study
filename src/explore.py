import os
import random

ROOT = r"C:\Users\hkana\Downloads\sbom-cra-research\data\raw"

def detect_format(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(2000)  # Read more — 2000 bytes
        
        content_lower = content.lower()
        
        if "spdxversion" in content_lower:
            return "SPDX-JSON"
        elif "bomformat" in content_lower and "cyclonedx" in content_lower:
            return "CycloneDX-JSON"
        elif content.strip().startswith("<"):
            if "spdxversion" in content_lower or "spdx" in content_lower:
                return "SPDX-XML"
            elif "bom" in content_lower:
                return "CycloneDX-XML"
            else:
                return "XML-UNKNOWN"
        else:
            return "UNKNOWN"
    except Exception as e:
        return "ERROR"

def collect_all_files():
    all_files = []
    for folder in os.listdir(ROOT):
        folder_path = os.path.join(ROOT, folder)
        if os.path.isdir(folder_path):
            for fname in os.listdir(folder_path):
                fpath = os.path.join(folder_path, fname)
                if os.path.isfile(fpath):
                    all_files.append(fpath)
    return all_files

def sample_files(n=500):
    print("Collecting file list...")
    all_files = collect_all_files()
    print(f"Total files found: {len(all_files)}")

    sample = random.sample(all_files, min(n, len(all_files)))
    print(f"Sampling {len(sample)} files...\n")

    counts = {
        "SPDX-JSON": 0,
        "CycloneDX-JSON": 0,
        "SPDX-XML": 0,
        "CycloneDX-XML": 0,
        "XML-UNKNOWN": 0,
        "UNKNOWN": 0,
        "ERROR": 0
    }

    size_buckets = {
        "tiny (<1KB)": 0,
        "small (1-10KB)": 0,
        "medium (10-100KB)": 0,
        "large (100KB-1MB)": 0,
        "huge (>1MB)": 0
    }

    for fpath in sample:
        fmt = detect_format(fpath)
        counts[fmt] += 1

        size = os.path.getsize(fpath)
        if size < 1024:
            size_buckets["tiny (<1KB)"] += 1
        elif size < 10240:
            size_buckets["small (1-10KB)"] += 1
        elif size < 102400:
            size_buckets["medium (10-100KB)"] += 1
        elif size < 1048576:
            size_buckets["large (100KB-1MB)"] += 1
        else:
            size_buckets["huge (>1MB)"] += 1

    print(f"FORMAT BREAKDOWN (n={len(sample)}):")
    for fmt, count in counts.items():
        pct = (count / len(sample)) * 100
        bar = "█" * int(pct / 2)
        print(f"  {fmt:20s}: {count:5d} ({pct:5.1f}%)")

    print(f"\nSIZE BREAKDOWN:")
    for bucket, count in size_buckets.items():
        pct = (count / len(sample)) * 100
        bar = "█" * int(pct / 2)
        print(f"  {bucket:25s}: {count:5d} ({pct:5.1f}%)")

    # Show 3 UNKNOWN examples so we can debug
    print(f"\nDEBUG — First 3 UNKNOWN file previews:")
    shown = 0
    for fpath in sample:
        if shown >= 3:
            break
        if detect_format(fpath) == "UNKNOWN":
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    preview = f.read(300)
                print(f"\n  File: {os.path.basename(fpath)}")
                print(f"  Preview: {repr(preview[:200])}")
                shown += 1
            except:
                pass

if __name__ == "__main__":
    sample_files(500)
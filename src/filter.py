import os
import json
import random
import shutil
from tqdm import tqdm

ROOT     = r"C:\Users\hkana\Downloads\sbom-cra-research\data\raw"
OUT_DIR  = r"C:\Users\hkana\Downloads\sbom-cra-research\data\filtered"
TARGET   = 5000   # how many files we want in final corpus
MIN_COMPONENTS = 5

os.makedirs(OUT_DIR, exist_ok=True)

# ── helpers ──────────────────────────────────────────────────────────────────

def collect_all_files():
    all_files = []
    for folder in os.listdir(ROOT):
        fp = os.path.join(ROOT, folder)
        if os.path.isdir(fp):
            for fname in os.listdir(fp):
                full = os.path.join(fp, fname)
                if os.path.isfile(full):
                    all_files.append(full)
    return all_files


def detect_format(content_start: str):
    cl = content_start.lower()
    if "spdxversion" in cl:
        return "SPDX-JSON"
    if "bomformat" in cl and "cyclonedx" in cl:
        return "CycloneDX-JSON"
    if content_start.strip().startswith("<"):
        if "cyclonedx" in cl or "<bom" in cl:
            return "CycloneDX-XML"
    return None   # reject


def extract_tool_cdx(data: dict) -> str:
    """Pull tool name from CycloneDX metadata."""
    try:
        tools = data.get("metadata", {}).get("tools", {})
        # CycloneDX 1.5 style: tools.components[]
        if isinstance(tools, dict):
            comps = tools.get("components", [])
            if comps:
                return comps[0].get("name", "unknown")
        # CycloneDX 1.4 style: tools[]
        if isinstance(tools, list) and tools:
            return tools[0].get("name", "unknown")
    except Exception:
        pass
    return "unknown"


def extract_tool_spdx(data: dict) -> str:
    """Pull tool name from SPDX creationInfo.creators."""
    try:
        creators = data.get("creationInfo", {}).get("creators", [])
        for c in creators:
            if c.startswith("Tool:"):
                # e.g. "Tool: trivy-0.43.0"  →  "trivy"
                raw = c.replace("Tool:", "").strip()
                return raw.split("-")[0].lower()
    except Exception:
        pass
    return "unknown"


def count_components(data: dict, fmt: str) -> int:
    if "CycloneDX" in fmt:
        return len(data.get("components", []))
    if "SPDX" in fmt:
        pkgs = data.get("packages", [])
        # SPDX root package is always present; real components = len - 1
        return max(0, len(pkgs) - 1)
    return 0


def passes_filters(fpath: str):
    """
    Returns (True, fmt, tool, n_components) or (False, reason, '', 0).
    """
    # 1. size gate — skip tiny files fast
    if os.path.getsize(fpath) < 1024:
        return False, "too_small", "", 0

    # 2. read and detect format
    try:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return False, "read_error", "", 0

    fmt = detect_format(content[:2000])
    if fmt is None:
        return False, "unknown_format", "", 0

    # 3. parse JSON (XML handling minimal — accept but don't deep-parse)
    if "XML" in fmt:
        # Accept CycloneDX-XML if it parses; tool extraction skipped
        return True, fmt, "unknown", 99   # treat as passing component count

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return False, "json_parse_error", "", 0

    # 4. component count gate
    n = count_components(data, fmt)
    if n < MIN_COMPONENTS:
        return False, "too_few_components", "", 0

    # 5. tool provenance
    if "CycloneDX" in fmt:
        tool = extract_tool_cdx(data)
    else:
        tool = extract_tool_spdx(data)

    return True, fmt, tool, n


# ── main ─────────────────────────────────────────────────────────────────────

def run_filter():
    print("Collecting file list...")
    all_files = collect_all_files()
    random.shuffle(all_files)   # shuffle so sample is representative
    print(f"Total files: {len(all_files)}")

    passed   = []   # list of (fpath, fmt, tool, n_components)
    rejected = {}   # reason → count

    print("Filtering...")
    for fpath in tqdm(all_files):
        ok, fmt_or_reason, tool, n = passes_filters(fpath)
        if ok:
            passed.append((fpath, fmt_or_reason, tool, n))
        else:
            rejected[fmt_or_reason] = rejected.get(fmt_or_reason, 0) + 1

        # stop early once we have enough candidates
        if len(passed) >= TARGET * 3:
            print(f"\nEarly stop — found {len(passed)} candidates.")
            break

    print(f"\nPassed filters : {len(passed)}")
    print(f"Rejection breakdown:")
    for reason, count in sorted(rejected.items(), key=lambda x: -x[1]):
        print(f"  {reason:25s}: {count}")

    # sample down to TARGET
    selected = passed[:TARGET] if len(passed) >= TARGET else passed
    print(f"\nSelecting {len(selected)} files for corpus.")

    # copy to filtered/ and write manifest
    manifest_path = os.path.join(OUT_DIR, "manifest.csv")
    with open(manifest_path, "w", encoding="utf-8") as mf:
        mf.write("filename,format,tool,n_components,source_path\n")
        for fpath, fmt, tool, n in tqdm(selected, desc="Copying"):
            fname = os.path.basename(fpath)
            dest  = os.path.join(OUT_DIR, fname)
            shutil.copy2(fpath, dest)
            mf.write(f"{fname},{fmt},{tool},{n},{fpath}\n")

    print(f"\nDone. Corpus in : {OUT_DIR}")
    print(f"Manifest written: {manifest_path}")

    # format / tool summary
    from collections import Counter
    fmt_counts  = Counter(fmt  for _, fmt,  _, _ in selected)
    tool_counts = Counter(tool for _, _, tool, _ in selected)

    print("\nCorpus format breakdown:")
    for fmt, c in fmt_counts.most_common():
        print(f"  {fmt:20s}: {c} ({c/len(selected)*100:.1f}%)")

    print("\nCorpus tool breakdown:")
    for tool, c in tool_counts.most_common(10):
        print(f"  {tool:20s}: {c} ({c/len(selected)*100:.1f}%)")


if __name__ == "__main__":
    run_filter()
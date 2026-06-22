"""
Runs Tier C checks across the filtered corpus.
Appends C1 and C2 columns to a new CSV.
"""

import os, csv, sys
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(__file__))
from parser import parse_file
from checks_c import run_all

FILTERED = r"C:\Users\hkana\Downloads\sbom-cra-research\data\filtered"
TIER_A   = r"C:\Users\hkana\Downloads\sbom-cra-research\results\tier_a_results.csv"
OUT_CSV  = r"C:\Users\hkana\Downloads\sbom-cra-research\results\tier_c_results.csv"

CHECK_IDS = ["C1", "C2"]

def check_cols():
    cols = []
    for cid in CHECK_IDS:
        cols += [f"{cid}_result", f"{cid}_score", f"{cid}_detail"]
    return cols

def run():
    # load existing Tier A rows for metadata
    with open(TIER_A, newline="", encoding="utf-8") as f:
        tier_a_rows = {r["filename"]: r for r in csv.DictReader(f)}

    files = [
        f for f in os.listdir(FILTERED)
        if f != "manifest.csv" and os.path.isfile(os.path.join(FILTERED, f))
    ]

    all_cols = ["filename", "format", "tool", "n_components"] + check_cols()

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=all_cols)
        writer.writeheader()

        for fname in tqdm(files, desc="Tier C"):
            fpath = os.path.join(FILTERED, fname)
            row = {col: "" for col in all_cols}

            meta = tier_a_rows.get(fname, {})
            row["filename"]     = fname
            row["format"]       = meta.get("format", "")
            row["tool"]         = meta.get("tool", "")
            row["n_components"] = meta.get("n_components", "")

            sbom = parse_file(fpath)
            if sbom is None:
                continue

            results = run_all(sbom)
            for r in results:
                cid = r["check_id"]
                row[f"{cid}_result"] = r["result"]
                row[f"{cid}_score"]  = r["score"]
                row[f"{cid}_detail"] = r["detail"]

            writer.writerow(row)

    # summary
    print("\nTier C pass rates:")
    import pandas as pd
    df = pd.read_csv(OUT_CSV)
    for cid in CHECK_IDS:
        col = f"{cid}_result"
        total  = len(df[df[col] != ""])
        passed = len(df[df[col] == "PASS"])
        pct    = passed / total * 100 if total else 0
        print(f"  {cid}: {passed}/{total} PASS ({pct:.1f}%)")

if __name__ == "__main__":
    run()
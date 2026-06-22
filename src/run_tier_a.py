"""
Orchestrator — Tier A only.
Runs all 13 Tier A checks across the filtered corpus.
Writes one row per file to results/tier_a_results.csv
"""

import os
import csv
import json
from tqdm import tqdm
import sys

# make sure src/ imports work
sys.path.insert(0, os.path.dirname(__file__))

from parser import parse_file
from checks_a import run_all

FILTERED  = r"C:\Users\hkana\Downloads\sbom-cra-research\data\filtered"
MANIFEST  = os.path.join(FILTERED, "manifest.csv")
OUT_CSV   = r"C:\Users\hkana\Downloads\sbom-cra-research\results\tier_a_results.csv"

os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)

# ── load manifest so we have tool + format metadata ───────────────────────────

def load_manifest():
    index = {}
    with open(MANIFEST, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            index[row["filename"]] = row
    return index

# ── CSV columns ───────────────────────────────────────────────────────────────

META_COLS = ["filename", "format", "tool", "n_components"]

CHECK_IDS = [
    "A1","A2","A3","A4","A5","A6","A7",
    "A8","A9","A10","A11","A12","A13"
]

# For each check we write three columns: result, score, detail
def check_cols():
    cols = []
    for cid in CHECK_IDS:
        cols += [f"{cid}_result", f"{cid}_score", f"{cid}_detail"]
    return cols

ALL_COLS = META_COLS + check_cols() + ["parse_error"]

# ── main ──────────────────────────────────────────────────────────────────────

def run():
    manifest = load_manifest()

    files = [
        f for f in os.listdir(FILTERED)
        if f != "manifest.csv" and os.path.isfile(os.path.join(FILTERED, f))
    ]

    print(f"Files to process : {len(files)}")
    print(f"Output           : {OUT_CSV}\n")

    parsed_ok  = 0
    parse_fail = 0

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=ALL_COLS)
        writer.writeheader()

        for fname in tqdm(files, desc="Tier A"):
            fpath = os.path.join(FILTERED, fname)
            row   = {col: "" for col in ALL_COLS}

            # metadata from manifest
            meta = manifest.get(fname, {})
            row["filename"]     = fname
            row["format"]       = meta.get("format", "")
            row["tool"]         = meta.get("tool", "")
            row["n_components"] = meta.get("n_components", "")

            # parse
            sbom = parse_file(fpath)
            if sbom is None:
                row["parse_error"] = "FAILED"
                parse_fail += 1
                writer.writerow(row)
                continue

            parsed_ok += 1
            row["parse_error"] = ""

            # run all 13 checks
            results = run_all(sbom)
            for r in results:
                cid = r["check_id"]
                row[f"{cid}_result"] = r["result"]
                row[f"{cid}_score"]  = r["score"]
                row[f"{cid}_detail"] = r["detail"]

            writer.writerow(row)

    print(f"\nDone.")
    print(f"  Parsed OK  : {parsed_ok}")
    print(f"  Parse fail : {parse_fail}")
    print(f"  Output     : {OUT_CSV}")

    # quick summary to screen
    print("\nQuick pass-rate preview:")
    import pandas as pd
    df = pd.read_csv(OUT_CSV)
    for cid in CHECK_IDS:
        col = f"{cid}_result"
        if col in df.columns:
            total = len(df[df[col] != ""])
            passed = len(df[df[col] == "PASS"])
            pct = (passed / total * 100) if total else 0
            print(f"  {cid:4s}: {passed:5d}/{total:5d} PASS ({pct:5.1f}%)")

if __name__ == "__main__":
    run()
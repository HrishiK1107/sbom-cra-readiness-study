"""
Merge Tier A, B, C results into one master CSV.
One row per SBOM file, 19 checks worth of columns plus metadata.

Run this LAST, after all three tiers are complete.
"""

import csv
import os

# ── EDIT THESE PATHS to match your machine ────────────────────────────────────
RESULTS_DIR = r"C:\Users\hkana\Downloads\sbom-cra-research\results"

TIER_A_CSV = os.path.join(RESULTS_DIR, "tier_a_results.csv")
TIER_B_CSV = os.path.join(RESULTS_DIR, "tier_b_results_full.csv")
TIER_C_CSV = os.path.join(RESULTS_DIR, "tier_c_results.csv")
OUT_CSV    = os.path.join(RESULTS_DIR, "master_results.csv")

ALL_CHECK_IDS = [
    "A1","A2","A3","A4","A5","A6","A7","A8","A9","A10","A11","A12","A13",
    "B1","B2","B3","B4",
    "C1","C2"
]

META_COLS = ["filename", "format", "tool", "n_components"]


def check_cols(prefix_list):
    cols = []
    for cid in prefix_list:
        cols += [f"{cid}_result", f"{cid}_score", f"{cid}_detail"]
    return cols


def load_csv_indexed(path):
    with open(path, newline="", encoding="utf-8") as f:
        return {r["filename"]: r for r in csv.DictReader(f)}


def run():
    print("Loading Tier A...")
    tier_a = load_csv_indexed(TIER_A_CSV)
    print(f"  {len(tier_a)} rows")

    print("Loading Tier B...")
    tier_b = load_csv_indexed(TIER_B_CSV)
    print(f"  {len(tier_b)} rows")

    print("Loading Tier C...")
    tier_c = load_csv_indexed(TIER_C_CSV)
    print(f"  {len(tier_c)} rows")

    # use Tier A as the master file list (it's the most complete / authoritative)
    filenames = list(tier_a.keys())
    print(f"\nMaster file count: {len(filenames)}")

    all_cols = META_COLS + check_cols(ALL_CHECK_IDS) + ["parse_error"]

    matched_b = 0
    matched_c = 0

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=all_cols)
        writer.writeheader()

        for fname in filenames:
            a_row = tier_a.get(fname, {})
            b_row = tier_b.get(fname, {})
            c_row = tier_c.get(fname, {})

            if b_row and any(b_row.get(f"{c}_result","").strip() for c in ["B1","B2","B3","B4"]):
                matched_b += 1
            if c_row and any(c_row.get(f"{c}_result","").strip() for c in ["C1","C2"]):
                matched_c += 1

            row = {col: "" for col in all_cols}

            # metadata from Tier A
            row["filename"]     = fname
            row["format"]       = a_row.get("format", "")
            row["tool"]         = a_row.get("tool", "")
            row["n_components"] = a_row.get("n_components", "")
            row["parse_error"]  = a_row.get("parse_error", "")

            # Tier A checks
            for cid in ["A1","A2","A3","A4","A5","A6","A7","A8","A9","A10","A11","A12","A13"]:
                row[f"{cid}_result"] = a_row.get(f"{cid}_result", "")
                row[f"{cid}_score"]  = a_row.get(f"{cid}_score", "")
                row[f"{cid}_detail"] = a_row.get(f"{cid}_detail", "")

            # Tier B checks
            for cid in ["B1","B2","B3","B4"]:
                row[f"{cid}_result"] = b_row.get(f"{cid}_result", "")
                row[f"{cid}_score"]  = b_row.get(f"{cid}_score", "")
                row[f"{cid}_detail"] = b_row.get(f"{cid}_detail", "")

            # Tier C checks
            for cid in ["C1","C2"]:
                row[f"{cid}_result"] = c_row.get(f"{cid}_result", "")
                row[f"{cid}_score"]  = c_row.get(f"{cid}_score", "")
                row[f"{cid}_detail"] = c_row.get(f"{cid}_detail", "")

            writer.writerow(row)

    print(f"\nMatched with Tier B data: {matched_b}")
    print(f"Matched with Tier C data: {matched_c}")
    print(f"\nMaster CSV written: {OUT_CSV}")

    # ── final summary across all 19 checks ──────────────────────────────────
    import pandas as pd
    df = pd.read_csv(OUT_CSV)

    print("\n" + "="*60)
    print("FINAL PASS RATES — ALL 19 CHECKS")
    print("="*60)

    for cid in ALL_CHECK_IDS:
        col = f"{cid}_result"
        total_scored = len(df[df[col].isin(["PASS","PARTIAL","FAIL"])])
        passed = len(df[df[col] == "PASS"])
        skipped = len(df[df[col] == "SKIP"])
        pct = (passed / total_scored * 100) if total_scored else 0
        print(f"  {cid:4s}: {passed:5d}/{total_scored:5d} PASS ({pct:5.1f}%)  [{skipped} SKIP]")


if __name__ == "__main__":
    run()
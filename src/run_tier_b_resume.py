"""
Tier B orchestrator — RESUME version.
Skips files already present in the existing partial results CSV.
Appends new results to a combined output file.
"""

import os, csv, sys
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(__file__))
from parser import parse_file
from checks_b import run_all

FILTERED   = r"C:\Users\hkana\Downloads\sbom-cra-research\data\filtered"
TIER_A     = r"C:\Users\hkana\Downloads\sbom-cra-research\results\tier_a_results.csv"
EXISTING   = r"C:\Users\hkana\Downloads\sbom-cra-research\results\tier_b_results_partial.csv"
OUT_CSV    = r"C:\Users\hkana\Downloads\sbom-cra-research\results\tier_b_results_full.csv"

CHECK_IDS = ["B1", "B2", "B3", "B4"]

def check_cols():
    cols = []
    for cid in CHECK_IDS:
        cols += [f"{cid}_result", f"{cid}_score", f"{cid}_detail"]
    return cols

ALL_COLS = ["filename", "format", "tool", "n_components"] + check_cols()


def run():
    # load Tier A metadata
    with open(TIER_A, newline="", encoding="utf-8") as f:
        tier_a = {r["filename"]: r for r in csv.DictReader(f)}

    # load already-processed files
    already_done = {}
    if os.path.exists(EXISTING):
        with open(EXISTING, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                # only count as done if it has actual B-check data
                if r.get("B1_result","").strip() or r.get("B2_result","").strip() \
                   or r.get("B3_result","").strip() or r.get("B4_result","").strip():
                    already_done[r["filename"]] = r

    print(f"Already processed: {len(already_done)}")

    all_files = [
        f for f in os.listdir(FILTERED)
        if f != "manifest.csv" and os.path.isfile(os.path.join(FILTERED, f))
    ]

    remaining = [f for f in all_files if f not in already_done]
    print(f"Remaining to process: {len(remaining)}")
    print(f"Output: {OUT_CSV}\n")

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=ALL_COLS)
        writer.writeheader()

        # first, write out the already-done rows unchanged
        for fname, r in already_done.items():
            row = {col: r.get(col, "") for col in ALL_COLS}
            writer.writerow(row)
        out.flush()

        # now process remaining files
        for fname in tqdm(remaining, desc="Tier B (resume)"):
            fpath = os.path.join(FILTERED, fname)
            row   = {col: "" for col in ALL_COLS}

            meta = tier_a.get(fname, {})
            row["filename"]     = fname
            row["format"]       = meta.get("format", "")
            row["tool"]         = meta.get("tool", "")
            row["n_components"] = meta.get("n_components", "")

            sbom = parse_file(fpath)
            if sbom is None:
                writer.writerow(row)
                continue

            results = run_all(sbom)
            for r in results:
                cid = r["check_id"]
                row[f"{cid}_result"] = r["result"]
                row[f"{cid}_score"]  = r["score"]
                row[f"{cid}_detail"] = r["detail"]

            writer.writerow(row)
            out.flush()

    print(f"\nDone. Output: {OUT_CSV}")

    import pandas as pd
    df = pd.read_csv(OUT_CSV)
    print(f"Total rows: {len(df)}")

    print("\nTier B pass rates (excluding SKIP):")
    for cid in CHECK_IDS:
        col    = f"{cid}_result"
        active = df[df[col].isin(["PASS","PARTIAL","FAIL"])]
        passed = len(active[active[col] == "PASS"])
        total  = len(active)
        skips  = len(df[df[col] == "SKIP"])
        pct    = passed / total * 100 if total else 0
        print(f"  {cid}: {passed}/{total} PASS ({pct:.1f}%) — {skips} SKIPped")


if __name__ == "__main__":
    run()
"""
Tier B orchestrator — API-validated checks.
Runs selectively: only processes files where relevant data exists.
Writes results to results/tier_b_results.csv
Expected runtime: 2-6 hours depending on API response times.
Run overnight.
"""

import os, csv, sys
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(__file__))
from parser import parse_file
from checks_b import run_all

FILTERED = r"C:\Users\hkana\Downloads\sbom-cra-research\data\filtered"
TIER_A   = r"C:\Users\hkana\Downloads\sbom-cra-research\results\tier_a_results.csv"
OUT_CSV  = r"C:\Users\hkana\Downloads\sbom-cra-research\results\tier_b_results.csv"

CHECK_IDS = ["B1", "B2", "B3", "B4"]

def check_cols():
    cols = []
    for cid in CHECK_IDS:
        cols += [f"{cid}_result", f"{cid}_score", f"{cid}_detail"]
    return cols

ALL_COLS = ["filename", "format", "tool", "n_components"] + check_cols()


def run():
    # load Tier A to get metadata and know which files have relevant data
    with open(TIER_A, newline="", encoding="utf-8") as f:
        tier_a = {r["filename"]: r for r in csv.DictReader(f)}

    files = [
        f for f in os.listdir(FILTERED)
        if f != "manifest.csv" and os.path.isfile(os.path.join(FILTERED, f))
    ]

    print(f"Total files     : {len(files)}")
    print(f"Output          : {OUT_CSV}")
    print(f"Rate delay      : 0.5s per API call")
    print(f"Starting...\n")

    processed = 0
    skipped   = 0

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=ALL_COLS)
        writer.writeheader()

        for fname in tqdm(files, desc="Tier B"):
            fpath = os.path.join(FILTERED, fname)
            row   = {col: "" for col in ALL_COLS}

            meta = tier_a.get(fname, {})
            row["filename"]     = fname
            row["format"]       = meta.get("format", "")
            row["tool"]         = meta.get("tool", "")
            row["n_components"] = meta.get("n_components", "")

            sbom = parse_file(fpath)
            if sbom is None:
                skipped += 1
                writer.writerow(row)
                continue

            processed += 1
            results = run_all(sbom)

            for r in results:
                cid = r["check_id"]
                row[f"{cid}_result"] = r["result"]
                row[f"{cid}_score"]  = r["score"]
                row[f"{cid}_detail"] = r["detail"]

            writer.writerow(row)

            # flush every 100 files so progress is saved if interrupted
            if processed % 100 == 0:
                out.flush()

    print(f"\nDone.")
    print(f"  Processed : {processed}")
    print(f"  Skipped   : {skipped}")

    import pandas as pd
    df = pd.read_csv(OUT_CSV)

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
import os, json
from parser import parse_file
from checks_a import run_all

# Point to your filtered folder
FILTERED = r"C:\Users\hkana\Downloads\sbom-cra-research\data\filtered"

files = [f for f in os.listdir(FILTERED) if f != "manifest.csv"][:5]

for fname in files:
    fpath = os.path.join(FILTERED, fname)
    sbom  = parse_file(fpath)
    if sbom is None:
        print(f"PARSE FAILED: {fname}")
        continue

    results = run_all(sbom)
    print("="*60)
    print(f"File   : {fname}")
    print(f"Format : {sbom['_format']} {sbom['_format_version']}")
    print(f"Tool   : {sbom['_tool']}")
    print(f"Components: {len(sbom['components'])}")
    print("-"*60)
    for r in results:
        print(f"  {r['check_id']:4s} {r['result']:8s} {r['score']:.2f}  {r['detail']}")
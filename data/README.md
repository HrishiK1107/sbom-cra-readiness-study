# Data Directory

## What's Here

| File | Description |
|---|---|
| `manifest.csv` | The 5,000-file corpus manifest: filename, SBOM format (SPDX/CycloneDX), detected tool, and component count (`n_components`) for each file in the study |

## What's NOT Here (and Why)

The raw SBOM files (~5 GB, 5,000 files) are **not included** in this repository. They are part of the **Wild SBOMs dataset** published by Soeiro et al. (MSR 2025), which is already publicly available. We do not redistribute their data.

Original dataset: https://github.com/chains-project/sbom-files  
Citation: Soeiro et al., "The Wild SBOMs Dataset," MSR 2025.

## How to Regenerate the Corpus

1. Clone or download the Wild SBOMs dataset from the link above (~78,612 SBOM files from 1,782 code-hosting forges via the Software Heritage Archive).

2. Run the sampling script from the repo root:

```bash
python src/filter.py --input /path/to/wild-sboms/ --output /path/to/corpus/ --n 5000
```

This will produce a local directory of 5,000 SBOMs drawn from the archive using `random.shuffle()`.

**Important:** `filter.py` does not set a random seed, so your exact 5,000-file sample will differ from ours. The `manifest.csv` in this directory records the exact filenames used in the original study. If you want to reproduce our exact results rather than an equivalent study, download the files listed in `manifest.csv` directly from the Wild SBOMs archive.

## manifest.csv Schema

| Column | Description |
|---|---|
| `filename` | Original filename in the Wild SBOMs archive |
| `format` | SBOM format: `spdx-json`, `spdx-tv`, `cdx-json`, `cdx-xml`, etc. |
| `tool` | Detected generator tool (e.g., `cdxgen`, `syft`, `Node.js module` artifact — see §4.1 of the paper) |
| `n_components` | Number of components parsed (note: CycloneDX-XML files received hardcoded value of 99 — see §4.1) |

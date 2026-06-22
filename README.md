# Are Real-World SBOMs Ready for the EU Cyber Resilience Act?

**A Large-Scale Empirical Study of CRA Annex I Compliance Across 5,000 Software Bills of Materials**

> Hrishikesh Kanapuram (2026)  
> Symbiosis Skills and Professional University, India

---

## Overview

This repository contains all implementation code, merged results, and the corpus manifest for the paper:

> *"Are Real-World SBOMs Ready for the EU Cyber Resilience Act? A Large-Scale Empirical Study of CRA Annex I Compliance Across 5,000 Software Bills of Materials"*

We evaluated 5,000 SBOMs drawn from the [Wild SBOMs dataset](https://github.com/chains-project/sbom-files) (Soeiro et al., MSR 2025) against a 19-check taxonomy spanning NTIA-equivalent requirements, CRA Annex I provisions, general SBOM quality, and conditional vulnerability checks.

### Headline Findings

| Group | Mean Pass Rate |
|---|---|
| NTIA-equivalent (9 checks) | 77.0% (median 90.7%) |
| CRA-specific (4 checks) | **4.9%** (median 4.4%) |
| **Gap** | **72.2 percentage points** |
| General SBOM quality (3 checks) | 20.7% |

The gap is statistically significant (Wilcoxon signed-rank W=0, p<0.001, n=4,999). The full sensitivity range across all exclusion scenarios is 65.6–72.2 pp.

---

## Repository Structure

```
sbom-cra-readiness-study/
├── README.md
├── LICENSE
├── CITATION.cff
├── requirements.txt
│
├── data/
│   ├── manifest.csv          ← 5,000 filenames + format + tool + n_components
│   └── README.md             ← how to regenerate the corpus from Wild SBOMs
│
├── src/
│   ├── filter.py             ← samples 5,000 SBOMs from the archive
│   ├── parser.py             ← shared SBOM parsing utilities
│   ├── checks_a.py           ← Tier A checks (A1–A13), field-presence, no external APIs
│   ├── checks_b.py           ← Tier B checks (B1–B4), requires internet
│   ├── checks_c.py           ← Tier C checks (C1, C2), structural heuristics
│   ├── run_tier_a.py         ← runner for Tier A
│   ├── run_tier_b.py         ← runner for Tier B
│   ├── run_tier_b_resume.py  ← resume runner (Tier B was interrupted and resumed)
│   ├── run_tier_c.py         ← runner for Tier C
│   ├── merge_results.py      ← merges tier outputs into master_results.csv
│   ├── explore.py            ← exploratory analysis utilities
│   └── test_parser.py        ← parser unit tests
│
├── notebooks/
│   └── analysis.ipynb        ← full analysis notebook (all statistics and figures)
│
├── results/
│   ├── master_results.csv         ← main dataset: 5,000 rows × 19 checks
│   ├── tier_b_results_full.csv    ← complete Tier B output (authoritative)
│   ├── wilson_cis.csv             ← Wilson 95% CIs for all 19 checks
│   ├── sensitivity_extended.csv   ← 5-row sensitivity analysis table
│   ├── tool_check_matrix.csv      ← Table 3 data
│   ├── format_check_matrix.csv    ← Table 4 data
│   ├── check_ranking_bar_v2.png   ← Figure 1 (4-colour scheme)
│   └── failure_heatmap.png        ← supplementary heatmap
│
└── paper/
    ├── main.tex
    ├── main.bbl
    ├── references.bib
    ├── table1_related_work.tex
    └── figure1_check_pass_rates.pdf
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Obtain the SBOM corpus

The raw SBOM files (~5 GB) are not included. See [`data/README.md`](data/README.md) for how to regenerate an equivalent corpus from the Wild SBOMs dataset using `src/filter.py`.

### 3. Run the checks

```bash
# Tier A — fast, no internet needed
python src/run_tier_a.py

# Tier B — requires internet (OSV.dev, endoflife.date, npm/PyPI/Maven/Go registries, SPDX)
python src/run_tier_b.py
# If interrupted, resume with:
python src/run_tier_b_resume.py

# Tier C — fast, no internet needed
python src/run_tier_c.py

# Merge all tier outputs into master_results.csv
python src/merge_results.py
```

### 4. Reproduce the analysis

Open `notebooks/analysis.ipynb` and run all cells. All statistics and figures in the paper are generated here.

---

## Implementation Notes

- **No random seed:** `filter.py` uses `random.shuffle()` without a fixed seed. The exact 5,000-file sample is not reproducible, but the procedure is identical. An equivalent corpus from the same source will yield statistically comparable results.
- **Tier B sampling caps:** B1 caps at 20 vulnerability entries per SBOM; B2/B4 cap at 30 components; B3 caps at 15 PURLs. See §4.6 of the paper.
- **Tier B query dates:** APIs were queried 13–14 June 2026. Results reflect vulnerability and EOL data as of that date.
- **CycloneDX-XML:** 315 XML files (6.3% of corpus) received hardcoded `n_components=99` and `tool="unknown"` due to parser limitations. See §4.1 and §7.
- **Node.js module artifact:** 917 files (18.3%) show "Node.js module" as tool — this is a parsing artifact from CycloneDX metadata self-declaration, not the actual generator. See §4.1.

---

## External APIs Used (Tier B)

All APIs are free, public, and require no authentication:

| Check | API |
|---|---|
| B1 (vulnerability presence) | [OSV.dev](https://osv.dev) |
| B2 (EOL status) | [endoflife.date](https://endoflife.date) |
| B3 (registry presence) | npm / PyPI / Maven Central / Go proxy |
| B4 (licence validity) | [SPDX licence list](https://spdx.org/licenses/) |

---

## Citation

If you use this code or data, please cite:

```bibtex
@misc{kanapuram2026sbom,
  author    = {Kanapuram, Hrishikesh},
  title     = {Are Real-World SBOMs Ready for the {EU} Cyber Resilience Act?
               A Large-Scale Empirical Study of {CRA} Annex {I} Compliance
               Across 5,000 Software Bills of Materials},
  year      = {2026},
  url       = {https://github.com/HrishiK1107/sbom-cra-readiness-study}
}
```

---

## License

Code: [MIT License](LICENSE)  
Data (`results/master_results.csv`, `data/manifest.csv`): [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)  
The underlying SBOM corpus belongs to Soeiro et al. and is governed by their dataset licence.

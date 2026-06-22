"""
Tier B — 4 cross-reference validated checks.
Requires network access. Rate-limited to avoid API abuse.

B1: Declared CVE IDs are real and current (OSV.dev)
B2: Component versions not end-of-life (endoflife.date)
B3: PURL resolves to real package (ecosystem registries)
B4: License identifiers valid SPDX (SPDX license list)
"""

import time
import requests

# single shared session for connection reuse
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "sbom-cra-research/1.0 (academic)"})

RATE_DELAY = 0.5   # seconds between API calls — adjust if you hit rate limits


def _get(url: str, timeout: int = 10) -> requests.Response | None:
    try:
        time.sleep(RATE_DELAY)
        r = _SESSION.get(url, timeout=timeout)
        return r
    except requests.RequestException:
        return None


# ── B1 — CVE validation via OSV.dev ──────────────────────────────────────────

def check_b1(sbom: dict) -> dict:
    vulns = sbom.get("vulnerabilities", [])
    if not vulns:
        return {
            "check_id":   "B1",
            "check_name": "Declared CVEs valid (OSV.dev)",
            "result":     "SKIP",
            "score":      0.0,
            "detail":     "No vulnerabilities declared — A8 failed"
        }

    total   = 0
    valid   = 0
    invalid = []

    for v in vulns[:20]:   # cap at 20 per SBOM to control runtime
        vid = v.get("id", "").strip()
        if not vid:
            continue
        total += 1

        r = _get(f"https://api.osv.dev/v1/vulns/{vid}")
        if r is not None and r.status_code == 200:
            valid += 1
        else:
            invalid.append(vid)

    if total == 0:
        return {
            "check_id":   "B1",
            "check_name": "Declared CVEs valid (OSV.dev)",
            "result":     "SKIP",
            "score":      0.0,
            "detail":     "Vulnerability entries present but no IDs extractable"
        }

    score = valid / total
    result = "PASS" if score == 1.0 else ("PARTIAL" if score > 0 else "FAIL")
    return {
        "check_id":   "B1",
        "check_name": "Declared CVEs valid (OSV.dev)",
        "result":     result,
        "score":      round(score, 3),
        "detail":     f"{valid}/{total} CVE IDs confirmed via OSV.dev"
                      + (f"; invalid: {', '.join(invalid[:3])}" if invalid else "")
    }


# ── B2 — End-of-life check via endoflife.date ─────────────────────────────────

EOL_ECOSYSTEM_MAP = {
    "npm":    "nodejs",
    "pypi":   "python",
    "maven":  "java",
    "golang": "go",
    "cargo":  "rust",
}

def _major_version(version: str) -> str:
    """Extract major version number e.g. '3.11.2' → '3.11'"""
    parts = version.lstrip("v").split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return parts[0] if parts else ""

def check_b2(sbom: dict) -> dict:
    components = sbom.get("components", [])
    checked  = 0
    eol      = 0
    supported = 0
    unknown  = 0

    for c in components[:30]:   # cap at 30 per SBOM
        purl = c.get("purl", "")
        if not purl.startswith("pkg:"):
            continue

        parts = purl[4:].split("/")
        ecosystem = parts[0].lower()
        product   = EOL_ECOSYSTEM_MAP.get(ecosystem)
        if not product:
            continue

        version = c.get("version", "")
        if not version:
            continue

        mv = _major_version(version)
        if not mv:
            continue

        checked += 1
        r = _get(f"https://endoflife.date/api/{product}/{mv}.json")
        if r is None or r.status_code != 200:
            unknown += 1
            continue

        try:
            data = r.json()
            eol_val = data.get("eol", False)
            if eol_val is True or (isinstance(eol_val, str) and eol_val < "2026-06-13"):
                eol += 1
            else:
                supported += 1
        except Exception:
            unknown += 1

    if checked == 0:
        return {
            "check_id":   "B2",
            "check_name": "Component versions not end-of-life",
            "result":     "SKIP",
            "score":      0.0,
            "detail":     "No components with mappable ecosystem/version"
        }

    scoreable = supported + eol
    score = supported / scoreable if scoreable else 0.0
    result = "PASS" if score == 1.0 else ("PARTIAL" if score > 0 else "FAIL")
    return {
        "check_id":   "B2",
        "check_name": "Component versions not end-of-life",
        "result":     result,
        "score":      round(score, 3),
        "detail":     f"{supported} supported, {eol} EOL, {unknown} unknown (of {checked} checked)"
    }


# ── B3 — PURL resolution ──────────────────────────────────────────────────────

def _resolve_purl(purl: str) -> bool:
    if not purl.startswith("pkg:"):
        return False

    rest      = purl[4:]
    ecosystem = rest.split("/")[0].lower()

    try:
        if ecosystem == "npm":
            pkg = rest.split("/", 1)[1].split("@")[0]
            r   = _get(f"https://registry.npmjs.org/{pkg}")
            return r is not None and r.status_code == 200

        elif ecosystem == "pypi":
            pkg = rest.split("/", 1)[1].split("@")[0]
            r   = _get(f"https://pypi.org/pypi/{pkg}/json")
            return r is not None and r.status_code == 200

        elif ecosystem == "maven":
            # pkg:maven/group/artifact@version
            path  = rest.split("/", 1)[1]
            parts = path.split("/")
            if len(parts) < 2:
                return False
            group    = parts[0].replace(".", "/")
            artifact = parts[1].split("@")[0]
            r = _get(
                f"https://search.maven.org/solrsearch/select"
                f"?q=g:{parts[0]}+AND+a:{artifact}&rows=1&wt=json"
            )
            return r is not None and r.status_code == 200

        elif ecosystem == "golang":
            pkg = rest.split("/", 1)[1].split("@")[0]
            r   = _get(f"https://pkg.go.dev/{pkg}")
            return r is not None and r.status_code == 200

    except Exception:
        return False

    return False   # unsupported ecosystem


def check_b3(sbom: dict) -> dict:
    components = sbom.get("components", [])
    purls = [
        c.get("purl", "") for c in components
        if c.get("purl", "").startswith("pkg:")
    ]

    if not purls:
        return {
            "check_id":   "B3",
            "check_name": "PURL resolves to real package",
            "result":     "SKIP",
            "score":      0.0,
            "detail":     "No PURLs found in SBOM"
        }

    sample  = purls[:15]   # cap at 15 per SBOM
    total   = len(sample)
    resolved = sum(1 for p in sample if _resolve_purl(p))

    score  = resolved / total
    result = "PASS" if score == 1.0 else ("PARTIAL" if score > 0 else "FAIL")
    return {
        "check_id":   "B3",
        "check_name": "PURL resolves to real package",
        "result":     result,
        "score":      round(score, 3),
        "detail":     f"{resolved}/{total} PURLs resolved successfully"
    }


# ── B4 — SPDX license identifier validation ───────────────────────────────────

_SPDX_LICENSE_CACHE: set[str] = set()

def _load_spdx_licenses() -> set[str]:
    global _SPDX_LICENSE_CACHE
    if _SPDX_LICENSE_CACHE:
        return _SPDX_LICENSE_CACHE

    r = _get("https://spdx.org/licenses/licenses.json")
    if r is None or r.status_code != 200:
        return set()

    try:
        data     = r.json()
        licenses = {lic["licenseId"] for lic in data.get("licenses", [])}
        _SPDX_LICENSE_CACHE = licenses
        return licenses
    except Exception:
        return set()


def _extract_license_ids(component: dict) -> list[str]:
    ids = []
    for lic in component.get("licenses", []):
        if isinstance(lic, dict):
            # CycloneDX: {"license": {"id": "MIT"}} or {"expression": "MIT"}
            inner = lic.get("license", {})
            if isinstance(inner, dict):
                lid = inner.get("id", "") or inner.get("name", "")
                if lid:
                    ids.append(lid)
            expr = lic.get("expression", "")
            if expr:
                ids.append(expr)
    return ids


def check_b4(sbom: dict) -> dict:
    valid_ids = _load_spdx_licenses()
    if not valid_ids:
        return {
            "check_id":   "B4",
            "check_name": "License identifiers valid SPDX",
            "result":     "SKIP",
            "score":      0.0,
            "detail":     "Could not load SPDX license list"
        }

    components  = sbom.get("components", [])
    with_license = [c for c in components if c.get("licenses")]

    if not with_license:
        return {
            "check_id":   "B4",
            "check_name": "License identifiers valid SPDX",
            "result":     "SKIP",
            "score":      0.0,
            "detail":     "No license data to validate — A11 failed"
        }

    total   = 0
    valid   = 0
    invalid = []

    for c in with_license[:30]:
        for lid in _extract_license_ids(c):
            total += 1
            # handle compound expressions like "MIT AND Apache-2.0"
            tokens = [
                t.strip() for t in lid.replace("(", "").replace(")", "")
                .replace(" AND ", "|").replace(" OR ", "|")
                .replace(" WITH ", "|").split("|")
                if t.strip() and t.strip() not in ("AND", "OR", "WITH")
            ]
            if all(t in valid_ids for t in tokens):
                valid += 1
            else:
                invalid.extend([t for t in tokens if t not in valid_ids])

    if total == 0:
        return {
            "check_id":   "B4",
            "check_name": "License identifiers valid SPDX",
            "result":     "SKIP",
            "score":      0.0,
            "detail":     "License fields present but no IDs extractable"
        }

    score  = valid / total
    result = "PASS" if score == 1.0 else ("PARTIAL" if score > 0 else "FAIL")
    return {
        "check_id":   "B4",
        "check_name": "License identifiers valid SPDX",
        "result":     result,
        "score":      round(score, 3),
        "detail":     f"{valid}/{total} license IDs are valid SPDX"
                      + (f"; invalid examples: {', '.join(set(invalid[:3]))}" if invalid else "")
    }


# ── run all 4 ─────────────────────────────────────────────────────────────────

ALL_CHECKS = [check_b1, check_b2, check_b3, check_b4]

def run_all(sbom: dict) -> list[dict]:
    return [fn(sbom) for fn in ALL_CHECKS]
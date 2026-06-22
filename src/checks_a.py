"""
Tier A — 13 directly verifiable CRA Annex I checks.
Pure static analysis. No network calls. No external APIs.

Each check function takes a normalized SBOM dict and returns:
{
    "check_id":   str,
    "check_name": str,
    "result":     "PASS" | "PARTIAL" | "FAIL" | "SKIP",
    "score":      float (0.0 – 1.0),
    "detail":     str
}
"""

# ── helpers ───────────────────────────────────────────────────────────────────

def _component_score(passing: int, total: int) -> tuple[float, str]:
    """Return (score, result) based on per-component pass ratio."""
    if total == 0:
        return 0.0, "SKIP"
    score = passing / total
    if score == 1.0:
        return 1.0, "PASS"
    elif score == 0.0:
        return 0.0, "FAIL"
    else:
        return round(score, 3), "PARTIAL"


VALID_HASH_ALGOS = {
    "SHA-256", "SHA-384", "SHA-512",
    "SHA256",  "SHA384",  "SHA512",
    "sha-256", "sha256"
}

KNOWN_FORMATS = {
    "CycloneDX-JSON", "CycloneDX-XML", "SPDX-JSON", "SPDX-XML"
}

KNOWN_VERSIONS = {
    "CycloneDX-JSON": {"1.3", "1.4", "1.5", "1.6"},
    "CycloneDX-XML":  {"1.3", "1.4", "1.5", "1.6"},
    "SPDX-JSON":      {"SPDX-2.2", "SPDX-2.3"},
    "SPDX-XML":       {"SPDX-2.2", "SPDX-2.3"},
}

CVE_PREFIXES = ("CVE-", "GHSA-", "OSV-", "SNYK-", "PYSEC-")


# ── A1 — Component name ───────────────────────────────────────────────────────

def check_a1(sbom: dict) -> dict:
    components = sbom.get("components", [])
    total = len(components)
    passing = sum(1 for c in components if c.get("name", "").strip())
    score, result = _component_score(passing, total)
    return {
        "check_id":   "A1",
        "check_name": "Component name present",
        "result":     result,
        "score":      score,
        "detail":     f"{passing}/{total} components have name"
    }


# ── A2 — Component version ────────────────────────────────────────────────────

def check_a2(sbom: dict) -> dict:
    components = sbom.get("components", [])
    total = len(components)
    passing = sum(1 for c in components if c.get("version", "").strip())
    score, result = _component_score(passing, total)
    return {
        "check_id":   "A2",
        "check_name": "Component version present",
        "result":     result,
        "score":      score,
        "detail":     f"{passing}/{total} components have version"
    }


# ── A3 — Supplier / originator ────────────────────────────────────────────────

def check_a3(sbom: dict) -> dict:
    components = sbom.get("components", [])
    total = len(components)

    def has_supplier(c):
        # CycloneDX: supplier or publisher field
        if c.get("supplier") or c.get("publisher") or c.get("author"):
            return True
        # SPDX: originator field
        if c.get("originator", "").strip() not in ("", "NOASSERTION"):
            return True
        return False

    passing = sum(1 for c in components if has_supplier(c))
    score, result = _component_score(passing, total)
    return {
        "check_id":   "A3",
        "check_name": "Supplier/originator present",
        "result":     result,
        "score":      score,
        "detail":     f"{passing}/{total} components have supplier"
    }


# ── A4 — Unique identifier (PURL or CPE) ──────────────────────────────────────

def check_a4(sbom: dict) -> dict:
    components = sbom.get("components", [])
    total = len(components)

    def has_uid(c):
        if c.get("purl", "").startswith("pkg:"):
            return True
        cpes = c.get("cpe", "")
        if isinstance(cpes, str) and cpes.startswith("cpe:"):
            return True
        if isinstance(cpes, list) and any(
                x.startswith("cpe:") for x in cpes):
            return True
        return False

    passing = sum(1 for c in components if has_uid(c))
    score, result = _component_score(passing, total)
    return {
        "check_id":   "A4",
        "check_name": "Unique identifier (PURL/CPE) present",
        "result":     result,
        "score":      score,
        "detail":     f"{passing}/{total} components have PURL or CPE"
    }


# ── A5 — Dependency relationships ─────────────────────────────────────────────

def check_a5(sbom: dict) -> dict:
    # CycloneDX: top-level "dependencies" array
    deps_cdx = sbom.get("dependencies", [])
    # SPDX: top-level "relationships" array
    deps_spdx = sbom.get("relationships", [])

    if deps_cdx:
        n = len(deps_cdx)
        return {
            "check_id":   "A5",
            "check_name": "Dependency relationships declared",
            "result":     "PASS",
            "score":      1.0,
            "detail":     f"CycloneDX dependencies array has {n} entries"
        }
    if deps_spdx:
        n = len(deps_spdx)
        return {
            "check_id":   "A5",
            "check_name": "Dependency relationships declared",
            "result":     "PASS",
            "score":      1.0,
            "detail":     f"SPDX relationships array has {n} entries"
        }
    return {
        "check_id":   "A5",
        "check_name": "Dependency relationships declared",
        "result":     "FAIL",
        "score":      0.0,
        "detail":     "No dependency or relationship data found"
    }


# ── A6 — SBOM author ──────────────────────────────────────────────────────────

def check_a6(sbom: dict) -> dict:
    # CycloneDX: metadata.authors or metadata.tools
    meta = sbom.get("metadata", {})
    authors = meta.get("authors", [])
    tools_raw = meta.get("tools", {})

    has_author = bool(authors)
    has_tool   = False

    if isinstance(tools_raw, dict):
        has_tool = bool(tools_raw.get("components", []))
    elif isinstance(tools_raw, list):
        has_tool = bool(tools_raw)

    # SPDX: creationInfo.creators
    creators = sbom.get("creationInfo", {}).get("creators", [])
    has_creator = any(c.startswith("Tool:") or
                      c.startswith("Organization:") for c in creators)

    if has_author or has_tool or has_creator:
        return {
            "check_id":   "A6",
            "check_name": "SBOM author declared",
            "result":     "PASS",
            "score":      1.0,
            "detail":     "Author/tool/creator field populated"
        }
    return {
        "check_id":   "A6",
        "check_name": "SBOM author declared",
        "result":     "FAIL",
        "score":      0.0,
        "detail":     "No author, tool, or creator field found"
    }


# ── A7 — SBOM timestamp ───────────────────────────────────────────────────────

import re
ISO8601_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
)

def check_a7(sbom: dict) -> dict:
    # CycloneDX
    ts = sbom.get("metadata", {}).get("timestamp", "")
    # SPDX
    if not ts:
        ts = sbom.get("creationInfo", {}).get("created", "")

    if ts and ISO8601_RE.match(ts):
        return {
            "check_id":   "A7",
            "check_name": "SBOM timestamp valid ISO 8601",
            "result":     "PASS",
            "score":      1.0,
            "detail":     f"Timestamp: {ts}"
        }
    if ts:
        return {
            "check_id":   "A7",
            "check_name": "SBOM timestamp valid ISO 8601",
            "result":     "PARTIAL",
            "score":      0.5,
            "detail":     f"Timestamp present but invalid format: {ts}"
        }
    return {
        "check_id":   "A7",
        "check_name": "SBOM timestamp valid ISO 8601",
        "result":     "FAIL",
        "score":      0.0,
        "detail":     "No timestamp found"
    }


# ── A8 — Known vulnerabilities declared ───────────────────────────────────────

def check_a8(sbom: dict) -> dict:
    # CycloneDX: top-level vulnerabilities array
    vulns_cdx = sbom.get("vulnerabilities", [])
    if vulns_cdx:
        return {
            "check_id":   "A8",
            "check_name": "Known vulnerabilities declared",
            "result":     "PASS",
            "score":      1.0,
            "detail":     f"{len(vulns_cdx)} vulnerability entries declared"
        }

    # SPDX: packages with externalRefs of type SECURITY
    packages = sbom.get("packages", [])
    sec_refs = 0
    for pkg in packages:
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceCategory", "") == "SECURITY":
                sec_refs += 1
    if sec_refs:
        return {
            "check_id":   "A8",
            "check_name": "Known vulnerabilities declared",
            "result":     "PASS",
            "score":      1.0,
            "detail":     f"{sec_refs} SECURITY externalRefs found"
        }

    return {
        "check_id":   "A8",
        "check_name": "Known vulnerabilities declared",
        "result":     "FAIL",
        "score":      0.0,
        "detail":     "No vulnerability data declared"
    }


# ── A9 — Vulnerability ID format valid ────────────────────────────────────────

def check_a9(sbom: dict) -> dict:
    vulns = sbom.get("vulnerabilities", [])
    if not vulns:
        return {
            "check_id":   "A9",
            "check_name": "Vulnerability ID format valid",
            "result":     "SKIP",
            "score":      0.0,
            "detail":     "No vulnerabilities section — A8 already failed"
        }

    total   = len(vulns)
    passing = 0
    for v in vulns:
        vid = v.get("id", "")
        if any(vid.startswith(p) for p in CVE_PREFIXES):
            passing += 1

    score, result = _component_score(passing, total)
    return {
        "check_id":   "A9",
        "check_name": "Vulnerability ID format valid",
        "result":     result,
        "score":      score,
        "detail":     f"{passing}/{total} vuln IDs match known prefixes"
    }


# ── A10 — Component integrity hash ────────────────────────────────────────────

def check_a10(sbom: dict) -> dict:
    components = sbom.get("components", [])
    total = len(components)

    def has_strong_hash(c):
        hashes = c.get("hashes", [])
        if isinstance(hashes, list):
            return any(
                h.get("alg", "") in VALID_HASH_ALGOS for h in hashes
            )
        if isinstance(hashes, dict):
            return any(k in VALID_HASH_ALGOS for k in hashes)
        # SPDX: checksums list
        checksums = c.get("checksums", [])
        return any(
            cs.get("algorithm", "") in VALID_HASH_ALGOS
            for cs in checksums
        )

    passing = sum(1 for c in components if has_strong_hash(c))
    score, result = _component_score(passing, total)
    return {
        "check_id":   "A10",
        "check_name": "Component integrity hash (SHA-256+)",
        "result":     result,
        "score":      score,
        "detail":     f"{passing}/{total} components have SHA-256+ hash"
    }


# ── A11 — License per component ───────────────────────────────────────────────

def check_a11(sbom: dict) -> dict:
    components = sbom.get("components", [])
    total = len(components)

    def has_license(c):
        # CycloneDX: licenses array
        lics = c.get("licenses", [])
        if lics:
            return True
        # SPDX style inside component
        if c.get("licenseConcluded", "").strip() not in ("", "NOASSERTION"):
            return True
        if c.get("licenseDeclared", "").strip() not in ("", "NOASSERTION"):
            return True
        return False

    passing = sum(1 for c in components if has_license(c))
    score, result = _component_score(passing, total)
    return {
        "check_id":   "A11",
        "check_name": "License expression per component",
        "result":     result,
        "score":      score,
        "detail":     f"{passing}/{total} components have license"
    }


# ── A12 — Recognised SBOM format ──────────────────────────────────────────────

def check_a12(sbom: dict) -> dict:
    fmt = sbom.get("_format", "")
    if fmt in KNOWN_FORMATS:
        return {
            "check_id":   "A12",
            "check_name": "Recognised SBOM format",
            "result":     "PASS",
            "score":      1.0,
            "detail":     f"Format: {fmt}"
        }
    return {
        "check_id":   "A12",
        "check_name": "Recognised SBOM format",
        "result":     "FAIL",
        "score":      0.0,
        "detail":     f"Unrecognised format: {fmt}"
    }


# ── A13 — Format version declared ─────────────────────────────────────────────

def check_a13(sbom: dict) -> dict:
    fmt     = sbom.get("_format", "")
    version = sbom.get("_format_version", "")

    allowed = KNOWN_VERSIONS.get(fmt, set())
    if version and version in allowed:
        return {
            "check_id":   "A13",
            "check_name": "SBOM format version declared",
            "result":     "PASS",
            "score":      1.0,
            "detail":     f"{fmt} version {version}"
        }
    if version:
        return {
            "check_id":   "A13",
            "check_name": "SBOM format version declared",
            "result":     "PARTIAL",
            "score":      0.5,
            "detail":     f"Version present ({version}) but not in known set for {fmt}"
        }
    return {
        "check_id":   "A13",
        "check_name": "SBOM format version declared",
        "result":     "FAIL",
        "score":      0.0,
        "detail":     "No format version found"
    }


# ── run all 13 ────────────────────────────────────────────────────────────────

ALL_CHECKS = [
    check_a1, check_a2, check_a3, check_a4, check_a5,
    check_a6, check_a7, check_a8, check_a9, check_a10,
    check_a11, check_a12, check_a13
]

def run_all(sbom: dict) -> list[dict]:
    return [fn(sbom) for fn in ALL_CHECKS]
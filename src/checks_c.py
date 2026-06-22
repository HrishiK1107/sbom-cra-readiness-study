"""
Tier C — 2 structurally inferred checks.
No standardised SBOM field exists for these CRA requirements.
We infer from metadata patterns. Absence is itself a finding.

C1: Intended deployment environment inferable
C2: Security support period / lifecycle phase declared
"""


# ── C1 — Deployment environment ───────────────────────────────────────────────

CONTAINER_TYPES   = {"container", "machine-image", "device", "firmware"}
OS_PKG_TYPES      = {"rpm", "deb", "apk", "pkg", "portage"}
CONTAINER_PURLS   = ("pkg:oci/", "pkg:docker/")

def check_c1(sbom: dict) -> dict:
    evidence = []

    # 1. CycloneDX metadata.component.type
    meta_comp = sbom.get("metadata", {}).get("component", {})
    comp_type = meta_comp.get("type", "").lower()
    if comp_type in CONTAINER_TYPES:
        evidence.append(f"metadata.component.type={comp_type}")

    # 2. CycloneDX lifecyclePhase or environment in metadata
    meta = sbom.get("metadata", {})
    if meta.get("lifecyclePhase") or meta.get("environment"):
        evidence.append("lifecycle/environment field present")

    # 3. OCI/Docker PURL in any component
    for c in sbom.get("components", []):
        purl = c.get("purl", "")
        if any(purl.startswith(p) for p in CONTAINER_PURLS):
            evidence.append("OCI/Docker PURL found")
            break

    # 4. OS package types in component PURLs
    for c in sbom.get("components", []):
        purl = c.get("purl", "")
        pkg_type = purl.split(":")[1].split("/")[0] if ":" in purl else ""
        if pkg_type in OS_PKG_TYPES:
            evidence.append(f"OS package type ({pkg_type}) found in PURLs")
            break

    # 5. SPDX primaryPackagePurpose on root
    for pkg in sbom.get("packages", []):
        purpose = pkg.get("primaryPackagePurpose", "").upper()
        if purpose in ("OPERATING-SYSTEM", "CONTAINER", "DEVICE", "FIRMWARE"):
            evidence.append(f"SPDX primaryPackagePurpose={purpose}")
            break

    if evidence:
        return {
            "check_id":   "C1",
            "check_name": "Deployment environment inferable",
            "result":     "PASS",
            "score":      1.0,
            "detail":     "; ".join(evidence)
        }
    return {
        "check_id":   "C1",
        "check_name": "Deployment environment inferable",
        "result":     "FAIL",
        "score":      0.0,
        "detail":     "No deployment environment signal found"
    }


# ── C2 — Security support period / lifecycle ──────────────────────────────────

def check_c2(sbom: dict) -> dict:
    evidence = []

    # 1. CycloneDX 1.5 metadata.lifecycles array
    lifecycles = sbom.get("metadata", {}).get("lifecycles", [])
    if lifecycles:
        phases = [lc.get("phase", "") for lc in lifecycles if lc.get("phase")]
        if phases:
            evidence.append(f"CycloneDX lifecycles: {', '.join(phases)}")

    # 2. Any component with an endOfLife or eol field
    for c in sbom.get("components", []):
        raw = c.get("_raw", {})
        if raw.get("endOfLife") or raw.get("eol") or raw.get("support"):
            evidence.append("Component end-of-life/support field found")
            break

    # 3. CycloneDX externalReferences of type "advisories" or "support"
    for c in sbom.get("components", []):
        raw = c.get("_raw", {})
        for ref in raw.get("externalReferences", []):
            if ref.get("type", "") in ("advisories", "support", "mailing-list"):
                evidence.append(f"externalReference type={ref['type']} found")
                break

    # 4. SPDX packages with validUntilDate or supportEndDate
    for pkg in sbom.get("packages", []):
        if pkg.get("validUntilDate") or pkg.get("supportEndDate"):
            evidence.append("SPDX validUntilDate/supportEndDate found")
            break

    if evidence:
        return {
            "check_id":   "C2",
            "check_name": "Security support period declared",
            "result":     "PASS",
            "score":      1.0,
            "detail":     "; ".join(evidence)
        }
    return {
        "check_id":   "C2",
        "check_name": "Security support period declared",
        "result":     "FAIL",
        "score":      0.0,
        "detail":     "No lifecycle, EOL, or support period data found"
    }


# ── run both ──────────────────────────────────────────────────────────────────

ALL_CHECKS = [check_c1, check_c2]

def run_all(sbom: dict) -> list[dict]:
    return [fn(sbom) for fn in ALL_CHECKS]
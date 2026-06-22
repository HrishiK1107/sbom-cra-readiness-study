"""
Parses CycloneDX-JSON, CycloneDX-XML, and SPDX-JSON into a
normalized dict that checks_a / checks_b / checks_c operate on.

Normalized keys:
    _format          : str   e.g. "CycloneDX-JSON"
    _format_version  : str   e.g. "1.5" or "SPDX-2.3"
    _tool            : str   e.g. "cdxgen"
    _filename        : str
    metadata         : dict  (raw CycloneDX metadata or {})
    creationInfo     : dict  (raw SPDX creationInfo or {})
    components       : list  (normalized component dicts)
    dependencies     : list  (raw CycloneDX dependencies or [])
    relationships    : list  (raw SPDX relationships or [])
    vulnerabilities  : list  (raw CycloneDX vulnerabilities or [])
    packages         : list  (raw SPDX packages or [])
"""

import json
import xml.etree.ElementTree as ET


# ── CycloneDX JSON ────────────────────────────────────────────────────────────

def _tool_from_cdx(meta: dict) -> str:
    tools = meta.get("tools", {})
    if isinstance(tools, dict):
        comps = tools.get("components", [])
        if comps:
            return comps[0].get("name", "unknown")
    if isinstance(tools, list) and tools:
        return tools[0].get("name", "unknown")
    return "unknown"


def _normalize_cdx_component(c: dict) -> dict:
    return {
        "name":      c.get("name", ""),
        "version":   c.get("version", ""),
        "supplier":  c.get("supplier") or c.get("publisher") or c.get("author") or "",
        "purl":      c.get("purl", ""),
        "cpe":       c.get("cpe", ""),
        "hashes":    c.get("hashes", []),
        "licenses":  c.get("licenses", []),
        "_raw":      c,
    }


def parse_cyclonedx_json(data: dict, filename: str) -> dict:
    meta    = data.get("metadata", {})
    version = str(data.get("specVersion", ""))
    raw_components = data.get("components", [])

    return {
        "_format":         "CycloneDX-JSON",
        "_format_version": version,
        "_tool":           _tool_from_cdx(meta),
        "_filename":       filename,
        "metadata":        meta,
        "creationInfo":    {},
        "components":      [_normalize_cdx_component(c) for c in raw_components],
        "dependencies":    data.get("dependencies", []),
        "relationships":   [],
        "vulnerabilities": data.get("vulnerabilities", []),
        "packages":        [],
    }


# ── SPDX JSON ─────────────────────────────────────────────────────────────────

def _tool_from_spdx(creation: dict) -> str:
    for c in creation.get("creators", []):
        if c.startswith("Tool:"):
            raw = c.replace("Tool:", "").strip()
            return raw.split("-")[0].lower()
    return "unknown"


def _normalize_spdx_package(p: dict) -> dict:
    return {
        "name":      p.get("name", ""),
        "version":   p.get("versionInfo", ""),
        "supplier":  p.get("supplier", "") or p.get("originator", ""),
        "purl":      next(
            (r["referenceLocator"] for r in p.get("externalRefs", [])
             if r.get("referenceType") == "purl"),
            ""
        ),
        "cpe":       next(
            (r["referenceLocator"] for r in p.get("externalRefs", [])
             if "cpe" in r.get("referenceType", "")),
            ""
        ),
        "hashes":    [],
        "checksums": p.get("checksums", []),
        "licenses":  _spdx_licenses(p),
        "_raw":      p,
    }


def _spdx_licenses(p: dict) -> list:
    out = []
    for field in ("licenseConcluded", "licenseDeclared"):
        val = p.get(field, "").strip()
        if val and val not in ("NOASSERTION", "NONE", ""):
            out.append({"expression": val})
    return out


def parse_spdx_json(data: dict, filename: str) -> dict:
    creation = data.get("creationInfo", {})
    version  = data.get("spdxVersion", "")
    packages = data.get("packages", [])

    return {
        "_format":         "SPDX-JSON",
        "_format_version": version,
        "_tool":           _tool_from_spdx(creation),
        "_filename":       filename,
        "metadata":        {},
        "creationInfo":    creation,
        "components":      [_normalize_spdx_package(p) for p in packages],
        "dependencies":    [],
        "relationships":   data.get("relationships", []),
        "vulnerabilities": [],
        "packages":        packages,
    }


# ── CycloneDX XML ─────────────────────────────────────────────────────────────

CDX_NS = {
    "1.4": "http://cyclonedx.org/schema/bom/1.4",
    "1.5": "http://cyclonedx.org/schema/bom/1.5",
    "1.6": "http://cyclonedx.org/schema/bom/1.6",
}

def parse_cyclonedx_xml(content: str, filename: str) -> dict:
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return None

    # detect namespace / version
    ns  = ""
    ver = ""
    for v, uri in CDX_NS.items():
        if uri in root.tag:
            ns  = uri
            ver = v
            break

    def tag(name):
        return f"{{{ns}}}{name}" if ns else name

    def find_text(element, path):
        el = element.find(path)
        return el.text.strip() if el is not None and el.text else ""

    # tool
    tool = "unknown"
    for comp in root.findall(f".//{tag('component')}"):
        name_el = comp.find(tag("name"))
        if name_el is not None:
            tool = name_el.text or "unknown"
            break

    # timestamp
    ts = find_text(root, f"{tag('metadata')}/{tag('timestamp')}")

    # components
    components = []
    for c in root.findall(f".//{tag('component')}"):
        name    = find_text(c, tag("name"))
        version = find_text(c, tag("version"))
        purl    = find_text(c, tag("purl"))
        hashes  = [
            {"alg": h.get("alg",""), "content": h.text or ""}
            for h in c.findall(f".//{tag('hash')}")
        ]
        components.append({
            "name":     name,
            "version":  version,
            "supplier": "",
            "purl":     purl,
            "cpe":      "",
            "hashes":   hashes,
            "licenses": [],
            "_raw":     {},
        })

    meta = {"timestamp": ts, "tools": {"components": [{"name": tool}]}}

    return {
        "_format":         "CycloneDX-XML",
        "_format_version": ver,
        "_tool":           tool,
        "_filename":       filename,
        "metadata":        meta,
        "creationInfo":    {},
        "components":      components,
        "dependencies":    [],
        "relationships":   [],
        "vulnerabilities": [],
        "packages":        [],
    }


# ── top-level dispatcher ──────────────────────────────────────────────────────

def parse_file(filepath: str) -> dict | None:
    import os
    filename = os.path.basename(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return None

    head = content[:2000].lower()

    # CycloneDX XML
    if content.strip().startswith("<") and ("cyclonedx" in head or "<bom" in head):
        return parse_cyclonedx_xml(content, filename)

    # JSON formats
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return None

    if "bomFormat" in data and data.get("bomFormat") == "CycloneDX":
        return parse_cyclonedx_json(data, filename)

    if "spdxVersion" in data:
        return parse_spdx_json(data, filename)

    return None
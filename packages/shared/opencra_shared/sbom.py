"""CycloneDX 1.6 subset parser and PURL normalization."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from packageurl import PackageURL
from pydantic import ValidationError

from opencra_shared.models import Component, SbomDocument, SbomMetadata, SbomTool

logger = logging.getLogger("opencra.sbom")

# Map common Syft/CycloneDX purl types we synthesize when purl is missing.
_TYPE_TO_ECOSYSTEM = {
    "pypi": "pypi",
    "npm": "npm",
    "golang": "golang",
    "go": "golang",
    "maven": "maven",
    "cargo": "cargo",
    "nuget": "nuget",
    "gem": "gem",
    "composer": "composer",
    "hex": "hex",
    "pub": "pub",
    "swift": "swift",
    "apk": "apk",
    "deb": "deb",
    "rpm": "rpm",
}


def _has_broken_percent_encoding(text: str) -> bool:
    i = 0
    while i < len(text):
        if text[i] == "%":
            hexpart = text[i + 1 : i + 3]
            if len(hexpart) < 2 or any(c not in "0123456789abcdefABCDEF" for c in hexpart):
                return True
            i += 3
        else:
            i += 1
    return False


def normalize_purl(value: str | None) -> str | None:
    """Parse and re-serialize a PURL, dropping invalid/unencodable qualifiers.

    Returns None if the value cannot be made into a valid Package URL.
    """
    if not value or not value.strip():
        return None
    raw = value.strip()
    if "?" in raw and _has_broken_percent_encoding(raw.split("?", 1)[1]):
        raw = raw.split("?", 1)[0].split("#", 1)[0]
    try:
        parsed = PackageURL.from_string(raw)
        return str(parsed)
    except (ValueError, TypeError):
        pass

    base = raw.split("?", 1)[0].split("#", 1)[0]
    try:
        parsed = PackageURL.from_string(base)
        return str(parsed)
    except (ValueError, TypeError):
        logger.warning("Dropping invalid PURL: %s", value)
        return None


def _licenses_from_cdx(raw: Any) -> list[str]:
    if not raw:
        return []
    out: list[str] = []
    if not isinstance(raw, list):
        return out
    for item in raw:
        if isinstance(item, str):
            out.append(item)
            continue
        if not isinstance(item, dict):
            continue
        license_obj = item.get("license") or item
        if isinstance(license_obj, dict):
            ident = license_obj.get("id") or license_obj.get("name")
            if ident:
                out.append(str(ident))
        expression = item.get("expression")
        if expression:
            out.append(str(expression))
    return out


def _hashes_from_cdx(raw: Any) -> dict[str, str]:
    hashes: dict[str, str] = {}
    if not isinstance(raw, list):
        return hashes
    for item in raw:
        if isinstance(item, dict) and item.get("alg") and item.get("content"):
            hashes[str(item["alg"])] = str(item["content"])
    return hashes


def _synthesize_purl(component: dict[str, Any]) -> str | None:
    name = component.get("name")
    version = component.get("version")
    if not name or not version:
        return None
    cdx_type = str(component.get("type") or "library").lower()
    purl_type = component.get("purl-type") or _TYPE_TO_ECOSYSTEM.get(cdx_type)
    # Prefer bom-ref hints like pkg:pypi/...
    bom_ref = str(component.get("bom-ref") or "")
    if bom_ref.startswith("pkg:"):
        return normalize_purl(bom_ref)
    if not purl_type:
        # Last resort: generic generic type is invalid; skip synthesis.
        return None
    try:
        return str(PackageURL(type=purl_type, name=str(name), version=str(version)))
    except (ValueError, TypeError):
        return None


def normalize_component(raw: dict[str, Any]) -> Component | None:
    name = raw.get("name")
    if not name:
        return None
    purl = normalize_purl(raw.get("purl")) or _synthesize_purl(raw)
    skipped = None if purl else "invalid or missing PURL"
    try:
        return Component(
            type=str(raw.get("type") or "library"),
            name=str(name),
            version=str(raw["version"]) if raw.get("version") is not None else None,
            purl=purl,
            licenses=_licenses_from_cdx(raw.get("licenses")),
            hashes=_hashes_from_cdx(raw.get("hashes")),
            skipped_reason=skipped,
        )
    except ValidationError:
        return None


def parse_cyclonedx(payload: dict[str, Any]) -> SbomDocument:
    """Parse a CycloneDX JSON document, dropping unknown fields and bad components."""
    metadata_raw = payload.get("metadata") or {}
    component_raw = metadata_raw.get("component") or {}
    tools: list[SbomTool] = []
    tools_raw = metadata_raw.get("tools")
    # CycloneDX 1.5+ uses tools.components; 1.4 uses a list.
    if isinstance(tools_raw, dict):
        for item in tools_raw.get("components") or tools_raw.get("services") or []:
            if isinstance(item, dict) and item.get("name"):
                tools.append(SbomTool(name=str(item["name"]), version=item.get("version")))
    elif isinstance(tools_raw, list):
        for item in tools_raw:
            if isinstance(item, dict) and item.get("name"):
                tools.append(SbomTool(name=str(item["name"]), version=item.get("version")))

    timestamp = metadata_raw.get("timestamp")
    parsed_ts: datetime | None = None
    if isinstance(timestamp, str):
        try:
            parsed_ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            parsed_ts = None

    components: list[Component] = []
    for raw in payload.get("components") or []:
        if not isinstance(raw, dict):
            continue
        component = normalize_component(raw)
        if component is not None:
            components.append(component)

    serial = payload.get("serialNumber") or f"urn:uuid:{uuid4()}"
    return SbomDocument(
        bom_format=str(payload.get("bomFormat") or "CycloneDX"),
        spec_version=str(payload.get("specVersion") or "1.6"),
        serial_number=str(serial),
        version=int(payload.get("version") or 1),
        metadata=SbomMetadata(
            timestamp=parsed_ts or datetime.now(timezone.utc),
            name=component_raw.get("name"),
            version=component_raw.get("version"),
            component_type=str(component_raw.get("type") or "application"),
            tools=tools,
        ),
        components=components,
        raw=payload,
    )


def serialize_cyclonedx(document: SbomDocument) -> dict[str, Any]:
    """Rebuild a CycloneDX-shaped dict from the normalized document."""
    if document.raw:
        # Preserve original Syft document when present; overlay serial if missing.
        out = dict(document.raw)
        out.setdefault("bomFormat", "CycloneDX")
        out.setdefault("specVersion", document.spec_version)
        out.setdefault("serialNumber", document.serial_number)
        return out

    components = []
    for component in document.components:
        item: dict[str, Any] = {
            "type": component.type,
            "name": component.name,
        }
        if component.version:
            item["version"] = component.version
        if component.purl:
            item["purl"] = component.purl
        if component.licenses:
            item["licenses"] = [{"license": {"id": lic}} for lic in component.licenses]
        if component.hashes:
            item["hashes"] = [{"alg": k, "content": v} for k, v in component.hashes.items()]
        components.append(item)

    ts = document.metadata.timestamp or datetime.now(timezone.utc)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": document.spec_version,
        "serialNumber": document.serial_number,
        "version": document.version,
        "metadata": {
            "timestamp": ts.isoformat(),
            "component": {
                "type": document.metadata.component_type,
                "name": document.metadata.name or "unknown",
                "version": document.metadata.version or "0.0.0",
            },
            "tools": {
                "components": [
                    {"name": t.name, **({"version": t.version} if t.version else {})}
                    for t in document.metadata.tools
                ]
            },
        },
        "components": components,
    }


def cyclonedx_to_spdx(document: SbomDocument) -> dict[str, Any]:
    """Minimal SPDX 2.3 JSON adapter. Not a full SPDX implementation."""
    packages = []
    for component in document.components:
        pkg: dict[str, Any] = {
            "name": component.name,
            "SPDXID": f"SPDXRef-{_spdx_id(component.name, component.version)}",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        }
        if component.version:
            pkg["versionInfo"] = component.version
        if component.purl:
            pkg["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": component.purl,
                }
            ]
        if component.licenses:
            pkg["licenseConcluded"] = component.licenses[0]
        packages.append(pkg)

    created = (document.metadata.timestamp or datetime.now(timezone.utc)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": document.metadata.name or document.serial_number,
        "documentNamespace": document.serial_number,
        "creationInfo": {
            "created": created,
            "creators": ["Tool: opencra-0.1.5"],
        },
        "packages": packages,
    }


def _spdx_id(name: str, version: str | None) -> str:
    base = f"{name}-{version or 'unknown'}"
    return "".join(ch if ch.isalnum() else "-" for ch in base)

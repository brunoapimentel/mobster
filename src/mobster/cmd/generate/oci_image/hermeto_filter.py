"""A module for filtering Hermeto SBOM by architecture."""

import logging
from typing import Any
from urllib.parse import parse_qs, urlparse

LOGGER = logging.getLogger(__name__)


def _extract_arch_and_checksum_from_purl(purl: str) -> tuple[str | None, str | None]:
    """
    Extract architecture and checksum from a Package URL (purl).

    Args:
        purl: The Package URL string (e.g., "pkg:rpm/redhat/binutils@2.35.2-67.el9?arch=x86_64&checksum=sha256:...")

    Returns:
        tuple[str | None, str | None]: A tuple of (architecture, checksum)
    """
    parsed = urlparse(purl)
    query_params = parse_qs(parsed.query)

    arch = query_params.get("arch", [None])[0]
    checksum = query_params.get("checksum", [None])[0]

    return arch, checksum


def filter_spdx_sbom_by_arch(
    sbom_dict: dict[str, Any], target_arch: str
) -> dict[str, Any]:
    """
    Filter an SPDX SBOM by architecture, keeping only packages that match
    the specified architecture or are 'noarch'. Deduplicates 'noarch' packages
    by checksum.

    Args:
        sbom_dict: The SBOM dictionary in SPDX format
        target_arch: The architecture to filter by (e.g., "x86_64", "aarch64")

    Returns:
        dict[str, Any]: The filtered SBOM dictionary
    """
    LOGGER.info(f"Filtering SPDX SBOM by architecture: {target_arch}")

    packages = sbom_dict.get("packages", [])
    if not packages:
        LOGGER.warning("No packages found in SBOM")
        return sbom_dict

    filtered_packages = []
    removed_spdx_ids = set()
    noarch_checksums = set()

    for package in packages:
        external_refs = package.get("externalRefs", [])
        if not external_refs:
            filtered_packages.append(package)
            continue

        purl_ref = next(
            (
                ref
                for ref in external_refs
                if ref.get("referenceType") == "purl"
                and ref.get("referenceLocator", "").startswith("pkg:rpm")
            ),
            None,
        )

        if not purl_ref:
            filtered_packages.append(package)
            continue

        purl = purl_ref.get("referenceLocator", "")
        arch, checksum = _extract_arch_and_checksum_from_purl(purl)

        if arch == "noarch":
            if checksum and checksum in noarch_checksums:
                LOGGER.debug(
                    f"Removing duplicate noarch package: {package.get('name')} "
                    f"(checksum: {checksum})"
                )
                removed_spdx_ids.add(package.get("SPDXID"))
                continue

            if checksum:
                noarch_checksums.add(checksum)
            filtered_packages.append(package)
        elif arch == target_arch:
            filtered_packages.append(package)
        else:
            LOGGER.debug(
                f"Removing package {package.get('name')} with arch={arch} "
                f"(target: {target_arch})"
            )
            removed_spdx_ids.add(package.get("SPDXID"))

    original_count = len(packages)
    filtered_count = len(filtered_packages)
    removed_count = original_count - filtered_count

    LOGGER.info(
        f"Filtered {removed_count} packages out of {original_count} "
        f"({filtered_count} remaining)"
    )

    sbom_dict["packages"] = filtered_packages

    if removed_spdx_ids:
        relationships = sbom_dict.get("relationships", [])
        original_rel_count = len(relationships)

        filtered_relationships = [
            rel
            for rel in relationships
            if rel.get("spdxElementId") not in removed_spdx_ids
            and rel.get("relatedSpdxElement") not in removed_spdx_ids
        ]

        filtered_rel_count = len(filtered_relationships)
        removed_rel_count = original_rel_count - filtered_rel_count

        LOGGER.info(
            f"Removed {removed_rel_count} relationships out of {original_rel_count} "
            f"({filtered_rel_count} remaining)"
        )

        sbom_dict["relationships"] = filtered_relationships

    return sbom_dict


def filter_cyclonedx_sbom_by_arch(
    sbom_dict: dict[str, Any], target_arch: str
) -> dict[str, Any]:
    """
    Filter a CycloneDX SBOM by architecture, keeping only packages that match
    the specified architecture or are 'noarch'. Deduplicates 'noarch' packages
    by checksum.

    Args:
        sbom_dict: The SBOM dictionary in CycloneDX format
        target_arch: The architecture to filter by (e.g., "x86_64", "aarch64")

    Returns:
        dict[str, Any]: The filtered SBOM dictionary
    """
    LOGGER.info(f"Filtering CycloneDX SBOM by architecture: {target_arch}")

    components = sbom_dict.get("components", [])
    if not components:
        LOGGER.warning("No components found in SBOM")
        return sbom_dict

    filtered_components = []
    removed_bom_refs = set()
    noarch_checksums = set()

    for component in components:
        purl = component.get("purl", "")

        if not purl.startswith("pkg:rpm"):
            filtered_components.append(component)
            continue

        arch, checksum = _extract_arch_and_checksum_from_purl(purl)

        if arch == "noarch":
            if checksum and checksum in noarch_checksums:
                LOGGER.debug(
                    f"Removing duplicate noarch component: {component.get('name')} "
                    f"(checksum: {checksum})"
                )
                bom_ref = component.get("bom-ref")
                if bom_ref:
                    removed_bom_refs.add(bom_ref)
                continue

            if checksum:
                noarch_checksums.add(checksum)
            filtered_components.append(component)
        elif arch == target_arch:
            filtered_components.append(component)
        else:
            LOGGER.debug(
                f"Removing component {component.get('name')} with arch={arch} "
                f"(target: {target_arch})"
            )
            bom_ref = component.get("bom-ref")
            if bom_ref:
                removed_bom_refs.add(bom_ref)

    original_count = len(components)
    filtered_count = len(filtered_components)
    removed_count = original_count - filtered_count

    LOGGER.info(
        f"Filtered {removed_count} components out of {original_count} "
        f"({filtered_count} remaining)"
    )

    sbom_dict["components"] = filtered_components

    if removed_bom_refs:
        dependencies = sbom_dict.get("dependencies", [])
        if dependencies:
            original_dep_count = len(dependencies)

            filtered_dependencies = []
            for dep in dependencies:
                dep_ref = dep.get("ref")
                if dep_ref in removed_bom_refs:
                    continue

                depends_on = dep.get("dependsOn", [])
                if depends_on:
                    filtered_depends_on = [
                        ref for ref in depends_on if ref not in removed_bom_refs
                    ]
                    dep["dependsOn"] = filtered_depends_on

                filtered_dependencies.append(dep)

            filtered_dep_count = len(filtered_dependencies)
            removed_dep_count = original_dep_count - filtered_dep_count

            LOGGER.info(
                f"Removed {removed_dep_count} dependencies out of {original_dep_count} "
                f"({filtered_dep_count} remaining)"
            )

            sbom_dict["dependencies"] = filtered_dependencies

    return sbom_dict


def filter_hermeto_sbom_by_arch(
    sbom_dict: dict[str, Any], target_arch: str
) -> dict[str, Any]:
    """
    Filter a Hermeto SBOM by architecture, supporting both SPDX and CycloneDX formats.

    Args:
        sbom_dict: The SBOM dictionary
        target_arch: The architecture to filter by (e.g., "x86_64", "aarch64")

    Returns:
        dict[str, Any]: The filtered SBOM dictionary

    Raises:
        ValueError: If the SBOM format is not recognized
    """
    if not target_arch:
        LOGGER.debug("No target architecture specified, skipping filtering")
        return sbom_dict

    if sbom_dict.get("bomFormat") == "CycloneDX":
        return filter_cyclonedx_sbom_by_arch(sbom_dict, target_arch)
    elif "spdxVersion" in sbom_dict:
        return filter_spdx_sbom_by_arch(sbom_dict, target_arch)
    else:
        raise ValueError("Unknown SBOM format, cannot filter by architecture")

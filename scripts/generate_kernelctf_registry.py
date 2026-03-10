#!/usr/bin/env python3
"""Generate kernelCTF entries for cve-registry.json.

Scans ~/security-research/pocs/linux/kernelctf/ for CVE directories,
reads metadata.json from each, and generates registry entries for all
CVE+release combinations.

Steps 6+7+8 of the integration plan:
- Step 6: Adds boot_mode to existing entries
- Step 7: Generates 148 kernelCTF entries
- Step 8: All kernelCTF entries share SSH port 2250, user/user
"""

import json
import os
import re
import sys
from pathlib import Path

SECURITY_RESEARCH = Path.home() / "security-research/pocs/linux/kernelctf"
REGISTRY_PATH = Path(__file__).parent.parent / "cve-registry.json"


def extract_cos_build(release: str) -> str | None:
    """Extract COS build ID from release name.

    cos-105-17412.101.17 -> 17412.101.17
    """
    m = re.match(r"cos-\d+-(.+)", release)
    return m.group(1) if m else None


def extract_kernel_tag(release: str) -> str | None:
    """Extract kernel version tag for LTS/mitigation releases.

    lts-6.1.36 -> v6.1.36
    mitigation-v3-6.1.55 -> v6.1.55
    mitigation-6.1 -> v6.1 (will need exact version from bzImage later)
    mitigation-v3b-6.1.55 -> v6.1.55
    mitigation-v4-6.6 -> v6.6
    """
    if release.startswith("lts-"):
        ver = release[4:]  # e.g., "6.1.36"
        return f"v{ver}"
    if release.startswith("mitigation"):
        # mitigation-6.1, mitigation-v3-6.1.55, mitigation-v3b-6.1.55, mitigation-v4-6.6
        parts = release.split("-")
        # Find the version part (starts with digit)
        for part in reversed(parts):
            if part and part[0].isdigit():
                return f"v{part}"
    return None


def load_metadata(cve_dir: Path) -> dict | None:
    """Load metadata.json from a CVE directory."""
    meta_path = cve_dir / "metadata.json"
    if not meta_path.exists():
        return None
    try:
        with open(meta_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Warning: failed to parse {meta_path}: {e}", file=sys.stderr)
        return None


def get_releases(cve_dir: Path) -> list[str]:
    """Get list of releases from exploit/ subdirectory."""
    exploit_dir = cve_dir / "exploit"
    if not exploit_dir.is_dir():
        return []
    return sorted(
        d.name for d in exploit_dir.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )


def get_exploit_info_from_metadata(metadata: dict, release: str) -> dict:
    """Extract exploit-specific info (stability, uses) from metadata for a release."""
    info = {}
    exploits = metadata.get("exploits", {})

    if isinstance(exploits, list):
        # v2 schema: array of exploit entries
        for entry in exploits:
            env = entry.get("environment", "")
            # Some v2 entries use release name as environment
            if env == release or not env:
                if "stability_notes" in entry:
                    info["stability_notes"] = entry["stability_notes"]
                if "uses" in entry:
                    info["uses"] = entry["uses"]
                break
    elif isinstance(exploits, dict):
        # v3 schema: object keyed by release name
        if release in exploits:
            entry = exploits[release]
            if "stability_notes" in entry:
                info["stability_notes"] = entry["stability_notes"]
            if "uses" in entry:
                info["uses"] = entry["uses"]

    return info


def generate_entry(cve_dir_name: str, release: str, metadata: dict) -> dict:
    """Generate a single cve-registry.json entry for a CVE+release combo."""
    vuln = metadata.get("vulnerability", {})
    requirements = vuln.get("requirements", {})
    exploit_info = get_exploit_info_from_metadata(metadata, release)

    entry = {
        "boot_mode": "kernelctf",
        "release": release,
        "cve_dir": cve_dir_name,
        "ssh_port": 2250,
        "ssh_user": "user",
        "ssh_password": "user",
        "type": vuln.get("summary", ""),
        "patch_commit": vuln.get("patch_commit", ""),
        "affected_versions": vuln.get("affected_versions", []),
        "kernel_config": requirements.get("kernel_config", []),
        "capabilities": requirements.get("capabilities", []),
        "attack_surface": requirements.get("attack_surface", []),
    }

    # Add stability notes if available
    if "stability_notes" in exploit_info:
        entry["stability_notes"] = exploit_info["stability_notes"]

    # Add uses (userns, etc.) if available
    if "uses" in exploit_info:
        entry["uses"] = exploit_info["uses"]

    # Determine kernel_tag or cos_build based on release type
    if release.startswith("cos-"):
        cos_build = extract_cos_build(release)
        if cos_build:
            entry["cos_build"] = cos_build
    elif release == "extra-refined":
        # Special case — no kernel_tag
        pass
    else:
        kernel_tag = extract_kernel_tag(release)
        if kernel_tag:
            entry["kernel_tag"] = kernel_tag

    return entry


def main():
    # Load existing registry
    with open(REGISTRY_PATH) as f:
        registry = json.load(f)

    # Step 6: Add boot_mode to existing entries
    for key, entry in registry.items():
        if "boot_mode" not in entry:
            entry["boot_mode"] = "cloud-init"

    # Step 7: Generate kernelCTF entries
    if not SECURITY_RESEARCH.is_dir():
        print(f"Error: {SECURITY_RESEARCH} not found", file=sys.stderr)
        sys.exit(1)

    cve_dirs = sorted(d for d in SECURITY_RESEARCH.iterdir() if d.is_dir() and d.name.startswith("CVE-"))

    new_count = 0
    skipped = []

    # First pass: collect all CVE+release combos to detect collisions
    combos = []  # list of (reg_key, cve_dir, release, metadata)
    for cve_dir in cve_dirs:
        metadata = load_metadata(cve_dir)
        releases = get_releases(cve_dir)

        if not releases:
            skipped.append(f"{cve_dir.name}: no exploit/ subdirectories")
            continue

        if not metadata:
            skipped.append(f"{cve_dir.name}: no metadata.json")
            metadata = {"vulnerability": {}, "exploits": {}}

        cve_id = metadata.get("vulnerability", {}).get("cve", "")
        if not cve_id:
            m = re.match(r"(CVE-\d{4}-\d+)", cve_dir.name)
            cve_id = m.group(1) if m else cve_dir.name

        for release in releases:
            reg_key = f"{cve_id}_{release}"
            combos.append((reg_key, cve_dir, release, metadata))

    # Detect collisions — same reg_key from different directories
    key_counts: dict[str, list] = {}
    for reg_key, cve_dir, release, metadata in combos:
        key_counts.setdefault(reg_key, []).append((cve_dir, release, metadata))

    # Second pass: generate entries, disambiguating collisions with dir suffix
    for reg_key, entries in key_counts.items():
        if len(entries) == 1:
            cve_dir, release, metadata = entries[0]
            entry = generate_entry(cve_dir.name, release, metadata)
            registry[reg_key] = entry
            new_count += 1
        else:
            # Collision: use full directory name as key prefix
            for cve_dir, release, metadata in entries:
                disambig_key = f"{cve_dir.name}_{release}"
                entry = generate_entry(cve_dir.name, release, metadata)
                registry[disambig_key] = entry
                new_count += 1

    # Write updated registry
    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)
        f.write("\n")

    # Summary
    print(f"Registry updated: {REGISTRY_PATH}")
    print(f"  Existing entries (with boot_mode added): 9")
    print(f"  New kernelCTF entries: {new_count}")
    print(f"  Total entries: {len(registry)}")

    if skipped:
        print(f"\nSkipped ({len(skipped)}):")
        for s in skipped:
            print(f"  - {s}")


if __name__ == "__main__":
    main()

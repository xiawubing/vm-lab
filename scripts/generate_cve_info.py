#!/usr/bin/env python3
"""Generate cve-info markdown files for all CVEs.

Step 12 of the integration plan:
- Generates 96 kernelCTF cve-info files from metadata.json
- Rewrites 9 existing CVE Lab files to remove PoC/exploitation strategy

Each file contains ONLY:
- Vulnerability summary
- CVE ID, affected versions, patch commit URL
- Vulnerability type and affected subsystem
- Required kernel config
- Required capabilities/attack surface
- Pointer to vulnerable source files (from patch commit)
- Stability hints

Does NOT contain: PoC source code, exploit strategy, step-by-step guide
"""

import json
import re
import sys
from pathlib import Path

SECURITY_RESEARCH = Path.home() / "security-research/pocs/linux/kernelctf"
CVE_INFO_DIR = Path(__file__).parent.parent / "agent-container" / "cve-info"
REGISTRY_PATH = Path(__file__).parent.parent / "cve-registry.json"


def extract_subsystem_from_patch(patch_url: str) -> str:
    """Try to extract the subsystem from a known patch commit URL.

    This is a best-effort heuristic — the actual affected files are in the
    patch diff, which we don't fetch. The agent will find them via the
    kernel source at /src/.
    """
    # Common patterns in commit messages/paths
    return ""


def load_metadata(cve_dir_name: str) -> dict | None:
    """Load metadata.json for a kernelCTF CVE directory."""
    meta_path = SECURITY_RESEARCH / cve_dir_name / "metadata.json"
    if not meta_path.exists():
        return None
    try:
        with open(meta_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def load_vulnerability_doc(cve_dir_name: str) -> str | None:
    """Load docs/vulnerability.md if it exists."""
    doc_path = SECURITY_RESEARCH / cve_dir_name / "docs" / "vulnerability.md"
    if not doc_path.exists():
        return None
    try:
        return doc_path.read_text()
    except OSError:
        return None


def generate_kernelctf_cve_info(cve_dir_name: str, releases: list[dict]) -> str:
    """Generate cve-info markdown for a kernelCTF CVE."""
    metadata = load_metadata(cve_dir_name)
    if not metadata:
        metadata = {"vulnerability": {}, "exploits": {}}

    vuln = metadata.get("vulnerability", {})
    requirements = vuln.get("requirements", {})
    cve_id = vuln.get("cve", "")
    if not cve_id:
        m = re.match(r"(CVE-\d{4}-\d+)", cve_dir_name)
        cve_id = m.group(1) if m else cve_dir_name

    summary = vuln.get("summary", "")
    patch_commit = vuln.get("patch_commit", "")
    affected_versions = vuln.get("affected_versions", [])
    kernel_config = requirements.get("kernel_config", [])
    capabilities = requirements.get("capabilities", [])
    attack_surface = requirements.get("attack_surface", [])

    # Try to load vulnerability description from docs/
    vuln_doc = load_vulnerability_doc(cve_dir_name)

    lines = []
    title = f"# {cve_id}"
    if summary:
        title += f" — {summary}"
    lines.append(title)
    lines.append("")

    lines.append("## Overview")
    lines.append("")
    if summary:
        lines.append(summary)
    else:
        lines.append(f"Kernel vulnerability {cve_id}.")
    lines.append("")

    # Basic info table
    lines.append(f"- **CVE**: {cve_id}")
    if affected_versions:
        lines.append(f"- **Affected versions**: {', '.join(affected_versions)}")
    if patch_commit:
        lines.append(f"- **Patch commit**: {patch_commit}")
    lines.append("")

    # Requirements
    if kernel_config or capabilities or attack_surface:
        lines.append("## Requirements")
        lines.append("")
        if kernel_config:
            lines.append(f"- **Kernel config**: {', '.join(f'`{c}`' for c in kernel_config)}")
        if capabilities:
            lines.append(f"- **Capabilities**: {', '.join(f'`{c}`' for c in capabilities)}")
        if attack_surface:
            lines.append(f"- **Attack surface**: {', '.join(attack_surface)}")
        lines.append("")

    # Releases
    if releases:
        lines.append("## Target Releases")
        lines.append("")
        for r in releases:
            release = r.get("release", "")
            stability = r.get("stability_notes", "")
            uses = r.get("uses", [])
            line = f"- **{release}**"
            if stability:
                line += f" — {stability}"
            if uses:
                line += f" (uses: {', '.join(uses)})"
            lines.append(line)
        lines.append("")

    # Vulnerability description from docs
    if vuln_doc:
        lines.append("## Vulnerability Description")
        lines.append("")
        # Strip any exploitation strategy sections
        cleaned = strip_exploitation_sections(vuln_doc)
        lines.append(cleaned.strip())
        lines.append("")

    # Source files hint
    if patch_commit:
        lines.append("## Source Files")
        lines.append("")
        lines.append("Refer to the patch commit to identify the affected source files.")
        lines.append(f"The kernel source tree is mounted at `/src/` in the container.")
        lines.append("")

    return "\n".join(lines)


def strip_exploitation_sections(text: str) -> str:
    """Remove exploitation strategy sections from markdown text."""
    # Remove sections with headers containing exploit-related keywords
    result = []
    skip_section = False
    skip_level = 0

    for line in text.split("\n"):
        # Check if this is a header
        header_match = re.match(r"^(#{1,6})\s+(.*)", line)
        if header_match:
            level = len(header_match.group(1))
            title = header_match.group(2).lower()
            # Check if header contains exploitation-related keywords
            exploit_keywords = ["exploit", "strategy", "poc", "proof of concept",
                                "payload", "shellcode", "privilege escalation technique"]
            if any(kw in title for kw in exploit_keywords):
                skip_section = True
                skip_level = level
                continue
            else:
                # If we encounter a same-level or higher header, stop skipping
                if skip_section and level <= skip_level:
                    skip_section = False

        if not skip_section:
            result.append(line)

    return "\n".join(result)


def rewrite_existing_cve_info(filepath: Path) -> str:
    """Rewrite an existing CVE Lab cve-info file to remove exploitation sections."""
    text = filepath.read_text()
    return strip_exploitation_sections(text)


def main():
    # Load registry for release info
    with open(REGISTRY_PATH) as f:
        registry = json.load(f)

    # Group kernelCTF registry entries by cve_dir
    cve_dir_releases: dict[str, list[dict]] = {}
    for key, entry in registry.items():
        if entry.get("boot_mode") != "kernelctf":
            continue
        cve_dir = entry.get("cve_dir", "")
        if not cve_dir:
            continue
        cve_dir_releases.setdefault(cve_dir, []).append(entry)

    # Generate kernelCTF cve-info files
    generated = 0
    for cve_dir_name, releases in sorted(cve_dir_releases.items()):
        # Extract CVE ID from metadata or directory name
        metadata = load_metadata(cve_dir_name)
        if metadata:
            cve_id = metadata.get("vulnerability", {}).get("cve", "")
        else:
            cve_id = ""
        if not cve_id:
            m = re.match(r"(CVE-\d{4}-\d+)", cve_dir_name)
            cve_id = m.group(1) if m else cve_dir_name

        # Use cve_dir_name for filename to avoid collisions
        filename = f"{cve_dir_name}.md"
        content = generate_kernelctf_cve_info(cve_dir_name, releases)
        out_path = CVE_INFO_DIR / filename
        out_path.write_text(content)
        generated += 1

    # Rewrite existing CVE Lab cve-info files
    rewritten = 0
    for existing_file in sorted(CVE_INFO_DIR.glob("CVE-*.md")):
        # Skip kernelCTF files we just generated
        if any(existing_file.name.startswith(d) for d in cve_dir_releases):
            continue
        # Only rewrite the original 9
        if existing_file.name in [
            "CVE-2017-5123.md", "CVE-2017-6074.md", "CVE-2017-7308.md",
            "CVE-2017-16995.md", "CVE-2017-1000112.md", "CVE-2017-1000367.md",
            "CVE-2018-1000001.md", "CVE-2018-18955.md", "CVE-2022-0847.md"
        ]:
            new_content = rewrite_existing_cve_info(existing_file)
            existing_file.write_text(new_content)
            rewritten += 1

    print(f"Generated: {generated} kernelCTF cve-info files")
    print(f"Rewritten: {rewritten} existing CVE Lab cve-info files")
    print(f"Total files in {CVE_INFO_DIR}: {len(list(CVE_INFO_DIR.glob('CVE-*.md')))}")


if __name__ == "__main__":
    main()

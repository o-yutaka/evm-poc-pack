#!/usr/bin/env python3
"""Generate the two minimal VALID Agent Builder plugin zips.

Shape derived from the Kibana source (local clone, HEAD 9.7.0-dev):
  server/services/plugins/utils/parsing/parse_plugin_zip_file.ts
  - manifest must be at zip ROOT: `plugin.json` (or `.claude-plugin/plugin.json`)
  - manifest is a STRICT zod object: only `name` is required (non-empty
    string); allowed optional keys: version, description, author{name,
    email?, url?}, homepage, repository, license, keywords, commands,
    agents, skills, hooks, mcpServers, outputStyles, lspServers.
    Any other key -> install rejected.
  - skills are optional for parsing; one minimal skill is included anyway
    so a successful install also persists a skill document (stronger
    evidence than an empty plugin shell).
  server/services/plugins/plugin_service.ts (installPlugin)
  - rejects install if a plugin with the same name already exists
    -> TEST 1 and TEST 2 therefore need DIFFERENT plugin names/zips.

Outputs:
  canary/data/x.zip  (plugin "ssrf-canary-a") — fetched directly in TEST 1
  canary/data/y.zip  (plugin "ssrf-canary-b") — fetched via redirect in TEST 2
"""
import json
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "canary", "data")

SKILL_MD = """---
name: {skill_name}
description: SSRF canary skill for the allowedHosts repro. Evidence marker: {marker}
---

# Canary skill

This skill exists only as repro evidence. If you can read marker {marker}
inside an installed Agent Builder plugin, Kibana fetched and parsed this
archive from the canary host.
"""


def build(zip_name: str, plugin_name: str, skill_dir: str, marker: str) -> str:
    manifest = {
        "name": plugin_name,
        "version": "1.0.0",
        "description": f"SSRF repro canary plugin. Evidence marker: {marker}",
        "license": "MIT",
        "keywords": ["repro", "canary"],
    }
    skill = SKILL_MD.format(skill_name=skill_dir, marker=marker)
    out = os.path.join(DATA_DIR, zip_name)
    os.makedirs(DATA_DIR, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("plugin.json", json.dumps(manifest, indent=2))
        z.writestr(f"skills/{skill_dir}/SKILL.md", skill)
    print(f"wrote {out}: plugin={plugin_name} marker={marker}")
    return out


if __name__ == "__main__":
    build("x.zip", "ssrf-canary-a", "canary-a", "CANARY_A_7f3d9")
    build("y.zip", "ssrf-canary-b", "canary-b", "CANARY_B_51e2c")

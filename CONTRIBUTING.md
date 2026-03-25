# Contributing

## Adding new IOCs

If the TeamPCP attack evolves — new persistence mechanisms, additional C2 domains, new payload filenames — open a PR updating the relevant check function in `scan_litellm_compromise.sh`.

**Where to add what:**

| IOC type | Function to update |
|----------|--------------------|
| New C2 domain or hostname | `check_c2_connections` — add to the `c2_domains` array |
| New malicious filename (payload, archive) | `check_exfil_artifacts` — add a new `find` block |
| New persistence path or service name | `check_persistence` — add a file/directory check |
| New malicious .pth filename | `check_pth_file` — update the `find` pattern |
| New compromised version number | All `check_installed_versions` and `check_dependency_files` version comparisons |

**When adding a new IOC, include:**

1. The source (security advisory URL, malware analysis post, etc.)
2. A comment in the code explaining what the IOC indicates
3. An update to the sources list at the top of the script if the reference is new

## Adding a new check category

1. Write a new `check_*()` function following the existing pattern:
   - Set `CURRENT_CATEGORY` at the top (used for JSON output)
   - Call `section "N. Description"` for the section header
   - Use `warn` for confirmed findings, `info` for ambiguous findings, `ok` for clean results
   - Use `start_spinner` / `stop_spinner` around long `find` operations
   - Collect results in arrays before printing (so spinner stops before output appears)

2. Call the new function in the `Main` section at the bottom of the script.

3. Document the new category in [README.md](README.md) (the "What this script checks" table).

## Code style

- Keep the script POSIX-bash compatible (`#!/usr/bin/env bash`, `set -euo pipefail`)
- All `find` commands must use `-print0` / `read -d ''` for safe filename handling
- All `find` commands must append `2>/dev/null || true` to suppress permission errors
- Run `shellcheck scan_litellm_compromise.sh quick_triage.sh` before submitting — both must pass clean
- No external dependencies beyond coreutils, bash, and optional tools (kubectl, docker, etc.)

## Running shellcheck locally

```bash
# Install shellcheck
brew install shellcheck        # macOS
apt-get install shellcheck     # Debian/Ubuntu

# Run
shellcheck scan_litellm_compromise.sh quick_triage.sh
```

## Testing

Test on both macOS and Linux before submitting. Key scenarios to verify:

- Clean system (no litellm installed) → exit code 0, no findings
- `--help` and `--version` flags exit cleanly
- `--json` output is valid JSON: `./scan_litellm_compromise.sh --json | python3 -m json.tool`
- `--quiet` suppresses banners and progress but shows findings
- Non-TTY detection: `./scan_litellm_compromise.sh | cat` (no color codes in output)
- Graceful handling when optional tools are absent (kubectl, docker, systemctl)

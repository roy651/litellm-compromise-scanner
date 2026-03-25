# LiteLLM Supply Chain Compromise Scanner

![Incident: 2026-03-24](https://img.shields.io/badge/incident-2026--03--24-red)
![Affected: litellm 1.82.7 / 1.82.8](https://img.shields.io/badge/affected-litellm%201.82.7%20%2F%201.82.8-orange)
![Shell: bash](https://img.shields.io/badge/shell-bash-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

One-command scanner for the TeamPCP / LiteLLM supply chain attack (March 24, 2026). Checks 9 IOC categories across all Python environments, caches, persistence mechanisms, C2 domains, Kubernetes, Docker, and dependency lockfiles.

---

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/litellm-malware-scan/main/scan_litellm_compromise.sh \
  | bash
```

> **Security note:** Piping a shell script directly from the internet is convenient — but it's also exactly the kind of trust assumption that supply chain attacks exploit. Before running, consider:
>
> ```bash
> # Download first, inspect, then run
> curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/litellm-malware-scan/main/scan_litellm_compromise.sh \
>   -o scan_litellm_compromise.sh
> less scan_litellm_compromise.sh   # read it
> chmod +x scan_litellm_compromise.sh && ./scan_litellm_compromise.sh
> ```

---

## The attack

On March 24, 2026, threat actor **TeamPCP** published two malicious versions of the `litellm` PyPI package (1.82.7 and 1.82.8) after stealing the maintainer's credentials through an earlier Trivy GitHub Actions compromise. The packages were available for approximately 3 hours before PyPI quarantined them — during a window when litellm receives ~3.4 million daily downloads.

**Attack stages:**

| Stage | What it does |
|-------|-------------|
| 1 — Credential harvest | Exfiltrates SSH keys, cloud credentials (AWS/GCP/Azure), K8s configs, `.env` files, and crypto wallets as an encrypted `tpcp.tar.gz` archive sent to `models.litellm.cloud` |
| 2 — Kubernetes lateral movement | Creates privileged Alpine pods (`node-setup-*`) in `kube-system` if `kubectl` is available |
| 3 — Persistent backdoor | Installs `~/.config/sysmon/sysmon.py` with a systemd user service that polls `checkmarx.zone/raw` every 50 minutes for new commands |

**Two injection vectors:**

- **v1.82.7** — malicious code injected directly into `litellm/proxy/proxy_server.py` (activated when the LiteLLM proxy is started)
- **v1.82.8** — malicious `litellm_init.pth` added to site-packages (executes on **any** Python startup, not just when using litellm)

**Why you may be affected even if you didn't install litellm directly:**

litellm is a transitive dependency of many AI frameworks — CrewAI, DSPy, LangGraph, Browser-Use, AutoGen, and others. Users of these frameworks may have pulled the compromised package without knowing.

---

## What this script checks

| # | Category | What it looks for |
|---|----------|-------------------|
| 1 | Installed versions | litellm 1.82.7/1.82.8 across all pip envs, venvs, conda, uv, pipx, pyenv, rye |
| 2 | Malicious .pth file | `litellm_init.pth` in site-packages, uv cache, pip cache |
| 3 | Persistence | `~/.config/sysmon/sysmon.py`, `sysmon.service`, active systemd unit |
| 4 | Exfiltration artifacts | `tpcp.tar.gz`, suspicious `p.py` payload scripts in /tmp |
| 5 | C2 domains | `models.litellm.cloud`, `checkmarx.zone` in DNS cache, shell history, /etc/hosts, active connections |
| 6 | Injected proxy_server.py | Base64-encoded `exec()` calls in litellm's proxy module (v1.82.7 vector) |
| 7 | Kubernetes | Rogue `node-setup-*` pods and Alpine containers in `kube-system` |
| 8 | Docker | Image layer history and Dockerfiles referencing compromised versions |
| 9 | Dependency files | `requirements*.txt`, lockfiles, `pyproject.toml` pinning 1.82.7/1.82.8 |

---

## Usage

```
Usage: scan_litellm_compromise.sh [OPTIONS] [SCAN_ROOT]

Arguments:
  SCAN_ROOT         Root directory to scan (default: $HOME)

Options:
  -h, --help        Show help and exit
  -v, --version     Show version and exit
  -q, --quiet       Only print findings and summary (no banners or progress)
      --json        Output machine-readable JSON (implies --no-color)
      --no-color    Disable colored output

Exit code = number of issues found (0 = clean)
```

**Examples:**

```bash
# Standard scan of $HOME
./scan_litellm_compromise.sh

# Scan entire filesystem (slower, more thorough)
sudo ./scan_litellm_compromise.sh /

# Quiet mode: only print findings, suppress banners and progress
./scan_litellm_compromise.sh --quiet

# JSON output for further processing
./scan_litellm_compromise.sh --json | jq '.findings'

# Save a report
./scan_litellm_compromise.sh --json > scan-report.json
```

**macOS note:** macOS may show permission popups when the script scans protected folders (Documents, Downloads, etc.). Click **Allow** to include those areas, or **Don't Allow** to skip them — the script will continue either way. To avoid repeated prompts, grant Full Disk Access to your terminal app under System Settings → Privacy & Security.

---

## CI/CD integration

The script is designed to work in CI environments — non-interactive, exit code reflects findings, JSON output available.

**GitHub Actions example:**

```yaml
- name: Scan for LiteLLM supply chain compromise
  run: |
    curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/litellm-malware-scan/main/scan_litellm_compromise.sh \
      -o scan_litellm_compromise.sh
    chmod +x scan_litellm_compromise.sh
    ./scan_litellm_compromise.sh --json > scan-report.json
    cat scan-report.json
    # Exit code is the number of issues found
```

Colors are automatically disabled when stdout is not a TTY (standard in CI environments).

---

## If you find issues: remediation steps

1. **Remove compromised package** from all environments:
   ```bash
   pip uninstall litellm -y
   # For uv projects:
   uv remove litellm
   ```

2. **Purge caches** (they can re-infect on next install):
   ```bash
   pip cache purge
   rm -rf ~/.cache/uv
   ```

3. **Remove persistence mechanisms:**
   ```bash
   systemctl --user stop sysmon.service 2>/dev/null || true
   systemctl --user disable sysmon.service 2>/dev/null || true
   rm -rf ~/.config/sysmon
   rm -f ~/.config/systemd/user/sysmon.service
   ```

4. **Rotate all credentials** on any machine that ran the compromised package:
   - SSH keys (`~/.ssh/`)
   - AWS/GCP/Azure credentials (`~/.aws/`, `~/.config/gcloud/`, `~/.config/az/`)
   - Kubernetes configs (`~/.kube/config`)
   - All `.env` files and API keys
   - CI/CD secrets and Docker registry credentials

5. **Audit outbound connections** to `models.litellm.cloud` and `checkmarx.zone` in your network logs.

6. **Pin litellm** to a safe version in all projects: `litellm>=1.82.9` or `litellm<=1.82.6`.

---

## References

- [LiteLLM official security advisory](https://docs.litellm.ai/blog/security-update-march-2026)
- [FutureSearch — technical deep dive](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/)
- [Snyk — poisoned security scanner analysis](https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/)
- [Wiz — TeamPCP campaign context](https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign)
- [The Hacker News](https://thehackernews.com/2026/03/teampcp-backdoors-litellm-versions.html)
- [Comet — affected frameworks list](https://www.comet.com/site/blog/litellm-supply-chain-attack/)
- [ARMO — backdoor analysis](https://www.armosec.io/blog/litellm-supply-chain-attack-backdoor-analysis/)
- [Sonatype — multi-stage credential stealer breakdown](https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer)
- [CyberInsider — scale and impact](https://cyberinsider.com/new-supply-chain-attack-hits-litellm-with-95m-monthly-downloads/)
- [DreamFactory — complete technical breakdown](https://blog.dreamfactory.com/the-litellm-supply-chain-attack-a-complete-technical-breakdown-of-what-happened-who-is-affected-and-what-comes-next)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add new IOCs if the attack evolves.

## License

MIT — see [LICENSE](LICENSE).

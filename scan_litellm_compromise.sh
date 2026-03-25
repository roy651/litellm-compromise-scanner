#!/usr/bin/env bash
# ============================================================================
# LiteLLM Supply Chain Compromise Scanner (TeamPCP / March 24, 2026)
# ============================================================================
# Scans for indicators of compromise from the litellm 1.82.7 / 1.82.8
# malicious PyPI packages published by TeamPCP on 2026-03-24.
#
# Sources:
#   - https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/
#   - https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/
#   - https://www.wiz.io/blog/threes-a-crowd-teampcp-trojanizes-litellm-in-continuation-of-campaign
#   - https://thehackernews.com/2026/03/teampcp-backdoors-litellm-versions.html
#   - https://docs.litellm.ai/blog/security-update-march-2026
#
# Usage: ./scan_litellm_compromise.sh [OPTIONS] [SCAN_ROOT]
#
# Why not just `find / -name "litellm_init.pth"`?
#   This was a multi-stage attack with two distinct injection vectors,
#   persistence mechanisms, lateral movement, and exfiltration — each
#   leaving different traces. A find for the .pth file only covers
#   v1.82.8's delivery method. v1.82.7 injected code into proxy_server.py
#   instead. Even after removal, the malware drops a persistent systemd
#   backdoor (~/.config/sysmon/) that keeps polling the C2 server. Cached
#   wheels in pip/uv can silently re-infect on next install. And if you
#   run Kubernetes, the malware creates privileged pods for lateral movement.
#   This script checks all 9 IOC categories so you don't have to remember
#   each one. It scans venv, virtualenv, conda, uv, pipx, pyenv, and rye
#   environments — including pip-less envs (uv) via direct METADATA inspection.
#   For a quick triage first:
#     pip show litellm 2>/dev/null | grep Version; \
#     find ~ -name "litellm_init.pth" -o -name "sysmon.py" -path "*/.config/sysmon/*"
#
# macOS permissions note:
#   This script scans directories (Documents, Downloads, Desktop, etc.) that
#   macOS protects. You may see system popups asking to grant your terminal
#   access to these folders. This is normal — macOS requires permission per
#   app (Terminal.app / iTerm2), not per script, so there's no way to
#   batch-request it upfront. You can either:
#     (a) Click "Allow" on each popup as it appears, or
#     (b) Grant Full Disk Access to your terminal app once:
#         System Settings → Privacy & Security → Full Disk Access → add Terminal/iTerm2
#         (recommended if you run security tools regularly)
#   Clicking "Don't Allow" is safe — the script will simply skip that folder
#   and continue. It won't crash or give false results for other areas.
# ============================================================================

VERSION="1.0.0"

set -euo pipefail
trap 'stop_spinner 2>/dev/null; exit 130' INT TERM

# ── Flags ────────────────────────────────────────────────────────────────────
QUIET=0       # --quiet: suppress banners, progress, and ok messages
JSON_MODE=0   # --json:  machine-readable JSON output (implies --no-color)
NO_COLOR=0    # --no-color: disable ANSI color codes
SCAN_ROOT=""

show_help() {
    cat <<EOF
Usage: scan_litellm_compromise.sh [OPTIONS] [SCAN_ROOT]

Scans for indicators of compromise from the LiteLLM supply chain attack
(TeamPCP, March 24, 2026). Checks 9 IOC categories across all Python
environments, persistence mechanisms, exfiltration artifacts, C2 domains,
Kubernetes, Docker, and dependency lockfiles.

Arguments:
  SCAN_ROOT         Root directory to scan (default: \$HOME)

Options:
  -h, --help        Show this help message and exit
  -v, --version     Show version and exit
  -q, --quiet       Only print findings and final summary (no banners or progress)
      --json        Output machine-readable JSON to stdout (implies --no-color)
      --no-color    Disable colored output

Exit code equals the number of issues found (0 = clean).

Examples:
  ./scan_litellm_compromise.sh                      # scan \$HOME
  ./scan_litellm_compromise.sh /                    # scan entire filesystem
  ./scan_litellm_compromise.sh --quiet              # terse output (CI-friendly)
  ./scan_litellm_compromise.sh --json | jq .        # JSON output
  ./scan_litellm_compromise.sh --json > report.json # save report

Quick triage (no script required):
  pip show litellm 2>/dev/null | grep Version
  find ~ -name "litellm_init.pth" -o -name "sysmon.py" -path "*/.config/sysmon/*"
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)    show_help; exit 0 ;;
        -v|--version) echo "scan_litellm_compromise.sh $VERSION"; exit 0 ;;
        -q|--quiet)   QUIET=1; shift ;;
        --json)       JSON_MODE=1; shift ;;
        --no-color)   NO_COLOR=1; shift ;;
        --)           shift; SCAN_ROOT="${1:-}"; break ;;
        -*)           echo "Unknown option: $1" >&2; echo "Run with --help for usage." >&2; exit 1 ;;
        *)            SCAN_ROOT="$1"; shift ;;
    esac
done

SCAN_ROOT="${SCAN_ROOT:-$HOME}"

# JSON mode implies no-color (colors corrupt JSON output)
[[ $JSON_MODE -eq 1 ]] && NO_COLOR=1

# Auto-detect non-interactive stdout and disable colors
[[ -t 1 ]] || NO_COLOR=1

# ── Colors ───────────────────────────────────────────────────────────────────
if [[ $NO_COLOR -eq 0 ]]; then
    RED='\033[0;31m'
    YEL='\033[0;33m'
    GRN='\033[0;32m'
    CYN='\033[0;36m'
    RST='\033[0m'
else
    RED='' YEL='' GRN='' CYN='' RST=''
fi

# ── State ────────────────────────────────────────────────────────────────────
FOUND_ISSUES=0
SPIN_PID=""
CURRENT_CATEGORY="general"
JSON_FINDINGS=()

# ── Output helpers ───────────────────────────────────────────────────────────
banner() {
    [[ $QUIET -eq 1 || $JSON_MODE -eq 1 ]] && return
    echo ""
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo -e "${CYN}  LiteLLM / TeamPCP Supply Chain Compromise Scanner  v${VERSION}${RST}"
    echo -e "${CYN}  Incident date: 2026-03-24  |  Affected: litellm 1.82.7, 1.82.8${RST}"
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo ""
    echo -e "  Scan root: ${SCAN_ROOT}"
    echo -e "  Date:      $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    if [[ "$(uname -s)" == "Darwin" ]]; then
        echo -e "  ${YEL}Note:${RST} macOS may show popups asking your terminal to access"
        echo -e "  folders like Documents or Downloads. This is normal — click Allow"
        echo -e "  to let the scan cover those areas, or Don't Allow to skip them."
        echo -e "  To avoid popups entirely, grant Full Disk Access to your terminal:"
        echo -e "  System Settings → Privacy & Security → Full Disk Access"
        echo ""
    fi
}

section() {
    [[ $QUIET -eq 1 || $JSON_MODE -eq 1 ]] && return
    echo ""
    echo -e "${CYN}── $1 ──${RST}"
}

warn() {
    FOUND_ISSUES=$((FOUND_ISSUES + 1))
    if [[ $JSON_MODE -eq 1 ]]; then
        local msg="${1//\"/\\\"}"
        JSON_FINDINGS+=("{\"severity\":\"critical\",\"category\":\"${CURRENT_CATEGORY}\",\"message\":\"${msg}\"}")
        return
    fi
    echo -e "  ${RED}[!] FOUND:${RST} $1"
}

info() {
    if [[ $JSON_MODE -eq 1 ]]; then
        local msg="${1//\"/\\\"}"
        JSON_FINDINGS+=("{\"severity\":\"info\",\"category\":\"${CURRENT_CATEGORY}\",\"message\":\"${msg}\"}")
        return
    fi
    [[ $QUIET -eq 1 ]] && return
    echo -e "  ${YEL}[~]${RST} $1"
}

ok() {
    [[ $QUIET -eq 1 || $JSON_MODE -eq 1 ]] && return
    echo -e "  ${GRN}[✓]${RST} $1"
}

# ── Spinner ──────────────────────────────────────────────────────────────────
# Writes to stderr so it doesn't pollute captured stdout or JSON output.
start_spinner() {
    [[ $QUIET -eq 1 || $JSON_MODE -eq 1 ]] && return
    [[ -t 2 ]] || return  # don't spin if stderr is not a tty
    local msg="$1"
    printf "  %s " "$msg" >&2
    ( while true; do printf "." >&2; sleep 1; done ) &
    SPIN_PID=$!
}

stop_spinner() {
    if [[ -n "$SPIN_PID" ]]; then
        kill "$SPIN_PID" 2>/dev/null
        wait "$SPIN_PID" 2>/dev/null || true
        SPIN_PID=""
        echo "" >&2
    fi
}

# ============================================================================
# 1. Check installed litellm versions across all discoverable Python envs
# ============================================================================
check_installed_versions() {
    CURRENT_CATEGORY="installed_versions"
    section "1. Checking installed litellm versions"

    local safe_count=0
    local pip_cmds=()

    for cmd in pip pip3 pip3.10 pip3.11 pip3.12 pip3.13; do
        if command -v "$cmd" &>/dev/null; then
            pip_cmds+=("$(command -v "$cmd")")
        fi
    done

    start_spinner "Discovering Python environments under $SCAN_ROOT"
    while IFS= read -r -d '' venv_pip; do
        pip_cmds+=("$venv_pip")
    done < <(find "$SCAN_ROOT" -maxdepth 6 \
        \( -path "*/bin/pip" -o -path "*/bin/pip3" \
           -o -path "*/Scripts/pip.exe" -o -path "*/Scripts/pip3.exe" \) \
        -type f -print0 2>/dev/null || true)

    for conda_base in "$HOME/miniconda3" "$HOME/anaconda3" "$HOME/miniforge3" "/opt/conda"; do
        if [[ -d "$conda_base/envs" ]]; then
            while IFS= read -r -d '' venv_pip; do
                pip_cmds+=("$venv_pip")
            done < <(find "$conda_base/envs" -maxdepth 4 -path "*/bin/pip" -type f -print0 2>/dev/null || true)
        fi
    done
    stop_spinner

    # Deduplicate by realpath
    local seen=()
    local unique_pips=()
    for p in "${pip_cmds[@]+"${pip_cmds[@]}"}"; do
        local real
        real=$(realpath "$p" 2>/dev/null || echo "$p")
        local already=0
        for s in "${seen[@]+"${seen[@]}"}"; do
            [[ "$s" == "$real" ]] && already=1 && break
        done
        if [[ $already -eq 0 ]]; then
            seen+=("$real")
            unique_pips+=("$p")
        fi
    done

    start_spinner "Checking ${#unique_pips[@]} pip environment(s) + site-packages"
    for pip_cmd in "${unique_pips[@]+"${unique_pips[@]}"}"; do
        local ver
        ver=$("$pip_cmd" show litellm 2>/dev/null | grep -i '^Version:' | awk '{print $2}') || true
        if [[ -n "$ver" ]]; then
            if [[ "$ver" == "1.82.7" || "$ver" == "1.82.8" ]]; then
                warn "COMPROMISED litellm $ver found via: $pip_cmd"
            else
                safe_count=$((safe_count + 1))
            fi
        fi
    done

    # Direct site-packages scan (catches pip-less envs: uv, pipx, pyenv, rye)
    local sp_dirs=()
    for extra_root in \
        "$HOME/.local/share/uv/tools" \
        "$HOME/.local/pipx/venvs" \
        "$HOME/.pyenv/versions" \
        "$HOME/.cache/uv" \
        "$HOME/.rye/tools"; do
        [[ -d "$extra_root" ]] && sp_dirs+=("$extra_root")
    done
    sp_dirs+=("$SCAN_ROOT")

    local compromised_paths=()
    while IFS= read -r -d '' meta; do
        local meta_ver
        meta_ver=$(grep -i '^Version:' "$meta" 2>/dev/null | head -1 | awk '{print $2}') || true
        if [[ -n "$meta_ver" ]]; then
            local env_path="${meta%/*}"
            env_path="${env_path%/*}"
            if [[ "$meta_ver" == "1.82.7" || "$meta_ver" == "1.82.8" ]]; then
                compromised_paths+=("litellm $meta_ver in: $env_path")
            else
                safe_count=$((safe_count + 1))
            fi
        fi
    done < <(find "${sp_dirs[@]}" /usr/lib /usr/local/lib \
        -maxdepth 8 -path "*/litellm-*.dist-info/METADATA" \
        -type f -print0 2>/dev/null || true)
    stop_spinner

    for msg in "${compromised_paths[@]+"${compromised_paths[@]}"}"; do
        warn "COMPROMISED $msg"
    done

    if [[ $FOUND_ISSUES -eq 0 && $safe_count -eq 0 ]]; then
        ok "No litellm installations detected"
    elif [[ ${#compromised_paths[@]} -eq 0 ]]; then
        ok "Scanned $safe_count litellm installation(s) — none compromised"
    fi
}

# ============================================================================
# 2. Check for the malicious .pth file (primary v1.82.8 payload)
# ============================================================================
check_pth_file() {
    CURRENT_CATEGORY="pth_file"
    section "2. Searching for malicious litellm_init.pth file"

    start_spinner "Scanning filesystem and package caches"
    local pth_results=()
    while IFS= read -r -d '' pth; do
        pth_results+=("$pth")
    done < <(find "$SCAN_ROOT" /usr/lib /usr/local/lib \
        -name "litellm_init.pth" -type f -print0 2>/dev/null || true)

    if [[ -d "$HOME/.cache/uv" ]]; then
        while IFS= read -r -d '' pth; do
            pth_results+=("uv-cache: $pth")
        done < <(find "$HOME/.cache/uv" -name "litellm_init.pth" -print0 2>/dev/null || true)
    fi

    for cache_dir in "$HOME/.cache/pip" "$HOME/Library/Caches/pip"; do
        if [[ -d "$cache_dir" ]]; then
            while IFS= read -r -d '' pth; do
                pth_results+=("pip-cache: $pth")
            done < <(find "$cache_dir" -name "litellm_init.pth" -print0 2>/dev/null || true)
        fi
    done
    stop_spinner

    for p in "${pth_results[@]+"${pth_results[@]}"}"; do
        warn "Malicious .pth file found: $p"
    done

    if [[ ${#pth_results[@]} -eq 0 ]]; then
        ok "No litellm_init.pth files found"
    fi
}

# ============================================================================
# 3. Check for persistence mechanisms
# ============================================================================
check_persistence() {
    CURRENT_CATEGORY="persistence"
    section "3. Checking for TeamPCP persistence mechanisms"

    if [[ -f "$HOME/.config/sysmon/sysmon.py" ]]; then
        warn "Backdoor script found: $HOME/.config/sysmon/sysmon.py"
    else
        ok "No sysmon.py backdoor found"
    fi

    if [[ -f "$HOME/.config/systemd/user/sysmon.service" ]]; then
        warn "Persistence service found: $HOME/.config/systemd/user/sysmon.service"
    else
        ok "No sysmon.service persistence found"
    fi

    if command -v systemctl &>/dev/null; then
        if systemctl --user is-active sysmon.service &>/dev/null; then
            warn "sysmon.service is ACTIVELY RUNNING"
        fi
    fi

    if [[ -d "$HOME/.config/sysmon" ]]; then
        warn "Suspicious directory exists: $HOME/.config/sysmon/"
        while IFS= read -r -d '' entry; do
            echo "       ${entry}"
        done < <(find "$HOME/.config/sysmon/" -maxdepth 1 -mindepth 1 -print0 2>/dev/null || true)
    fi
}

# ============================================================================
# 4. Check for exfiltration artifacts
# ============================================================================
check_exfil_artifacts() {
    CURRENT_CATEGORY="exfil_artifacts"
    section "4. Searching for exfiltration artifacts"

    local found_exfil=0

    while IFS= read -r -d '' f; do
        warn "Exfiltration archive found: $f"
        found_exfil=1
    done < <(find "$SCAN_ROOT" /tmp /var/tmp \
        -name "tpcp.tar.gz" -type f -print0 2>/dev/null || true)

    while IFS= read -r -d '' f; do
        if grep -ql "base64\|litellm\|models\.litellm\|checkmarx\.zone" "$f" 2>/dev/null; then
            warn "Suspicious payload script: $f"
            found_exfil=1
        fi
    done < <(find /tmp /var/tmp -maxdepth 2 -name "p.py" -type f -print0 2>/dev/null || true)

    if [[ $found_exfil -eq 0 ]]; then
        ok "No exfiltration artifacts found"
    fi
}

# ============================================================================
# 5. Check for C2 domain references in connections / DNS / history
# ============================================================================
check_c2_connections() {
    CURRENT_CATEGORY="c2_domains"
    section "5. Checking for C2 domain indicators"

    local c2_domains=("models.litellm.cloud" "checkmarx.zone")
    local found_c2=0

    if command -v dscacheutil &>/dev/null; then
        for domain in "${c2_domains[@]}"; do
            if dscacheutil -cachedump 2>/dev/null | grep -qi "$domain"; then
                warn "C2 domain $domain found in DNS cache"
                found_c2=1
            fi
        done
    fi

    for hist_file in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.local/share/fish/fish_history"; do
        if [[ -f "$hist_file" ]]; then
            for domain in "${c2_domains[@]}"; do
                if grep -q "$domain" "$hist_file" 2>/dev/null; then
                    warn "C2 domain $domain referenced in $hist_file"
                    found_c2=1
                fi
            done
        fi
    done

    for domain in "${c2_domains[@]}"; do
        if grep -q "$domain" /etc/hosts 2>/dev/null; then
            info "C2 domain $domain in /etc/hosts (could be a block rule — verify manually)"
            found_c2=1
        fi
    done

    if command -v ss &>/dev/null; then
        for domain in "${c2_domains[@]}"; do
            if ss -tunap 2>/dev/null | grep -qi "$domain"; then
                warn "ACTIVE connection to C2 domain: $domain"
                found_c2=1
            fi
        done
    elif command -v netstat &>/dev/null; then
        for domain in "${c2_domains[@]}"; do
            if netstat -an 2>/dev/null | grep -qi "$domain"; then
                warn "Connection to C2 domain: $domain"
                found_c2=1
            fi
        done
    fi

    if [[ $found_c2 -eq 0 ]]; then
        ok "No C2 domain indicators found"
    fi
}

# ============================================================================
# 6. Check for compromised proxy_server.py (v1.82.7 injection vector)
# ============================================================================
check_proxy_server_injection() {
    CURRENT_CATEGORY="proxy_server_injection"
    section "6. Searching for injected proxy_server.py (v1.82.7 vector)"

    local found_inj=0

    start_spinner "Scanning for proxy_server.py files"
    local inj_results=()
    while IFS= read -r -d '' ps; do
        if grep -ql "base64.b64decode\|subprocess.Popen.*b64decode\|exec(base64" "$ps" 2>/dev/null; then
            inj_results+=("$ps")
        fi
    done < <(find "$SCAN_ROOT" /usr/lib /usr/local/lib \
        -path "*/litellm/proxy/proxy_server.py" -type f -print0 2>/dev/null || true)
    stop_spinner

    for p in "${inj_results[@]+"${inj_results[@]}"}"; do
        warn "Suspicious base64 exec in: $p"
        found_inj=1
    done

    if [[ $found_inj -eq 0 ]]; then
        ok "No injected proxy_server.py files found"
    fi
}

# ============================================================================
# 7. Check for Kubernetes compromise indicators (if kubectl available)
# ============================================================================
check_kubernetes() {
    CURRENT_CATEGORY="kubernetes"
    section "7. Checking Kubernetes indicators (if applicable)"

    if ! command -v kubectl &>/dev/null; then
        info "kubectl not found — skipping Kubernetes checks"
        return
    fi

    if ! kubectl cluster-info &>/dev/null 2>&1; then
        info "No active Kubernetes cluster connection — skipping"
        return
    fi

    local bad_pods
    bad_pods=$(kubectl get pods -n kube-system --no-headers 2>/dev/null | grep "^node-setup-" || true)
    if [[ -n "$bad_pods" ]]; then
        warn "Suspicious node-setup-* pods in kube-system namespace:"
        while IFS= read -r line; do
            echo "       $line"
        done <<< "$bad_pods"
    else
        ok "No suspicious node-setup-* pods in kube-system"
    fi

    local alpine_pods
    alpine_pods=$(kubectl get pods -n kube-system \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[0].image}{"\n"}{end}' 2>/dev/null \
        | grep -i "alpine" || true)
    if [[ -n "$alpine_pods" ]]; then
        warn "Alpine-based pods in kube-system (review manually):"
        while IFS= read -r line; do
            echo "       $line"
        done <<< "$alpine_pods"
    fi
}

# ============================================================================
# 8. Check for cached compromised wheels in Docker layer history
# ============================================================================
check_docker() {
    CURRENT_CATEGORY="docker"
    section "8. Checking Docker images for compromised litellm"

    if ! command -v docker &>/dev/null; then
        info "Docker not found — skipping"
        return
    fi

    local found_docker=0
    while IFS= read -r image; do
        if docker history "$image" 2>/dev/null | grep -qi "litellm.*1\.82\.\(7\|8\)"; then
            warn "Docker image may contain compromised litellm: $image"
            found_docker=1
        fi
    done < <(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | head -50)

    start_spinner "Scanning Dockerfiles"
    local docker_warns=()
    local docker_infos=()
    while IFS= read -r -d '' df; do
        if grep -qi "litellm" "$df" 2>/dev/null; then
            if grep -qE "litellm[=>~!]*1\.82\.[78]" "$df" 2>/dev/null; then
                docker_warns+=("$df")
            elif grep -qE "pip install.*litellm" "$df" 2>/dev/null && ! grep -qE "litellm==" "$df" 2>/dev/null; then
                docker_infos+=("$df")
            fi
        fi
    done < <(find "$SCAN_ROOT" -maxdepth 6 \
        \( -name "Dockerfile" -o -name "Dockerfile.*" -o -name "*.dockerfile" \) \
        -type f -print0 2>/dev/null || true)
    stop_spinner

    for df in "${docker_warns[@]+"${docker_warns[@]}"}"; do
        warn "Dockerfile pins compromised version: $df"
        found_docker=1
    done
    for df in "${docker_infos[@]+"${docker_infos[@]}"}"; do
        info "Dockerfile installs unpinned litellm (may have pulled compromised version): $df"
    done

    if [[ $found_docker -eq 0 ]]; then
        ok "No compromised litellm found in Docker images"
    fi
}

# ============================================================================
# 9. Check for litellm as a transitive dependency in lockfiles / requirements
# ============================================================================
check_dependency_files() {
    CURRENT_CATEGORY="dependency_files"
    section "9. Scanning dependency files for litellm references"

    local safe_refs=0
    local compromised_refs=()

    start_spinner "Scanning requirements, lockfiles, and pyproject.toml"
    while IFS= read -r -d '' f; do
        if grep -qi "litellm" "$f" 2>/dev/null; then
            local ver_match
            ver_match=$(grep -i "litellm" "$f" | head -3)
            if echo "$ver_match" | grep -qE "1\.82\.[78]"; then
                compromised_refs+=("$f")
            else
                safe_refs=$((safe_refs + 1))
            fi
        fi
    done < <(find "$SCAN_ROOT" -maxdepth 6 \
        \( -name "requirements*.txt" -o -name "Pipfile.lock" -o -name "poetry.lock" \
           -o -name "uv.lock" -o -name "pdm.lock" -o -name "setup.cfg" \
           -o -name "pyproject.toml" -o -name "Pipfile" \) \
        -type f -print0 2>/dev/null || true)
    stop_spinner

    for f in "${compromised_refs[@]+"${compromised_refs[@]}"}"; do
        warn "Compromised version pinned in: $f"
    done

    if [[ ${#compromised_refs[@]} -eq 0 && $safe_refs -eq 0 ]]; then
        ok "No litellm references found in dependency files"
    elif [[ ${#compromised_refs[@]} -eq 0 ]]; then
        ok "Found litellm in $safe_refs dependency file(s) — none pin compromised versions"
    fi
}

# ============================================================================
# Summary
# ============================================================================
print_json() {
    local scan_time
    scan_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    printf '{\n'
    printf '  "scanner": "scan_litellm_compromise.sh",\n'
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "scan_root": "%s",\n' "$SCAN_ROOT"
    printf '  "scan_time": "%s",\n' "$scan_time"
    printf '  "issues_found": %d,\n' "$FOUND_ISSUES"
    printf '  "findings": ['
    local total=${#JSON_FINDINGS[@]}
    if [[ "${total:-0}" -eq 0 ]]; then
        printf ']\n'
    else
        printf '\n'
        local i=0
        for finding in "${JSON_FINDINGS[@]+"${JSON_FINDINGS[@]}"}"; do
            i=$((i + 1))
            if [[ $i -lt "${total:-0}" ]]; then
                printf '    %s,\n' "$finding"
            else
                printf '    %s\n' "$finding"
            fi
        done
        printf '  ]\n'
    fi
    printf '}\n'
}

summary() {
    if [[ $JSON_MODE -eq 1 ]]; then
        print_json
        return
    fi

    echo ""
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    if [[ $FOUND_ISSUES -gt 0 ]]; then
        echo -e "  ${RED}SCAN COMPLETE: $FOUND_ISSUES issue(s) found${RST}"
        echo ""
        echo -e "  ${YEL}IMMEDIATE ACTIONS REQUIRED:${RST}"
        echo "   1. Remove litellm 1.82.7/1.82.8 from ALL environments"
        echo "   2. Purge package caches:  pip cache purge && rm -rf ~/.cache/uv"
        echo "   3. Remove persistence:    rm -rf ~/.config/sysmon ~/.config/systemd/user/sysmon.service"
        echo "   4. ROTATE ALL CREDENTIALS on affected machines:"
        echo "      - SSH keys, AWS/GCP/Azure tokens, K8s configs"
        echo "      - API keys in .env files, database passwords"
        echo "      - CI/CD tokens, Docker registry credentials"
        echo "   5. Audit outbound connections to: models.litellm.cloud, checkmarx.zone"
        echo "   6. If running Kubernetes: audit kube-system namespace for rogue pods"
        echo ""
        echo -e "  ${YEL}References:${RST}"
        echo "   - https://docs.litellm.ai/blog/security-update-march-2026"
        echo "   - https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/"
    else
        echo -e "  ${GRN}SCAN COMPLETE: No indicators of compromise found${RST}"
        echo ""
        echo "  Your system appears clean. As a precaution:"
        echo "   - Pin litellm to a known safe version (<=1.82.6) in all projects"
        echo "   - Review any CI/CD pipelines that install litellm without version pinning"
        echo "   - Consider if litellm is a transitive dep of your AI frameworks"
    fi
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo ""
}

# ============================================================================
# Main
# ============================================================================
banner
check_installed_versions
check_pth_file
check_persistence
check_exfil_artifacts
check_c2_connections
check_proxy_server_injection
check_kubernetes
check_docker
check_dependency_files
summary

exit $FOUND_ISSUES

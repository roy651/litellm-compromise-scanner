#!/usr/bin/env bash
# ============================================================================
# LiteLLM Compromise Quick Triage (TeamPCP / March 24, 2026)
# ============================================================================
# Fast (~30s) early-warning check. Targets the highest-signal IOCs using
# known paths and active Python environments instead of scanning $HOME.
#
# What this covers:
#   - Active backdoor / persistence files  (instant)
#   - C2 domain indicators                 (instant)
#   - Exfiltration artifacts in /tmp       (instant)
#   - litellm version in active Python envs (seconds)
#   - Malicious .pth in active site-packages + caches (seconds)
#   - Injected proxy_server.py in active site-packages (seconds)
#   - Kubernetes rogue pods                (instant, if kubectl present)
#   - Docker image layers                  (seconds, if docker present)
#   - Dependency files in current dir      (seconds)
#
# Limitations vs full scan:
#   Will NOT find the compromised package buried in a nested venv or conda
#   environment outside your active Python. Run scan_litellm_compromise.sh
#   for comprehensive coverage once this triage is complete.
#
# Usage: ./quick_triage.sh [--json] [--quiet] [--no-color]
# ============================================================================

VERSION="1.0.0"

set -euo pipefail
trap 'stop_spinner 2>/dev/null; exit 130' INT TERM

# ── Flags ────────────────────────────────────────────────────────────────────
QUIET=0
JSON_MODE=0
NO_COLOR=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -q|--quiet)   QUIET=1; shift ;;
        --json)       JSON_MODE=1; shift ;;
        --no-color)   NO_COLOR=1; shift ;;
        -h|--help)
            echo "Usage: quick_triage.sh [--json] [--quiet] [--no-color]"
            echo "Fast (~30s) triage for the LiteLLM TeamPCP supply chain compromise."
            echo "Run scan_litellm_compromise.sh for full coverage."
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

[[ $JSON_MODE -eq 1 ]] && NO_COLOR=1
[[ -t 1 ]] || NO_COLOR=1

# ── Colors ───────────────────────────────────────────────────────────────────
if [[ $NO_COLOR -eq 0 ]]; then
    RED='\033[0;31m'; YEL='\033[0;33m'; GRN='\033[0;32m'
    CYN='\033[0;36m'; RST='\033[0m'
else
    RED='' YEL='' GRN='' CYN='' RST=''
fi

# ── State ────────────────────────────────────────────────────────────────────
FOUND_ISSUES=0
SPIN_PID=""
CURRENT_CATEGORY="general"
JSON_FINDINGS=()

# ── Output helpers ────────────────────────────────────────────────────────────
banner() {
    [[ $QUIET -eq 1 || $JSON_MODE -eq 1 ]] && return
    echo ""
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo -e "${CYN}  LiteLLM / TeamPCP Quick Triage  v${VERSION}${RST}"
    echo -e "${CYN}  Incident: 2026-03-24  |  Affected: litellm 1.82.7, 1.82.8${RST}"
    echo -e "${CYN}  ~30 second scan — active envs + known paths only${RST}"
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
    echo -e "  Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
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

start_spinner() {
    [[ $QUIET -eq 1 || $JSON_MODE -eq 1 ]] && return
    [[ -t 2 ]] || return
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

# ── Helper: collect active site-packages directories ─────────────────────────
# Queries each Python interpreter in PATH for its site-packages — no find needed.
collect_site_packages() {
    local sp_dirs=()
    for py_cmd in python3 python python3.13 python3.12 python3.11 python3.10; do
        if command -v "$py_cmd" &>/dev/null; then
            # avoid querying the same interpreter twice
            local dirs
            dirs=$("$py_cmd" -c \
                "import site, sys; dirs=getattr(site,'getsitepackages',lambda:[])(); dirs+=[site.getusersitepackages()]; print('\n'.join(set(dirs)))" \
                2>/dev/null) || true
            while IFS= read -r d; do
                [[ -n "$d" && -d "$d" ]] && sp_dirs+=("$d")
            done <<< "$dirs"
        fi
    done

    # Active virtualenv
    if [[ -n "${VIRTUAL_ENV:-}" && -d "$VIRTUAL_ENV/lib" ]]; then
        while IFS= read -r d; do
            [[ -n "$d" && -d "$d" ]] && sp_dirs+=("$d")
        done < <(find "$VIRTUAL_ENV/lib" -maxdepth 2 -name "site-packages" -type d 2>/dev/null || true)
    fi

    # uv active env
    if [[ -n "${UV_PROJECT_ENVIRONMENT:-}" && -d "$UV_PROJECT_ENVIRONMENT/lib" ]]; then
        while IFS= read -r d; do
            [[ -n "$d" && -d "$d" ]] && sp_dirs+=("$d")
        done < <(find "$UV_PROJECT_ENVIRONMENT/lib" -maxdepth 2 -name "site-packages" -type d 2>/dev/null || true)
    fi

    # Deduplicate
    local seen=() unique=()
    for d in "${sp_dirs[@]+"${sp_dirs[@]}"}"; do
        local real
        real=$(realpath "$d" 2>/dev/null || echo "$d")
        local already=0
        for s in "${seen[@]+"${seen[@]}"}"; do
            [[ "$s" == "$real" ]] && already=1 && break
        done
        if [[ $already -eq 0 ]]; then
            seen+=("$real")
            unique+=("$d")
        fi
    done

    printf '%s\n' "${unique[@]+"${unique[@]}"}"
}

# ============================================================================
# 1. Installed litellm versions — active Python envs only
# ============================================================================
check_installed_versions() {
    CURRENT_CATEGORY="installed_versions"
    section "1. Checking litellm version in active Python environments"

    local safe_count=0
    local found_bad=0

    start_spinner "Querying pip / active interpreters"

    # pip commands in PATH
    for cmd in pip pip3 pip3.10 pip3.11 pip3.12 pip3.13; do
        if command -v "$cmd" &>/dev/null; then
            local ver
            ver=$("$cmd" show litellm 2>/dev/null | grep -i '^Version:' | awk '{print $2}') || true
            if [[ -n "$ver" ]]; then
                if [[ "$ver" == "1.82.7" || "$ver" == "1.82.8" ]]; then
                    stop_spinner
                    warn "COMPROMISED litellm $ver via $(command -v "$cmd")"
                    found_bad=1
                    start_spinner "Continuing"
                else
                    safe_count=$((safe_count + 1))
                fi
            fi
        fi
    done

    # uv
    if command -v uv &>/dev/null; then
        local ver
        ver=$(uv pip show litellm 2>/dev/null | grep -i '^Version:' | awk '{print $2}') || true
        if [[ -n "$ver" ]]; then
            if [[ "$ver" == "1.82.7" || "$ver" == "1.82.8" ]]; then
                stop_spinner
                warn "COMPROMISED litellm $ver via uv pip"
                found_bad=1
                start_spinner "Continuing"
            else
                safe_count=$((safe_count + 1))
            fi
        fi
    fi

    # Direct METADATA check in active site-packages
    while IFS= read -r sp; do
        local meta
        meta=$(find "$sp" -maxdepth 2 -path "*/litellm-*.dist-info/METADATA" -type f 2>/dev/null | head -1)
        if [[ -n "$meta" ]]; then
            local ver
            ver=$(grep -i '^Version:' "$meta" 2>/dev/null | head -1 | awk '{print $2}') || true
            if [[ "$ver" == "1.82.7" || "$ver" == "1.82.8" ]]; then
                stop_spinner
                warn "COMPROMISED litellm $ver in site-packages: $sp"
                found_bad=1
                start_spinner "Continuing"
            elif [[ -n "$ver" ]]; then
                safe_count=$((safe_count + 1))
            fi
        fi
    done < <(collect_site_packages)

    stop_spinner

    if [[ $found_bad -eq 0 && $safe_count -eq 0 ]]; then
        ok "No litellm installations detected in active environments"
    elif [[ $found_bad -eq 0 ]]; then
        ok "Checked $safe_count litellm installation(s) in active envs — none compromised"
    fi

    info "Note: nested/inactive venvs not scanned — run full scan for complete coverage"
}

# ============================================================================
# 2. Malicious .pth file — active site-packages + caches
# ============================================================================
check_pth_file() {
    CURRENT_CATEGORY="pth_file"
    section "2. Searching for litellm_init.pth in active site-packages and caches"

    local found=0

    start_spinner "Checking site-packages and package caches"

    # Active site-packages
    while IFS= read -r sp; do
        if [[ -f "$sp/litellm_init.pth" ]]; then
            stop_spinner
            warn "Malicious .pth file found: $sp/litellm_init.pth"
            found=1
            start_spinner "Continuing"
        fi
    done < <(collect_site_packages)

    # uv cache — bounded depth (archive wheels are nested ~3-4 levels)
    if [[ -d "$HOME/.cache/uv" ]]; then
        while IFS= read -r -d '' pth; do
            warn "Malicious .pth in uv cache: $pth"
            found=1
        done < <(find "$HOME/.cache/uv" -maxdepth 5 -name "litellm_init.pth" -print0 2>/dev/null || true)
    fi

    # pip cache
    for cache_dir in "$HOME/.cache/pip" "$HOME/Library/Caches/pip"; do
        if [[ -d "$cache_dir" ]]; then
            while IFS= read -r -d '' pth; do
                warn "Malicious .pth in pip cache: $pth"
                found=1
            done < <(find "$cache_dir" -maxdepth 4 -name "litellm_init.pth" -print0 2>/dev/null || true)
        fi
    done

    stop_spinner

    [[ $found -eq 0 ]] && ok "No litellm_init.pth found in active site-packages or caches"
}

# ============================================================================
# 3. Persistence mechanisms (instant — fixed paths)
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
    fi
}

# ============================================================================
# 4. Exfiltration artifacts (instant — /tmp and /var/tmp only)
# ============================================================================
check_exfil_artifacts() {
    CURRENT_CATEGORY="exfil_artifacts"
    section "4. Searching for exfiltration artifacts in /tmp"

    local found=0

    while IFS= read -r -d '' f; do
        warn "Exfiltration archive found: $f"
        found=1
    done < <(find /tmp /var/tmp -name "tpcp.tar.gz" -type f -print0 2>/dev/null || true)

    while IFS= read -r -d '' f; do
        if grep -ql "base64\|litellm\|models\.litellm\|checkmarx\.zone" "$f" 2>/dev/null; then
            warn "Suspicious payload script: $f"
            found=1
        fi
    done < <(find /tmp /var/tmp -maxdepth 2 -name "p.py" -type f -print0 2>/dev/null || true)

    [[ $found -eq 0 ]] && ok "No exfiltration artifacts found in /tmp"
}

# ============================================================================
# 5. C2 domain indicators (instant)
# ============================================================================
check_c2_connections() {
    CURRENT_CATEGORY="c2_domains"
    section "5. Checking for C2 domain indicators"

    local c2_domains=("models.litellm.cloud" "checkmarx.zone")
    local found=0

    if command -v dscacheutil &>/dev/null; then
        for domain in "${c2_domains[@]}"; do
            if dscacheutil -cachedump 2>/dev/null | grep -qi "$domain"; then
                warn "C2 domain $domain found in DNS cache"
                found=1
            fi
        done
    fi

    for hist_file in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.local/share/fish/fish_history"; do
        if [[ -f "$hist_file" ]]; then
            for domain in "${c2_domains[@]}"; do
                if grep -q "$domain" "$hist_file" 2>/dev/null; then
                    warn "C2 domain $domain referenced in $hist_file"
                    found=1
                fi
            done
        fi
    done

    for domain in "${c2_domains[@]}"; do
        if grep -q "$domain" /etc/hosts 2>/dev/null; then
            info "C2 domain $domain in /etc/hosts (could be a block rule — verify manually)"
            found=1
        fi
    done

    if command -v ss &>/dev/null; then
        for domain in "${c2_domains[@]}"; do
            if ss -tunap 2>/dev/null | grep -qi "$domain"; then
                warn "ACTIVE connection to C2 domain: $domain"
                found=1
            fi
        done
    elif command -v netstat &>/dev/null; then
        for domain in "${c2_domains[@]}"; do
            if netstat -an 2>/dev/null | grep -qi "$domain"; then
                warn "Connection to C2 domain: $domain"
                found=1
            fi
        done
    fi

    [[ $found -eq 0 ]] && ok "No C2 domain indicators found"
}

# ============================================================================
# 6. Injected proxy_server.py — active site-packages only
# ============================================================================
check_proxy_server_injection() {
    CURRENT_CATEGORY="proxy_server_injection"
    section "6. Checking proxy_server.py in active site-packages (v1.82.7 vector)"

    local found=0

    start_spinner "Scanning active site-packages for proxy_server.py"

    while IFS= read -r sp; do
        local ps="$sp/litellm/proxy/proxy_server.py"
        if [[ -f "$ps" ]]; then
            if grep -ql "base64.b64decode\|subprocess.Popen.*b64decode\|exec(base64" "$ps" 2>/dev/null; then
                stop_spinner
                warn "Suspicious base64 exec in: $ps"
                found=1
                start_spinner "Continuing"
            fi
        fi
    done < <(collect_site_packages)

    stop_spinner

    [[ $found -eq 0 ]] && ok "No injected proxy_server.py in active site-packages"
}

# ============================================================================
# 7. Kubernetes (instant if kubectl present)
# ============================================================================
check_kubernetes() {
    CURRENT_CATEGORY="kubernetes"
    section "7. Checking Kubernetes indicators (if applicable)"

    if ! command -v kubectl &>/dev/null; then
        info "kubectl not found — skipping"
        return
    fi

    if ! kubectl cluster-info &>/dev/null 2>&1; then
        info "No active Kubernetes cluster connection — skipping"
        return
    fi

    local bad_pods
    bad_pods=$(kubectl get pods -n kube-system --no-headers 2>/dev/null | grep "^node-setup-" || true)
    if [[ -n "$bad_pods" ]]; then
        warn "Suspicious node-setup-* pods in kube-system:"
        while IFS= read -r line; do echo "       $line"; done <<< "$bad_pods"
    else
        ok "No suspicious node-setup-* pods in kube-system"
    fi

    local alpine_pods
    alpine_pods=$(kubectl get pods -n kube-system \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[0].image}{"\n"}{end}' 2>/dev/null \
        | grep -i "alpine" || true)
    if [[ -n "$alpine_pods" ]]; then
        warn "Alpine-based pods in kube-system (review manually):"
        while IFS= read -r line; do echo "       $line"; done <<< "$alpine_pods"
    fi
}

# ============================================================================
# 8. Docker image layer history (skips Dockerfile scan of $HOME)
# ============================================================================
check_docker() {
    CURRENT_CATEGORY="docker"
    section "8. Checking Docker images for compromised litellm"

    if ! command -v docker &>/dev/null; then
        info "Docker not found — skipping"
        return
    fi

    local found=0
    start_spinner "Scanning image layer history"
    while IFS= read -r image; do
        if docker history "$image" 2>/dev/null | grep -qi "litellm.*1\.82\.\(7\|8\)"; then
            stop_spinner
            warn "Docker image may contain compromised litellm: $image"
            found=1
            start_spinner "Continuing"
        fi
    done < <(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | head -50)
    stop_spinner

    [[ $found -eq 0 ]] && ok "No compromised litellm found in Docker image layers"
    info "Note: Dockerfile scan of \$HOME skipped — run full scan for complete coverage"
}

# ============================================================================
# 9. Dependency files — current directory only
# ============================================================================
check_dependency_files() {
    CURRENT_CATEGORY="dependency_files"
    section "9. Scanning dependency files in current directory"

    local safe_refs=0
    local found=0

    start_spinner "Scanning requirements/lockfiles in $(pwd)"
    while IFS= read -r -d '' f; do
        if grep -qi "litellm" "$f" 2>/dev/null; then
            local ver_match
            ver_match=$(grep -i "litellm" "$f" | head -3)
            if echo "$ver_match" | grep -qE "1\.82\.[78]"; then
                stop_spinner
                warn "Compromised version pinned in: $f"
                found=1
                start_spinner "Continuing"
            else
                safe_refs=$((safe_refs + 1))
            fi
        fi
    done < <(find "$(pwd)" -maxdepth 4 \
        \( -name "requirements*.txt" -o -name "Pipfile.lock" -o -name "poetry.lock" \
           -o -name "uv.lock" -o -name "pdm.lock" -o -name "setup.cfg" \
           -o -name "pyproject.toml" -o -name "Pipfile" \) \
        -type f -print0 2>/dev/null || true)
    stop_spinner

    if [[ $found -eq 0 && $safe_refs -eq 0 ]]; then
        ok "No litellm references found in dependency files"
    elif [[ $found -eq 0 ]]; then
        ok "Found litellm in $safe_refs dependency file(s) — none pin compromised versions"
    fi

    info "Note: only scanned current directory — run full scan for \$HOME coverage"
}

# ============================================================================
# Summary
# ============================================================================
print_json() {
    local scan_time
    scan_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    printf '{\n'
    printf '  "scanner": "quick_triage.sh",\n'
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "scan_time": "%s",\n' "$scan_time"
    printf '  "issues_found": %d,\n' "$FOUND_ISSUES"
    printf '  "findings": ['
    local total=${#JSON_FINDINGS[@]+"${#JSON_FINDINGS[@]}"}
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
        echo -e "  ${RED}TRIAGE COMPLETE: $FOUND_ISSUES issue(s) found — immediate action required${RST}"
        echo ""
        echo -e "  ${YEL}IMMEDIATE ACTIONS:${RST}"
        echo "   1. Remove litellm 1.82.7/1.82.8 from ALL environments"
        echo "   2. Purge caches:  pip cache purge && rm -rf ~/.cache/uv"
        echo "   3. Remove persistence:  rm -rf ~/.config/sysmon ~/.config/systemd/user/sysmon.service"
        echo "   4. ROTATE ALL CREDENTIALS (SSH, AWS/GCP/Azure, K8s, .env files, CI/CD tokens)"
        echo "   5. Audit outbound connections to: models.litellm.cloud, checkmarx.zone"
        echo ""
        echo -e "  ${YEL}Then run the full scan to check inactive venvs and \$HOME:${RST}"
        echo "   ./scan_litellm_compromise.sh"
    else
        echo -e "  ${GRN}TRIAGE COMPLETE: No indicators of compromise found in active environments${RST}"
        echo ""
        echo "  Active Python environments appear clean."
        echo -e "  ${YEL}For complete coverage (inactive venvs, full \$HOME):${RST}"
        echo "   ./scan_litellm_compromise.sh"
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

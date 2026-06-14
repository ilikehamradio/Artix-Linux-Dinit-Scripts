#!/usr/bin/env bash
#
# aur-atomic-arch-audit.sh
#
# Comprehensive auditor for the June 2026 "Atomic Arch" AUR supply-chain attack.
# Designed for Arch-based systems (Artix, Arch, Manjaro, EndeavourOS, etc.)
# with first-class support for dinit, plus systemd, runit, openrc, and s6.
#
# Usage:
#   ./aur-atomic-arch-audit.sh                 # standard audit
#   ./aur-atomic-arch-audit.sh --full          # include slow/deep scans
#   ./aur-atomic-arch-audit.sh --refresh       # fetch latest compromised list
#   ./aur-atomic-arch-audit.sh --output FILE   # save report to file
#   ./aur-atomic-arch-audit.sh --cscs-only      # run only the CSCS forum checker
#
# Exit codes:
#   0  clean (no indicators)
#   1  warnings only (inconclusive / needs manual review)
#   2  critical indicators found (treat as compromised)
#   3  script/runtime error
#
# References:
#   https://github.com/lenucksi/aur-malware-check
#   https://cscs.pastes.sh/aurvulntest20260611.sh  (commonsourcecs forum checker)
#   https://ioctl.fail/preliminary-analysis-of-aur-malware/
#   https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency

set -o pipefail

VERSION="1.1.1"
SCRIPT_NAME="$(basename "$0")"

# --- Attack window defaults (override with env vars) ---
ATTACK_START_DATE="${ATTACK_START_DATE:-2026-06-09}"
ATTACK_END_DATE="${ATTACK_END_DATE:-2026-06-14}"
ATTACK_START_EPOCH="$(date -d "$ATTACK_START_DATE 00:00:00" +%s 2>/dev/null || echo 0)"
ATTACK_END_EPOCH="$(date -d "$ATTACK_END_DATE 23:59:59" +%s 2>/dev/null || echo 9999999999)"

# --- Known IOCs ---
HASH_DEPS_ATOMIC="6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
HASH_DEPS_JS_DIGEST="7883bda1ff15425f2dbbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316"
HASH_CRYPTOMINER="47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204"
DEPS_SIZE=3040376
ONION_C2="olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion"

MALICIOUS_NPM_PKGS=(atomic-lockfile lockfile-js js-digest)
MALICIOUS_NPM_VERSION="1.4.2"
MALICIOUS_AUR_ACCOUNTS=(
    krisztinavarga franziskaweber tobiaswesterburg ellenmyklebust
    custodiatovar veramagalhaes
)

PACKAGE_LIST_URL="${PACKAGE_LIST_URL:-https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/package_list.txt}"
COMMUNITY_CHECK_URL="${COMMUNITY_CHECK_URL:-https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/aur_check-v2.sh}"
CSCS_PASTE_URL="${CSCS_PASTE_URL:-https://cscs.pastes.sh/raw/aurvulntest20260611.sh}"
IOC_URL="${IOC_URL:-https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/iocs.txt}"

# --- Runtime state ---
FULL_SCAN=false
REFRESH_LIST=false
USE_SUDO=false
OUTPUT_FILE=""
WORK_DIR=""
PACKAGE_LIST_FILE=""
COMMUNITY_SCRIPT=""
CSCS_SCRIPT=""
CSCS_ONLY=false
QUIET=false

CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0
SECTION=0
TOTAL_SECTIONS=21

# --- Colors (disabled when not a tty or NO_COLOR set) ---
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

log() {
    local level="$1"; shift
    local msg="$*"
    local prefix=""
    case "$level" in
        CRITICAL) prefix="${RED}${BOLD}[CRITICAL]${NC}"; CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
        WARNING)  prefix="${YELLOW}[WARNING]${NC}";  WARNING_COUNT=$((WARNING_COUNT + 1)) ;;
        OK)       prefix="${GREEN}[OK]${NC}" ;;
        INFO)     prefix="${BLUE}[INFO]${NC}";  INFO_COUNT=$((INFO_COUNT + 1)) ;;
        SECTION)  prefix="${CYAN}${BOLD}"; ;;
        *)        prefix="[LOG]" ;;
    esac
    if [[ "$level" == "SECTION" ]]; then
        SECTION=$((SECTION + 1))
        echo -e "\n${prefix}=== [$SECTION/$TOTAL_SECTIONS] $msg ===${NC}"
    else
        echo -e "$prefix $msg"
    fi
    if [[ -n "$OUTPUT_FILE" ]]; then
        # Strip ANSI for file output
        echo "[$level] $msg" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE"
    fi
}

die() {
    log CRITICAL "$*"
    exit 3
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

is_epoch_in_attack_window() {
    local epoch="$1"
    [[ -n "$epoch" && "$epoch" -ge "$ATTACK_START_EPOCH" && "$epoch" -le "$ATTACK_END_EPOCH" ]]
}

# Parse "Install Date" from pacman -Qi (locale-independent via epoch)
pkg_install_epoch() {
    local pkg="$1"
    local install_date
    install_date="$(pacman -Qi "$pkg" 2>/dev/null | awk -F': ' '/^Install Date/{print $2}')"
    [[ -n "$install_date" ]] && date -d "$install_date" +%s 2>/dev/null
}

# Load compromised package names from a plain-text list (one per line)
load_infected_pkg_array() {
    local list_file="$1"
    local -n _out_arr="$2"
    _out_arr=()
    [[ -f "$list_file" && -s "$list_file" ]] || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line// /}"
        [[ -n "$line" ]] && _out_arr+=("$line")
    done < "$list_file"
}

# Extract INFECTED_PKGS=(...) array from cscs paste script
extract_cscs_pkg_array_from_script() {
    local script_file="$1"
    local -n _out_arr="$2"
    _out_arr=()
    [[ -f "$script_file" ]] || return 1
    local in_array=false
    while IFS= read -r line; do
        if [[ "$line" =~ ^INFECTED_PKGS=\( ]]; then
            in_array=true
            continue
        fi
        if $in_array; then
            if [[ "$line" == ")" ]]; then
                break
            fi
            local pkg="${line// /}"
            pkg="${pkg//\"/}"
            [[ -n "$pkg" ]] && _out_arr+=("$pkg")
        fi
    done < "$script_file"
}

parse_pacman_log_date_epoch() {
    # pacman.log format: [2026-06-10T10:47:26-0500]
    local line="$1"
    if [[ "$line" =~ ^\[([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2}) ]]; then
        date -d "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}" +%s 2>/dev/null
    fi
}

parse_pacman_install_date_epoch() {
    local install_date="$1"
    date -d "$install_date" +%s 2>/dev/null
}

package_install_epoch() {
    local pkg="$1"
    local install_date
    install_date="$(pacman -Qi "$pkg" 2>/dev/null | awk -F': ' '/Install Date/{print $2}')"
    parse_pacman_install_date_epoch "$install_date"
}

is_cscs_campaign_month_day() {
    # Matches commonsourcecs forum script: Jun 9-14 install dates
    local install_date="$1"
    echo "$install_date" | grep -qE 'Jun (9|10|11|12|13|14)[[:space:]]'
}

run_privileged() {
    if $USE_SUDO && have_cmd sudo; then
        sudo -n "$@" 2>/dev/null || sudo "$@" 2>/dev/null
    else
        return 1
    fi
}

usage() {
    cat <<EOF
${BOLD}${SCRIPT_NAME}${NC} v${VERSION}
Comprehensive auditor for the June 2026 AUR "Atomic Arch" malware campaign.

${BOLD}USAGE${NC}
  $SCRIPT_NAME [OPTIONS]

${BOLD}OPTIONS${NC}
  --full           Enable slow/deep scans (full-home string grep, large hash sweep)
  --refresh        Download latest compromised package list from GitHub
  --sudo           Attempt privileged checks (bpftool, /var/lib, system systemd)
  --output FILE    Write plain-text report to FILE (in addition to stdout)
  --workdir DIR    Use DIR for cached downloads (default: \$TMPDIR/aur-audit-XXXX)
  --package-list F Use local compromised-package list instead of bundled default
  --quiet          Suppress INFO lines (still show warnings/criticals)
  --cscs-only      Run only the CSCS forum checker (aurvulntest20260611.sh)
  --help           Show this help

  Integrates aur-malware-check (lenucksi) and the CSCS forum checker
  (cscs.pastes.sh/aurvulntest20260611.sh) date-window logic.

${BOLD}ENVIRONMENT${NC}
  ATTACK_START_DATE   Default: 2026-06-09
  ATTACK_END_DATE     Default: 2026-06-14 (matches CSCS forum script)
  PACKAGE_LIST_URL    Remote list URL for --refresh
  NO_COLOR            Disable ANSI colors

${BOLD}EXIT CODES${NC}
  0  clean    1  warnings    2  critical    3  error

${BOLD}ARTIX / DINIT${NC}
  This script explicitly scans /etc/dinit.d, ~/.config/dinit.d, and user session
  services. It also checks runit, openrc, s6, and systemd paths when present.

EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --full) FULL_SCAN=true ;;
            --refresh) REFRESH_LIST=true ;;
            --sudo) USE_SUDO=true ;;
            --quiet) QUIET=true ;;
            --cscs-only) CSCS_ONLY=true ;;
            --output) OUTPUT_FILE="$2"; shift ;;
            --workdir) WORK_DIR="$2"; shift ;;
            --package-list) PACKAGE_LIST_FILE="$2"; shift ;;
            --help|-h) usage; exit 0 ;;
            *) die "Unknown argument: $1 (use --help)" ;;
        esac
        shift
    done
}

setup_workdir() {
    if [[ -z "$WORK_DIR" ]]; then
        WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aur-audit.XXXXXX")"
    else
        mkdir -p "$WORK_DIR" || die "Cannot create workdir: $WORK_DIR"
    fi

    if [[ -z "$PACKAGE_LIST_FILE" ]]; then
        PACKAGE_LIST_FILE="$WORK_DIR/package_list.txt"
    fi

    if ! $CSCS_ONLY; then
        if [[ ! -f "$PACKAGE_LIST_FILE" || ! -s "$PACKAGE_LIST_FILE" || "$REFRESH_LIST" == true ]]; then
            if have_cmd curl; then
                log INFO "Downloading compromised package list (~1900 packages)..."
                if ! curl -fsSL -o "$PACKAGE_LIST_FILE" "$PACKAGE_LIST_URL"; then
                    if [[ ! -s "$PACKAGE_LIST_FILE" ]]; then
                        die "Failed to download package list from $PACKAGE_LIST_URL"
                    fi
                    log WARNING "Download failed; using cached list at $PACKAGE_LIST_FILE"
                else
                    local pkg_count
                    pkg_count="$(wc -l < "$PACKAGE_LIST_FILE" | tr -d ' ')"
                    log OK "Downloaded package list ($pkg_count entries)"
                fi
            elif [[ ! -s "$PACKAGE_LIST_FILE" ]]; then
                die "No package list available. Install curl or pass --package-list /path/to/package_list.txt"
            fi
        elif [[ ! -f "$PACKAGE_LIST_FILE" ]]; then
            die "Package list not found: $PACKAGE_LIST_FILE"
        fi
    fi

    if have_cmd curl; then
        if ! $CSCS_ONLY; then
            curl -fsSL -o "$WORK_DIR/aur_check-v2.sh" "$COMMUNITY_CHECK_URL" 2>/dev/null && \
                chmod +x "$WORK_DIR/aur_check-v2.sh" && \
                COMMUNITY_SCRIPT="$WORK_DIR/aur_check-v2.sh" || true
            curl -fsSL -o "$WORK_DIR/malicious_npm_packages.txt" \
                "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/malicious_npm_packages.txt" 2>/dev/null || true
        fi
        curl -fsSL -o "$WORK_DIR/aurvulntest20260611.sh" "$CSCS_PASTE_URL" 2>/dev/null && \
            CSCS_SCRIPT="$WORK_DIR/aurvulntest20260611.sh" || true
    fi
}

init_report() {
    if [[ -n "$OUTPUT_FILE" ]]; then
        mkdir -p "$(dirname "$OUTPUT_FILE")" 2>/dev/null || true
        {
            echo "AUR Atomic Arch Comprehensive Audit Report"
            echo "=========================================="
            echo "Script: $SCRIPT_NAME v$VERSION"
            echo "Host: $(hostname 2>/dev/null || echo unknown)"
            echo "User: $(whoami 2>/dev/null || echo unknown)"
            echo "Date: $(date -Iseconds 2>/dev/null || date)"
            echo "Attack window: $ATTACK_START_DATE .. $ATTACK_END_DATE"
            echo ""
        } > "$OUTPUT_FILE"
    fi
}

# ---------------------------------------------------------------------------
section_system_info() {
    log SECTION "System identification"

    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        log INFO "OS: ${PRETTY_NAME:-$NAME} (${ID:-unknown})"
    else
        log WARNING "/etc/os-release not found"
    fi

    log INFO "Kernel: $(uname -r 2>/dev/null || echo unknown)"
    log INFO "Architecture: $(uname -m 2>/dev/null || echo unknown)"
    log INFO "Hostname: $(hostname 2>/dev/null || echo unknown)"

    local init_sys="unknown"
    if [[ -d /etc/dinit.d ]]; then init_sys="dinit"; fi
    if [[ -d /etc/runit ]]; then init_sys="${init_sys}/runit"; fi
    if [[ -d /etc/s6 ]]; then init_sys="${init_sys}/s6"; fi
    if [[ -d /etc/init.d && -f /etc/rc.conf ]]; then init_sys="${init_sys}/openrc"; fi
    if have_cmd systemctl; then init_sys="${init_sys}/systemd"; fi
    log INFO "Detected init stack: $init_sys"

    local aur_helper=""
    for h in yay paru pamac trizen aura; do
        if have_cmd "$h"; then aur_helper+="$h "; fi
    done
    if [[ -n "$aur_helper" ]]; then
        log INFO "AUR helpers: $aur_helper"
    else
        log WARNING "No common AUR helper found in PATH"
    fi

    if ! have_cmd pacman; then
        die "pacman not found — this script requires pacman"
    fi
}

# ---------------------------------------------------------------------------
section_prerequisites() {
    log SECTION "Tool availability"

    local optional_tools=(curl rg sha256sum ss journalctl bpftool find npm bun secret-tool)
    for t in "${optional_tools[@]}"; do
        if have_cmd "$t"; then
            [[ "$QUIET" == false ]] && log OK "$t available"
        else
            [[ "$QUIET" == false ]] && log INFO "$t not available (some checks skipped)"
        fi
    done

    if $REFRESH_LIST && ! have_cmd curl; then
        die "--refresh requires curl"
    fi
}

# ---------------------------------------------------------------------------
section_community_checker() {
    log SECTION "Community aur-malware-check integration"

    if [[ -x "$COMMUNITY_SCRIPT" && -f "$PACKAGE_LIST_FILE" && -s "$PACKAGE_LIST_FILE" ]]; then
        local npm_list="$WORK_DIR/malicious_npm_packages.txt"
        [[ -f "$npm_list" ]] || npm_list="/dev/null"

        log INFO "Running aur_check-v2.sh --full --all-time..."
        local out rc
        out="$(PACKAGE_LIST_FILE="$PACKAGE_LIST_FILE" MALICIOUS_NPM_LIST="$npm_list" \
            "$COMMUNITY_SCRIPT" --full --all-time 2>&1)" || rc=$?
        rc=${rc:-0}

        if [[ "$QUIET" == false ]]; then
            echo "$out" | sed 's/^/  /'
        fi

        if echo "$out" | grep -qi "RESULT: CLEAN"; then
            log OK "Community checker: CLEAN"
        elif echo "$out" | grep -qiE "INFECTED|indicators detected|COMPROMISED"; then
            log CRITICAL "Community checker reported indicators — see output above"
        elif [[ "$rc" -eq 2 ]]; then
            log CRITICAL "Community checker exit code 2 (infected)"
        else
            log WARNING "Community checker inconclusive (exit $rc)"
        fi

        log INFO "Running aur_check-v2.sh with attack-window filter..."
        out="$(PACKAGE_LIST_FILE="$PACKAGE_LIST_FILE" MALICIOUS_NPM_LIST="$npm_list" \
            ATTACK_START_DATE="$ATTACK_START_DATE" ATTACK_END_DATE="$ATTACK_END_DATE" \
            "$COMMUNITY_SCRIPT" --full 2>&1)" || rc=$?
        rc=${rc:-0}
        if echo "$out" | grep -qi "RESULT: CLEAN"; then
            log OK "Community checker (date window): CLEAN"
        elif [[ "$rc" -eq 2 ]]; then
            log CRITICAL "Community checker (date window) exit code 2"
        fi
    else
        if [[ ! -s "$PACKAGE_LIST_FILE" ]]; then
            log WARNING "Skipped community checker — no package list (use --refresh)"
        else
            log WARNING "Skipped community checker — script not downloaded (need curl)"
        fi
    fi
}

# ---------------------------------------------------------------------------
section_installed_foreign_packages() {
    log SECTION "Installed foreign (AUR) packages vs compromised list"

    if [[ ! -s "$PACKAGE_LIST_FILE" ]]; then
        log WARNING "No package list — skipping cross-reference"
        return
    fi

    local foreign
    foreign="$(pacman -Qmq 2>/dev/null | sort -u)"
    if [[ -z "$foreign" ]]; then
        log OK "No foreign packages installed"
        return
    fi

    local count
    count="$(echo "$foreign" | wc -l)"
    log INFO "Foreign packages installed: $count"
    [[ "$QUIET" == false ]] && echo "$foreign" | sed 's/^/  /'

    local matches
    matches="$(comm -12 <(echo "$foreign") <(sort -u "$PACKAGE_LIST_FILE"))"
    if [[ -n "$matches" ]]; then
        local in_window=() out_of_window=()
        while read -r pkg; do
            [[ -z "$pkg" ]] && continue
            local epoch install_date
            install_date="$(pacman -Qi "$pkg" 2>/dev/null | awk -F': ' '/Install Date/{print $2}')"
            epoch="$(package_install_epoch "$pkg")"
            if is_epoch_in_attack_window "$epoch"; then
                in_window+=("$pkg")
            else
                out_of_window+=("$pkg")
            fi
        done <<< "$matches"

        if [[ ${#in_window[@]} -gt 0 ]]; then
            log CRITICAL "Installed compromised-list packages within attack window:"
            printf '  %s\n' "${in_window[@]}"
            for pkg in "${in_window[@]}"; do
                pacman -Qi "$pkg" 2>/dev/null | grep -E 'Name|Version|Install Date|Packager' | sed 's/^/    /'
            done
        fi
        if [[ ${#out_of_window[@]} -gt 0 ]]; then
            log WARNING "On compromised list but installed OUTSIDE attack window (lower risk — verify PKGBUILD):"
            printf '  %s\n' "${out_of_window[@]}"
        fi
        [[ ${#in_window[@]} -eq 0 && ${#out_of_window[@]} -gt 0 ]] && \
            log INFO "No in-window installs; CSCS forum checker would also report clean"
    else
        log OK "No installed foreign packages match compromised list"
    fi
}

# Run the original CSCS forum paste script verbatim and return its output.
run_original_cscs_script() {
    [[ -f "$CSCS_SCRIPT" ]] || return 1
    bash "$CSCS_SCRIPT" 2>&1
}

# Map CSCS script output to exit code: 0 clean, 1 warning/infected, 3 error
cscs_script_exit_code() {
    local out="$1"
    if echo "$out" | grep -qi '^Clean:'; then
        return 0
    elif echo "$out" | grep -qi '^WARNING:'; then
        return 1
    fi
    return 3
}

# ---------------------------------------------------------------------------
# commonsourcecs forum checker (https://cscs.pastes.sh/aurvulntest20260611.sh)
# Batch pacman -Qq cross-reference + install-date window filter (Jun 9-14).
# ---------------------------------------------------------------------------
section_cscs_forum_checker() {
    log SECTION "CSCS forum checker (commonsourcecs date-window)"

    if [[ ! -f "$CSCS_SCRIPT" ]]; then
        log WARNING "CSCS paste script not downloaded (need curl) — using package_list.txt fallback"
    fi

    # Always run the original forum script when available (fast, matches Cachy forum workflow)
    if [[ -f "$CSCS_SCRIPT" ]]; then
        log INFO "Running original CSCS paste script (aurvulntest20260611.sh)..."
        local cscs_out
        cscs_out="$(run_original_cscs_script)" || true
        if [[ -n "$cscs_out" ]]; then
            if [[ "$QUIET" == false ]]; then
                echo "$cscs_out" | sed 's/^/  /'
            fi
            if echo "$cscs_out" | grep -qi '^Clean:'; then
                log OK "Original CSCS script: CLEAN"
            elif echo "$cscs_out" | grep -qi '^WARNING:'; then
                log CRITICAL "Original CSCS script reported possibly infected packages"
            fi
        fi
    fi

    local list_count=0
    if [[ -s "$PACKAGE_LIST_FILE" ]]; then
        list_count="$(wc -l < "$PACKAGE_LIST_FILE" | tr -d ' ')"
    fi

    # Ported CSCS logic: batch pacman -Qq against full infected list, then date filter
    local infected_pkgs=()
    if [[ -f "$CSCS_SCRIPT" ]] && extract_cscs_pkg_array_from_script "$CSCS_SCRIPT" infected_pkgs \
        && [[ ${#infected_pkgs[@]} -gt 0 ]]; then
        log INFO "Enhanced check using INFECTED_PKGS from CSCS paste (${#infected_pkgs[@]} entries)"
    elif [[ -s "$PACKAGE_LIST_FILE" ]]; then
        load_infected_pkg_array "$PACKAGE_LIST_FILE" infected_pkgs || true
        log INFO "Enhanced check using package_list.txt (${#infected_pkgs[@]} entries)"
    else
        log WARNING "No package list — skipping enhanced CSCS check"
        return
    fi

    log INFO "Checking for infected AUR packages (${#infected_pkgs[@]} on list)..."

    local installed_on_list=""
    if [[ ${#infected_pkgs[@]} -gt 0 ]]; then
        # CSCS core: pacman -Qq "${INFECTED_PKGS[@]}" — only returns installed matches
        installed_on_list="$(pacman -Qq "${infected_pkgs[@]}" 2>/dev/null | sort -u)"
    else
        installed_on_list="$(comm -12 <(pacman -Qmq 2>/dev/null | sort -u) <(sort -u "$PACKAGE_LIST_FILE"))"
    fi

    if [[ -z "$installed_on_list" ]]; then
        log OK "CSCS enhanced: Clean — none of the ${#infected_pkgs[@]} known infected packages are installed"
        return
    fi

    local found=() found_cscs_grep=()
    while read -r pkg; do
        [[ -z "$pkg" ]] && continue
        local install_date epoch
        install_date="$(pacman -Qi "$pkg" 2>/dev/null | awk -F': ' '/Install Date/{print $2}')"
        epoch="$(parse_pacman_install_date_epoch "$install_date")"

        # Primary: epoch-based attack window (configurable via env)
        if is_epoch_in_attack_window "$epoch"; then
            found+=("$pkg")
        fi
        # Secondary: reproduce CSCS grep-on-Install-Date quirk for audit trail
        if is_cscs_campaign_month_day "$install_date"; then
            found_cscs_grep+=("$pkg")
        fi
    done <<< "$installed_on_list"

    local installed_count
    installed_count="$(echo "$installed_on_list" | wc -l | tr -d ' ')"
    log INFO "$installed_count compromised-list package(s) installed (any date)"

    if [[ ${#found[@]} -eq 0 ]]; then
        log OK "CSCS: Clean — none installed during campaign window ($ATTACK_START_DATE .. $ATTACK_END_DATE)"
        if [[ ${#found_cscs_grep[@]} -gt 0 && "$QUIET" == false ]]; then
            log INFO "Note: CSCS Jun-grep would flag ${#found_cscs_grep[@]} pkg(s) but epoch window did not"
        fi
    else
        log CRITICAL "CSCS: ${#found[@]} possibly infected package(s) installed during campaign window:"
        for pkg in "${found[@]}"; do
            echo "  - $pkg"
            pacman -Qi "$pkg" 2>/dev/null | grep -E 'Version|Install Date' | sed 's/^/      /'
        done
    fi
}

# ---------------------------------------------------------------------------
section_pacman_log_history() {
    log SECTION "pacman.log historical analysis (attack window)"

    local log_files=()
    [[ -f /var/log/pacman.log ]] && log_files+=("/var/log/pacman.log")

    for f in /var/log/pacman.log.*; do
        [[ -f "$f" ]] && log_files+=("$f")
    done

    if [[ ${#log_files[@]} -eq 0 ]]; then
        log WARNING "No pacman.log found"
        return
    fi

    log INFO "Scanning ${#log_files[@]} log file(s)"

    local tmp_all="$WORK_DIR/pacman_window.txt"
    : > "$tmp_all"

    for lf in "${log_files[@]}"; do
        if [[ "$lf" == *.gz ]]; then
            have_cmd zgrep && zgrep -E '^\[20[0-9]{2}-' "$lf" 2>/dev/null >> "$tmp_all" || true
        elif [[ "$lf" == *.xz ]]; then
            have_cmd xzgrep && xzgrep -E '^\[20[0-9]{2}-' "$lf" 2>/dev/null >> "$tmp_all" || true
        elif [[ "$lf" == *.zst ]]; then
            have_cmd zstdgrep && zstdgrep -E '^\[20[0-9]{2}-' "$lf" 2>/dev/null >> "$tmp_all" || true
        else
            grep -E '^\[20[0-9]{2}-' "$lf" 2>/dev/null >> "$tmp_all" || true
        fi
    done

    local window_lines=()
    while IFS= read -r line; do
        local epoch
        epoch="$(parse_pacman_log_date_epoch "$line")"
        if is_epoch_in_attack_window "$epoch"; then
            window_lines+=("$line")
        fi
    done < "$tmp_all"

    log INFO "Log lines in attack window: ${#window_lines[@]}"

    # AUR installs via yay/paru (pacman -U)
    local aur_installs=()
    for line in "${window_lines[@]}"; do
        if echo "$line" | grep -qE 'pacman -U'; then
            if echo "$line" | grep -qE 'yay/|paru/|\.cache/(yay|paru)/'; then
                aur_installs+=("$line")
            fi
        fi
    done

    if [[ ${#aur_installs[@]} -gt 0 ]]; then
        log INFO "AUR package installs/upgrades during attack window:"
        printf '  %s\n' "${aur_installs[@]}"

        if [[ -s "$PACKAGE_LIST_FILE" ]]; then
            local aur_pkgs=()
            for line in "${aur_installs[@]}"; do
                while read -r pkg; do
                    [[ -n "$pkg" ]] && aur_pkgs+=("$pkg")
                done < <(echo "$line" | grep -oE '(yay|paru)/[^/]+' | sed 's|.*/||' | sort -u)
            done
            local aur_matches=()
            for pkg in $(printf '%s\n' "${aur_pkgs[@]}" | sort -u); do
                if grep -qx "$pkg" "$PACKAGE_LIST_FILE"; then
                    aur_matches+=("$pkg")
                fi
            done
            if [[ ${#aur_matches[@]} -gt 0 ]]; then
                log CRITICAL "AUR packages installed during window AND on compromised list:"
                printf '  %s\n' "${aur_matches[@]}"
            else
                log OK "AUR activity during window — none on compromised list"
            fi
        fi
    else
        log OK "No yay/paru installs logged during attack window"
    fi

    # ALPM installed/upgraded foreign during window
    local foreign_changes=()
    for line in "${window_lines[@]}"; do
        if echo "$line" | grep -qE '\[ALPM\] (installed|upgraded|reinstalled)'; then
            foreign_changes+=("$line")
        fi
    done

    if [[ ${#foreign_changes[@]} -gt 0 && "$QUIET" == false ]]; then
        log INFO "All ALPM install/upgrade events in window (review for foreign pkgs):"
        printf '  %s\n' "${foreign_changes[@]}" | head -60
        [[ ${#foreign_changes[@]} -gt 60 ]] && log INFO "... and $((${#foreign_changes[@]} - 60)) more"
    fi
}

# ---------------------------------------------------------------------------
section_yay_paru_cache() {
    log SECTION "yay/paru build cache inspection"

    local cache_roots=()
    [[ -d "$HOME/.cache/yay" ]] && cache_roots+=("$HOME/.cache/yay")
    [[ -d "$HOME/.cache/paru" ]] && cache_roots+=("$HOME/.cache/paru")

    if [[ ${#cache_roots[@]} -eq 0 ]]; then
        log INFO "No yay/paru cache directories found"
        return
    fi

    local pattern='atomic-lockfile|lockfile-js|js-digest|herbsobering|npm install atomic|bun install js'
    local hits
    hits="$(grep -rE "$pattern" "${cache_roots[@]}" 2>/dev/null || true)"

    if [[ -n "$hits" ]]; then
        log CRITICAL "Malware strings found in yay/paru cache:"
        echo "$hits" | sed 's/^/  /'
    else
        log OK "No malware strings in yay/paru caches"
    fi

    # Per-package PKGBUILD / .install / .hook scan
    local malicious_pkgs=()
    for root in "${cache_roots[@]}"; do
        for dir in "$root"/*/; do
            [[ -d "$dir" ]] || continue
            local pkg
            pkg="$(basename "$dir")"
            [[ "$pkg" == "completion.cache" || "$pkg" == "vcs.json" ]] && continue
            if find "$dir" -maxdepth 3 \( -name PKGBUILD -o -name '*.install' -o -name '*.hook' \) \
                -exec grep -lE "$pattern" {} \; 2>/dev/null | grep -q .; then
                malicious_pkgs+=("$pkg")
            fi
        done
    done

    if [[ ${#malicious_pkgs[@]} -gt 0 ]]; then
        log CRITICAL "Cache directories with malicious build files: ${malicious_pkgs[*]}"
    fi

    # Cache dir names vs compromised list
    if [[ -s "$PACKAGE_LIST_FILE" ]]; then
        for root in "${cache_roots[@]}"; do
            local overlap
            overlap="$(comm -12 <(ls "$root" 2>/dev/null | grep -vE 'completion.cache|vcs.json' | sort) \
                <(sort -u "$PACKAGE_LIST_FILE"))"
            if [[ -n "$overlap" ]]; then
                log WARNING "Cache dirs matching compromised list (may be old builds):"
                echo "$overlap" | sed 's/^/  /'
            fi
        done
    fi

    # npm/bun in any PKGBUILD
    local npm_builds
    npm_builds="$(grep -rE 'npm install|bun install|npx ' "${cache_roots[@]}"/*/PKGBUILD \
        "${cache_roots[@]}"/*/*.install 2>/dev/null | grep -vE '^#|node-|nodejs' || true)"
    if [[ -n "$npm_builds" && "$FULL_SCAN" == true ]]; then
        log INFO "PKGBUILDs containing npm/bun install (review manually):"
        echo "$npm_builds" | sed 's/^/  /' | head -30
    fi
}

# ---------------------------------------------------------------------------
section_live_aur_pkgbuild_fetch() {
    log SECTION "Live AUR PKGBUILD fetch for installed foreign packages"

    if ! have_cmd curl; then
        log WARNING "curl not available — skipping live PKGBUILD fetch"
        return
    fi

    local foreign
    foreign="$(pacman -Qmq 2>/dev/null)"
    [[ -z "$foreign" ]] && return

    local pattern='atomic-lockfile|lockfile-js|js-digest|herbsobering'
    local bad=()

    for pkg in $foreign; do
        local body
        body="$(curl -fsSL --max-time 15 "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=$pkg" 2>/dev/null || true)"
        if [[ -z "$body" ]]; then
            log INFO "Could not fetch current PKGBUILD for $pkg (may not be on AUR)"
            continue
        fi
        if echo "$body" | grep -qE "$pattern"; then
            bad+=("$pkg")
            log CRITICAL "Current AUR PKGBUILD for $pkg contains malware strings!"
        fi

        # Also fetch .install if referenced
        if echo "$body" | grep -qE '\.install'; then
            local install_file
            install_file="$(echo "$body" | grep -oE '[a-zA-Z0-9_.-]+\.install' | head -1)"
            if [[ -n "$install_file" ]]; then
                local ibody
                ibody="$(curl -fsSL --max-time 15 \
                    "https://aur.archlinux.org/cgit/aur.git/plain/$install_file?h=$pkg" 2>/dev/null || true)"
                if echo "$ibody" | grep -qE "$pattern"; then
                    bad+=("${pkg}:${install_file}")
                    log CRITICAL "Current AUR $install_file for $pkg contains malware strings!"
                fi
            fi
        fi
    done

    if [[ ${#bad[@]} -eq 0 ]]; then
        log OK "Live AUR PKGBUILDs for installed foreign packages: clean"
    fi
}

# ---------------------------------------------------------------------------
section_npm_bun_cache() {
    log SECTION "npm and bun cache / global module check"

    local found=()

    for pkg in "${MALICIOUS_NPM_PKGS[@]}"; do
        for base in "$HOME/.npm" "$HOME/.cache/npm" /usr/lib/node_modules /usr/local/lib/node_modules; do
            [[ -d "$base" ]] || continue
            while IFS= read -r match; do
                [[ -n "$match" ]] && found+=("$match")
            done < <(find "$base" -iname "*${pkg}*" 2>/dev/null | head -20)
        done
    done

    if have_cmd npm; then
        for pkg in "${MALICIOUS_NPM_PKGS[@]}"; do
            if npm ls -g "$pkg" 2>/dev/null | grep -qv 'empty'; then
                found+=("global npm: $pkg")
            fi
        done
    fi

    if [[ -d "$HOME/.bun" ]]; then
        for pkg in "${MALICIOUS_NPM_PKGS[@]}"; do
            while IFS= read -r match; do
                [[ -n "$match" ]] && found+=("$match")
            done < <(find "$HOME/.bun" -iname "*${pkg}*" 2>/dev/null | head -20)
        done
    fi

    # Search for preinstall hook pattern in caches
    if have_cmd rg; then
        local rg_hits
        rg_hits="$(rg -l 'preinstall.*\./src/hooks/deps|"preinstall": "./src/hooks/deps"' \
            "$HOME/.npm" "$HOME/.bun" 2>/dev/null || true)"
        [[ -n "$rg_hits" ]] && found+=("$rg_hits")
    else
        local grep_hits
        grep_hits="$(grep -r 'src/hooks/deps' "$HOME/.npm" "$HOME/.bun" 2>/dev/null || true)"
        [[ -n "$grep_hits" ]] && found+=("$grep_hits")
    fi

    if [[ ${#found[@]} -gt 0 ]]; then
        log CRITICAL "Malicious npm/bun artifacts found:"
        printf '  %s\n' "${found[@]}" | sort -u
    else
        log OK "No malicious npm/bun packages in caches"
    fi
}

# ---------------------------------------------------------------------------
section_malware_file_hashes() {
    log SECTION "Malware ELF hash and size search"

    local hashes=("$HASH_DEPS_ATOMIC" "$HASH_DEPS_JS_DIGEST" "$HASH_CRYPTOMINER")
    local search_roots=("$HOME/.local" "$HOME/.npm" "$HOME/.bun" /tmp /var/tmp)

    # Exact size search for deps binary (fast, targeted paths only)
    local size_matches=()
    for root in "${search_roots[@]}"; do
        [[ -d "$root" ]] || continue
        while IFS= read -r f; do
            [[ -n "$f" ]] && size_matches+=("$f")
        done < <(timeout 15 find "$root" -name 'deps' -size "${DEPS_SIZE}c" -type f 2>/dev/null | head -20)
    done

    if $USE_SUDO; then
        while IFS= read -r f; do
            [[ -n "$f" ]] && size_matches+=("$f")
        done < <(run_privileged timeout 30 find /var/lib -maxdepth 4 -name 'deps' -size "${DEPS_SIZE}c" -type f 2>/dev/null | head -20)
    fi

    if $FULL_SCAN; then
        while IFS= read -r f; do
            [[ -n "$f" ]] && size_matches+=("$f")
        done < <(timeout 60 find "$HOME" -name 'deps' -size "${DEPS_SIZE}c" -type f \
            -not -path '*/.cache/*' -not -path '*/build/*' -not -path '*/_autogen/*' 2>/dev/null | head -30)
    fi

    if [[ ${#size_matches[@]} -gt 0 ]]; then
        log WARNING "Files named 'deps' with exact malware size (${DEPS_SIZE} bytes):"
        for f in "${size_matches[@]}"; do
            # Exclude common build-system false positives
            if echo "$f" | grep -qE '_autogen/deps|/build/.*/deps$|CMakeFiles'; then
                log INFO "  (likely build artifact) $f"
            else
                log CRITICAL "  SUSPICIOUS: $f"
                have_cmd sha256sum && sha256sum "$f" | sed 's/^/    /'
            fi
        done
    else
        log OK "No exact-size 'deps' binaries found"
    fi

    # Hash scan on medium-sized files in key dirs (bounded)
    local hash_roots=("$HOME/.local" "$HOME/.npm" "$HOME/.bun" /tmp)
    for root in "${hash_roots[@]}"; do
        [[ -d "$root" ]] || continue
        while IFS= read -r f; do
            local h
            h="$(sha256sum "$f" 2>/dev/null | awk '{print tolower($1)}')"
            for known in "${hashes[@]}"; do
                if [[ "$h" == "$known" ]]; then
                    log CRITICAL "KNOWN MALWARE HASH: $f ($h)"
                fi
            done
        done < <(timeout 20 find "$root" -type f -size +2M -size -4M 2>/dev/null | head -50)
    done

    if $FULL_SCAN; then
        log INFO "Full scan: checking deps files in key directories..."
        local full_dirs=("$HOME/.local" "$HOME/.npm" "$HOME/.bun" "$HOME/bin" "$HOME/.config" "$HOME/Documents" "$HOME/code")
        for dir in "${full_dirs[@]}"; do
            [[ -d "$dir" ]] || continue
            while IFS= read -r f; do
                echo "$f" | grep -qE '_autogen/|/build/' && continue
                local h
                h="$(sha256sum "$f" 2>/dev/null | awk '{print tolower($1)}')"
                for known in "${hashes[@]}"; do
                    [[ "$h" == "$known" ]] && log CRITICAL "KNOWN MALWARE HASH: $f"
                done
            done < <(timeout 15 find "$dir" -name 'deps' -type f 2>/dev/null)
        done
    fi
}

# ---------------------------------------------------------------------------
section_systemd_persistence() {
    log SECTION "systemd persistence check"

    local suspicious_units=()

    # User systemd
    if [[ -d "$HOME/.config/systemd/user" ]]; then
        while IFS= read -r f; do
            if grep -qE 'Restart=always|RestartSec=30' "$f" 2>/dev/null; then
                suspicious_units+=("user: $f")
            fi
        done < <(find "$HOME/.config/systemd/user" -type f -name '*.service' 2>/dev/null)
        log INFO "User systemd units: $(find "$HOME/.config/systemd/user" -name '*.service' 2>/dev/null | wc -l)"
    else
        log OK "No user systemd directory"
    fi

    if have_cmd systemctl; then
        local enabled_user
        enabled_user="$(systemctl --user list-unit-files --type=service --no-pager 2>/dev/null || true)"
        if [[ -n "$enabled_user" && "$QUIET" == false ]]; then
            log INFO "Enabled user services:"
            echo "$enabled_user" | sed 's/^/  /'
        fi
    fi

    # System systemd (privileged)
    if $USE_SUDO; then
        while IFS= read -r f; do
            if grep -qE 'Restart=always|RestartSec=30' "$f" 2>/dev/null; then
                suspicious_units+=("system: $f")
            fi
        done < <(run_privileged find /etc/systemd/system -type f -name '*.service' 2>/dev/null)

        run_privileged find /var/lib -maxdepth 3 -type f -executable -newermt "$ATTACK_START_DATE" \
            ! -path '*/pacman/*' ! -path '*/systemd/catalog/*' 2>/dev/null | while read -r f; do
            log WARNING "New executable in /var/lib since attack: $f"
        done
    else
        log INFO "System systemd /var/lib scan skipped (use --sudo)"
    fi

    if [[ ${#suspicious_units[@]} -gt 0 ]]; then
        log WARNING "systemd units with malware-like restart policy (review manually):"
        printf '  %s\n' "${suspicious_units[@]}"
    else
        log OK "No suspicious systemd restart policies found"
    fi
}

# ---------------------------------------------------------------------------
section_dinit_persistence() {
    log SECTION "dinit persistence check (Artix)"

    local dinit_paths=(
        /etc/dinit.d
        /etc/dinit.d/user
        "$HOME/.config/dinit.d"
        "$HOME/.config/dinit.d/boot.d"
    )

    local found_dinit=false
    for p in "${dinit_paths[@]}"; do
        [[ -d "$p" ]] || continue
        found_dinit=true
        log INFO "Scanning $p"

        # Services modified since attack
        local new_files
        new_files="$(find "$p" -maxdepth 3 -newermt "$ATTACK_START_DATE" -type f 2>/dev/null || true)"
        if [[ -n "$new_files" ]]; then
            log WARNING "dinit files modified since $ATTACK_START_DATE:"
            echo "$new_files" | sed 's/^/  /'
            while read -r f; do
                [[ -z "$f" ]] && continue
                if grep -qE 'atomic-lockfile|js-digest|lockfile-js' "$f" 2>/dev/null; then
                    log CRITICAL "Suspicious content in dinit service: $f"
                fi
            done <<< "$new_files"
        fi

        # List all service files
        if [[ "$QUIET" == false ]]; then
            find "$p" -maxdepth 2 -type f 2>/dev/null | while read -r f; do
                echo "  $f"
            done
        fi

        # Broken symlinks (informational — often stale user config)
        find "$p" -maxdepth 2 -type l ! -exec test -e {} \; -print 2>/dev/null | while read -r b; do
            log INFO "Broken dinit symlink: $b -> $(readlink "$b" 2>/dev/null)"
        done
    done

    if ! $found_dinit; then
        log INFO "No dinit directories found (not Artix/dinit?)"
    else
        log OK "dinit scan complete (review WARNINGs above)"
    fi
}

# ---------------------------------------------------------------------------
section_other_init_systems() {
    log SECTION "runit / openrc / s6 persistence check"

    local checked=false

    # runit
    for svdir in /etc/runit/runsvdir /etc/sv "$HOME/.config/runit"; do
        [[ -d "$svdir" ]] || continue
        checked=true
        log INFO "Scanning runit: $svdir"
        local new_sv
        new_sv="$(find "$svdir" -newermt "$ATTACK_START_DATE" -type f 2>/dev/null || true)"
        [[ -n "$new_sv" ]] && log WARNING "New/modified runit files:" && echo "$new_sv" | sed 's/^/  /'
    done

    # openrc
    if [[ -d /etc/init.d ]]; then
        checked=true
        log INFO "Scanning openrc: /etc/init.d"
        find /etc/init.d -newermt "$ATTACK_START_DATE" -type f 2>/dev/null | while read -r f; do
            log WARNING "Modified openrc script: $f"
        done
    fi

    # s6
    for s6dir in /etc/s6 /run/service "$HOME/.config/s6"; do
        [[ -d "$s6dir" ]] || continue
        checked=true
        log INFO "Scanning s6: $s6dir"
        find "$s6dir" -newermt "$ATTACK_START_DATE" -type f 2>/dev/null | while read -r f; do
            log WARNING "Modified s6 file: $f"
        done
    done

    # cron
    if crontab -l 2>/dev/null | grep -q .; then
        log INFO "User crontab present — review:"
        crontab -l 2>/dev/null | sed 's/^/  /'
    else
        log OK "No user crontab"
    fi

    # XDG autostart
    if [[ -d "$HOME/.config/autostart" ]]; then
        local new_as
        new_as="$(find "$HOME/.config/autostart" -newermt "$ATTACK_START_DATE" -type f 2>/dev/null || true)"
        if [[ -n "$new_as" ]]; then
            log INFO "Autostart files modified since attack (review if unexpected):"
            echo "$new_as" | sed 's/^/  /'
        fi
    fi

    $checked || log INFO "No runit/openrc/s6 directories detected"
}

# ---------------------------------------------------------------------------
section_ebpf_rootkit() {
    log SECTION "eBPF rootkit indicator check"

    local bpf_bad=false
    for marker in hidden_pids hidden_names hidden_inodes; do
        if [[ -e "/sys/fs/bpf/$marker" || -e "/sys/fs/bpf/hidden_${marker#hidden_}" ]]; then
            log CRITICAL "eBPF rootkit marker found: /sys/fs/bpf/$marker"
            bpf_bad=true
        fi
    done
    shopt -s nullglob
    for f in /sys/fs/bpf/hidden_*; do
        [[ -e "$f" ]] && log CRITICAL "eBPF hidden map: $f" && bpf_bad=true
    done
    shopt -u nullglob

    if $USE_SUDO && have_cmd bpftool; then
        local prog_out
        prog_out="$(run_privileged bpftool prog list 2>/dev/null || true)"
        if [[ -n "$prog_out" && "$QUIET" == false ]]; then
            log INFO "BPF programs (privileged):"
            echo "$prog_out" | sed 's/^/  /' | head -40
        fi
        if echo "$prog_out" | grep -qi hidden; then
            log CRITICAL "Suspicious BPF program names detected"
            bpf_bad=true
        fi
    else
        log INFO "bpftool full listing skipped (use --sudo and install bpftool)"
    fi

    $bpf_bad || log OK "No eBPF rootkit markers detected"
}

# ---------------------------------------------------------------------------
section_network_processes() {
    log SECTION "Network listeners and suspicious processes"

    if have_cmd ss; then
        log INFO "Localhost listeners:"
        ss -tlnp 2>/dev/null | grep '127.0.0.1' | sed 's/^/  /' || log INFO "  (none)"
    fi

    # Match actual malware process names, not substrings in shell command lines
    local sus_procs=""
    if have_cmd pgrep; then
        sus_procs="$(pgrep -a -x deps 2>/dev/null || true)"
        for p in atomic-lockfile js-digest lockfile-js; do
            sus_procs+="$(pgrep -a -f "/${p}([[:space:]]|$)" 2>/dev/null || true)"$'\n'
        done
    fi
    sus_procs="$(echo "$sus_procs" | grep -vE 'pgrep|aur-atomic-arch-audit|grep' | sed '/^$/d' || true)"
    if [[ -n "$sus_procs" ]]; then
        log CRITICAL "Suspicious processes running:"
        echo "$sus_procs" | sed 's/^/  /'
    else
        log OK "No suspicious process names"
    fi

    if have_cmd journalctl; then
        local journal_hits
        journal_hits="$(journalctl --since "$ATTACK_START_DATE" --no-pager 2>/dev/null | \
            grep -iE 'temp\.sh|atomic-lockfile|js-digest|lockfile-js|olrh4mibs' | head -20 || true)"
        if [[ -n "$journal_hits" ]]; then
            log WARNING "Journal references to IOC strings:"
            echo "$journal_hits" | sed 's/^/  /'
        else
            log OK "No IOC strings in journal since $ATTACK_START_DATE"
        fi
    fi

    if [[ -x /usr/bin/monero-wallet-gui ]]; then
        log WARNING "monero-wallet-gui present (malware staging reference in IOCs)"
    else
        log OK "monero-wallet-gui not present"
    fi
}

# ---------------------------------------------------------------------------
section_shell_profiles() {
    log SECTION "Shell profile and SSH integrity"

    local profile_files=(
        "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"
        "$HOME/.zshrc" "$HOME/.config/fish/config.fish"
    )
    local profile_pattern='atomic-lockfile|js-digest|lockfile-js|curl.*\|.*sh|wget.*\|.*sh|base64 -d|eval.*\$\(|olrh4mibs'

    local profile_hits=()
    for f in "${profile_files[@]}"; do
        [[ -f "$f" ]] || continue
        if grep -qE "$profile_pattern" "$f" 2>/dev/null; then
            profile_hits+=("$f")
        fi
        if [[ "$f" == *".bashrc" || "$f" == *".zshrc" || "$f" == *".profile" ]]; then
            if [[ "$(find "$f" -newermt "$ATTACK_START_DATE" 2>/dev/null)" ]]; then
                log INFO "Profile modified since attack: $f"
            fi
        fi
    done

    if [[ ${#profile_hits[@]} -gt 0 ]]; then
        log CRITICAL "Suspicious content in shell profiles: ${profile_hits[*]}"
    else
        log OK "Shell profiles clean"
    fi

    # SSH keys modified during attack window
    if [[ -d "$HOME/.ssh" ]]; then
        local changed_keys
        changed_keys="$(find "$HOME/.ssh" -type f -newermt "$ATTACK_START_DATE" 2>/dev/null || true)"
        if [[ -n "$changed_keys" ]]; then
            log WARNING "SSH files modified since attack (may be legitimate):"
            echo "$changed_keys" | sed 's/^/  /'
        fi
    fi
}

# ---------------------------------------------------------------------------
section_deep_string_scan() {
    log SECTION "Deep IOC string scan"

    local pattern="olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid|atomic-lockfile|lockfile-js|js-digest|herbsobering|temp\\.sh/upload|src/hooks/deps"

    local hits=""
    if have_cmd rg; then
        hits="$(timeout 60 rg -l "$pattern" \
            --glob '!**/.cache/**' \
            --glob '!**/node_modules/**' \
            --glob '!**/.cursor/**' \
            --glob '!**/Trash/**' \
            --glob '!**/.local/share/Steam/**' \
            --glob '!**/Games/**' \
            --glob '!**/.var/**' \
            --glob '!**/*.git/**' \
            --glob '!**/build/**' \
            "$HOME" 2>/dev/null || true)"
    else
        hits="$(timeout 60 grep -rE "$pattern" "$HOME" \
            --exclude-dir=.cache --exclude-dir=node_modules --exclude-dir=.cursor \
            --exclude-dir=Trash --exclude-dir=Games --exclude-dir=.var --exclude-dir=build \
            2>/dev/null | cut -d: -f1 | sort -u || true)"
    fi

    if [[ -z "$hits" && "$FULL_SCAN" == true ]]; then
        log INFO "Scanning dotfiles and config (fast path)..."
        for sub in .config .local/bin .local/share Documents Desktop code; do
            [[ -d "$HOME/$sub" ]] || continue
            if have_cmd rg; then
                hits+="$(timeout 30 rg -l "$pattern" "$HOME/$sub" 2>/dev/null || true)"$'\n'
            fi
        done
    fi

    if [[ -n "$hits" ]]; then
        while read -r f; do
            [[ -z "$f" ]] && continue
            # Whitelist this audit script itself
            if [[ "$f" == *aur-atomic-arch-audit.sh* || "$f" == *check.sh* || "$f" == *check2.sh* ]]; then
                log INFO "IOC string match in audit script (benign): $f"
            else
                log WARNING "IOC string match: $f"
            fi
        done <<< "$hits"
    else
        log OK "No IOC strings in home directory"
    fi
}

# ---------------------------------------------------------------------------
section_install_dates() {
    log SECTION "Install dates for all foreign packages"

    local foreign
    foreign="$(pacman -Qmq 2>/dev/null)"
    [[ -z "$foreign" ]] && log INFO "No foreign packages" && return

    for pkg in $foreign; do
        local info epoch install_date
        info="$(pacman -Qi "$pkg" 2>/dev/null)"
        install_date="$(echo "$info" | awk -F': ' '/Install Date/{print $2}')"
        epoch="$(date -d "$install_date" +%s 2>/dev/null || echo 0)"

        local flag=""
        if is_epoch_in_attack_window "$epoch"; then
            flag="${YELLOW}[IN WINDOW]${NC}"
        fi
        if [[ -s "$PACKAGE_LIST_FILE" ]] && grep -qx "$pkg" "$PACKAGE_LIST_FILE"; then
            flag+="${RED}[ON LIST]${NC}"
        fi

        echo -e "  ${BOLD}$pkg${NC} $flag"
        echo "$info" | grep -E 'Version|Install Date|Packager' | sed 's/^/    /'
    done
}

# ---------------------------------------------------------------------------
section_historical_all_yay_packages() {
    log SECTION "All-time yay/paru history vs compromised list"

    [[ ! -s "$PACKAGE_LIST_FILE" ]] && log WARNING "No package list — skipping" && return

    local all_aur_pkgs=()
    for lf in /var/log/pacman.log /var/log/pacman.log.*; do
        [[ -f "$lf" ]] || continue
        local content=""
        case "$lf" in
            *.gz) have_cmd zgrep && content="$(zgrep 'pacman -U' "$lf" 2>/dev/null)" ;;
            *.xz) have_cmd xzgrep && content="$(xzgrep 'pacman -U' "$lf" 2>/dev/null)" ;;
            *) content="$(grep 'pacman -U' "$lf" 2>/dev/null)" ;;
        esac
        while read -r pkg; do
            [[ -n "$pkg" ]] && all_aur_pkgs+=("$pkg")
        done < <(echo "$content" | grep -oE '(yay|paru)/[^/]+' | sed 's|.*/||' | sort -u)
    done

    local unique
    unique="$(printf '%s\n' "${all_aur_pkgs[@]}" | sort -u)"
    if [[ -z "$unique" ]]; then
        log INFO "No yay/paru history in pacman.log"
        return
    fi

    local hist_matches
    hist_matches="$(comm -12 <(echo "$unique") <(sort -u "$PACKAGE_LIST_FILE"))"
    if [[ -n "$hist_matches" ]]; then
        log CRITICAL "Packages ever built via yay/paru that are on compromised list:"
        echo "$hist_matches" | sed 's/^/  /'
    else
        log OK "No historical yay/paru packages on compromised list"
    fi
}

# ---------------------------------------------------------------------------
section_recommendations() {
    log SECTION "Remediation guidance (if anything was found)"

    if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
        cat <<EOF

${RED}${BOLD}CRITICAL INDICATORS WERE FOUND. Treat this system as potentially compromised.${NC}

Recommended actions:
  1. Disconnect from network immediately
  2. Do NOT power off yet if you need forensic evidence
  3. Boot from trusted Arch/Artix ISO on separate media
  4. Rotate ALL credentials from a CLEAN machine:
     - GitHub PATs, SSH keys, GPG keys
     - npm tokens, Discord/Slack/Teams sessions
     - Browser passwords, Vault tokens, cloud API keys
  5. Remove unknown systemd/dinit services and /var/lib executables
  6. Strongly consider full OS reinstall
  7. Report: aur-general@lists.archlinux.org

IOC references:
  - https://ioctl.fail/preliminary-analysis-of-aur-malware/
  - https://github.com/lenucksi/aur-malware-check

EOF
    elif [[ "$WARNING_COUNT" -gt 0 ]]; then
        cat <<EOF

${YELLOW}Warnings were found — manual review recommended.${NC}
Review flagged dinit/systemd files, pacman.log AUR activity, and any
PKGBUILD/npm hits above. If anything confirms malware, follow critical steps.

EOF
    else
        cat <<EOF

${GREEN}${BOLD}No indicators found. System appears clean for this campaign.${NC}

Ongoing precautions:
  - Always review PKGBUILDs: yay -P <pkgname>
  - Use yay --diff before updating AUR packages
  - Prefer official repos when possible
  - Re-run this script after installing new AUR packages

EOF
    fi
}

# ---------------------------------------------------------------------------
print_summary() {
    log SECTION "Final summary"

    echo ""
    echo -e "${BOLD}Counts:${NC}  ${RED}Critical: $CRITICAL_COUNT${NC}  ${YELLOW}Warnings: $WARNING_COUNT${NC}  Info: $INFO_COUNT"
    echo -e "${BOLD}Attack window:${NC} $ATTACK_START_DATE .. $ATTACK_END_DATE"
    [[ -n "$OUTPUT_FILE" ]] && echo -e "${BOLD}Report saved:${NC} $OUTPUT_FILE"
    [[ -n "$WORK_DIR" ]] && echo -e "${DIM}Work dir: $WORK_DIR${NC}"
    echo ""

    if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
        echo -e "${RED}${BOLD}VERDICT: POTENTIALLY COMPROMISED${NC}"
        return 2
    elif [[ "$WARNING_COUNT" -gt 0 ]]; then
        echo -e "${YELLOW}${BOLD}VERDICT: REVIEW WARNINGS MANUALLY${NC}"
        return 1
    else
        echo -e "${GREEN}${BOLD}VERDICT: CLEAN${NC}"
        return 0
    fi
}

# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    init_report

    setup_workdir

    if $CSCS_ONLY; then
        echo -e "${BOLD}${BLUE}CSCS Forum Checker (integrated)${NC}"
        echo -e "${DIM}Source: $CSCS_PASTE_URL${NC}\n"
        if [[ ! -f "$CSCS_SCRIPT" ]]; then
            die "Failed to download CSCS script from $CSCS_PASTE_URL"
        fi
        local cscs_out
        cscs_out="$(run_original_cscs_script)" || true
        echo "$cscs_out"
        [[ -n "$OUTPUT_FILE" ]] && echo "$cscs_out" >> "$OUTPUT_FILE"
        cscs_script_exit_code "$cscs_out"
        exit $?
    fi

    echo -e "${BOLD}${BLUE}"
    cat <<'BANNER'
    _   _ ____  ____      _    _   _   _                      _                _
   / \ | |  _ \|  _ \    / \  | \ | | / \   ___  __ _  __ _  / \   _ __  _ __ | |__  _   _ _ __ ___  _ __
  / _ \| | |_) | |_) |  / _ \ |  \| |/ _ \ / __|/ _` |/ _` |/ _ \ | '_ \| '_ \| '_ \| | | | '_ ` _ \| '_ \
 / ___ \ |  _ <|  __/  / ___ \| |\  / ___ \\__ \ (_| | (_| / ___ \| | | | | | | |_) | |_| | | | | | | |_) |
/_/   \_\_| \_\_|    /_/   \_\_| \_/_/   \_\___/\__,_|\__,_/_/   \_\_| |_|_| |_|_.__/ \__,_|_| |_| |_| .__/
                                                                                                      |_|

  Atomic Arch AUR Supply-Chain Auditor  |  Artix / dinit edition
BANNER
    echo -e "${NC}"
    log INFO "$SCRIPT_NAME v$VERSION starting..."

    section_system_info
    section_prerequisites
    section_community_checker
    section_installed_foreign_packages
    section_cscs_forum_checker
    section_pacman_log_history
    section_yay_paru_cache
    section_live_aur_pkgbuild_fetch
    section_npm_bun_cache
    section_malware_file_hashes
    section_systemd_persistence
    section_dinit_persistence
    section_other_init_systems
    section_ebpf_rootkit
    section_network_processes
    section_shell_profiles
    section_deep_string_scan
    section_install_dates
    section_historical_all_yay_packages
    section_recommendations

    print_summary
}

main "$@"

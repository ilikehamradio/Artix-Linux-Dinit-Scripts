#!/usr/bin/env bash
# Prefer Cursor classic IDE (not Agents/Glass) with a clean empty session.
# Idempotent: safe to re-run. Quit Cursor fully before relaunching for changes to stick.
set -euo pipefail

CHANGED=()
WARNINGS=()

log() { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; WARNINGS+=("$*"); }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# --- 1. Detect Cursor User config dir ---
detect_user_dir() {
  if [[ -n "${CURSOR_CONFIG_DIR:-}" ]]; then
    if [[ -d "$CURSOR_CONFIG_DIR" ]]; then
      printf '%s\n' "$CURSOR_CONFIG_DIR"
      return 0
    fi
    die "CURSOR_CONFIG_DIR is set to '$CURSOR_CONFIG_DIR' but that directory does not exist."
  fi
  local linux_dir="${HOME}/.config/Cursor/User"
  local mac_dir="${HOME}/Library/Application Support/Cursor/User"
  if [[ -d "$linux_dir" ]]; then
    printf '%s\n' "$linux_dir"
    return 0
  fi
  if [[ -d "$mac_dir" ]]; then
    printf '%s\n' "$mac_dir"
    return 0
  fi
  die "Cursor User config directory not found.
Tried:
  - \$CURSOR_CONFIG_DIR (unset or empty)
  - ${linux_dir}
  - ${mac_dir}
Set CURSOR_CONFIG_DIR to your Cursor User folder and re-run."
}

USER_DIR="$(detect_user_dir)"
log "Using Cursor User dir: $USER_DIR"

# --- 2. Warn if Cursor appears to be running ---
if pgrep -af 'cursor(\.appimage|/cursor |Cursor)' >/dev/null 2>&1; then
  warn "Cursor appears to be running. Fully quit Cursor first so state changes stick. Proceeding anyway."
elif pgrep -af '[Cc]ursor' >/dev/null 2>&1; then
  warn "A process matching Cursor may be running. Fully quit Cursor first so state changes stick. Proceeding anyway."
fi

# --- 3. Update settings.json ---
SETTINGS_JSON="${USER_DIR}/settings.json"
SETTINGS_MSG="$(python3 - "$SETTINGS_JSON" <<'PY'
import json, os, sys

path = sys.argv[1]
data = {}
if os.path.isfile(path):
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip()
        if raw:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise SystemExit(f"settings.json is not a JSON object: {path}")
else:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

wanted = {
    "window.restoreWindows": "none",
    "files.hotExit": "off",
    "workbench.startupEditor": "none",
}
changed_keys = []
for k, v in wanted.items():
    if data.get(k) != v:
        data[k] = v
        changed_keys.append(k)

with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")

if changed_keys:
    print("updated: " + ", ".join(changed_keys))
else:
    print("already set (no write changes needed for keys)")
PY
)"
CHANGED+=("settings.json: $SETTINGS_MSG")

# --- 4. Update globalStorage/state.vscdb ---
GLOBAL_STORAGE="${USER_DIR}/globalStorage"
STATE_DB="${GLOBAL_STORAGE}/state.vscdb"

if ! command -v sqlite3 >/dev/null 2>&1; then
  warn "sqlite3 not found; skipping state.vscdb updates."
elif [[ ! -f "$STATE_DB" ]]; then
  warn "state.vscdb not found at $STATE_DB; skipping DB updates."
else
  sqlite3 "$STATE_DB" <<'SQL'
INSERT INTO ItemTable (key, value)
VALUES ('cursor/userOpenAgentsWindowOnStartupPreference', 'false')
ON CONFLICT(key) DO UPDATE SET value = excluded.value;

INSERT INTO ItemTable (key, value)
VALUES ('cursor/unifiedAppLayout', 'editor')
ON CONFLICT(key) DO UPDATE SET value = excluded.value;
SQL
  CHANGED+=("state.vscdb: cursor/userOpenAgentsWindowOnStartupPreference=false, cursor/unifiedAppLayout=editor")
fi

# --- 5. Update globalStorage/storage.json ---
STORAGE_JSON="${GLOBAL_STORAGE}/storage.json"
mkdir -p "$GLOBAL_STORAGE"
STORAGE_MSG="$(python3 - "$STORAGE_JSON" <<'PY'
import json, os, sys

path = sys.argv[1]
data = {}
if os.path.isfile(path):
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip()
        if raw:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise SystemExit(f"storage.json is not a JSON object: {path}")

data["windowsState"] = {"openedWindows": []}
data["backupWorkspaces"] = {
    "workspaces": [],
    "folders": [],
    "emptyWindows": [],
}

with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")

print("set windowsState and backupWorkspaces to empty")
PY
)"
CHANGED+=("storage.json: $STORAGE_MSG")

# --- 6. Clear Backups (keep directory) ---
BACKUPS_DIR="$(dirname "$USER_DIR")/Backups"
mkdir -p "$BACKUPS_DIR"
find "$BACKUPS_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
CHANGED+=("Backups: emptied $BACKUPS_DIR (directory kept)")

# --- 7. Patch desktop launchers (Linux) ---
patch_desktop_py() {
  python3 - "$@" <<'PY'
import os, re, shutil, sys

user_apps = os.path.expanduser("~/.local/share/applications")
os.makedirs(user_apps, exist_ok=True)

candidates = []
seen = set()
for p in sys.argv[1:]:
    if not p or not os.path.isfile(p):
        continue
    rp = os.path.realpath(p)
    if rp in seen:
        continue
    seen.add(rp)
    candidates.append(p)

field_re = re.compile(r"(%[FfUu])\b")

def ensure_user_copy(path):
    abspath = os.path.abspath(path)
    if abspath.startswith(user_apps + os.sep):
        return abspath
    dest = os.path.join(user_apps, os.path.basename(path))
    if not os.path.isfile(dest):
        shutil.copy2(path, dest)
    return dest

def patch_exec_line(line):
    if not line.startswith("Exec="):
        return line, False
    body = line[5:]
    if not re.search(r"(?i)cursor|\.appimage", body):
        return line, False
    if re.search(r"(^|\s)--classic(\s|$)", body):
        return line, False
    m = field_re.search(body)
    if m:
        i = m.start()
        before = body[:i].rstrip()
        after = body[i:]
        new_body = f"{before} --classic {after}"
    else:
        new_body = body.rstrip() + " --classic"
    new_body = re.sub(r"  +", " ", new_body)
    return "Exec=" + new_body, True

for path in candidates:
    target = ensure_user_copy(path)
    with open(target, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    lines = content.splitlines(keepends=True)
    changed = False
    out = []
    for line in lines:
        nl = ""
        core = line
        if core.endswith("\n"):
            nl = "\n"
            core = core[:-1]
        if core.endswith("\r"):
            core = core[:-1]
        new_core, did = patch_exec_line(core)
        if did:
            changed = True
        out.append(new_core + nl)
    if changed:
        text = "".join(out)
        if text and not text.endswith("\n"):
            text += "\n"
        with open(target, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"PATCHED:{target}")
    else:
        print(f"SKIPPED:{target}")
PY
}

if [[ "$(uname -s)" == "Linux" ]]; then
  DESKTOP_CANDIDATES=()
  [[ -f "${HOME}/.local/share/applications/cursor.desktop" ]] && \
    DESKTOP_CANDIDATES+=("${HOME}/.local/share/applications/cursor.desktop")
  [[ -f /usr/share/applications/cursor.desktop ]] && \
    DESKTOP_CANDIDATES+=("/usr/share/applications/cursor.desktop")
  shopt -s nullglob
  for f in "${HOME}"/.local/share/applications/*cursor*.desktop; do
    DESKTOP_CANDIDATES+=("$f")
  done
  shopt -u nullglob

  if [[ ${#DESKTOP_CANDIDATES[@]} -gt 0 ]]; then
    while IFS= read -r line; do
      case "$line" in
        PATCHED:*)
          CHANGED+=("desktop: added --classic to ${line#PATCHED:}")
          ;;
        SKIPPED:*)
          CHANGED+=("desktop: already OK (has --classic or no matching Exec): ${line#SKIPPED:}")
          ;;
      esac
    done < <(patch_desktop_py "${DESKTOP_CANDIDATES[@]}")
  else
    warn "No cursor.desktop files found; skipped --classic launcher patch."
  fi
else
  warn "Non-Linux OS: skipped desktop launcher --classic patch."
fi

# --- 8. Summary ---
log ""
log "======== SUMMARY ========"
log "Config User dir: $USER_DIR"
if [[ ${#CHANGED[@]} -gt 0 ]]; then
  log "Actions:"
  for c in "${CHANGED[@]}"; do
    log "  - $c"
  done
else
  log "No changes recorded."
fi
if [[ ${#WARNINGS[@]} -gt 0 ]]; then
  log "Warnings:"
  for w in "${WARNINGS[@]}"; do
    log "  - $w"
  done
fi
log ""
log "Next steps:"
log "  1. Fully quit Cursor (all windows)."
log "  2. Relaunch from the app menu / desktop entry so --classic applies."
log "  3. If launching an AppImage from the CLI, use:"
log "       cursor.appimage --classic"
log "========================="

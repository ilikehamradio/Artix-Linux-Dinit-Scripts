#!/usr/bin/env bash
# Artix / KDE Plasma: stop KWallet focus-stealing password prompts.
# Keeps the wallet working; relies on pam_kwallet when wallet password == login password.
set -euo pipefail

mkdir -p "${HOME}/.config" \
         "${HOME}/.config/autostart" \
         "${HOME}/.local/share/dbus-1/services"

# Stay unlocked; don't re-lock on idle/screensaver; no extra open prompt
cat > "${HOME}/.config/kwalletrc" << 'EOF'
[Wallet]
Enabled=true
First Use=false
Close When Idle=false
Close on Screensaver=false
Leave Open=true
Prompt on Open=false
Idle Time=999999
Launch Manager=false
EOF

# Prefer KDE ksecretd over gnome-keyring for org.freedesktop.secrets
cat > "${HOME}/.local/share/dbus-1/services/org.freedesktop.secrets.service" << 'EOF'
[D-BUS Service]
Name=org.freedesktop.secrets
Exec=/usr/bin/ksecretd
EOF

# Early session: start ksecretd with PAM env, then feed the PAM socket
cat > "${HOME}/.config/autostart/zz-kwallet-pam-unlock.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=KWallet silent PAM unlock
Comment=Unlock KWallet from login credentials without prompting
Exec=/bin/sh -c 'if [ -n "$PAM_KWALLET5_LOGIN" ]; then /usr/bin/ksecretd >/dev/null 2>&1 & sleep 0.4; /usr/lib/pam_kwallet_init; fi'
NoDisplay=true
X-KDE-autostart-phase=0
X-KDE-StartupNotify=false
X-GNOME-Autostart-enabled=true
EOF

echo "KWallet quiet-unlock config written."
echo "Log out/in (or unlock the wallet once) for it to take effect this session."

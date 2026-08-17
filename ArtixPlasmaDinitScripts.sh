

# Flatpak Framework
sudo pacman -S --needed --noconfirm flatpak
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo

# Install Flatpaks
flatpak install -y com.nomachine.nxplayer com.protonvpn.www.Locale com.vscodium.codium io.github.seadve.Kooha com.etlegacy.ETLegacy com.brave.Browser com.github.unrud.VideoDownloader it.mijorus.gearlever com.github.tchx84.Flatseal io.dbeaver.DBeaverCommunity com.spotify.Client com.slack.Slack com.nextcloud.desktopclient.nextcloud com.valvesoftware.Steam net.lutris.Lutris org.signal.Signal

# Development SDKs and Native Tools
sudo pacman -S --needed --noconfirm rustup dotnet-sdk-8.0 nodejs npm dotnet-sdk-9.0 dotnet-sdk-10.0 aspnet-targeting-pack jdk-openjdk spectacle libreoffice-fresh system-config-printer traceroute partitionmanager ntfs-3g unzip sshpass vlc vlc-plugins-extra

# Set default Rust / Cargo
rustup default stable

# Power profile daemon
sudo pacman -Syu --needed --noconfirm tlp power-profiles-daemon powerdevil power-profiles-daemon-dinit

# Enable power profile daemon
sudo dinitctl enable power-profiles-daemon

# UFW Firewall
sudo pacman -S --needed --noconfirm ufw ufw-dinit
sudo dinitctl enable ufw

# Remove wacomtablet safely
sudo pacman -R --noconfirm wacomtablet 2>/dev/null || true

# OpenVPN support
sudo pacman -S --needed --noconfirm networkmanager-openvpn

# Brave (Flathub explicit sync verification)
sudo pacman -S --needed --noconfirm wget
flatpak install -y flathub com.brave.Browser

# KVM/QEMU Virtualization Permissions and Tools
sudo usermod -aG kvm,libvirt,wheel,storage "$USER"
sudo pacman -S --needed --noconfirm spice-gtk spice-vdagent virt-manager gnome-boxes

# Printer network address resolution (mDNS)
sudo pacman -Sy --needed --noconfirm avahi-dinit nss-mdns
sudo dinitctl enable avahi-daemon
sudo dinitctl start avahi-daemon
grep -q "mdns_minimal" /etc/nsswitch.conf || sudo sed -i 's/hosts: \(.*\)dns/hosts: \1mdns_minimal [NOTFOUND=return] dns/' /etc/nsswitch.conf

# Online account integration
sudo pacman -S --needed --noconfirm kio-gdrive kaccounts-integration kaccounts-providers

# appimagetool support
# Continues on individual failures; does not abort the parent script.
(
  _ok=0
  _fail() { echo "warning: $*" >&2; _ok=1; }

  sudo pacman -S --needed --noconfirm squashfs-tools fuse2 fuse3 curl \
    || _fail "pacman could not install squashfs-tools/fuse2/fuse3/curl"

  echo fuse | sudo tee /etc/modules-load.d/fuse.conf >/dev/null \
    || _fail "could not write /etc/modules-load.d/fuse.conf"
  sudo modprobe fuse \
    || _fail "modprobe fuse failed (continuing; wrapper uses APPIMAGE_EXTRACT_AND_RUN)"

  sudo mkdir -p /usr/local/lib/appimagetool /usr/local/bin \
    || _fail "could not create /usr/local/{lib/appimagetool,bin}"

  if curl -fsSL \
    "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" \
    -o /tmp/appimagetool-x86_64.AppImage
  then
    sudo install -m 755 /tmp/appimagetool-x86_64.AppImage \
      /usr/local/lib/appimagetool/appimagetool.AppImage \
      || _fail "could not install appimagetool.AppImage into /usr/local/lib"
  else
    _fail "download of appimagetool continuous AppImage failed"
  fi
  rm -f /tmp/appimagetool-x86_64.AppImage

  if sudo tee /usr/local/bin/appimagetool >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export APPIMAGE_EXTRACT_AND_RUN="${APPIMAGE_EXTRACT_AND_RUN:-1}"
exec /usr/local/lib/appimagetool/appimagetool.AppImage "$@"
EOF
  then
    sudo chmod 755 /usr/local/bin/appimagetool \
      || _fail "could not chmod /usr/local/bin/appimagetool"
  else
    _fail "could not write /usr/local/bin/appimagetool wrapper"
  fi

  rm -f "${HOME}/.local/bin/appimagetool"

  command -v appimagetool >/dev/null 2>&1 \
    || _fail "appimagetool not on PATH after install"
  command -v mksquashfs >/dev/null 2>&1 \
    || _fail "mksquashfs not on PATH after install"
  appimagetool --version >/dev/null 2>&1 \
    || _fail "appimagetool --version failed"
  [[ -e /dev/fuse ]] \
    || _fail "/dev/fuse missing (packaging can still work via extract-and-run)"

  if [[ "${_ok}" -eq 0 ]]; then
    echo "appimagetool: OK ($(command -v appimagetool))"
  else
    echo "appimagetool: completed with warnings" >&2
  fi
  exit 0
)


#chronyd for system clock
sudo pacman -S --needed chrony chrony-dinit \
  && sudo dinitctl enable chronyd \
  && sudo dinitctl start chronyd \
  && sleep 2 \
  && sudo chronyc burst 4/4 \
  && sudo chronyc makestep \
  && chronyc tracking

# ProtonDrive rclone engine support
sudo pacman -S --needed --noconfirm rclone

# KDE Kioworker Removable Device Preview Bug workaround
if command -v kwriteconfig6 &>/dev/null; then
  kwriteconfig6 --file kdeglobals --group PreviewSettings --key SkipRemovableDevices true
  kwriteconfig6 --file kdeglobals --group PreviewSettings --key Tooltips false
else
  sed -i '/\[PreviewSettings\]/,/^\[/ { /SkipRemovableDevices=/d; /Tooltips=/d; }' ~/.config/kdeglobals
  if ! grep -q "\[PreviewSettings\]" ~/.config/kdeglobals; then
    echo -e "\n[PreviewSettings]" >> ~/.config/kdeglobals
  fi
  sed -i '/\[PreviewSettings\]/a SkipRemovableDevices=true\nTooltips=false' ~/.config/kdeglobals
fi

# Ollama local AI deployment
curl -fsSL https://ollama.com/install.sh | sh

sudo tee /etc/dinit.d/user/ollama > /dev/null <<EOF
type            = process
command         = /usr/local/bin/ollama serve
restart         = false
smooth-recovery = true
log-type        = buffer
EOF

# Ensure user-level directory path context safely exists for dinitctl user supervision
mkdir -p ~/.config/dinit.d
dinitctl enable ollama

# Virtualbox deployment 
sudo pacman -Syu --needed --noconfirm virtualbox \
  $([[ $(uname -r) == *"-arch"* ]] && echo "virtualbox-host-modules-arch" || echo "virtualbox-host-dkms linux-headers")
sudo modprobe vboxdrv vboxnetadp vboxnetflt || true
sudo mkdir -p /etc/modules-load.d
echo -e "vboxdrv\nvboxnetadp\nvboxnetflt" | sudo tee /etc/modules-load.d/virtualbox.conf
sudo gpasswd -a "$USER" vboxusers

# Set default text editor mappings to Kate
xdg-mime default org.kde.kate.desktop text/plain
xdg-mime default org.kde.kate.desktop application/x-zerosize
xdg-mime default org.kde.kate.desktop text/markdown

# Paru AUR Helper Installation
sudo pacman -S --needed --noconfirm base-devel git
rm -rf /tmp/paru && mkdir -p /tmp/paru
git clone https://aur.archlinux.org/paru.git /tmp/paru
cd /tmp/paru
makepkg -si --noconfirm
cd ~ && rm -rf /tmp/paru

# Paru optimization — native chroot build support via artools isolation shims
sudo pacman -S --needed --noconfirm artools-pkg
sudo ln -sf /usr/bin/mkchrootpkg  /usr/local/bin/makechrootpkg
sudo ln -sf /usr/bin/mkchroot     /usr/local/bin/mkarchroot
sudo ln -sf /usr/bin/chroot-run   /usr/local/bin/arch-nspawn

sudo tee /etc/paru.conf > /dev/null << 'EOF'
[options]
PgpFetch
Devel
Provides
DevelSuffixes = -git -cvs -svn -bzr -darcs -always -hg -fossil
UseAsk
SaveChanges
CleanAfter
UpgradeMenu
Chroot
EOF

# Shell Theming via Starship Prompt engine
sudo pacman -S --needed --noconfirm starship
mkdir -p ~/.config

# Prevent duplicate starship init hooks if script runs multiple times
grep -q "starship init bash" ~/.bashrc || echo 'eval "$(starship init bash)"' >> ~/.bashrc

cat > ~/.config/starship.toml << 'EOF'
"$schema" = 'https://starship.rs/config-schema.json'
format = """
┌─$username$hostname$directory$git_branch$git_status$rust$python$nodejs$java$package
└─▪ """

[username]
format = "[$user]($style)"
style_user = "bold green"
style_root = "bold red"
show_always = true

[hostname]
format = "[@$hostname]($style)"
style = "green"
ssh_only = false

[directory]
format = "[ $path]($style)[$read_only]($read_only_style)"
style = "cyan"
truncation_length = 4
truncate_to_repo = true

[git_branch]
format = "[ $symbol$branch]($style)"
symbol = "±"
style = "bold green"

[git_status]
format = "[$all_status$ahead_behind]($style)"
style = "bold yellow"
conflicted = " ✗"
ahead = " ⇡${count}"
behind = " ⇣${count}"
diverged = " ⇕⇡${ahead_count}⇣${behind_count}"
untracked = " ?"
stashed = " $"
modified = " !"
staged = " +"
renamed = " »"
deleted = " ✘"

[rust]
format = "[ $symbol$version]($style)"
style = "bold red"

[python]
format = "[ $symbol$version]($style)"
style = "bold yellow"
detect_files = ["requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", ".python-version"]
detect_extensions = ["py"]
detect_folders = [".venv", "venv"]

[nodejs]
format = "[ $symbol$version]($style)"
style = "bold green"

[java]
format = "[ $symbol$version]($style)"
style = "bold red"

[package]
format = "[ $symbol$version]($style)"
style = "bold blue"

[line_break]
disabled = true
EOF

# Desktop Environment Fixes
# Fix flatpak apps complaining about canberra-gtk-module
flatpak override --user --unset-env=GTK_MODULES

# Fix DBUS_SESSION_BUS_ADDRESS being set to "disabled:" on X11 environment pipelines
grep -q "DBUS_SESSION_BUS_ADDRESS" ~/.xprofile 2>/dev/null || echo 'export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$UID/bus' >> ~/.xprofile

#brave origin
paru -S brave-origin-bin

#hard limits for gaming
sudo grep -q "^$USER[[:space:]]\+hard[[:space:]]\+nofile[[:space:]]\+524288$" /etc/security/limits.conf || echo "$USER hard nofile 524288" | sudo tee -a /etc/security/limits.conf >/dev/null

#flatpak steam symlink
mkdir -p ~/Games/Steam
ln -s ~/.var/app/com.valvesoftware.Steam/.steam/steam/steamapps/common ~/Games/Steam

sudo groupadd dialout
sudo groupadd uucp
sudo usermod -aG dialout $USER
sudo usermod -aG uucp $USER

#PAM fix
# KDE lock screen: kscreenlocker cancels PAM on suspend/resume and pam_faillock
# treats that as real failed logins (instant "Failed login", multi-minute lockouts).
# Override only the lock-screen stack; SDDM/console/sudo keep system-auth faillock.
sudo tee /etc/pam.d/kde > /dev/null << 'EOF'
#%PAM-1.0
auth       required   pam_shells.so
auth       requisite  pam_nologin.so
auth       required   pam_unix.so          try_first_pass nullok
auth       optional   pam_permit.so
auth       required   pam_env.so
account    include    system-local-login
password   include    system-local-login
session    include    system-local-login
EOF



echo -e "\n--- Installation & Configuration Complete ---\nNote: If the kernel was updated during this process, please reboot.\nOtherwise, just log out and back in to refresh your group permissions."

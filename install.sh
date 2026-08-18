#!/data/data/com.termux/files/usr/bin/env bash
# Termux Sentinel installer.
#
# Must be run from a normal Termux shell, not from inside PRoot: Termux refuses
# package operations as root, and the scanner needs native Termux to reach the
# Android layer at all.

set -euo pipefail

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[36m%s\033[0m\n' "$*"; }
warn()  { printf '\033[33m%s\033[0m\n' "$*"; }

blue "Termux Sentinel installer"
echo

if [ "$(id -u)" = "0" ]; then
    red "Running as root. Termux blocks package installs as root."
    red "Exit any PRoot/chroot session and run this from a plain Termux shell."
    exit 1
fi

if [ ! -d "$PREFIX" ]; then
    red "Termux prefix not found at $PREFIX. This installer is for Termux only."
    exit 1
fi

# --- packages ---------------------------------------------------------------
# python  : the scanner itself
# clamav  : signature engine and its database updater
# yara    : behavioural rule engine
# openssl : signer certificate fingerprints
# termux-api : Android notifications from the watcher (optional but useful)
PACKAGES=(python clamav yara openssl-tool termux-api)

blue "Installing packages: ${PACKAGES[*]}"
pkg install -y "${PACKAGES[@]}"
echo

# --- storage ----------------------------------------------------------------
if [ ! -d "$HOME/storage" ]; then
    warn "Shared storage is not set up yet."
    warn "Running termux-setup-storage; approve the Android permission prompt."
    termux-setup-storage || true
    sleep 2
fi

# --- launcher ---------------------------------------------------------------
mkdir -p "$PREFIX/bin"
ln -sf "$REPO/bin/sentinel" "$PREFIX/bin/sentinel"
chmod +x "$REPO/bin/sentinel"
green "Installed launcher: $PREFIX/bin/sentinel"

# --- config -----------------------------------------------------------------
"$PREFIX/bin/sentinel" config init || true

echo
blue "Next steps"
echo "  1. sentinel doctor          check what this environment can inspect"
echo "  2. sentinel update          download signatures (~250 MB, once)"
echo "  3. sentinel scan --full     scan installed apps and storage"
echo "  4. sentinel watch           real-time watch on download folders"
echo
warn "Read docs/CAPABILITIES.md before relying on this. An unrooted Android"
warn "device places hard limits on what any scanner, including this one, can see."

#!/usr/bin/env bash
#
# portveil installer.
#
#   curl -fsSL https://raw.githubusercontent.com/rsendz/portveil/main/install.sh | bash
#
# Environment overrides:
#   PORTVEIL_REPO   owner/name to install from      (default rsendz/portveil)
#   PORTVEIL_REF    branch or tag to build          (default main)
#   PREFIX          install location                (default /usr/local)
#   PORTVEIL_NO_DEPS=1  never install packages, only report what is missing

set -euo pipefail

REPO="${PORTVEIL_REPO:-rsendz/portveil}"
REF="${PORTVEIL_REF:-main}"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"

if [ -t 1 ]; then
  BOLD=$'\033[1m'; CYAN=$'\033[36m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; OFF=$'\033[0m'
else
  BOLD=""; CYAN=""; RED=""; YELLOW=""; OFF=""
fi

step() { printf '%s==>%s %s\n' "$CYAN" "$OFF" "$*"; }
warn() { printf '%swarning:%s %s\n' "$YELLOW" "$OFF" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Runs a command, echoing it first, with sudo when we are not already root.
run_privileged() {
  if [ "$(id -u)" -eq 0 ]; then
    printf '    %s\n' "$*"; "$@"
  else
    have sudo || die "need root to run: $*"
    printf '    sudo %s\n' "$*"; sudo "$@"
  fi
}

OS="$(uname -s)"
case "$OS" in
  Darwin|Linux) ;;
  *) die "portveil supports macOS and Linux; this is $OS." ;;
esac

# --- dependencies ------------------------------------------------------------

missing=()
have git   || missing+=(git)
have cmake || missing+=(cmake)
if ! have c++ && ! have g++ && ! have clang++; then missing+=(compiler); fi

# libpcap headers: on macOS they ship inside the SDK, elsewhere look in the
# usual include paths.
pcap_ok=0
if [ "$OS" = "Darwin" ]; then
  if have xcrun && [ -f "$(xcrun --show-sdk-path 2>/dev/null)/usr/include/pcap.h" ]; then
    pcap_ok=1
  fi
else
  for d in /usr/include /usr/local/include; do
    [ -f "$d/pcap.h" ] && pcap_ok=1
  done
fi
[ "$pcap_ok" -eq 1 ] || missing+=(libpcap)

if [ ${#missing[@]} -gt 0 ]; then
  step "Installing build dependencies: ${missing[*]}"

  if [ "${PORTVEIL_NO_DEPS:-0}" = "1" ]; then
    die "missing: ${missing[*]} (PORTVEIL_NO_DEPS is set, so nothing was installed)"
  fi

  if [ "$OS" = "Darwin" ]; then
    # The compiler and libpcap both come from the command line tools.
    if ! have xcrun || [ ! -d "$(xcrun --show-sdk-path 2>/dev/null || echo /nonexistent)" ]; then
      die "Xcode command line tools are required. Install them, then re-run:
    xcode-select --install"
    fi
    if ! have cmake; then
      have brew || die "cmake is required. Install Homebrew (https://brew.sh) then:
    brew install cmake"
      printf '    brew install cmake\n'; brew install cmake
    fi
    if ! have git; then
      die "git is required. Install it with: brew install git"
    fi
  elif have apt-get; then
    run_privileged apt-get update -qq
    run_privileged apt-get install -y git cmake build-essential libpcap-dev
  elif have dnf; then
    run_privileged dnf install -y git cmake gcc-c++ make libpcap-devel
  elif have yum; then
    run_privileged yum install -y git cmake gcc-c++ make libpcap-devel
  elif have pacman; then
    run_privileged pacman -Sy --needed --noconfirm git cmake base-devel libpcap
  elif have zypper; then
    run_privileged zypper install -y git cmake gcc-c++ make libpcap-devel
  elif have apk; then
    run_privileged apk add --no-cache git cmake build-base libpcap-dev
  else
    die "missing: ${missing[*]}
Install them with your package manager, then run this script again."
  fi
fi

# --- source ------------------------------------------------------------------

# Building from a checkout (./install.sh) uses it directly; piped from curl we
# fetch a shallow clone into a temp directory.
here=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [ -n "$here" ] && [ -f "$here/CMakeLists.txt" ] && [ -f "$here/src/main.cpp" ]; then
  SRC="$here"
  step "Building from $SRC"
  BUILD="$SRC/build"
else
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  SRC="$TMP/portveil"
  step "Fetching $REPO ($REF)"
  git clone --depth 1 --branch "$REF" "https://github.com/$REPO.git" "$SRC" \
    >/dev/null 2>&1 || die "could not clone https://github.com/$REPO (branch $REF)"
  BUILD="$SRC/build"
fi

# --- build -------------------------------------------------------------------

if have nproc; then JOBS="$(nproc)"; else JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"; fi

step "Configuring"
cmake -S "$SRC" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release >/dev/null ||
  die "cmake configuration failed; re-run without >/dev/null to see why"

step "Compiling with $JOBS jobs (this fetches FTXUI on first build)"
cmake --build "$BUILD" -j "$JOBS" >/dev/null || die "build failed"

[ -x "$BUILD/portveil" ] || die "build finished but $BUILD/portveil is missing"

# --- install -----------------------------------------------------------------

step "Installing to $BIN_DIR/portveil"
if [ -w "$BIN_DIR" ] 2>/dev/null; then
  install -m 755 "$BUILD/portveil" "$BIN_DIR/portveil"
else
  run_privileged mkdir -p "$BIN_DIR"
  run_privileged install -m 755 "$BUILD/portveil" "$BIN_DIR/portveil"
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on your PATH; add it to your shell profile." ;;
esac

printf '\n%sportveil %s installed.%s\n\n' "$BOLD" "$("$BIN_DIR/portveil" --version | awk '{print $2}')" "$OFF"
printf 'Start capturing:\n\n    %ssudo portveil%s\n\n' "$BOLD" "$OFF"

if [ "$OS" = "Darwin" ] && [ -r /dev/bpf0 ]; then
  printf 'Your account can already read /dev/bpf*, so plain %sportveil%s works too.\n' "$BOLD" "$OFF"
fi

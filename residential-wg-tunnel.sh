#!/usr/bin/env bash
set -euo pipefail
dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ "${1:-}" == "install-deps" ]]; then
  if [[ "$(uname -s)" != Linux || "$EUID" != 0 ]]; then
    printf '%s\n' 'Run install-deps as root on Linux.' >&2
    exit 2
  fi
  if ! command -v apt-get >/dev/null; then
    printf '%s\n' 'Install Python 3.9+, iproute2, wireguard-tools and nftables using your distribution package manager.' >&2
    exit 2
  fi
  packages=()
  command -v python3 >/dev/null || packages+=(python3)
  command -v ip >/dev/null || packages+=(iproute2)
  command -v wg >/dev/null || packages+=(wireguard-tools)
  command -v nft >/dev/null || packages+=(nftables)
  if (( ${#packages[@]} == 0 )); then
    printf '%s\n' 'All dependencies are already installed.'
    exit
  fi
  apt-get update
  apt-get install -y --no-upgrade --no-install-recommends "${packages[@]}"
  exit
fi
if ! command -v python3 >/dev/null; then
  printf '%s\n' 'Python 3.9+ is required. On Debian or Ubuntu, run this script with install-deps.' >&2
  exit 2
fi
exec python3 "$dir/residential-wg-tunnel.py" "$@"

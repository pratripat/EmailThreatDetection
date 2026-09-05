#!/usr/bin/env bash
# ==============================================================================
# Script: download_ip_ranges.sh
# Purpose: Refresh datacenter and VPN/Tor exit CIDR blocks from public feeds.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${SCRIPT_DIR}/../data/ip_ranges"

mkdir -p "${TARGET_DIR}"

echo "[*] Downloading Datacenter IPv4 / IPv6 CIDR blocks..."
# Example public datacenter list or placeholder update
curl -sSf "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/master/abuseipdb-s100-all.ipv4" -o "${TARGET_DIR}/datacenter_ipv4.txt" || echo "[!] Failed to fetch remote datacenter list, keeping local fallback."

echo "[*] Downloading Tor / VPN IPv4 exit nodes..."
curl -sSf "https://check.torproject.org/torbulkexitlist" -o "${TARGET_DIR}/vpn_ipv4.txt" || echo "[!] Failed to fetch remote Tor list, keeping local fallback."

echo "[+] IP ranges update complete in ${TARGET_DIR}"

#!/usr/bin/env sh
# Air-Gapped Field USB Packaging & Self-Integrity Manifest Sealer
# Usage: ./scripts/package_airgapped_usb.sh [DEST_DIR]
set -eu

DEST_DIR="${1:-/mnt/ir_usb_ro}"

BINARIES="
fsr-forensic-verdict
fsr-remediation-advisor
fsr-ova-attribution
fsr-qa-fixture-harness
fsr-deep-audit
fsr-net-crypto-audit
fsr-clone-cluster-audit
fsr-supplychain-backdoor-audit
"

echo "[1/3] Building zero-dependency release binaries across all 8 workspace crates..."
cargo build --workspace --release

echo "[2/3] Stripping symbol tables from release binaries..."
for bin in $BINARIES; do
    if [ -f "target/release/$bin" ]; then
        strip "target/release/$bin" 2>/dev/null || true
    fi
done

mkdir -p "$DEST_DIR"
MANIFEST_FILE="$DEST_DIR/fsr-suite-manifest.sha256"
: > "$MANIFEST_FILE"

echo "[3/3] Staging binaries and sealing SHA-256 Self-Integrity Manifest at $MANIFEST_FILE..."
for bin in $BINARIES; do
    src="target/release/$bin"
    if [ -f "$src" ]; then
        cp -f "$src" "$DEST_DIR/$bin"
        chmod 0555 "$DEST_DIR/$bin" 2>/dev/null || true
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "target/release/$bin" >> "$MANIFEST_FILE"
        else
            shasum -a 256 "target/release/$bin" >> "$MANIFEST_FILE"
        fi
    fi
done

echo "Sealed air-gapped USB bundle in: $DEST_DIR"
cat "$MANIFEST_FILE"

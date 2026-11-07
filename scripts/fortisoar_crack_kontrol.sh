#!/usr/bin/env bash
# ==============================================================================
# FortiSOAR & FortiGate Tek Komutla Crack / Lisans Baypası / Arka Kapı Kontrolü
# Kurumsal Siber Güvenlik, SOC ve Bağımsız Bütünlük Denetim Saha Betiği
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="${REPO_ROOT}/target/release/fsr-forensic-verdict"

if [[ ! -x "${BIN_PATH}" ]]; then
  echo "[*] fsr-forensic-verdict release ikilisi derleniyor (sıfır harici bağımlılık)..." >&2
  (cd "${REPO_ROOT}" && cargo build -p fsr-forensic-verdict --release)
fi

if [[ "${1:-}" == "--portal" ]]; then
  PORT_ADDR="${2:-127.0.0.1:8090}"
  TARGET_ROOT="${3:-/}"
  echo "[*] Yerel Kurumsal Crack Doğrulama Web Portalı başlatılıyor: http://${PORT_ADDR}" >&2
  exec "${BIN_PATH}" --serve "${PORT_ADDR}" --root "${TARGET_ROOT}"
fi

TARGET="${1:-/}"
REPORT_JSON="${2:-/tmp/fortisoar_kanit_zarfi.json}"

echo "[*] Hedef inceleniyor: ${TARGET}" >&2
"${BIN_PATH}" --quick-check "${TARGET}" --format json -o "${REPORT_JSON}"

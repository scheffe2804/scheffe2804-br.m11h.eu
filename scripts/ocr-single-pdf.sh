#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 /path/to/input.pdf" >&2
  exit 2
fi

INPUT="$1"
if [[ ! -f "$INPUT" ]]; then
  echo "Input file not found: $INPUT" >&2
  exit 1
fi

ROOT="${BR_STORAGE_ROOT:-/srv/br-wissensdatenbank}"
BASENAME_BIN="/usr/bin/basename"
DATE_BIN="/usr/bin/date"
MKDIR_BIN="/usr/bin/mkdir"
SHA256SUM_BIN="/usr/bin/sha256sum"
CUT_BIN="/usr/bin/cut"
ALLOWED_OCRMYPDF_PATHS=(/usr/bin/ocrmypdf /usr/local/bin/ocrmypdf)
OCRMYPDF_BIN=""
PDFTOTEXT_BIN="/usr/bin/pdftotext"
WC_BIN="/usr/bin/wc"
TEE_BIN="/usr/bin/tee"
CHMOD_BIN="/usr/bin/chmod"
BASENAME="$($BASENAME_BIN "$INPUT")"
SAFE_BASE="${BASENAME%.pdf}"
STAMP="$($DATE_BIN -u +%Y%m%dT%H%M%SZ)"
OCR_OUT="${ROOT}/ocr/${SAFE_BASE}.ocr.pdf"
TEXT_OUT="${ROOT}/text/${SAFE_BASE}.txt"
LOG_FILE="${ROOT}/logs/ocr-${SAFE_BASE}-${STAMP}.log"

for candidate in "${ALLOWED_OCRMYPDF_PATHS[@]}"; do
  if [[ -f "$candidate" && -x "$candidate" && ! -L "$candidate" ]]; then
    OCRMYPDF_BIN="$candidate"
    break
  fi
done

if [[ -z "$OCRMYPDF_BIN" ]]; then
  echo "ocr_status=missing_ocrmypdf" >&2
  exit 1
fi

"$MKDIR_BIN" -p "${ROOT}/ocr" "${ROOT}/text" "${ROOT}/logs"

{
  echo "# OCR single PDF"
  echo "timestamp=${STAMP}"
  echo "input=${INPUT}"
  echo "ocr_out=${OCR_OUT}"
  echo "text_out=${TEXT_OUT}"
  echo "sha256_input=$("$SHA256SUM_BIN" "$INPUT" | "$CUT_BIN" -d' ' -f1)"
  echo
  "$OCRMYPDF_BIN" --skip-text --deskew --rotate-pages --language deu+eng "$INPUT" "$OCR_OUT"
  "$PDFTOTEXT_BIN" -layout "$OCR_OUT" "$TEXT_OUT"
  echo "sha256_ocr=$("$SHA256SUM_BIN" "$OCR_OUT" | "$CUT_BIN" -d' ' -f1)"
  echo "text_bytes=$("$WC_BIN" -c < "$TEXT_OUT")"
} | "$TEE_BIN" "$LOG_FILE"

"$CHMOD_BIN" 640 "$OCR_OUT" "$TEXT_OUT" "$LOG_FILE"

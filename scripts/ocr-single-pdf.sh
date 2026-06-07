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
BASENAME="$(basename "$INPUT")"
SAFE_BASE="${BASENAME%.pdf}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OCR_OUT="${ROOT}/ocr/${SAFE_BASE}.ocr.pdf"
TEXT_OUT="${ROOT}/text/${SAFE_BASE}.txt"
LOG_FILE="${ROOT}/logs/ocr-${SAFE_BASE}-${STAMP}.log"

mkdir -p "${ROOT}/ocr" "${ROOT}/text" "${ROOT}/logs"

{
  echo "# OCR single PDF"
  echo "timestamp=${STAMP}"
  echo "input=${INPUT}"
  echo "ocr_out=${OCR_OUT}"
  echo "text_out=${TEXT_OUT}"
  echo "sha256_input=$(sha256sum "$INPUT" | cut -d' ' -f1)"
  echo
  ocrmypdf --skip-text --deskew --rotate-pages --language deu+eng "$INPUT" "$OCR_OUT"
  pdftotext -layout "$OCR_OUT" "$TEXT_OUT"
  echo "sha256_ocr=$(sha256sum "$OCR_OUT" | cut -d' ' -f1)"
  echo "text_bytes=$(wc -c < "$TEXT_OUT")"
} | tee "$LOG_FILE"

chmod 640 "$OCR_OUT" "$TEXT_OUT" "$LOG_FILE"

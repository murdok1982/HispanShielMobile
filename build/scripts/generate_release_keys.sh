#!/usr/bin/env bash
# HispaShield Release Key Generation Script
# Generates AVB signing keys, platform signing keys, and APEX keys
# following the GrapheneOS key generation workflow.
#
# Usage: ./generate_release_keys.sh [OUTPUT_DIR]
#
# Requirements: openssl >= 3.0, zip, java (for APEX)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-${SCRIPT_DIR}/../../keys}"
LOG_FILE="${OUTPUT_DIR}/keygen.log"

# Key sizes and parameters
RSA_BITS=4096
EC_CURVE="prime256v1"   # P-256 for AVB
VALIDITY_DAYS=10000     # ~27 years

# Subject fields
SUBJECT_BASE="/O=HispaShield/OU=Mobile Security/L=Madrid/C=ES"

##############################################################################
# Helpers
##############################################################################
log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" | tee -a "${LOG_FILE}"; }
die() { log "ERROR: $*" >&2; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

generate_rsa_key_and_cert() {
    local name="$1"
    local cn="$2"
    local out_dir="$3"

    log "Generating RSA-${RSA_BITS} key: ${name}"
    openssl genrsa -out "${out_dir}/${name}.key" ${RSA_BITS} 2>>"${LOG_FILE}"

    log "Generating self-signed certificate: ${name}"
    openssl req -new -x509 \
        -key "${out_dir}/${name}.key" \
        -out "${out_dir}/${name}.crt" \
        -days ${VALIDITY_DAYS} \
        -subj "${SUBJECT_BASE}/CN=${cn}" \
        -sha256 2>>"${LOG_FILE}"

    # Generate DER format for AOSP
    openssl x509 -in "${out_dir}/${name}.crt" \
        -out "${out_dir}/${name}.der" \
        -outform DER 2>>"${LOG_FILE}"

    # Generate PKCS#8 DER private key (AOSP format)
    openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt \
        -in "${out_dir}/${name}.key" \
        -out "${out_dir}/${name}.pk8" 2>>"${LOG_FILE}"

    log "  -> ${name}.key, ${name}.crt, ${name}.der, ${name}.pk8"
}

generate_ec_key_and_cert() {
    local name="$1"
    local cn="$2"
    local out_dir="$3"

    log "Generating EC (${EC_CURVE}) key: ${name}"
    openssl ecparam -name "${EC_CURVE}" -genkey -noout \
        -out "${out_dir}/${name}.key" 2>>"${LOG_FILE}"

    log "Generating self-signed EC certificate: ${name}"
    openssl req -new -x509 \
        -key "${out_dir}/${name}.key" \
        -out "${out_dir}/${name}.crt" \
        -days ${VALIDITY_DAYS} \
        -subj "${SUBJECT_BASE}/CN=${cn}" \
        -sha256 2>>"${LOG_FILE}"

    openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt \
        -in "${out_dir}/${name}.key" \
        -out "${out_dir}/${name}.pk8" 2>>"${LOG_FILE}"

    log "  -> ${name}.key, ${name}.crt, ${name}.pk8"
}

##############################################################################
# Main
##############################################################################
require_cmd openssl

log "=== HispaShield Key Generation ==="
log "Output directory: ${OUTPUT_DIR}"

# Create directory structure
mkdir -p \
    "${OUTPUT_DIR}/platform" \
    "${OUTPUT_DIR}/avb" \
    "${OUTPUT_DIR}/apex" \
    "${OUTPUT_DIR}/media" \
    "${OUTPUT_DIR}/shared" \
    "${OUTPUT_DIR}/releasekey" \
    "${OUTPUT_DIR}/testkey"

touch "${LOG_FILE}"

##############################################################################
# 1. AVB (Android Verified Boot) key — EC P-256
##############################################################################
log "--- AVB Keys ---"
AVB_DIR="${OUTPUT_DIR}/avb"
generate_ec_key_and_cert "avb" "HispaShield AVB Signing Key" "${AVB_DIR}"

# Convert to AVB raw key format expected by avbtool
openssl ec -in "${AVB_DIR}/avb.key" -pubout \
    -out "${AVB_DIR}/avb_public_key.pem" 2>>"${LOG_FILE}"
log "AVB public key: avb_public_key.pem"

##############################################################################
# 2. Platform signing keys (AOSP platform, shared, media, releasekey)
##############################################################################
log "--- Platform Signing Keys ---"
PLATFORM_DIR="${OUTPUT_DIR}/platform"
generate_rsa_key_and_cert "platform" "HispaShield Platform" "${PLATFORM_DIR}"
generate_rsa_key_and_cert "shared"   "HispaShield Shared"   "${OUTPUT_DIR}/shared"
generate_rsa_key_and_cert "media"    "HispaShield Media"    "${OUTPUT_DIR}/media"

##############################################################################
# 3. Release key (used for signing APKs / OTA packages)
##############################################################################
log "--- Release Key ---"
generate_rsa_key_and_cert "releasekey" "HispaShield Release" "${OUTPUT_DIR}/releasekey"

# Create PKCS#12 keystore for use with apksigner / jarsigner
openssl pkcs12 -export \
    -in "${OUTPUT_DIR}/releasekey/releasekey.crt" \
    -inkey "${OUTPUT_DIR}/releasekey/releasekey.key" \
    -out "${OUTPUT_DIR}/releasekey/releasekey.p12" \
    -name "releasekey" \
    -passout pass:hispashield 2>>"${LOG_FILE}"
log "Keystore: releasekey.p12 (password: hispashield)"

##############################################################################
# 4. APEX signing keys
##############################################################################
log "--- APEX Keys ---"
APEX_DIR="${OUTPUT_DIR}/apex"
for apex_name in com.hispashield.npd com.hispashield.sensorguard \
                 com.hispashield.settings com.hispashield.profileisolation \
                 com.hispashield.gmscompat com.hispashield.autoreboot \
                 com.hispashield.basebandproxy com.hispashield.mediaisolate; do
    apex_subdir="${APEX_DIR}/${apex_name}"
    mkdir -p "${apex_subdir}"
    generate_rsa_key_and_cert "apex_payload" "${apex_name} APEX Payload" "${apex_subdir}"
    generate_ec_key_and_cert  "apex_container" "${apex_name} APEX Container" "${apex_subdir}"
    log "  APEX keys for ${apex_name}"
done

##############################################################################
# 5. OTA package signing key
##############################################################################
log "--- OTA Package Key ---"
OTA_DIR="${OUTPUT_DIR}/ota"
mkdir -p "${OTA_DIR}"
generate_rsa_key_and_cert "ota" "HispaShield OTA Signing" "${OTA_DIR}"

##############################################################################
# 6. Print fingerprints
##############################################################################
log "--- Key Fingerprints ---"
for crt in $(find "${OUTPUT_DIR}" -name "*.crt" | sort); do
    fp=$(openssl x509 -in "${crt}" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    log "  ${crt##${OUTPUT_DIR}/}: SHA256=${fp}"
done

##############################################################################
# 7. Set restrictive permissions
##############################################################################
find "${OUTPUT_DIR}" -name "*.key" -exec chmod 400 {} \;
find "${OUTPUT_DIR}" -name "*.pk8" -exec chmod 400 {} \;
find "${OUTPUT_DIR}" -name "*.p12" -exec chmod 400 {} \;
chmod 700 "${OUTPUT_DIR}"

log "=== Key generation complete. Store keys in a Hardware Security Module for production. ==="
log "=== NEVER commit private keys to version control. ==="

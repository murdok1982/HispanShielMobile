#!/usr/bin/env bash
# HispaShield ROM Build Script
# Builds a hardened AOSP-based ROM for Google Pixel 8 (shiba)
#
# Usage: ./build_rom.sh [OPTIONS]
#   -t, --target DEVICE    AOSP device target (default: shiba)
#   -v, --variant VARIANT  Build variant: user|userdebug|eng (default: user)
#   -j, --jobs N           Parallel jobs (default: nproc)
#   -s, --source DIR       AOSP source root (default: $AOSP_SOURCE_ROOT or ./aosp)
#   --keys-dir DIR         Release keys directory (default: ./keys)
#   --no-sign              Skip signing (for development builds only)
#   -h, --help             Show this help

set -euo pipefail

##############################################################################
# Defaults
##############################################################################
DEVICE="shiba"
VARIANT="user"
JOBS="$(nproc)"
AOSP_SOURCE="${AOSP_SOURCE_ROOT:-${PWD}/aosp}"
HISPASHIELD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KEYS_DIR="${HISPASHIELD_ROOT}/keys"
SIGN_BUILD=true
LOG_DIR="${HISPASHIELD_ROOT}/build/logs"
TIMESTAMP="$(date -u '+%Y%m%d_%H%M%S')"
BUILD_LOG="${LOG_DIR}/build_${TIMESTAMP}.log"

##############################################################################
# Colours
##############################################################################
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[BUILD]${NC} $*" | tee -a "${BUILD_LOG}"; }
ok()   { echo -e "${GREEN}[OK]${NC}   $*" | tee -a "${BUILD_LOG}"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "${BUILD_LOG}"; }
die()  { echo -e "${RED}[FAIL]${NC} $*" | tee -a "${BUILD_LOG}" >&2; exit 1; }

##############################################################################
# Argument parsing
##############################################################################
usage() {
    grep '^#' "${BASH_SOURCE[0]}" | grep -v '#!/' | sed 's/^# *//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)    DEVICE="$2"; shift 2 ;;
        -v|--variant)   VARIANT="$2"; shift 2 ;;
        -j|--jobs)      JOBS="$2"; shift 2 ;;
        -s|--source)    AOSP_SOURCE="$2"; shift 2 ;;
        --keys-dir)     KEYS_DIR="$2"; shift 2 ;;
        --no-sign)      SIGN_BUILD=false; shift ;;
        -h|--help)      usage ;;
        *)              die "Unknown argument: $1" ;;
    esac
done

##############################################################################
# Validation
##############################################################################
mkdir -p "${LOG_DIR}"
log "=== HispaShield ROM Build ==="
log "Device:    ${DEVICE}"
log "Variant:   ${VARIANT}"
log "Jobs:      ${JOBS}"
log "AOSP root: ${AOSP_SOURCE}"
log "Keys dir:  ${KEYS_DIR}"
log "Log file:  ${BUILD_LOG}"

[[ -d "${AOSP_SOURCE}" ]] || die "AOSP source directory not found: ${AOSP_SOURCE}"
[[ -f "${AOSP_SOURCE}/build/envsetup.sh" ]] || die "Not a valid AOSP tree (missing build/envsetup.sh)"

if [[ "${SIGN_BUILD}" == true ]]; then
    [[ -d "${KEYS_DIR}" ]] || die "Keys directory not found: ${KEYS_DIR}. Run generate_release_keys.sh first."
fi

case "${VARIANT}" in
    user|userdebug|eng) ;;
    *) die "Invalid variant '${VARIANT}'. Must be user, userdebug, or eng." ;;
esac

##############################################################################
# Step 1: Apply HispaShield patches to AOSP
##############################################################################
log "--- Step 1: Applying HispaShield patches ---"

PATCHES_DIR="${HISPASHIELD_ROOT}/patches"

if [[ -d "${PATCHES_DIR}" ]]; then
    for patch in "${PATCHES_DIR}"/*.patch; do
        [[ -f "${patch}" ]] || continue
        log "  Applying patch: $(basename "${patch}")"
        (cd "${AOSP_SOURCE}" && git apply "${patch}") \
            || warn "Patch $(basename "${patch}") did not apply cleanly — check manually"
    done
    ok "Patches applied"
else
    warn "No patches directory found at ${PATCHES_DIR} — skipping patch step"
fi

##############################################################################
# Step 2: Copy HispaShield services and SEPolicy into AOSP tree
##############################################################################
log "--- Step 2: Integrating HispaShield into AOSP tree ---"

HISPASHIELD_VENDOR="${AOSP_SOURCE}/vendor/hispashield"
mkdir -p "${HISPASHIELD_VENDOR}"

# Copy Rust services
log "  Copying Rust daemons..."
cp -r "${HISPASHIELD_ROOT}/services" "${HISPASHIELD_VENDOR}/"

# Copy SELinux policy
log "  Copying SELinux policy..."
SEPOLICY_DEST="${HISPASHIELD_VENDOR}/sepolicy"
mkdir -p "${SEPOLICY_DEST}"
cp -r "${HISPASHIELD_ROOT}/sepolicy/private/"*.te "${SEPOLICY_DEST}/" 2>/dev/null || true

# Copy build files
log "  Copying Android.mk / Android.bp stubs..."
cat > "${HISPASHIELD_VENDOR}/Android.bp" << 'BPEOF'
// HispaShield vendor module — Rust daemons are built via cargo-android
// and installed via the vendor image.
package {
    default_applicable_licenses: ["hispashield_license"],
}
license {
    name: "hispashield_license",
    visibility: [":__subpackages__"],
    license_kinds: ["SPDX-license-identifier-Apache-2.0"],
}
BPEOF

ok "HispaShield integration complete"

##############################################################################
# Step 3: Configure AOSP build environment
##############################################################################
log "--- Step 3: Setting up AOSP build environment ---"

# Android build requires bash (not POSIX sh), sourcing envsetup
# We use a subprocess to avoid polluting our current shell
ENVSETUP_CMD="source ${AOSP_SOURCE}/build/envsetup.sh && lunch ${DEVICE}-${VARIANT}"

log "  Running: ${ENVSETUP_CMD}"
eval "${ENVSETUP_CMD}" >> "${BUILD_LOG}" 2>&1 \
    || die "Failed to set up build environment"

ok "Build environment configured"

##############################################################################
# Step 4: Apply HispaShield security hardening build flags
##############################################################################
log "--- Step 4: Setting HispaShield build flags ---"

export HISPASHIELD_BUILD=1
export HISPASHIELD_DEVICE="${DEVICE}"

# Enable full RELRO, stack protector, and CFI for all native code
export TARGET_ENABLE_CFI=true
export SANITIZE_TARGET=address  # Only for userdebug/eng
[[ "${VARIANT}" == "user" ]] && unset SANITIZE_TARGET

# Harden SELinux — enforce for all domains
export BOARD_SEPOLICY_ENFORCE_ALL=true

# Disable Google Play Services check-in by default
export HISPASHIELD_DISABLE_GMS_CHECKIN=true

ok "Build flags set"

##############################################################################
# Step 5: Build the ROM
##############################################################################
log "--- Step 5: Building ROM (this will take a while) ---"
log "  Running: m -j${JOBS} 2>&1"

START_TIME=$(date +%s)

(cd "${AOSP_SOURCE}" && \
    source build/envsetup.sh >> "${BUILD_LOG}" 2>&1 && \
    lunch "${DEVICE}-${VARIANT}" >> "${BUILD_LOG}" 2>&1 && \
    m -j"${JOBS}" 2>>"${BUILD_LOG}") \
    || die "Build failed. Check log: ${BUILD_LOG}"

END_TIME=$(date +%s)
BUILD_DURATION=$(( END_TIME - START_TIME ))
ok "Build completed in $((BUILD_DURATION / 60))m $((BUILD_DURATION % 60))s"

##############################################################################
# Step 6: Sign the build
##############################################################################
if [[ "${SIGN_BUILD}" == true ]]; then
    log "--- Step 6: Signing ROM images ---"

    OUT_DIR="${AOSP_SOURCE}/out/target/product/${DEVICE}"
    SIGNED_DIR="${OUT_DIR}/signed"
    mkdir -p "${SIGNED_DIR}"

    # Sign target-files package
    TARGET_FILES="${OUT_DIR}/${DEVICE}-target_files-*.zip"
    TARGET_FILES="$(ls -1t ${TARGET_FILES} 2>/dev/null | head -1)"

    if [[ -z "${TARGET_FILES}" ]]; then
        die "target-files package not found in ${OUT_DIR}"
    fi

    log "  Signing target-files: $(basename "${TARGET_FILES}")"

    # Use AOSP's sign_target_files_apks
    SIGN_TOOL="${AOSP_SOURCE}/build/tools/releasetools/sign_target_files_apks.py"
    python3 "${SIGN_TOOL}" \
        -o \
        --key_mapping "build/target/product/security/platform=${KEYS_DIR}/platform/platform" \
        --key_mapping "build/target/product/security/shared=${KEYS_DIR}/shared/shared" \
        --key_mapping "build/target/product/security/media=${KEYS_DIR}/media/media" \
        --key_mapping "build/target/product/security/releasekey=${KEYS_DIR}/releasekey/releasekey" \
        --avb_vbmeta_key "${KEYS_DIR}/avb/avb.key" \
        --avb_vbmeta_algorithm SHA256_RSA4096 \
        "${TARGET_FILES}" \
        "${SIGNED_DIR}/${DEVICE}-signed-target_files.zip" \
        >> "${BUILD_LOG}" 2>&1 \
        || die "Signing failed"

    log "  Generating OTA package..."
    OTA_TOOL="${AOSP_SOURCE}/build/tools/releasetools/ota_from_target_files.py"
    python3 "${OTA_TOOL}" \
        -k "${KEYS_DIR}/ota/ota" \
        "${SIGNED_DIR}/${DEVICE}-signed-target_files.zip" \
        "${SIGNED_DIR}/${DEVICE}-ota.zip" \
        >> "${BUILD_LOG}" 2>&1 \
        || die "OTA package generation failed"

    ok "ROM signed. OTA package: ${SIGNED_DIR}/${DEVICE}-ota.zip"
else
    warn "Signing skipped (--no-sign). Do NOT distribute unsigned builds."
fi

##############################################################################
# Done
##############################################################################
log "=== Build complete ==="
log "Output: ${AOSP_SOURCE}/out/target/product/${DEVICE}/"
[[ "${SIGN_BUILD}" == true ]] && log "Signed OTA: ${SIGNED_DIR}/${DEVICE}-ota.zip"
log "Build log: ${BUILD_LOG}"

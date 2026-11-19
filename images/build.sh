#!/usr/bin/env bash
set -euo pipefail

# Reproducible Linux ARM64 & x64 MicroVM golden guest image builder.
# Produces: kernel artifact, ext4 rootfs containing static /init (wardline-guest-agent),
# and unsigned manifest.json ready for `wardline image sign`.

ARCH="${1:-x64}"
OUT_DIR="${2:-./images/out-${ARCH}}"
mkdir -p "${OUT_DIR}"

case "${ARCH}" in
  arm64|aarch64)
    RUST_TARGET="aarch64-unknown-linux-musl"
    CANON_ARCH="arm64"
    ;;
  x64|x86_64)
    RUST_TARGET="x86_64-unknown-linux-musl"
    CANON_ARCH="x64"
    ;;
  *)
    echo "Unsupported arch: ${ARCH} (expected arm64 or x64)" >&2
    exit 1
    ;;
esac

echo "[wardline-image] Building static guest agent for ${RUST_TARGET}..."
cargo build --release --package wardline-guest-agent --target "${RUST_TARGET}"

STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "${STAGE_DIR}"' EXIT

mkdir -p "${STAGE_DIR}/workspace" "${STAGE_DIR}/bin" "${STAGE_DIR}/dev" "${STAGE_DIR}/proc" "${STAGE_DIR}/tmp"
cp "target/${RUST_TARGET}/release/wardline-guest-agent" "${STAGE_DIR}/init"
chmod 0755 "${STAGE_DIR}/init"

ROOTFS_IMG="${OUT_DIR}/rootfs.ext4"
KERNEL_IMG="${OUT_DIR}/vmlinux"

if command -v mke2fs >/dev/null 2>&1; then
  rm -f "${ROOTFS_IMG}"
  mke2fs -t ext4 -d "${STAGE_DIR}" -r 1 -N 0 -m 5 -L wardline-guest "${ROOTFS_IMG}" 32M
else
  tar -cf "${ROOTFS_IMG}" -C "${STAGE_DIR}" .
fi

if [ ! -f "${KERNEL_IMG}" ]; then
  if [ -n "${WARDLINE_KERNEL_PATH:-}" ] && [ -f "${WARDLINE_KERNEL_PATH}" ]; then
    cp "${WARDLINE_KERNEL_PATH}" "${KERNEL_IMG}"
  else
    echo "Note: place guest kernel at ${KERNEL_IMG} (or set WARDLINE_KERNEL_PATH) before signing." >&2
    printf "WARDLINE_KERNEL_PLACEHOLDER_%s\n" "${CANON_ARCH}" > "${KERNEL_IMG}"
  fi
fi

KERNEL_SHA="$(sha256sum "${KERNEL_IMG}" | awk '{print $1}')"
ROOTFS_SHA="$(sha256sum "${ROOTFS_IMG}" | awk '{print $1}')"
EPOCH="$(date -u +%s)"

cat > "${OUT_DIR}/manifest.json" <<EOF
{
  "format_version": 2,
  "arch": "${CANON_ARCH}",
  "kernel_file": "vmlinux",
  "kernel_sha256": "${KERNEL_SHA}",
  "rootfs_file": "rootfs.ext4",
  "rootfs_sha256": "${ROOTFS_SHA}",
  "snapshot_file": null,
  "snapshot_sha256": null,
  "build_epoch": ${EPOCH}
}
EOF

echo "[wardline-image] Built ${OUT_DIR}/manifest.json (arch=${CANON_ARCH})"
echo "[wardline-image] Next: wardline image sign --dir ${OUT_DIR} --key-hex <64_HEX>"

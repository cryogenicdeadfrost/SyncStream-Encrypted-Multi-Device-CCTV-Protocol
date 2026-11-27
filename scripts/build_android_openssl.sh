#!/usr/bin/env bash
set -euo pipefail

OPENSSL_VERSION="${OPENSSL_VERSION:-3.6.5}"
NDK_VERSION="${NDK_VERSION:-r27c}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/third_party/android-openssl"
CACHE="${ROOT}/.cache"
mkdir -p "${CACHE}" "${OUT}"

case "$(uname -s)" in
  Linux*) HOST_TAG="linux-x86_64" ;;
  Darwin*) HOST_TAG="darwin-x86_64" ;;
  *) echo "Use WSL/Linux/macOS for the OpenSSL cross-build." >&2; exit 2 ;;
esac

NDK="${ANDROID_NDK_ROOT:-}"
if [[ -z "${NDK}" ]]; then
  echo "ANDROID_NDK_ROOT must point to an installed Android NDK." >&2
  exit 2
fi

TARBALL="${CACHE}/openssl-${OPENSSL_VERSION}.tar.gz"
URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"

if [[ ! -f "${TARBALL}" ]]; then
  curl -L --fail --retry 3 "${URL}" -o "${TARBALL}"
fi

SRC="${CACHE}/openssl-${OPENSSL_VERSION}"
if [[ ! -d "${SRC}" ]]; then
  tar -xf "${TARBALL}" -C "${CACHE}"
fi

export PATH="${NDK}/toolchains/llvm/prebuilt/${HOST_TAG}/bin:${PATH}"

build_one() {
  local target="$1"
  local abi="$2"
  local prefix="${OUT}/${abi}"

  rm -rf "${SRC}/android-build-${abi}"
  cp -a "${SRC}" "${SRC}/android-build-${abi}"
  cd "${SRC}/android-build-${abi}"

  ./Configure "${target}" \
    -D__ANDROID_API__=24 \
    no-shared no-tests no-apps \
    --prefix="${prefix}"

  make -j"$(getconf _NPROCESSORS_ONLN || echo 2)"
  make install_sw

  rm -rf "${SRC}/android-build-${abi}"
}

build_one android-arm64 arm64-v8a
build_one android-x86_64 x86_64

echo "Android OpenSSL prefixes generated under ${OUT}"

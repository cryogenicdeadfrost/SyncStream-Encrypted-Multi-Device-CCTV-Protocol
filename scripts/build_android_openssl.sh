#!/usr/bin/env bash
set -euo pipefail

OPENSSL_VERSION="${OPENSSL_VERSION:-3.6.5}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/third_party/android-openssl"
CACHE="${ROOT}/.cache"
TARBALL="${CACHE}/openssl-${OPENSSL_VERSION}.tar.gz"
SOURCE_ROOT="${CACHE}/openssl-source-${OPENSSL_VERSION}"
BUILD_ROOT="${CACHE}/openssl-build-${OPENSSL_VERSION}"

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

if [[ ! -f "${TARBALL}" ]]; then
  curl -L --fail --retry 3 "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" -o "${TARBALL}"
fi

rm -rf "${SOURCE_ROOT}" "${BUILD_ROOT}"
mkdir -p "${SOURCE_ROOT}" "${BUILD_ROOT}"
tar -xf "${TARBALL}" -C "${SOURCE_ROOT}"

export PATH="${NDK}/toolchains/llvm/prebuilt/${HOST_TAG}/bin:${PATH}"

build_one() {
  local target="$1"
  local abi="$2"
  local prefix="${OUT}/${abi}"
  local build_dir="${BUILD_ROOT}/${abi}"

  rm -rf "${build_dir}" "${prefix}"
  mkdir -p "${build_dir}"

  # The source tree lives outside the build directory. This avoids the
  # previous recursive "copy a directory into itself" failure.
  cp -a "${SOURCE_ROOT}/openssl-${OPENSSL_VERSION}/." "${build_dir}/"

  cd "${build_dir}"
  ./Configure "${target}" \
    -D__ANDROID_API__=24 \
    no-shared no-tests no-apps \
    --prefix="${prefix}"

  make -j"$(getconf _NPROCESSORS_ONLN || echo 2)"
  make install_sw
}

build_one android-arm64 arm64-v8a
build_one android-x86_64 x86_64

rm -rf "${SOURCE_ROOT}" "${BUILD_ROOT}"

echo "Android OpenSSL prefixes generated under ${OUT}"

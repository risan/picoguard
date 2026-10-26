#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

targets=(
    x86_64-unknown-linux-musl
    aarch64-unknown-linux-musl
    armv7-unknown-linux-musleabihf
)
armv7_target=armv7-unknown-linux-musleabihf
armv7_size_limit=$((4 * 1024 * 1024))
target_dir="$PWD/target"

for target in "${targets[@]}"; do
    cargo zigbuild --release --target "$target" --target-dir "$target_dir"
    mkdir -p "dist/bin/$target"
    cp "$target_dir/$target/release/picoguard" "dist/bin/$target/picoguard"
    echo "$target: $(stat -c %s "dist/bin/$target/picoguard") bytes"
done

armv7_size=$(stat -c %s "dist/bin/$armv7_target/picoguard")
if [ "$armv7_size" -gt "$armv7_size_limit" ]; then
    echo "error: $armv7_target binary is $armv7_size bytes, limit is $armv7_size_limit" >&2
    exit 1
fi

# Release assets: one file per target named picoguard-<target>, the two install
# scripts, and SHA256SUMS over all of them, as docs/install.md expects.
mkdir -p dist/release
rm -f dist/release/picoguard-* dist/release/install.sh dist/release/proxmox-lxc.sh dist/release/SHA256SUMS
for target in "${targets[@]}"; do
    cp "dist/bin/$target/picoguard" "dist/release/picoguard-$target"
done

cp scripts/install.sh scripts/proxmox-lxc.sh dist/release/

(cd dist/release && sha256sum picoguard-* install.sh proxmox-lxc.sh > SHA256SUMS)
echo "release assets: dist/release/"

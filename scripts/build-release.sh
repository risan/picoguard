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

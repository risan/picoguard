#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# install.sh embeds the service files, so a script piped from curl needs nothing
# else. Fail when an embedded copy differs from its file in dist/.
check_embedded() {
    local script=$1 tag=$2 file=$3

    if ! diff <(sed -n "/<<'$tag'\$/,/^$tag\$/p" "$script" | sed '1d;$d') "$file" >/dev/null; then
        echo "error: the $tag copy in $script differs from $file" >&2
        diff <(sed -n "/<<'$tag'\$/,/^$tag\$/p" "$script" | sed '1d;$d') "$file" >&2 || true
        exit 1
    fi
}

check_embedded scripts/install.sh SYSTEMD_UNIT dist/picoguard.service
check_embedded scripts/install.sh OPENRC_SCRIPT dist/picoguard.openrc

dash -n scripts/install.sh
bash -n scripts/proxmox-lxc.sh
scripts/test-release.sh

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -s sh scripts/install.sh
    shellcheck -s bash scripts/proxmox-lxc.sh scripts/build-release.sh scripts/check.sh \
        scripts/release-preflight.sh scripts/sign-release.sh scripts/publish-crate.sh \
        scripts/publish-github-release.sh scripts/test-release.sh \
        scripts/audit-history.sh scripts/test-audit-history.sh
fi

cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked

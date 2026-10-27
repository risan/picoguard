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
check_embedded scripts/install.sh COMMON dist/picoguard-common.sh
check_embedded scripts/install.sh UPDATE_HELPER dist/picoguard-update.sh
check_embedded scripts/install.sh SYSTEMD_UPDATE_PATH dist/picoguard-update.path
check_embedded scripts/install.sh SYSTEMD_UPDATE_SERVICE dist/picoguard-update.service
check_embedded scripts/install.sh OPENRC_UPDATE_SCRIPT dist/picoguard-update.openrc

dash -n scripts/install.sh
dash -n dist/picoguard-common.sh
dash -n dist/picoguard-update.sh
bash -n scripts/proxmox-lxc.sh
scripts/test-release.sh

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -s sh scripts/install.sh dist/picoguard-common.sh \
        dist/picoguard-update.sh scripts/test-update-helper/cases.sh scripts/test-update-helper/start.sh
    shellcheck -s bash scripts/proxmox-lxc.sh scripts/build-release.sh scripts/check.sh \
        scripts/release-preflight.sh scripts/sign-release.sh scripts/publish-crate.sh \
        scripts/publish-github-release.sh scripts/test-release.sh \
        scripts/audit-history.sh scripts/test-audit-history.sh scripts/test-update-helper.sh
fi

cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
# Every failing test binary is reported in one run, not only the first.
cargo test --locked --no-fail-fast

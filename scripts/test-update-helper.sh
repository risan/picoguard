#!/usr/bin/env bash
# Runs install.sh and the root update installer in disposable containers: Debian with systemd
# and Alpine with OpenRC. The test binary is built for a throwaway release key, so a signed
# "release" can be made here without the real key.
#
#   scripts/test-update-helper.sh [systemd|openrc|all] [case ...]
#
# Needs Docker (the systemd container is privileged) and, the first time, a network to
# download crates into the named volume $CARGO_VOLUME. Prints PASS or FAIL per case and
# exits 1 when any failed. Not part of scripts/check.sh for those reasons.
set -euo pipefail

cd "$(dirname "$0")/.."
repo=$PWD
work=$repo/target/update-helper-test
fixtures=$work/fixtures
cases_dir=$repo/scripts/test-update-helper
asset=picoguard-x86_64-unknown-linux-musl
CARGO_VOLUME=picoguard-test-cargo
BUILD_IMAGE=rust:1.99.1-alpine
CONTAINERS="picoguard-test-build picoguard-test-systemd picoguard-test-openrc"

die() {
    echo "error: $*" >&2
    exit 1
}

cleanup() {
    # shellcheck disable=SC2086 # the names have no spaces
    docker rm -f $CONTAINERS >/dev/null 2>&1 || true
}

# The working tree is built as it is, with the repo's release key replaced by the public half
# of a throwaway key, so that a release signed here is accepted by the test binary alone.
build_test_binary() {
    mkdir -p "$work/src" "$work/target"

    if [ ! -f "$work/key.pem" ]; then
        openssl genpkey -algorithm ed25519 -out "$work/key.pem"
    fi

    git ls-files -z -co --exclude-standard -- . ':(exclude).works' |
        tar --null --ignore-failed-read -T - -cf - | tar -xf - -C "$work/src" --exclude=dist/release-key.der
    openssl pkey -in "$work/key.pem" -pubout -outform DER -out "$work/release-key.der"

    if cmp -s "$work/release-key.der" dist/release-key.der; then
        die "the test key is the repo's release key"
    fi

    # Only a changed key may touch the file, or cargo would rebuild the binary every run.
    if ! cmp -s "$work/release-key.der" "$work/src/dist/release-key.der"; then
        cp "$work/release-key.der" "$work/src/dist/release-key.der"
    fi

    # A test binary does not need the size of the shipped one, so the build skips the
    # slow link-time optimization.
    docker run --rm --name picoguard-test-build \
        -v "$CARGO_VOLUME:/usr/local/cargo/registry" \
        -v "$work/src:/src:ro" -v "$work/target:/target" -w /src \
        -e PICOGUARD_BUILD=release -e CARGO_TARGET_DIR=/target \
        -e CARGO_PROFILE_RELEASE_LTO=false -e CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
        "$BUILD_IMAGE" \
        sh -c "cargo build --release --locked; status=\$?; chown -R $(id -u):$(id -g) /target; exit \$status"
}

# make_release NAME [SIGNED_FILE]: a release directory whose picoguard is the script on
# stdin. SHA256SUMS names the script's hash; the signature covers SIGNED_FILE instead of
# SHA256SUMS when one is given.
make_release() {
    local dir=$fixtures/releases/$1

    mkdir -p "$dir"
    cat >"$dir/picoguard"
    chmod 0755 "$dir/picoguard"
    printf '%s  %s\n' "$(sha256sum "$dir/picoguard" | cut -d' ' -f1)" "$asset" >"$dir/SHA256SUMS"
    openssl pkeyutl -sign -inkey "$work/key.pem" -rawin -in "${2:-$dir/SHA256SUMS}" \
        -out "$dir/SHA256SUMS.sig"
}

release_script() {
    cat <<SCRIPT
#!${INTERPRETER:-/bin/sh}
REAL=/opt/picoguard-test/picoguard
$1
SCRIPT
}

make_releases() {
    # shellcheck disable=SC2016 # the release scripts expand these themselves
    local pass_version='if [ "${1:-}" = --version ]; then echo "picoguard 9.9.9"; exit 0; fi'
    # shellcheck disable=SC2016 # same
    local good_run='exec "$REAL" "$@"'

    release_script "$pass_version
$good_run" | make_release good
    release_script "$pass_version
if [ \"\${1:-}\" = --check ]; then $good_run; fi
exec sleep 3600" | make_release silent
    release_script "$pass_version
if [ \"\${1:-}\" = --check ]; then $good_run; fi
exit 1" | make_release dies
    release_script "$pass_version
if [ \"\${1:-}\" = --check ]; then echo 'unknown key'; exit 1; fi
$good_run" | make_release badconfig
    release_script "$pass_version
if [ \"\${1:-}\" = --check ]; then exec sleep 3600; fi
$good_run" | make_release hangcheck
    release_script "if [ \"\${1:-}\" = --version ]; then sleep 8; echo 'picoguard 9.9.9'; exit 0; fi
$good_run" | make_release slow
    release_script "$pass_version
if [ \"\${1:-}\" = --check ]; then $good_run; fi
sleep 31
$good_run" | make_release late
    INTERPRETER=/opt/picoguard-test/root-only/sh release_script "$pass_version
$good_run" | make_release cannot_exec

    # Signed over other bytes, and changed after it was signed.
    release_script "$pass_version
$good_run" | make_release badsig "$fixtures/releases/silent/SHA256SUMS"
    release_script "$pass_version
$good_run" | make_release changed
    printf '\n# changed after signing\n' >>"$fixtures/releases/changed/picoguard"
}

prepare_fixtures() {
    build_test_binary

    rm -rf "$fixtures"
    mkdir -p "$fixtures/releases"
    cp "$work/target/release/picoguard" "$fixtures/picoguard"
    cp scripts/install.sh "$fixtures/install.sh"
    cp -r dist "$fixtures/dist"
    cp "$cases_dir/cases.sh" "$fixtures/cases.sh"
    git show main:scripts/install.sh >"$fixtures/old-install.sh"
    make_releases
    chmod -R a+rX "$fixtures"
}

# Done booting: "running", or "degraded" (a unit that a container cannot run failed).
wait_for_systemd() {
    local state

    for _ in $(seq 120); do
        state=$(docker exec "$1" systemctl is-system-running 2>/dev/null || true)

        if [ "$state" = running ] || [ "$state" = degraded ]; then
            return 0
        fi

        sleep 1
    done

    die "systemd in $1 did not finish booting (state: ${state:-unknown})"
}

start_container() {
    local init=$1 name=picoguard-test-$1

    docker rm -f "$name" >/dev/null 2>&1 || true

    case $init in
        systemd)
            docker run -d --name "$name" --privileged --cgroupns=host \
                -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
                --network none -v "$fixtures:/fixtures:ro" "$name" >/dev/null
            wait_for_systemd "$name"
            ;;
        openrc)
            docker run -d --init --name "$name" --network none \
                -v "$fixtures:/fixtures:ro" "$name" >/dev/null
            until docker exec "$name" rc-service testnet status >/dev/null 2>&1; do
                sleep 0.5
            done
            ;;
    esac

    # root-only/sh is the interpreter of the cannot_exec release: root can run it, the
    # picoguard user cannot reach it. BusyBox needs the copy to be named sh.
    docker exec "$name" sh -c '
        mkdir -p /opt/picoguard-test/root-only
        cp /fixtures/picoguard /opt/picoguard-test/picoguard
        chmod 0755 /opt/picoguard-test /opt/picoguard-test/picoguard
        cp -L /bin/sh /opt/picoguard-test/root-only/sh
        chmod 0700 /opt/picoguard-test/root-only'
}

passed=0
failed=0

# Runs one case in the container and counts what it printed.
run_case() {
    local init=$1 case=$2 output status=0

    output=$(timeout 1500 docker exec -e "INIT=$init" "picoguard-test-$init" \
        sh /fixtures/cases.sh run "$case" 2>&1) || status=$?

    if [ "$status" = 124 ]; then
        output="FAIL $case: timed out after 25 minutes"
    fi

    printf '%s\n' "$output" | sed "s/^/[$init] /"

    if [[ $output == PASS* ]]; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi
}

wanted() {
    [ "${#only[@]}" -eq 0 ] && return 0

    local candidate
    for candidate in "${only[@]}"; do
        if [ "$candidate" = "$1" ]; then
            return 0
        fi
    done

    return 1
}

run_init() {
    local init=$1 group style name selected shared_started output

    docker build -q -t "picoguard-test-$init" -f "$cases_dir/Dockerfile.$init" "$cases_dir" >/dev/null

    for group in $(sh "$cases_dir/cases.sh" groups); do
        style=$(sh "$cases_dir/cases.sh" style "$group")
        selected=()

        for name in $(INIT=$init sh "$cases_dir/cases.sh" list "$group"); do
            if wanted "$name"; then
                selected+=("$name")
            fi
        done

        if [ "${#selected[@]}" -eq 0 ]; then
            continue
        fi

        shared_started=0

        for name in "${selected[@]}"; do
            if [ "$style" = each ] || [ "$shared_started" = 0 ]; then
                start_container "$init"
                shared_started=1

                if [ "$style" = setup ]; then
                    output=$(docker exec -e "INIT=$init" "picoguard-test-$init" sh /fixtures/cases.sh setup 2>&1) || {
                        printf '%s\n' "$output" >&2
                        die "the setup of the $group group failed on $init"
                    }
                fi
            fi

            run_case "$init" "$name"
        done

        docker rm -f "picoguard-test-$init" >/dev/null
    done
}

main() {
    local which=${1:-all}
    only=("${@:2}")

    case $which in
        systemd | openrc | all) ;;
        *) die "usage: $0 [systemd|openrc|all] [case ...]" ;;
    esac

    command -v docker >/dev/null || die "docker is needed"
    trap cleanup EXIT
    prepare_fixtures

    if [ "$which" != openrc ]; then
        run_init systemd
    fi

    if [ "$which" != systemd ]; then
        run_init openrc
    fi

    echo "$passed passed, $failed failed"

    if [ "$failed" != 0 ] || [ "$passed" = 0 ]; then
        exit 1
    fi
}

main "$@"

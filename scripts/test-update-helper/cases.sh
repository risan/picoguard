#!/bin/sh
# The cases of scripts/test-update-helper.sh. They run inside a container, as root, with the
# fixtures mounted at /fixtures:
#
#   sh cases.sh groups | style GROUP | list GROUP | setup | run CASE
#
# A case passes when it returns 0; `fail WHY` ends it with a reason. `run` prints one PASS or
# FAIL line (and the tail of the case's output for a FAIL).

set -eu

FIXTURES=/fixtures
B=/usr/local/bin/picoguard
REAL=/opt/picoguard-test/picoguard
CONFIG=/etc/picoguard/picoguard.toml
CASE_LOG=/tmp/case.log
CASE_REASON=/tmp/case.reason
INIT=${INIT:-}

# Groups. The style says how the host runs the group's cases: `each` in a fresh container,
# `shared` in one container after another, `setup` in one container that `setup` has made
# ready and `reset` puts back before every case.
GROUPS_LIST="baseline"

group_style() {
    case $1 in
        baseline) echo shared ;;
    esac
}

group_cases() {
    case $1 in
        baseline) echo "baseline_install baseline_rerun baseline_failed_upgrade baseline_uninstall" ;;
    esac
}

fail() {
    printf '%s\n' "$*" >"$CASE_REASON"
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

note() {
    printf 'note: %s\n' "$*"
}

# wait_for SECONDS COMMAND...
wait_for() {
    limit=$1
    shift
    end=$(($(date +%s) + limit))

    while ! "$@"; do
        if [ "$(date +%s)" -ge "$end" ]; then
            return 1
        fi

        sleep 1
    done
}

service_up() {
    case $INIT in
        systemd) systemctl is-active --quiet picoguard ;;
        openrc) rc-service picoguard status >/dev/null 2>&1 ;;
    esac
}

restart_picoguard() {
    case $INIT in
        systemd) systemctl restart picoguard ;;
        openrc) rc-service picoguard restart ;;
    esac
}

dns_answers() {
    "$REAL" dns-check 127.0.0.1 53 >/dev/null 2>&1
}

same_file() {
    cmp -s "$1" "$2"
}

# The config of D14: picoguard answers example.com by itself, so no network is needed.
write_test_config() {
    mkdir -p "$(dirname "$CONFIG")"
    cat >"$CONFIG" <<'TOML'
lists = []
rules = ["127.0.0.1 example.com"]

[server]
bind = ["127.0.0.1"]

[upstream]
servers = ["udp://127.0.0.1:9"]

[web]
bind = ["127.0.0.1"]

[update]
check = false
TOML
}

install_real() {
    sh "$FIXTURES/install.sh" --yes --binary "$FIXTURES/picoguard" --web-password none
}

setup() {
    install_real
    write_test_config
    restart_picoguard
    wait_for 30 dns_answers || fail "picoguard does not answer after the setup"
}

reset() {
    :
}

baseline_install() {
    out=$(install_real 2>&1) || fail "install.sh failed: $out"
    printf '%s\n' "$out"

    case $out in
        *"No lookup was tried"*) ;;
        *) fail "the report does not say the lookup was untested" ;;
    esac

    service_up || fail "picoguard is not active after the install"
    [ "$(stat -c '%a %U' "$B")" = "755 root" ] || fail "$B is not 0755 root"
    same_file "$B" "$REAL" || fail "$B is not the real binary"

    write_test_config
    restart_picoguard
    wait_for 30 dns_answers || fail "dns-check does not get an answer from picoguard"
}

baseline_rerun() {
    before=$(cksum <"$CONFIG")

    out=$(install_real 2>&1) || fail "the second install.sh run failed: $out"
    printf '%s\n' "$out"

    case $out in
        *"Keeping the existing config"*) ;;
        *) fail "the second run does not say it keeps the config" ;;
    esac

    [ "$(cksum <"$CONFIG")" = "$before" ] || fail "the second run changed the config"
    service_up || fail "picoguard is not active after the second run"
}

baseline_failed_upgrade() {
    if sh "$FIXTURES/install.sh" --yes --binary "$FIXTURES/releases/silent/picoguard"; then
        fail "an upgrade to a binary that never answers succeeded"
    fi

    same_file "$B" "$REAL" || fail "$B is not the real binary after the rollback"
    wait_for 30 service_up || fail "picoguard is not active after the rollback"
    wait_for 30 dns_answers || fail "picoguard does not answer after the rollback"
}

baseline_uninstall() {
    sh "$FIXTURES/install.sh" --uninstall --purge || fail "--uninstall --purge failed"

    [ ! -e "$B" ] || fail "$B is still there"
    [ ! -e /etc/systemd/system/picoguard.service ] || fail "the systemd unit is still there"
    [ ! -e /etc/init.d/picoguard ] || fail "the init script is still there"

    if grep -q '^picoguard:' /etc/passwd; then
        fail "the picoguard user is still there"
    fi
}

group_of() {
    for group in $GROUPS_LIST; do
        for name in $(group_cases "$group"); do
            if [ "$name" = "$1" ]; then
                echo "$group"

                return 0
            fi
        done
    done

    return 1
}

run_case() {
    name=$1
    group=$(group_of "$name") || {
        echo "FAIL $name: no such case"

        return 1
    }
    rm -f "$CASE_REASON"
    started=$(date +%s)

    # Not `( ... ) || status=$?`: set -e does not apply inside a list that ends in `||`.
    set +e
    (
        set -eu

        if [ "$(group_style "$group")" = setup ]; then
            reset
        fi

        "$name"
    ) >"$CASE_LOG" 2>&1
    status=$?
    set -e

    elapsed=$(($(date +%s) - started))

    if [ "$status" = 0 ]; then
        echo "PASS $name (${elapsed}s)"
        grep '^note: ' "$CASE_LOG" | sed 's/^note: /    /' || true

        return 0
    fi

    reason=$(cat "$CASE_REASON" 2>/dev/null || echo "a command failed with status $status")
    echo "FAIL $name: $reason (${elapsed}s)"
    tail -n 25 "$CASE_LOG" | sed 's/^/    | /'

    return 1
}

if [ -z "$INIT" ]; then
    if [ -d /run/systemd/system ]; then
        INIT=systemd
    else
        INIT=openrc
    fi
fi

case ${1:-} in
    groups) echo "$GROUPS_LIST" ;;
    style) group_style "$2" ;;
    list) group_cases "$2" ;;
    setup) setup ;;
    run) run_case "$2" ;;
    *) echo "usage: sh cases.sh groups | style GROUP | list GROUP | setup | run CASE" >&2; exit 2 ;;
esac

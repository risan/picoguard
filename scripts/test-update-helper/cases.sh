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
S=/var/lib/picoguard
STAGE=$S/update
I=/var/lib/picoguard-update
LIB=/usr/local/lib/picoguard
UPDATER=$LIB/update
CASE_LOG=/tmp/case.log
CASE_REASON=/tmp/case.reason
INIT=${INIT:-}

# Groups. The style says how the host runs the group's cases: `each` in a fresh container,
# `shared` in one container after another, `setup` in one container that `setup` has made
# ready and `reset` puts back before every case.
GROUPS_LIST="baseline helper removal fresh"

group_style() {
    case $1 in
        baseline) echo shared ;;
        helper | removal) echo setup ;;
        fresh) echo each ;;
    esac
}

HELPER_CASES="update_good update_silent update_dies restart_fails update_late update_refused
    verifier_hangs verifier_crashes no_verify_update update_repeat update_bad_request
    request_swap_race swap_fails rollback_fails_then_recovers install_files install_rerun
    install_answers_a_waiting_request privileges idle_cost
    interrupted_bad interrupted_good interrupted_before_swap interrupted_after_rollback_mv
    interrupted_during_verify interrupted_after_result install_waits_for_lock
    installer_waits_for_lock install_lock_timeout_stops_installer
    install_lock_timeout_during_verify lock_replaced_while_waiting lock_not_inherited"

# What only the OpenRC watcher has: a process that polls.
OPENRC_CASES="answered_request_left_in_place watcher_starts_with_stale_fifo"

group_cases() {
    case $1 in
        baseline) echo "baseline_install baseline_rerun baseline_failed_upgrade baseline_uninstall" ;;
        helper)
            echo "$HELPER_CASES"

            if [ "$INIT" = openrc ]; then
                echo "$OPENRC_CASES"
            fi
            ;;
        removal) echo "rollback_with_older_installer uninstall uninstall_purge" ;;
        fresh) echo "install_no_start rollback_without_installer" ;;
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

# ---- what the cases of the update installer share ----

# The id of the request `stage` wrote last, and how long `wait_result` waited.
STAGED_ID=
WAITED=0

new_id() {
    id=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')

    case $id in
        *[!0-9a-f]* | '') fail "a request id from od is not 16 hex digits: $id" ;;
    esac

    if [ "${#id}" != 16 ]; then
        fail "a request id from od is not 16 hex digits: $id"
    fi

    printf '%s' "$id"
}

# As the picoguard user, the way the daemon writes: private files.
as_picoguard() {
    su -s /bin/sh picoguard -c "umask 077; $1"
}

# write_request ID: `request.part`, then a rename, so that the request appears whole.
write_request() {
    as_picoguard "printf 'id=%s\nversion=9.9.9\n' $1 >$STAGE/request.part && mv $STAGE/request.part $STAGE/request"
}

# stage RELEASE [copy|symlink|fifo]: puts a release in $STAGE the way the daemon does, the
# request last, and sets STAGED_ID to its id. The variant is what the staged binary is.
stage() {
    STAGED_ID=$(new_id)
    release=$FIXTURES/releases/$1

    as_picoguard "mkdir -p $STAGE && rm -f $STAGE/picoguard && cp $release/SHA256SUMS $release/SHA256SUMS.sig $STAGE/"

    case ${2:-copy} in
        copy) as_picoguard "cp $release/picoguard $STAGE/picoguard" ;;
        symlink) as_picoguard "ln -s $FIXTURES/releases/good/picoguard $STAGE/picoguard" ;;
        fifo) as_picoguard "mkfifo $STAGE/picoguard" ;;
    esac

    write_request "$STAGED_ID"
}

result_value() {
    sed -n "s/^$1=//p" "$I/result"
}

# wait_result ID SECONDS: until $I/result answers the request ID. Sets WAITED.
wait_result() {
    started=$(date +%s)
    WAITED=0

    while ! [ -f "$I/result" ] || [ "$(result_value id)" != "$1" ]; do
        WAITED=$(($(date +%s) - started))

        if [ "$WAITED" -ge "$2" ]; then
            return 1
        fi

        sleep 1
    done

    WAITED=$(($(date +%s) - started))
}

# expect_result ID OUTCOME [PART OF THE REASON]...
expect_result() {
    id=$1
    outcome=$2
    shift 2

    [ "$(result_value id)" = "$id" ] || fail "the result is for $(result_value id), not $id"
    [ "$(result_value outcome)" = "$outcome" ] ||
        fail "the outcome is $(result_value outcome) ($(result_value reason)), not $outcome"

    reason=$(result_value reason)

    for part in "$@"; do
        case $reason in
            *"$part"*) ;;
            *) fail "the reason \"$reason\" does not contain \"$part\"" ;;
        esac
    done
}

# The processes that hold $I/lock open, by pid.
holders_of_lock() {
    for fd in /proc/[0-9]*/fd/*; do
        if [ "$(readlink "$fd" 2>/dev/null)" = "$I/lock" ]; then
            fd=${fd#/proc/}
            printf '%s ' "${fd%%/*}"
        fi
    done
}

# The names in a directory, sorted, each followed by a space.
listing() {
    find "$1" -mindepth 1 -maxdepth 1 | sed 's|.*/||' | sort | tr '\n' ' '
}

# What stays in $I once a pass is over: the answer and the lock.
expect_installer_dir_quiet() {
    [ "$(listing "$I")" = "lock result " ] || fail "$I holds: $(listing "$I")"
    [ -z "$(holders_of_lock)" ] || fail "something still holds $I/lock: $(holders_of_lock)"
}

# The pid of picoguard itself: systemd's main pid, or the child of OpenRC's supervise-daemon.
children_of() {
    grep -l "^PPid:[[:space:]]*$1\$" /proc/[0-9]*/status | sed 's|/proc/\([0-9]*\)/status|\1|'
}

picoguard_pid() {
    case $INIT in
        systemd) systemctl show -p MainPID --value picoguard ;;
        openrc) children_of "$(cat /run/supervise-picoguard.pid)" ;;
    esac
}

# No pass of the installer is running.
service_idle() {
    case $INIT in
        systemd)
            state=$(systemctl is-active picoguard-update.service || true)

            [ "$state" != active ] && [ "$state" != activating ]
            ;;
        openrc) [ -z "$(holders_of_lock)" ] ;;
    esac
}

# How long a trigger may take to notice a change: the watcher polls every 5 seconds.
trigger_gap() {
    case $INIT in
        openrc) sleep 7 ;;
    esac
}

# Waits until no pass runs: a change that arrives while one runs is merged into it.
settle() {
    case $INIT in
        systemd) sleep 1 ;;
        openrc) sleep 7 ;;
    esac

    wait_for 120 service_idle || fail "the installer does not end"
}

# Starts a pass by hand where the trigger needs it; the OpenRC watcher polls by itself.
start_pass() {
    case $INIT in
        systemd) systemctl start picoguard-update.service ;;
        openrc) rc-service picoguard-update restart ;;
    esac
}

installer_log() {
    case $INIT in
        systemd) journalctl -u picoguard-update --no-pager ;;
        openrc) cat /var/log/messages ;;
    esac
}

api_status() {
    case $INIT in
        systemd)
            bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080 && printf "GET /api/status HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n" >&3 && cat <&3'
            ;;
        openrc) wget -qO- http://127.0.0.1:8080/api/status ;;
    esac
}

install_state() {
    api_status | grep -o '"install":{[^}]*}' || true
}

install_state_is() {
    case $(install_state) in
        *"\"state\":\"$1\""*) return 0 ;;
    esac

    return 1
}

# A directory where the installer copies the new binary makes its `mv` over $B fail.
block_part() {
    mkdir "$B.update.part"
}

unblock_part() {
    rm -rf "$B.update.part"
}

# Puts a script at $B that stands in for a `verify-update` that misbehaves. The running
# picoguard keeps the file it started from.
install_fake_verifier() {
    # shellcheck disable=SC2016 # the fake script expands these itself
    case $1 in
        hangs)
            body='case $3 in */verified) exec sleep 200 ;; esac
cat "$2/request"
exit 1'
            ;;
        crashes)
            body='case $3 in */verified) kill -SEGV $$ ;; esac
cat "$2/request"
exit 1'
            ;;
        none) body='exit 2' ;;
    esac

    # shellcheck disable=SC2016 # same
    printf '#!/bin/sh\nif [ "$1" = verify-update ]; then\n%s\nfi\nexec %s "$@"\n' "$body" "$REAL" >"$B.fake"
    chmod 0755 "$B.fake"
    mv -f "$B.fake" "$B"
}

shorten_verify_wait() {
    sed -i "s/^VERIFY_WAIT=.*/VERIFY_WAIT=$1/" "$UPDATER"

    # The watcher reads its constants once, when it starts.
    case $INIT in
        openrc) rc-service picoguard-update restart ;;
    esac
}

# Back to a plain install of the real binary with nothing left by an earlier case.
reset() {
    unblock_part
    install_real >/dev/null
    write_test_config
    restart_picoguard
    as_picoguard "rm -rf $STAGE/* $STAGE/.[!.]*"
    settle
    rm -rf "${I:?}/installing" "${I:?}/previous" "${I:?}/verified" "${I:?}/verify.err" "${I:?}"/*.part
    # The restarts of the reset must not count towards systemd's limit of 5 starts in 10
    # seconds, or the update that follows could be refused one.
    case $INIT in
        systemd) systemctl reset-failed picoguard picoguard-update.service 2>/dev/null || true ;;
    esac

    wait_for 30 dns_answers || fail "picoguard does not answer after the reset"
}

# The files install.sh puts on the device: path, mode, owner and the file they must equal.
installed_files() {
    cat <<LIST
$UPDATER 755 root $FIXTURES/dist/picoguard-update.sh
$LIB/common.sh 644 root $FIXTURES/dist/picoguard-common.sh
LIST

    case $INIT in
        systemd)
            cat <<LIST
/etc/systemd/system/picoguard-update.path 644 root $FIXTURES/dist/picoguard-update.path
/etc/systemd/system/picoguard-update.service 644 root $FIXTURES/dist/picoguard-update.service
LIST
            ;;
        openrc)
            echo "/etc/init.d/picoguard-update 755 root $FIXTURES/dist/picoguard-update.openrc"
            ;;
    esac
}

expect_installed_files() {
    installed_files | while read -r path mode owner source; do
        [ "$(stat -c '%a %U' "$path")" = "$mode $owner" ] || fail "$path is $(stat -c '%a %U' "$path"), not $mode $owner"
        same_file "$path" "$source" || fail "$path differs from $source"
    done

    [ "$(stat -c '%a %U' "$LIB")" = "755 root" ] || fail "$LIB is not 0755 root"
    [ "$(stat -c '%a %U' "$I")" = "755 root" ] || fail "$I is not 0755 root"
    [ "$(stat -c '%a %U' "$I/lock")" = "600 root" ] || fail "$I/lock is not 0600 root"
}

# ---- baseline: install.sh as it is, before and after the installer ----

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

# ---- helper: a staged update is installed, or rolled back ----

update_good() {
    stage good
    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds"
    note "updated in ${WAITED}s"

    expect_result "$STAGED_ID" updated
    same_file "$B" "$FIXTURES/releases/good/picoguard" || fail "$B is not the good release"
    [ "$(stat -c '%a %U' "$B")" = "755 root" ] || fail "$B is not 0755 root"
    service_up || fail "picoguard is not active"
    wait_for 30 dns_answers || fail "dns-check gets no answer"
    wait_for 10 install_state_is updated || fail "the page does not say updated: $(install_state)"
    settle
    [ -z "$(find "$STAGE" -mindepth 1)" ] || fail "$STAGE is not empty: $(listing "$STAGE")"
    expect_installer_dir_quiet
    [ "$(stat -c '%a %U' "$I/lock")" = "600 root" ] || fail "$I/lock is not 0600 root"
    [ -z "$(find "$S" -user root)" ] || fail "root owns: $(find "$S" -user root)"
}

update_silent() {
    stage silent
    wait_result "$STAGED_ID" 90 || fail "no result within 90 seconds"
    note "rolled back in ${WAITED}s"

    expect_result "$STAGED_ID" rolled-back "did not answer DNS within 30 seconds" "runs again"
    same_file "$B" "$REAL" || fail "$B is not the real binary"
    service_up || fail "picoguard is not active"
    wait_for 30 dns_answers || fail "dns-check gets no answer"
    wait_for 10 install_state_is rolled_back || fail "the page does not say rolled back: $(install_state)"

    case $(install_state) in
        *"$(result_value reason)"*) ;;
        *) fail "the page does not show the reason: $(install_state)" ;;
    esac
}

update_dies() {
    stage dies
    wait_result "$STAGED_ID" 90 || fail "no result within 90 seconds"
    note "rolled back in ${WAITED}s"

    # supervise-daemon reports a service that crashes over and over as started, so OpenRC may
    # say "did not answer DNS" instead.
    expect_result "$STAGED_ID" rolled-back "runs again" "did not"
    same_file "$B" "$REAL" || fail "$B is not the real binary"
    service_up || fail "picoguard is not active"
}

restart_fails() {
    stage cannot_exec
    wait_result "$STAGED_ID" 90 || fail "no result within 90 seconds"
    note "rolled back in ${WAITED}s"

    # supervise-daemon reports a service that cannot start as started, so OpenRC may say "did
    # not answer DNS" instead; systemd never counts it as active.
    case $INIT in
        systemd) expect_result "$STAGED_ID" rolled-back "did not start" "runs again" ;;
        openrc) expect_result "$STAGED_ID" rolled-back "did not" "runs again" ;;
    esac

    same_file "$B" "$REAL" || fail "$B is not the real binary"
    service_up || fail "picoguard is not active"

    case $INIT in
        systemd)
            journalctl -u picoguard --no-pager | grep -Eq '203/EXEC|Failed at step EXEC' ||
                fail "the journal shows no failed start of the new binary"
            ;;
    esac
}

update_late() {
    stage late
    wait_result "$STAGED_ID" 90 || fail "no result within 90 seconds"
    note "rolled back in ${WAITED}s"

    expect_result "$STAGED_ID" rolled-back "did not answer DNS within 30 seconds"
    same_file "$B" "$REAL" || fail "$B is not the real binary"
}

# refuse RELEASE VARIANT PART-OF-THE-REASON: the request is answered `failed`, and neither
# the binary nor the running picoguard changed.
refuse() {
    pid=$(picoguard_pid)
    stage "$1" "$2"
    wait_result "$STAGED_ID" 60 || fail "$1 $2: no result within 60 seconds"
    settle

    expect_result "$STAGED_ID" failed "$3"
    note "$1 $2: $(result_value reason)"
    same_file "$B" "$REAL" || fail "$1 $2: $B changed"
    [ "$(picoguard_pid)" = "$pid" ] || fail "$1 $2: picoguard was restarted"
    expect_installer_dir_quiet
}

update_refused() {
    refuse badsig copy "signature"
    refuse changed copy "does not match"
    refuse good symlink "picoguard:"
    refuse good fifo "picoguard:"
    refuse badconfig copy "does not accept the config"
    refuse hangcheck copy "did not check the config within 30 seconds"
}

verifier_hangs() {
    shorten_verify_wait 5
    install_fake_verifier hangs
    pid=$(picoguard_pid)
    stage good
    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds"
    settle

    expect_result "$STAGED_ID" failed "verify-update did not finish within 5 seconds"
    [ "$(picoguard_pid)" = "$pid" ] || fail "picoguard was restarted"
    expect_installer_dir_quiet
}

verifier_crashes() {
    install_fake_verifier crashes
    pid=$(picoguard_pid)
    stage good
    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds"
    settle

    expect_result "$STAGED_ID" failed "verify-update ended with status 139"
    [ "$(picoguard_pid)" = "$pid" ] || fail "picoguard was restarted"
    expect_installer_dir_quiet
}

no_verify_update() {
    install_fake_verifier none
    pid=$(picoguard_pid)
    before=$(stat -c %Y "$I/result" 2>/dev/null || echo none)
    stage good
    sleep 8
    # Three polls of the OpenRC watcher: the line is logged once, not at every poll.
    trigger_gap
    trigger_gap
    settle

    [ "$(stat -c %Y "$I/result" 2>/dev/null || echo none)" = "$before" ] || fail "a result was written"
    [ "$(picoguard_pid)" = "$pid" ] || fail "picoguard was restarted"

    case $(listing "$I") in
        "lock " | "lock result ") ;;
        *) fail "$I holds: $(listing "$I")" ;;
    esac

    lines=$(installer_log | grep -c "cannot verify updates" || true)
    [ "$lines" = 1 ] || fail "the log has $lines lines about it, not 1"
}

update_repeat() {
    stage good
    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds"
    expect_result "$STAGED_ID" updated
    wait_for 10 install_state_is updated || fail "the page does not say updated"
    settle
    wait_for 30 dns_answers || fail "dns-check gets no answer"

    before=$(cksum <"$I/result")
    touch /tmp/stamp
    sleep 1
    as_picoguard "mkdir -p $STAGE"
    write_request "$STAGED_ID"
    start_pass
    settle

    [ "$(cksum <"$I/result")" = "$before" ] || fail "the result changed"
    same_file "$B" "$FIXTURES/releases/good/picoguard" || fail "$B changed"
    [ -z "$(find "$I" -newer /tmp/stamp)" ] || fail "written again: $(find "$I" -newer /tmp/stamp)"
}

# refuse_request WHAT COMMAND: a request the installer must not answer. No new result, nothing
# written in $I, and the pass is over soon.
refuse_request() {
    as_picoguard "rm -f $STAGE/request $STAGE/request.part"
    settle
    touch /tmp/stamp
    sleep 1
    before=$(cksum <"$I/result" 2>/dev/null || echo none)

    as_picoguard "$2"
    wait_for 6 service_idle || fail "$1: the installer does not end within 6 seconds"
    trigger_gap
    sleep 1

    [ "$(cksum <"$I/result" 2>/dev/null || echo none)" = "$before" ] || fail "$1: a result was written"
    [ -z "$(find "$I" -newer /tmp/stamp)" ] || fail "$1: written: $(find "$I" -newer /tmp/stamp)"
}

update_bad_request() {
    # A first answer, so that there is a result to compare.
    stage badsig
    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds"
    settle

    refuse_request "a link to /etc/shadow" "ln -s /etc/shadow $STAGE/request"
    refuse_request "a fifo" "mkfifo $STAGE/request"
    refuse_request "an uppercase id" "printf 'id=ABCDEF0123456789\nversion=9.9.9\n' >$STAGE/request"
    refuse_request "a v in the version" "printf 'id=0123456789abcdef\nversion=v9.9.9\n' >$STAGE/request"
    refuse_request "a third line" "printf 'id=0123456789abcdef\nversion=9.9.9\nx=1\n' >$STAGE/request"
    refuse_request "300 bytes" "printf 'id=0123456789abcdef\nversion=9.9.9\n%s\n' $(printf 'x%.0s' $(seq 270)) >$STAGE/request"
    refuse_request "no final newline" "printf 'id=0123456789abcdef\nversion=9.9.9' >$STAGE/request"

    # The trigger still works after all of that.
    as_picoguard "rm -f $STAGE/request"
    stage good
    wait_result "$STAGED_ID" 60 || fail "a good request after the bad ones gets no result"
    expect_result "$STAGED_ID" updated
}

request_swap_race() {
    printf 'id=bbbbbbbbbbbbbbbb\nversion=9.9.9\n' >/root/secret-request
    chmod 0600 /root/secret-request
    as_picoguard "mkdir -p $STAGE"
    settle

    as_picoguard "
        end=\$((\$(date +%s) + 20))
        while [ \$(date +%s) -lt \$end ]; do
            printf 'id=aaaaaaaaaaaaaaaa\nversion=9.9.9\n' >$STAGE/request.part
            mv -f $STAGE/request.part $STAGE/request
            sleep 0.2
            ln -sf /root/secret-request $STAGE/request.part
            mv -f $STAGE/request.part $STAGE/request
            sleep 0.2
        done"
    wait_for 5 service_idle || fail "the installer does not end within 5 seconds of the last change"
    settle

    if installer_log | grep -q bbbbbbbbbbbbbbbb; then
        fail "the log names the id of the root-only file"
    fi

    if grep -qs bbbbbbbbbbbbbbbb "$I/installing" "$I/result"; then
        fail "$I names the id of the root-only file"
    fi

    rm -f /root/secret-request

    # After that many starts the trigger still works: systemd's start limit must not have put
    # it out of action.
    as_picoguard "rm -f $STAGE/request $STAGE/request.part"
    settle
    stage good
    wait_result "$STAGED_ID" 60 || fail "a good request after the race gets no result"
    expect_result "$STAGED_ID" updated
}

swap_fails() {
    pid=$(picoguard_pid)
    stage slow
    wait_for 60 test -f "$I/installing" || fail "the pass never started"
    block_part
    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds"
    unblock_part
    settle

    expect_result "$STAGED_ID" failed "disk: could not write the new binary"
    same_file "$B" "$REAL" || fail "$B changed"
    [ "$(picoguard_pid)" = "$pid" ] || fail "picoguard was restarted"
    expect_installer_dir_quiet
}

rollback_failure_logged() {
    installer_log | grep -q "rollback failed"
}

rollback_fails_then_recovers() {
    stage silent
    wait_for 60 same_file "$B" "$FIXTURES/releases/silent/picoguard" || fail "the new binary never reached $B"
    block_part
    wait_for 90 rollback_failure_logged || fail "the log never names the failed rollback"

    case $INIT in
        systemd) wait_for 30 service_idle || fail "the pass does not end" ;;
    esac

    if [ -f "$I/result" ] && [ "$(result_value id)" = "$STAGED_ID" ]; then
        fail "a result was written"
    fi

    grep -q '^swap=1$' "$I/installing" || fail "the record has no swap line: $(cat "$I/installing")"
    [ -f "$I/previous" ] || fail "the backup was removed"

    unblock_part

    # The OpenRC watcher ended with the failed rollback and supervise-daemon starts it again,
    # which retries by itself.
    case $INIT in
        systemd) start_pass ;;
    esac

    wait_result "$STAGED_ID" 120 || fail "no result after the retry"
    settle

    expect_result "$STAGED_ID" rolled-back "runs again"
    same_file "$B" "$REAL" || fail "$B is not the real binary"
    [ ! -e "$I/installing" ] && [ ! -e "$I/previous" ] || fail "the record or the backup is still there"
}

install_files() {
    expect_installed_files

    case $INIT in
        systemd)
            [ "$(systemctl is-enabled picoguard-update.path)" = enabled ] || fail "the path unit is not enabled"
            [ "$(systemctl is-enabled picoguard-update.service)" = enabled ] || fail "the service is not enabled"
            systemctl is-active --quiet picoguard-update.path || fail "the path unit is not active"
            ;;
        openrc)
            rc-update show default | grep -q picoguard-update || fail "the watcher is not in the default runlevel"
            rc-service picoguard-update status >/dev/null || fail "the watcher is not running"
            ;;
    esac

    settle
    touch /tmp/stamp
    sleep 1
    start_pass
    settle
    [ -z "$(find "$I" -newer /tmp/stamp)" ] || fail "an idle pass wrote: $(find "$I" -newer /tmp/stamp)"
}

trigger_running() {
    case $INIT in
        systemd) systemctl is-active --quiet picoguard-update.path ;;
        openrc) rc-service picoguard-update status >/dev/null 2>&1 ;;
    esac
}

install_rerun() {
    install_real >/dev/null
    expect_installed_files
    trigger_running || fail "the trigger is not running"
}

install_answers_a_waiting_request() {
    case $INIT in
        systemd) systemctl stop picoguard-update.path ;;
        openrc) rc-service picoguard-update stop ;;
    esac

    stage good
    sleep 2

    if [ -f "$I/result" ] && [ "$(result_value id)" = "$STAGED_ID" ]; then
        fail "answered with the trigger stopped"
    fi

    install_real >/dev/null
    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds of the run"
    expect_result "$STAGED_ID" updated
    note "answered ${WAITED}s after the run"
}

privileges() {
    for dir in /usr/local/bin /etc/picoguard "$I" "$LIB"; do
        if as_picoguard "touch $dir/probe" 2>/dev/null; then
            rm -f "$dir/probe"
            fail "the picoguard user can write in $dir"
        fi
    done

    if as_picoguard ": <$I/lock" 2>/dev/null; then
        fail "the picoguard user can open $I/lock"
    fi

    case $INIT in
        systemd)
            shown=$(systemctl show picoguard -p ProtectSystem -p ReadWritePaths | sort | tr '\n' ' ')
            [ "$shown" = "ProtectSystem=strict ReadWritePaths= " ] || fail "picoguard.service shows: $shown"
            ;;
    esac

    [ -z "$(find "$LIB" "$I" ! -user root)" ] || fail "not root's: $(find "$LIB" "$I" ! -user root)"
}

# ---- fresh: each case in a container of its own ----

install_no_start() {
    out=$(sh "$FIXTURES/install.sh" --yes --binary "$FIXTURES/picoguard" --web-password none --no-start 2>&1) ||
        fail "install.sh --no-start failed: $out"
    printf '%s\n' "$out"

    expect_installed_files

    case $INIT in
        systemd)
            [ "$(systemctl is-enabled picoguard-update.path 2>/dev/null || true)" != enabled ] || fail "the path unit is enabled"
            [ "$(systemctl is-enabled picoguard-update.service 2>/dev/null || true)" != enabled ] || fail "the service is enabled"

            if systemctl is-active --quiet picoguard-update.path; then
                fail "the path unit is active"
            fi

            case $out in
                *"systemctl enable --now picoguard picoguard-update.path picoguard-update.service"*) ;;
                *) fail "the report does not show the start command" ;;
            esac
            ;;
        openrc)
            if rc-update show default | grep -q picoguard-update; then
                fail "the watcher is in the default runlevel"
            fi

            if rc-service picoguard-update status >/dev/null 2>&1; then
                fail "the watcher is running"
            fi

            case $out in
                *"rc-update add picoguard default && rc-update add picoguard-update default && rc-service picoguard start && rc-service picoguard-update start"*) ;;
                *) fail "the report does not show the start command" ;;
            esac
            ;;
    esac
}

# ---- OpenRC: what the polling watcher costs and how it starts ----

# The pids below a process, itself included.
tree_of() {
    echo "$1"

    for child in $(children_of "$1"); do
        tree_of "$child"
    done
}

idle_cost() {
    settle
    sleep 10

    case $INIT in
        systemd)
            if pgrep -f "$UPDATER" >/dev/null; then
                fail "an installer process runs while idle"
            fi
            ;;
        openrc)
            [ -f /run/supervise-picoguard-update.pid ] || fail "the watcher has no supervisor"
            pids=$(tree_of "$(cat /run/supervise-picoguard-update.pid)")
            count=0
            pss=0

            for pid in $pids; do
                count=$((count + 1))
                pss=$((pss + $(awk '/^Pss:/ { print $2 }' "/proc/$pid/smaps_rollup")))
            done

            note "the idle watcher: $count processes, $pss kB Pss"
            [ "$count" -ge 2 ] || fail "the watcher is not running: $pids"
            [ "$count" -le 2 ] || fail "$count processes: $pids"
            [ "$pss" -lt 1024 ] || fail "$pss kB Pss, not under 1024"

            # shellcheck disable=SC2086 # the pids are numbers, split on purpose
            expect_no_writes_for 60 $pids
            ;;
    esac
}

# expect_no_writes_for SECONDS PID...: the processes write nothing to disk meanwhile. Where
# the kernel counts bytes written per process (/proc/PID/io), those; else no file on the
# system changes (the WSL2 kernel has no /proc/PID/io).
expect_no_writes_for() {
    seconds=$1
    shift

    if [ -r "/proc/$1/io" ]; then
        before=
        for pid in "$@"; do
            before="$before $(awk '/^write_bytes/ { print $2 }' "/proc/$pid/io")"
        done

        sleep "$seconds"
        after=
        for pid in "$@"; do
            after="$after $(awk '/^write_bytes/ { print $2 }' "/proc/$pid/io")"
        done

        [ "$after" = "$before" ] || fail "written to disk while idle: $before, then $after"

        return 0
    fi

    note "no /proc/PID/io here: checking file modification times instead"
    touch /tmp/stamp
    sleep "$seconds"
    changed=$(find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /tmp \) -prune -o -newer /tmp/stamp -print)
    [ -z "$changed" ] || fail "changed while idle: $changed"
}

answered_request_left_in_place() {
    stage good
    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds"
    expect_result "$STAGED_ID" updated
    settle

    # The daemon is not there to clean up after the answer, so the request stays.
    rc-service picoguard stop
    as_picoguard "mkdir -p $STAGE"
    write_request "$STAGED_ID"
    watcher=$(children_of "$(cat /run/supervise-picoguard-update.pid)")
    touch /tmp/stamp
    sleep 1
    before=$(cksum <"$I/result")
    sleep 30

    [ "$(cksum <"$I/result")" = "$before" ] || fail "the result changed"
    [ -z "$(find "$I" -newer /tmp/stamp)" ] || fail "written: $(find "$I" -newer /tmp/stamp)"
    [ "$(children_of "$(cat /run/supervise-picoguard-update.pid)")" = "$watcher" ] || fail "the watcher was restarted"
    kill -0 "$watcher" || fail "the watcher is gone"
}

watcher_starts_with_stale_fifo() {
    rc-service picoguard-update stop
    mkfifo /run/picoguard-update.tick
    rc-service picoguard-update start
    rc-service picoguard-update status >/dev/null || fail "the watcher does not run"

    stage good
    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds"
    expect_result "$STAGED_ID" updated
}

# ---- interrupted runs and the lock ----

# plant_interrupted RELEASE: what a pass leaves when it stops after the swap: the previous
# binary, the verified copy of RELEASE, RELEASE at $B and a record with swap=1. Sets
# STAGED_ID to the record's id.
plant_interrupted() {
    STAGED_ID=$(new_id)
    cp -p "$REAL" "$I/previous"
    mkdir -m 0700 "$I/verified"
    cp "$FIXTURES/releases/$1/picoguard" "$I/verified/picoguard"
    cp "$FIXTURES/releases/$1/picoguard" "$B.new"
    chmod 0755 "$B.new"
    mv -f "$B.new" "$B"
    printf 'id=%s\nversion=9.9.9\nswap=1\n' "$STAGED_ID" >"$I/installing"
}

# The boot run: the installer service started at boot, or the watcher started.
boot_run() {
    case $INIT in
        systemd) systemctl start picoguard-update.service ;;
        openrc) rc-service picoguard-update restart ;;
    esac
}

enabled_at_boot() {
    case $INIT in
        systemd) [ "$(systemctl is-enabled picoguard-update.service)" = enabled ] ;;
        openrc) rc-update show default | grep -q picoguard-update ;;
    esac
}

expect_no_pass_files() {
    for name in installing previous verified verify.err; do
        [ ! -e "$I/$name" ] || fail "$I/$name is still there"
    done

    [ -z "$(find "$I" -name '*.part')" ] || fail "a part file is still there"
}

interrupted_bad() {
    plant_interrupted silent
    boot_run
    wait_result "$STAGED_ID" 120 || fail "no result within 120 seconds"
    settle

    expect_result "$STAGED_ID" rolled-back "runs again"
    same_file "$B" "$REAL" || fail "$B is not the real binary"
    expect_no_pass_files
    enabled_at_boot || fail "the installer does not run at boot"
}

interrupted_good() {
    plant_interrupted good
    boot_run
    wait_result "$STAGED_ID" 120 || fail "no result within 120 seconds"
    settle

    expect_result "$STAGED_ID" updated
    same_file "$B" "$FIXTURES/releases/good/picoguard" || fail "$B is not the good release"
    expect_no_pass_files
}

# interrupted_before SETUP-NAME: B is still the real binary and the record has no swap line.
interrupted_before() {
    STAGED_ID=$(new_id)
    printf 'id=%s\nversion=9.9.9\n' "$STAGED_ID" >"$I/installing"
    pid=$(picoguard_pid)

    case $1 in
        nothing) ;;
        verified_and_part)
            mkdir -m 0700 "$I/verified"
            cp "$FIXTURES/releases/good/picoguard" "$I/verified/picoguard"
            cp "$REAL" "$I/previous.part"
            ;;
        verified_and_previous)
            mkdir -m 0700 "$I/verified"
            cp "$FIXTURES/releases/good/picoguard" "$I/verified/picoguard"
            cp -p "$REAL" "$I/previous"
            ;;
        verified_equals_b)
            mkdir -m 0700 "$I/verified"
            cp "$B" "$I/verified/picoguard"
            cp -p "$REAL" "$I/previous"
            ;;
    esac

    boot_run
    wait_result "$STAGED_ID" 60 || fail "$1: no result within 60 seconds"
    settle

    expect_result "$STAGED_ID" failed "interrupted"
    same_file "$B" "$REAL" || fail "$1: $B changed"
    [ "$(picoguard_pid)" = "$pid" ] || fail "$1: picoguard was restarted"
    expect_no_pass_files
}

interrupted_before_swap() {
    interrupted_before nothing
    interrupted_before verified_and_part
    interrupted_before verified_and_previous
    interrupted_before verified_equals_b
}

interrupted_after_rollback_mv() {
    plant_interrupted silent
    cp -p "$REAL" "$B"
    pid=$(picoguard_pid)
    boot_run
    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds"
    settle

    expect_result "$STAGED_ID" failed "interrupted"
    [ "$(picoguard_pid)" != "$pid" ] || fail "picoguard was not restarted"
    service_up || fail "picoguard is not active"
    expect_no_pass_files
}

interrupted_during_verify() {
    pid=$(picoguard_pid)
    stage slow
    wait_for 60 test -f "$I/installing" || fail "the pass never started"

    case $INIT in
        systemd) systemctl kill -s KILL picoguard-update.service ;;
        openrc) kill -9 "$(children_of "$(cat /run/supervise-picoguard-update.pid)")" ;;
    esac

    # The next pass: by hand on systemd; on OpenRC supervise-daemon starts the watcher again,
    # and its first pass waits for the lock until the verification the kill left has ended.
    case $INIT in
        systemd)
            sleep 1
            systemctl start picoguard-update.service
            ;;
    esac

    wait_result "$STAGED_ID" 90 || fail "no result within 90 seconds"
    settle

    expect_result "$STAGED_ID" failed "interrupted"
    same_file "$B" "$REAL" || fail "$B changed"
    [ "$(picoguard_pid)" = "$pid" ] || fail "picoguard was restarted"
}

interrupted_after_result() {
    for outcome in updated rolled-back; do
        plant_interrupted silent
        cp -p "$REAL" "$B"
        pid=$(picoguard_pid)

        if [ "$outcome" = updated ]; then
            printf 'id=%s\noutcome=updated\n' "$STAGED_ID" >"$I/result"
        else
            printf 'id=%s\noutcome=rolled-back\nreason=the new version did not start; the previous version runs again\n' "$STAGED_ID" >"$I/result"
        fi

        chmod 0644 "$I/result"
        before=$(cksum <"$I/result")
        boot_run
        wait_for 60 test ! -e "$I/installing" || fail "$outcome: the record is still there"
        settle

        [ "$(cksum <"$I/result")" = "$before" ] || fail "$outcome: the result changed"
        [ "$(picoguard_pid)" = "$pid" ] || fail "$outcome: picoguard was restarted"
        expect_no_pass_files
    done
}

# hold_lock SECONDS: someone else, for example a pass of the installer, holds $I/lock.
install_with_lock_wait() {
    PICOGUARD_LOCK_WAIT=$1 sh "$FIXTURES/install.sh" --yes --binary "$FIXTURES/picoguard" --web-password none
}

hold_lock() {
    flock "$I/lock" sleep "$1" >/dev/null 2>&1 &
    HOLDER=$!
    sleep 1
}

install_waits_for_lock() {
    hold_lock 15
    started=$(date +%s)

    install_real >/dev/null || fail "install.sh failed"
    elapsed=$(($(date +%s) - started))
    wait "$HOLDER" || true

    note "install.sh took ${elapsed}s"
    [ "$elapsed" -ge 10 ] || fail "install.sh did not wait for the lock: ${elapsed}s"
}

installer_waits_for_lock() {
    hold_lock 15
    stage good
    sleep 10

    if [ -f "$I/result" ] && [ "$(result_value id)" = "$STAGED_ID" ]; then
        fail "answered while the lock was held"
    fi

    wait_result "$STAGED_ID" 60 || fail "no result after the lock was released"
    expect_result "$STAGED_ID" updated
    wait "$HOLDER" || true
}

install_lock_timeout_stops_installer() {
    stage silent
    wait_for 60 same_file "$B" "$FIXTURES/releases/silent/picoguard" || fail "the new binary never reached $B"

    out=$(install_with_lock_wait 5 2>&1) || fail "install.sh failed: $out"
    printf '%s\n' "$out"
    ended=$(date +%s)

    case $out in
        *"stopping it"*) ;;
        *) fail "install.sh did not warn about the wait" ;;
    esac

    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds of the run"
    note "answered $(($(date +%s) - ended))s after the run"
    expect_result "$STAGED_ID" failed "interrupted"
    same_file "$B" "$REAL" || fail "$B is not the real binary"
    wait_for 30 service_up || fail "picoguard is not active"
}

# The hung verifier of install_fake_verifier, which is `sleep 200`. Not `verify-update`: the
# installer's next pass runs the real one at once.
hung_verifier_running() {
    pgrep -f "sleep 200" >/dev/null
}

install_lock_timeout_during_verify() {
    shorten_verify_wait 20
    install_fake_verifier hangs
    stage good
    wait_for 60 test -f "$I/installing" || fail "the pass never started"

    started=$(date +%s)
    out=$(install_with_lock_wait 5 2>&1) || fail "install.sh failed: $out"
    printf '%s\n' "$out"
    note "install.sh took $(($(date +%s) - started))s"

    [ -z "$(holders_of_lock)" ] || fail "something still holds $I/lock: $(holders_of_lock)"

    if hung_verifier_running; then
        fail "the verification the stopped pass was waiting for is still running"
    fi

    same_file "$B" "$REAL" || fail "$B is not the real binary"
    wait_result "$STAGED_ID" 90 || fail "no result within 90 seconds"
    expect_result "$STAGED_ID" failed "interrupted"
}

lock_change_logged() {
    installer_log | grep -q "the lock changed while waiting"
}

lock_replaced_while_waiting() {
    flock "$I/lock" sleep 12 >/dev/null 2>&1 &
    holder=$!
    sleep 1
    stage good
    trigger_gap
    sleep 2

    : >"$I/lock.new"
    chmod 0600 "$I/lock.new"
    mv -f "$I/lock.new" "$I/lock"
    wait "$holder" || true

    wait_for 5 lock_change_logged || fail "the waiting pass did not log the changed lock"
    [ ! -e "$I/installing" ] || fail "a record was written"

    if [ -f "$I/result" ] && [ "$(result_value id)" = "$STAGED_ID" ]; then
        fail "the pass answered on the old lock"
    fi

    same_file "$B" "$REAL" || fail "$B changed"

    case $INIT in
        systemd) systemctl start picoguard-update.service ;;
    esac

    wait_result "$STAGED_ID" 60 || fail "no result on the new lock"
    expect_result "$STAGED_ID" updated
}

lock_not_inherited() {
    install_real >/dev/null
    settle
    [ -z "$(holders_of_lock)" ] || fail "install.sh left the lock held: $(holders_of_lock)"

    stage good
    wait_result "$STAGED_ID" 60 || fail "no result within 60 seconds"
    expect_result "$STAGED_ID" updated
    settle
    [ -z "$(holders_of_lock)" ] || fail "the update left the lock held: $(holders_of_lock)"
}

# ---- install.sh puts the installer back as it was, or removes it ----

expect_no_installer() {
    for path in "$LIB" "$I" /etc/systemd/system/picoguard-update.path \
        /etc/systemd/system/picoguard-update.service /etc/init.d/picoguard-update; do
        [ ! -e "$path" ] || fail "$path is still there"
    done

    case $INIT in
        systemd)
            if systemctl list-unit-files | grep -q picoguard-update; then
                fail "a picoguard-update unit is still known: $(systemctl list-unit-files | grep picoguard-update)"
            fi
            ;;
        openrc)
            if rc-update show | grep -q picoguard-update; then
                fail "picoguard-update is still in a runlevel"
            fi
            ;;
    esac

    if pgrep -f "$UPDATER" >/dev/null; then
        fail "an installer process is still running"
    fi
}

rollback_without_installer() {
    sh "$FIXTURES/old-install.sh" --yes --binary "$FIXTURES/picoguard" --web-password none >/dev/null ||
        fail "the installer of the last release failed"
    write_test_config
    restart_picoguard
    wait_for 30 dns_answers || fail "picoguard does not answer"

    if sh "$FIXTURES/install.sh" --yes --binary "$FIXTURES/releases/silent/picoguard" >/dev/null 2>&1; then
        fail "an upgrade to a binary that never answers succeeded"
    fi

    same_file "$B" "$REAL" || fail "$B is not the real binary after the rollback"
    expect_no_installer
    wait_for 30 service_up || fail "picoguard is not active after the rollback"
}

rollback_with_older_installer() {
    case $INIT in
        systemd) files="$UPDATER $LIB/common.sh /etc/systemd/system/picoguard-update.path /etc/systemd/system/picoguard-update.service" ;;
        openrc) files="$UPDATER $LIB/common.sh /etc/init.d/picoguard-update" ;;
    esac

    for file in $files; do
        echo "# older" >>"$file"
    done

    if sh "$FIXTURES/install.sh" --yes --binary "$FIXTURES/releases/silent/picoguard" >/dev/null 2>&1; then
        fail "an upgrade to a binary that never answers succeeded"
    fi

    for file in $files; do
        [ "$(tail -n 1 "$file")" = "# older" ] || fail "$file was not put back as it was"
    done

    same_file "$B" "$REAL" || fail "$B is not the real binary after the rollback"
    [ -f "$I/lock" ] || fail "$I/lock is gone"
    enabled_at_boot || fail "the trigger is not enabled"
    trigger_running || fail "the trigger is not running"
    wait_for 30 service_up || fail "picoguard is not active after the rollback"
}

uninstall() {
    sh "$FIXTURES/install.sh" --uninstall || fail "--uninstall failed"
    expect_no_installer
    [ ! -e "$B" ] || fail "$B is still there"
    [ -f "$CONFIG" ] || fail "the config was removed without --purge"
}

uninstall_purge() {
    sh "$FIXTURES/install.sh" --uninstall --purge || fail "--uninstall --purge failed"
    expect_no_installer
    [ ! -e "$B" ] || fail "$B is still there"
    [ ! -e /etc/picoguard ] || fail "/etc/picoguard is still there"
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
    *)
        echo "usage: sh cases.sh groups | style GROUP | list GROUP | setup | run CASE" >&2
        exit 2
        ;;
esac

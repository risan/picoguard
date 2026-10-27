#!/bin/sh
# The root installer of picoguard updates. The status page stages an update under
# /var/lib/picoguard/update, which the picoguard user owns, so nothing in it is trusted: the
# installed picoguard copies it and checks it again (`verify-update`), and only that copy is
# installed. Then it restarts picoguard, asks it for example.com, and puts the previous
# binary back when there is no answer.
#
#   update run systemd     one pass (the oneshot of picoguard-update.service)
#   update watch openrc    a pass at start and then whenever a request waits, polled every
#                          POLL seconds (the service picoguard-update, under supervise-daemon)
#
# install.sh writes this file to /usr/local/lib/picoguard/update; scripts/check.sh keeps its
# copy in install.sh equal to dist/picoguard-update.sh.

set -eu
umask 077

B=/usr/local/bin/picoguard
STAGED_DIR=/var/lib/picoguard/update
REQUEST=$STAGED_DIR/request
I=/var/lib/picoguard-update
LIB_DIR=/usr/local/lib/picoguard
VERIFY_WAIT=120
CHECK_WAIT=30
DNS_WAIT=30
POLL=5
TICK=/run/picoguard-update.tick

# What common.sh reads and sets.
CHECK_PATH=/etc/picoguard/picoguard.toml
DNS_HOST=127.0.0.1
DNS_PORT=53
INIT=

# The request being answered, and why the last DNS check failed.
ID=
VERSION=
DNS_FAILURE=

# Whether the last read of the request ended with "no verify-update": a watcher logs that once.
CANNOT_VERIFY=0

# shellcheck disable=SC1091 # checked on its own, as dist/picoguard-common.sh
. "$LIB_DIR/common.sh"

log() {
    printf 'picoguard update: %s\n' "$*" >&2

    # supervise-daemon discards stderr. Its logger option would keep a `logger` process
    # beside the watcher for as long as it runs, one process more than an idle watcher may be.
    if [ "$INIT" = openrc ]; then
        logger -t picoguard-update -p daemon.warning "$*" || true
    fi
}

# `timeout` ends with 124 (GNU) or 143 (BusyBox, which kills with SIGTERM) when time ran out.
ran_out() {
    [ "$1" = 124 ] || [ "$1" = 143 ]
}

# The id and version of a request as `verify-update` prints it, as "ID VERSION"; fails for
# anything but exactly those two lines.
parse_request() {
    id=$(printf '%s\n' "$1" | sed -n 's/^id=\([0-9a-f]\{16\}\)$/\1/p')
    version=$(printf '%s\n' "$1" | sed -n 's/^version=\([0-9]\{1,\}\.[0-9]\{1,\}\.[0-9]\{1,\}\)$/\1/p')

    if [ -z "$id" ] || [ -z "$version" ] || [ "$(printf '%s\n' "$1" | wc -l)" != 2 ]; then
        return 1
    fi

    printf '%s %s\n' "$id" "$version"
}

# Prints "ID VERSION" of the request that is waiting. Exit 1: there is none, or it is not
# whole; exit 2: the installed picoguard has no `verify-update`.
#
# `verify-update` is given `$I`, which exists, so it refuses and touches nothing. But it reads
# the request first, without following links and for at most 256 bytes, and prints it when it
# is valid.
read_request() {
    if [ ! -f "$REQUEST" ] || [ -L "$REQUEST" ]; then
        return 1
    fi

    status=0
    out=$(timeout 5 "$B" verify-update "$STAGED_DIR" "$I" 2>/dev/null) || status=$?

    case $status in
        1) ;;
        2) return 2 ;;
        *) return 1 ;;
    esac

    parse_request "$out"
}

# write_record [swap]: the record of the pass in progress, durable before it replaces the
# last one. A record with `swap=1` is the only sign that the new binary may be at $B.
write_record() {
    {
        printf 'id=%s\nversion=%s\n' "$ID" "$VERSION"

        if [ "${1:-}" = swap ]; then
            printf 'swap=1\n'
        fi
    } >"$I/installing.part" && sync && mv -f "$I/installing.part" "$I/installing" && sync
}

# write_result OUTCOME [REASON]: the answer, durable before anything that could still be
# needed to finish this update is removed.
write_result() {
    reason=
    if [ $# -ge 2 ]; then
        reason=$(printf '%s\n' "$2" | head -n 1 | tr -cd ' -~' | cut -c 1-200)
    fi

    if [ "$1" != updated ] && [ -z "$reason" ]; then
        reason="no reason was given"
    fi

    {
        printf 'id=%s\noutcome=%s\n' "$ID" "$1"

        if [ -n "$reason" ]; then
            printf 'reason=%s\n' "$reason"
        fi
    } >"$I/result.part"
    chmod 0644 "$I/result.part"
    sync
    mv -f "$I/result.part" "$I/result"
    sync
    log "$ID: $1${reason:+: $reason}"
}

remove_pass_files() {
    rm -rf "$I"/*.part "$I/verified" "$I/verify.err" "$I/previous" "$B.update.part"
    rm -f "$I/installing"
}

# Every end of a pass with an answer.
end_with() {
    write_result "$@"
    remove_pass_files
}

# Restarts picoguard and waits until the previous binary gets an answer from it, for at most
# DNS_WAIT seconds. The previous binary asks, so that a broken new version cannot pass its
# own check. On failure DNS_FAILURE says why; the state at the deadline decides, because a
# version that crashes over and over is between restarts at almost any moment.
check_dns() {
    read_dns_target
    deadline=$(($(date +%s) + DNS_WAIT))

    while [ "$(date +%s)" -lt "$deadline" ]; do
        # A probe takes up to 2 seconds, so one that started just before the deadline could
        # answer after it.
        if service_active && "$I/previous" dns-check "$DNS_HOST" "$DNS_PORT" >/dev/null 2>&1 &&
            [ "$(date +%s)" -lt "$deadline" ]; then
            return 0
        fi

        sleep 1
    done

    if service_active; then
        DNS_FAILURE="did not answer DNS within $DNS_WAIT seconds"
    else
        DNS_FAILURE="did not start"
    fi

    return 1
}

# Puts the previous binary back and answers `rolled-back`. Returns 1, with the record and
# the backup kept for the next pass, when it cannot put the binary back: the new binary is
# still at $B then, and `rolled-back` would be a lie.
roll_back() {
    if ! { cp -p "$I/previous" "$B.update.part" && sync && mv -f "$B.update.part" "$B" && sync; }; then
        rm -rf "$B.update.part"
        log "$ID: rollback failed: could not put the previous binary back"

        return 1
    fi

    restart_service || true

    if check_dns; then
        end_with rolled-back "the new version $1; the previous version runs again"
    else
        end_with rolled-back "the new version $1; the previous version does not answer either"
    fi
}

# After a restart: keep the new binary when it answers, else put the previous one back.
judge_new_binary() {
    if check_dns; then
        end_with updated
    else
        roll_back "$DNS_FAILURE"
    fi
}

# What an earlier pass left when it stopped part way (killed, timed out, power lost).
finish_interrupted() {
    ID=$(sed -n 's/^id=//p' "$I/installing")
    VERSION=$(sed -n 's/^version=//p' "$I/installing")
    swap=$(sed -n 's/^swap=//p' "$I/installing")

    if [ -z "$ID" ]; then
        remove_pass_files

        return 0
    fi

    log "$ID: finishing an interrupted update"

    if [ -f "$I/result" ] && [ "$(sed -n 's/^id=//p' "$I/result")" = "$ID" ]; then
        remove_pass_files
    elif [ "$swap" = 1 ] && [ -f "$I/verified/picoguard" ] && cmp -s "$B" "$I/verified/picoguard"; then
        restart_service || true
        judge_new_binary
    elif [ "$swap" = 1 ]; then
        # A rollback had put the previous binary back, or install.sh replaced the binary.
        restart_service || true
        end_with failed "the installer was interrupted"
    else
        end_with failed "the installer was interrupted"
    fi
}

# Verifies the staged update into $I/verified. Returns 0 to go on; any other end has
# answered or dropped the request already.
verify_staged() {
    status=0
    out=$(timeout "$VERIFY_WAIT" "$B" verify-update "$STAGED_DIR" "$I/verified" 2>"$I/verify.err") || status=$?
    shown=$(parse_request "$out" | cut -d' ' -f1)

    # What was verified must be the request this pass recorded; if the request changed under
    # the pass, the new one gets its own pass.
    if [ "$status" = 0 ] && [ "$shown" = "$ID" ]; then
        return 0
    fi

    if { [ -n "$shown" ] && [ "$shown" != "$ID" ]; } || [ "$status" = 0 ]; then
        remove_pass_files

        return 1
    fi

    if ran_out "$status"; then
        end_with failed "verify-update did not finish within $VERIFY_WAIT seconds"
    elif [ "$status" = 1 ] && [ -n "$shown" ]; then
        end_with failed "$(head -n 1 "$I/verify.err")"
    elif [ "$status" = 1 ]; then
        remove_pass_files
    else
        end_with failed "verify-update ended with status $status"
    fi

    return 1
}

install_verified() {
    status=0
    out=$(timeout "$CHECK_WAIT" "$I/verified/picoguard" --check -c "$CHECK_PATH" 2>&1) || status=$?

    if ran_out "$status"; then
        end_with failed "the new version did not check the config within $CHECK_WAIT seconds"

        return 0
    elif [ "$status" != 0 ]; then
        end_with failed "the new version does not accept the config: $(printf '%s\n' "$out" | head -n 1)"

        return 0
    fi

    if ! { cp -p "$B" "$I/previous.part" && sync && mv -f "$I/previous.part" "$I/previous" && sync; } ||
        ! write_record swap; then
        end_with failed "disk: could not keep the previous binary"

        return 0
    fi

    if ! { cp "$I/verified/picoguard" "$B.update.part" && chmod 0755 "$B.update.part" && sync &&
        mv -f "$B.update.part" "$B" && sync; }; then
        rm -rf "$B.update.part"
        end_with failed "disk: could not write the new binary"

        return 0
    fi

    restart_service || true
    judge_new_binary
}

# One pass: answers the request that waits, if there is one that is not answered yet. Every
# end returns 0 except a failed rollback, which returns 1.
run_once() {
    if [ ! -d "$I" ]; then
        return 0
    fi

    exec 9>>"$I/lock"
    flock 9

    # An uninstall or a rollback of install.sh removed $I while this pass waited.
    if [ "$(stat -L -c %d:%i /proc/self/fd/9)" != "$(stat -c %d:%i "$I/lock" 2>/dev/null || echo gone)" ]; then
        log "the lock changed while waiting"

        return 0
    fi

    if [ -f "$I/installing" ]; then
        finish_interrupted || return 1
    fi

    rm -rf "$I"/*.part "$I/verified" "$I/verify.err" "$I/previous" "$B.update.part"

    status=0
    request=$(read_request) || status=$?

    if [ "$status" = 2 ]; then
        # One line per run of this process, not one per poll of a watcher.
        if [ "$CANNOT_VERIFY" != 1 ]; then
            log "the installed picoguard cannot verify updates"
        fi

        CANNOT_VERIFY=1

        return 0
    fi

    CANNOT_VERIFY=0

    if [ "$status" != 0 ]; then
        return 0
    fi

    ID=${request% *}
    VERSION=${request#* }

    if [ -f "$I/result" ] && [ "$(sed -n 's/^id=//p' "$I/result")" = "$ID" ]; then
        return 0
    fi

    if ! write_record; then
        rm -f "$I/installing.part"
        log "$ID: could not write the record of the update"

        return 0
    fi

    if verify_staged; then
        install_verified
    fi
}

# Polls instead of watching the directory: it must start with no directory to watch, and a
# BusyBox `inotifyd` costs a third more memory. The pass runs in this process, not a subshell,
# so that stopping the service stops it. A failed rollback ends the watcher; supervise-daemon
# starts it again, and its first pass retries.
watch() {
    # A FIFO that nothing writes to: `read` on it is a sleep that is not a process of its own.
    rm -f "$TICK"
    mkfifo -m 0600 "$TICK"
    exec 3<>"$TICK"
    rm -f "$TICK"

    while :; do
        if [ -f "$I/installing" ] || [ -f "$REQUEST" ]; then
            # Not `run_once || ...`: set -e is off for everything inside a function that is
            # the left side of `||`.
            run_once
            exec 9>&-
        fi

        if [ -n "${BB_ASH_VERSION:-}" ]; then
            # shellcheck disable=SC3045 # only BusyBox ash gets here
            read -r -t "$POLL" _ <&3 || true
        else
            sleep "$POLL"
        fi
    done
}

case ${1:-}:${2:-} in
    watch:openrc)
        # shellcheck disable=SC2034 # common.sh reads it
        INIT=openrc
        watch
        ;;
    run:systemd)
        # shellcheck disable=SC2034 # common.sh reads it
        INIT=systemd
        run_once
        ;;
    *)
        echo "usage: update run systemd | watch openrc" >&2
        exit 2
        ;;
esac

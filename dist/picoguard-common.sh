# shellcheck disable=SC2034,SC2154 # DNS_HOST, DNS_PORT, CHECK_PATH and INIT belong to the script that sources this
# Shared by install.sh and the update installer (dist/picoguard-update.sh): the DNS address
# of a config and the picoguard service. install.sh holds this text too, and scripts/check.sh
# fails when the two differ.

is_port() {
    case $1 in
        ''|*[!0-9]*) return 1 ;;
    esac

    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# Where to ask picoguard: the port and an address of [server] bind that this machine can reach.
read_dns_target() {
    port=$(awk '/^\[/ { in_server = ($0 == "[server]") } in_server && $1 == "port" { print $3; exit }' "$CHECK_PATH")

    if is_port "$port"; then
        DNS_PORT=$port
    fi

    # The array may span several lines and use either TOML string quote. Comments are cut off first.
    addresses=$(awk '
        /^\[/ { in_server = ($0 == "[server]"); collecting = 0 }
        in_server && ($0 ~ /^[ \t]*bind[ \t]*=/ || collecting) {
            sub(/#.*/, "")
            print
            collecting = ($0 !~ /\]/)
        }' "$CHECK_PATH" | grep -o "[\"'][^\"']*[\"']" | tr -d "\"'" || true)

    has_ipv4_loopback=0
    has_ipv6_loopback=0
    first_address=

    for address in $addresses; do
        if [ -z "$first_address" ]; then
            first_address=$address
        fi

        case $address in
            0.0.0.0|127.*) has_ipv4_loopback=1 ;;
            ::|::1) has_ipv6_loopback=1 ;;
        esac
    done

    if [ "$has_ipv4_loopback" = 1 ]; then
        DNS_HOST=127.0.0.1
    elif [ "$has_ipv6_loopback" = 1 ]; then
        DNS_HOST=::1
    elif [ -n "$first_address" ]; then
        DNS_HOST=$first_address
    fi
}

service_active() {
    case $INIT in
        systemd) systemctl is-active --quiet picoguard ;;
        openrc) rc-service picoguard status >/dev/null 2>&1 ;;
    esac
}

# Closing fd 9 keeps a lock the caller holds there (install.sh and the update installer take
# one) from being inherited by the service: OpenRC's supervise-daemon keeps its inherited
# descriptors for as long as it lives, which would hold the lock until a reboot.
restart_service() {
    case $INIT in
        systemd) systemctl restart picoguard 9>&- ;;
        openrc) rc-service picoguard restart 9>&- ;;
    esac
}

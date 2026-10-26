#!/bin/sh
# Install, upgrade or remove picoguard on a Linux box with systemd or OpenRC.
# Run `sh install.sh --help` for the options. Written for POSIX sh (dash, BusyBox ash).

set -eu

REPO=risan/picoguard
BASE_URL=${PICOGUARD_BASE_URL:-https://github.com/$REPO/releases}
BIN_PATH=/usr/local/bin/picoguard
CONFIG_DIR=/etc/picoguard
CONFIG_PATH=$CONFIG_DIR/picoguard.toml
STATE_DIR=/var/lib/picoguard
SYSTEMD_UNIT=/etc/systemd/system/picoguard.service
SYSTEMD_UNIT_DIR=/etc/systemd/system/picoguard.service.d
SYSTEMD_MEMORY_DROPIN=$SYSTEMD_UNIT_DIR/memory.conf
# First line of a drop-in that install.sh wrote. Any other memory.conf is the user's.
MEMORY_DROPIN_MARKER='# Written by install.sh for the xlarge lists.'
OPENRC_SCRIPT=/etc/init.d/picoguard
UPDATE_HELPER_DIR=/usr/local/lib/picoguard
UPDATE_HELPER=$UPDATE_HELPER_DIR/update
UPDATE_COMMON=$UPDATE_HELPER_DIR/common.sh
UPDATE_DIR=/var/lib/picoguard-update
SYSTEMD_UPDATE_PATH=/etc/systemd/system/picoguard-update.path
SYSTEMD_UPDATE_SERVICE=/etc/systemd/system/picoguard-update.service
OPENRC_UPDATE_SCRIPT=/etc/init.d/picoguard-update
RESOLVED_DROPIN=/etc/systemd/resolved.conf.d/picoguard.conf
RESOLV_SAVED_LINK=$CONFIG_DIR/resolv.conf.original-link
RESOLV_SAVED_COPY=$CONFIG_DIR/resolv.conf.original
OLD_STATE_DIR=/var/lib/private/picoguard
SERVICE_USER=picoguard
HAGEZI=https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock
ADGUARD_DNS_FILTER=https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt

# How long to wait for an update that is being installed, and then for the one this run stopped.
LOCK_WAIT=${PICOGUARD_LOCK_WAIT:-300}
STOPPED_WAIT=150

BINARY_FILE=
VERSION=latest
INIT=
UPSTREAM=
UPSTREAM_URLS=
LISTS=
ROUTER=
WEB_PORT=
WEB_PASSWORD=
ASSUME_YES=0
NO_START=0
RECONFIGURE=0
UNINSTALL=0
PURGE=0

ANSWER=
HAVE_TTY=0
INTERACTIVE=0
WIZARD_FLAGS_GIVEN=0
TARGET=
TMP=
STAGED=
BINARY=
SCRIPT_DIR=
WRITE_CONFIG=0
PASSWORD_GENERATED=0
RESOLVED_APPLIED=0
INSTALL_DONE=0
BACKUP_DIR=
BACKUP_CONFIG=
LOOKUP=failed
DNS_HOST=127.0.0.1
DNS_PORT=53

usage() {
    cat <<'EOF'
Usage: sh install.sh [options]

Installs picoguard, or upgrades it when it is already installed. Run it as root.
A new install asks four questions; --yes takes the default for every question.

Binary:
  --binary FILE         Install this file, unchecked. Otherwise the script uses a
                        picoguard-<target> file next to it (SHA256SUMS must be there too),
                        or downloads the release and checks it.
  --version vX.Y.Z      Release to download (default: latest).

Questions (each has a flag; a flag skips its question):
  --upstream NAME       cloudflare-quad9 (default), cloudflare, quad9, adguard.
  --upstream-url URL    Your own upstream server; repeat for several. Replaces --upstream.
  --lists NAME          default (AdGuard DNS filter + HaGeZi Pro + TIF mini, 256 MB and up),
                        large (512 MB and up), xlarge (1 GB and up).
  --router IP|none      Router for local names and reverse lookups (default: the gateway).
  --web-port PORT       Status page port (default: 8080).
  --web-password PASS   Status page password, user admin. 'none' for no password
                        (default: a random one, shown once at the end).

Behavior:
  -y, --yes             Take the default for every question.
  --no-start            Install only; do not enable or start the service.
  --reconfigure         Ask again and replace the config (the old one is saved as .bak).
  --init systemd|openrc Init system (default: detected).
  --uninstall           Remove the binary, the service and the systemd-resolved change.
  --purge               With --uninstall, also remove /etc/picoguard, /var/lib/picoguard
                        and the picoguard user.
  -h, --help            Show this help.

An existing config is never overwritten without --reconfigure. If another DNS server holds
port 53, the script names it and stops; it only turns off the systemd-resolved stub listener,
after asking (--yes answers yes).
Environment: PICOGUARD_BASE_URL replaces https://github.com/risan/picoguard/releases.
EOF
}

say() {
    printf '%s\n' "$*"
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

tell() {
    if [ "$INTERACTIVE" = 1 ]; then
        printf '%s\n' "$*" >/dev/tty
    fi
}

need_value() {
    if [ "$1" -lt 2 ]; then
        fail "$2 needs a value (see --help)"
    fi
}

parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            --binary)
                need_value $# "$1"
                BINARY_FILE=$2
                shift 2
                ;;
            --version)
                need_value $# "$1"
                VERSION=$2
                shift 2
                ;;
            --init)
                need_value $# "$1"
                INIT=$2
                shift 2
                ;;
            --upstream)
                need_value $# "$1"
                UPSTREAM=$2
                WIZARD_FLAGS_GIVEN=1
                shift 2
                ;;
            --upstream-url)
                need_value $# "$1"
                UPSTREAM=custom
                UPSTREAM_URLS="$UPSTREAM_URLS $2"
                WIZARD_FLAGS_GIVEN=1
                shift 2
                ;;
            --lists)
                need_value $# "$1"
                LISTS=$2
                WIZARD_FLAGS_GIVEN=1
                shift 2
                ;;
            --router)
                need_value $# "$1"
                ROUTER=$2
                WIZARD_FLAGS_GIVEN=1
                shift 2
                ;;
            --web-port)
                need_value $# "$1"
                WEB_PORT=$2
                WIZARD_FLAGS_GIVEN=1
                shift 2
                ;;
            --web-password)
                need_value $# "$1"
                WEB_PASSWORD=$2
                WIZARD_FLAGS_GIVEN=1
                shift 2
                ;;
            -y|--yes)
                ASSUME_YES=1
                shift
                ;;
            --no-start)
                NO_START=1
                shift
                ;;
            --reconfigure)
                RECONFIGURE=1
                shift
                ;;
            --uninstall)
                UNINSTALL=1
                shift
                ;;
            --purge)
                PURGE=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fail "unknown option: $1 (see --help)"
                ;;
        esac
    done

    case $VERSION in
        latest|v*) ;;
        *) VERSION=v$VERSION ;;
    esac
}

require_root() {
    if [ "$(id -u)" != 0 ]; then
        fail "run this script as root, for example: sudo sh install.sh"
    fi
}

detect_init() {
    if [ -n "$INIT" ]; then
        case $INIT in
            systemd|openrc) return 0 ;;
        esac

        fail "--init must be systemd or openrc"
    fi

    if [ -d /run/systemd/system ]; then
        INIT=systemd
    elif [ -f /etc/alpine-release ] || command -v rc-service >/dev/null 2>&1; then
        INIT=openrc
    elif command -v systemctl >/dev/null 2>&1; then
        INIT=systemd
    else
        INIT=none
    fi
}

detect_target() {
    machine=$(uname -m)

    case $machine in
        x86_64|amd64)
            TARGET=x86_64-unknown-linux-musl
            ;;
        aarch64|arm64)
            TARGET=aarch64-unknown-linux-musl
            # A 64-bit kernel can run a 32-bit userland, where only the ARMv7 binary runs.
            if command -v getconf >/dev/null 2>&1 && [ "$(getconf LONG_BIT)" = 32 ]; then
                TARGET=armv7-unknown-linux-musleabihf
            fi
            ;;
        armv7*|armv8l)
            TARGET=armv7-unknown-linux-musleabihf
            ;;
        *)
            fail "no picoguard binary for '$machine'. Supported: x86_64, aarch64/arm64, armv7l (ARMv7 with hard float). ARMv6 boards such as the Raspberry Pi Zero and Pi 1 are not supported."
            ;;
    esac
}

setup_terminal() {
    if ( : </dev/tty ) 2>/dev/null; then
        HAVE_TTY=1
    fi

    if [ "$ASSUME_YES" != 1 ] && [ "$HAVE_TTY" = 1 ]; then
        INTERACTIVE=1
    fi
}

# Answers go to ANSWER. The question is read from /dev/tty so that
# `curl ... | sh` can ask.
ask() {
    if [ "$ASSUME_YES" = 1 ]; then
        ANSWER=$2
        return 0
    fi

    if [ "$HAVE_TTY" != 1 ]; then
        fail "cannot ask '$1' without a terminal. Give the matching flag, or use --yes for the defaults."
    fi

    printf '%s [%s]: ' "$1" "$2" >/dev/tty
    ANSWER=
    IFS= read -r ANSWER </dev/tty || ANSWER=

    if [ -z "$ANSWER" ]; then
        ANSWER=$2
    fi
}

ask_secret() {
    if [ "$ASSUME_YES" = 1 ]; then
        ANSWER=
        return 0
    fi

    if [ "$HAVE_TTY" != 1 ]; then
        fail "cannot ask '$1' without a terminal. Give the matching flag, or use --yes for the defaults."
    fi

    printf '%s: ' "$1" >/dev/tty
    stty -echo </dev/tty 2>/dev/null || true
    ANSWER=
    IFS= read -r ANSWER </dev/tty || ANSWER=
    stty echo </dev/tty 2>/dev/null || true
    printf '\n' >/dev/tty
}

# $1 question, $2 default (y or n).
confirm() {
    ask "$1 (y/n)" "$2"

    case $ANSWER in
        y|Y|yes|YES|Yes) return 0 ;;
    esac

    return 1
}

cleanup() {
    if [ "$INSTALL_DONE" != 1 ] && [ "$RESOLVED_APPLIED" = 1 ]; then
        warn "the install did not finish; undoing the systemd-resolved change"
        undo_resolved_fix
    fi

    if [ -n "$TMP" ]; then
        rm -rf "$TMP"
    fi

    if [ -n "$STAGED" ]; then
        rm -f "$STAGED"
    fi
}

download() {
    DOWNLOAD_CODE=

    if command -v curl >/dev/null 2>&1; then
        DOWNLOAD_CODE=$(curl -sSL -o "$2" -w '%{http_code}' "$1") || return 1

        if [ "$DOWNLOAD_CODE" != 200 ]; then
            return 1
        fi

        return 0
    fi

    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1" || return 1

        return 0
    fi

    fail "need curl or wget to download picoguard (or pass --binary FILE)"
}

release_url() {
    if [ "$VERSION" = latest ]; then
        printf '%s/latest/download/%s' "$BASE_URL" "$1"
    else
        printf '%s/download/%s/%s' "$BASE_URL" "$VERSION" "$1"
    fi
}

download_release_file() {
    url=$(release_url "$1")
    say "Downloading $url"

    if download "$url" "$TMP/$1"; then
        return 0
    fi

    if [ "$DOWNLOAD_CODE" = 000 ]; then
        DOWNLOAD_CODE=
    fi

    {
        printf 'error: could not download %s' "$url"
        if [ -n "$DOWNLOAD_CODE" ]; then
            printf ' (HTTP %s)' "$DOWNLOAD_CODE"
        fi
        printf '\n'
        printf 'Check that the version exists: %s\n' "$BASE_URL"
        printf 'To download the files by hand, then run the script from that folder:\n\n'
        printf '  curl -fsSLO %s\n' "$(release_url "picoguard-$TARGET")"
        printf '  curl -fsSLO %s\n' "$(release_url SHA256SUMS)"
        printf '  curl -fsSLO %s\n' "$(release_url install.sh)"
        printf '  sudo sh install.sh\n'
    } >&2

    exit 1
}

# $1 file, $2 SHA256SUMS, $3 name in SHA256SUMS.
verify_checksum() {
    if ! command -v sha256sum >/dev/null 2>&1; then
        fail "sha256sum is missing, so the download cannot be checked"
    fi

    expected=$(awk -v name="$3" '{ n = $2; sub(/^\*/, "", n); if (n == name) { print $1; exit } }' "$2")

    if [ -z "$expected" ]; then
        fail "SHA256SUMS has no entry for $3"
    fi

    actual=$(sha256sum "$1" | awk '{ print $1 }')

    if [ "$expected" != "$actual" ]; then
        fail "checksum mismatch for $3 (expected $expected, got $actual). Not installing."
    fi
}

find_script_dir() {
    case $0 in
        */*)
            SCRIPT_DIR=${0%/*}
            ;;
        *)
            if [ -f "$0" ]; then
                SCRIPT_DIR=.
            fi
            ;;
    esac
}

fetch_binary() {
    asset=picoguard-$TARGET

    if [ -n "$BINARY_FILE" ]; then
        if [ ! -f "$BINARY_FILE" ]; then
            fail "--binary: $BINARY_FILE is not a file"
        fi

        BINARY=$BINARY_FILE
        say "Using $BINARY (not checked against SHA256SUMS)"

        return 0
    fi

    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$asset" ]; then
        BINARY=$SCRIPT_DIR/$asset

        if [ ! -f "$SCRIPT_DIR/SHA256SUMS" ]; then
            fail "found $BINARY but no SHA256SUMS next to it. Download SHA256SUMS from the same release, or pass --binary FILE to skip the check."
        fi

        verify_checksum "$BINARY" "$SCRIPT_DIR/SHA256SUMS" "$asset"
        say "Using $BINARY (checksum OK)"

        return 0
    fi

    download_release_file "$asset"
    download_release_file SHA256SUMS
    verify_checksum "$TMP/$asset" "$TMP/SHA256SUMS" "$asset"
    BINARY=$TMP/$asset
    say "Checksum OK"
}

stage_binary() {
    mkdir -p "$(dirname "$BIN_PATH")"
    STAGED=$BIN_PATH.new.$$
    cp "$BINARY" "$STAGED"
    chmod 0755 "$STAGED"

    if ! NEW_VERSION=$("$STAGED" --version 2>&1); then
        fail "the binary does not run on this machine: $NEW_VERSION"
    fi

    OLD_VERSION=
    if [ -x "$BIN_PATH" ]; then
        OLD_VERSION=$("$BIN_PATH" --version 2>/dev/null || true)
    fi

    if [ -n "$OLD_VERSION" ]; then
        say "Upgrading: $OLD_VERSION -> $NEW_VERSION"
    else
        say "Installing: $NEW_VERSION"
    fi
}

ram_mib() {
    awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo 2>/dev/null || true
}

default_gateway() {
    gateway=

    if command -v ip >/dev/null 2>&1; then
        gateway=$(ip -4 route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) { if ($i == "via") { print $(i + 1); exit } } }')
    fi

    if [ -z "$gateway" ] && [ -r /proc/net/route ]; then
        hex=$(awk '$2 == "00000000" && $3 != "00000000" { print $3; exit }' /proc/net/route)

        if [ -n "$hex" ]; then
            # The kernel prints the address as little-endian hex.
            gateway=$(printf '%d.%d.%d.%d' \
                "0x$(printf '%s' "$hex" | cut -c7-8)" "0x$(printf '%s' "$hex" | cut -c5-6)" \
                "0x$(printf '%s' "$hex" | cut -c3-4)" "0x$(printf '%s' "$hex" | cut -c1-2)")
        fi
    fi

    printf '%s' "$gateway"
}

is_ipv4() {
    printf '%s\n' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

upstream_label() {
    case $1 in
        cloudflare-quad9) say "Cloudflare and Quad9 over DoH" ;;
        cloudflare) say "Cloudflare over DoH" ;;
        quad9) say "Quad9 over DoH" ;;
        adguard) say "AdGuard DNS, unfiltered, over DoH" ;;
        custom) say "Your own servers" ;;
    esac
}

upstream_servers() {
    case $UPSTREAM in
        cloudflare-quad9)
            say https://1.1.1.1/dns-query
            say https://1.0.0.1/dns-query
            say https://9.9.9.10/dns-query
            say https://149.112.112.10/dns-query
            ;;
        cloudflare)
            say https://1.1.1.1/dns-query
            say https://1.0.0.1/dns-query
            ;;
        quad9)
            say https://9.9.9.10/dns-query
            say https://149.112.112.10/dns-query
            ;;
        adguard)
            say https://unfiltered.adguard-dns.com/dns-query
            ;;
        custom)
            set -f
            for url in $UPSTREAM_URLS; do
                say "$url"
            done
            set +f
            ;;
    esac
}

# A host name in an upstream URL needs plain DNS servers to resolve it.
upstream_needs_bootstrap() {
    urls=$(upstream_servers)
    set -f

    for url in $urls; do
        rest=${url#*://}
        host=${rest%%[/#:]*}

        case $host in
            '['*) ;;
            *)
                if ! is_ipv4 "$host"; then
                    set +f

                    return 0
                fi
                ;;
        esac
    done

    set +f

    return 1
}

choose_upstream() {
    if [ -z "$UPSTREAM" ]; then
        tell ""
        tell "1) Upstream DNS servers (picoguard forwards the questions it does not block)"
        tell "   1  Cloudflare + Quad9 over DoH (default)"
        tell "   2  Cloudflare only"
        tell "   3  Quad9 only"
        tell "   4  AdGuard DNS, unfiltered"
        tell "   5  Your own URLs"
        ask "Choose" 1

        case $ANSWER in
            1) UPSTREAM=cloudflare-quad9 ;;
            2) UPSTREAM=cloudflare ;;
            3) UPSTREAM=quad9 ;;
            4) UPSTREAM=adguard ;;
            5) UPSTREAM=custom ;;
            *) fail "unknown choice: $ANSWER" ;;
        esac
    fi

    case $UPSTREAM in
        cloudflare-quad9|cloudflare|quad9|adguard)
            ;;
        custom)
            if [ -z "$(upstream_servers)" ]; then
                ask "Upstream URLs, separated by spaces (https://IP/path, tls://IP#name, udp://IP:port)" ""
                UPSTREAM_URLS=$(printf '%s\n' "$ANSWER" | tr ',' ' ')
            fi

            if [ -z "$(upstream_servers)" ]; then
                fail "no upstream URLs given"
            fi

            urls=$(upstream_servers)
            set -f
            for url in $urls; do
                case $url in
                    https://*|tls://*|udp://*|tcp://*) ;;
                    *) fail "upstream URL must start with https://, tls://, udp:// or tcp://: $url" ;;
                esac

                case $url in
                    *[\"\\]*) fail "upstream URL has a quote or a backslash: $url" ;;
                esac
            done
            set +f
            ;;
        *)
            fail "unknown upstream '$UPSTREAM' (cloudflare-quad9, cloudflare, quad9, adguard)"
            ;;
    esac
}

# One line per list: name, url.
lists_for() {
    case $1 in
        default)
            printf '%s %s\n' adguard-dns "$ADGUARD_DNS_FILTER"
            printf '%s %s\n' hagezi-pro "$HAGEZI/pro.txt"
            printf '%s %s\n' hagezi-tif-mini "$HAGEZI/tif.mini.txt"
            ;;
        large)
            printf '%s %s\n' adguard-dns "$ADGUARD_DNS_FILTER"
            printf '%s %s\n' hagezi-pro-plus "$HAGEZI/pro.plus.txt"
            printf '%s %s\n' hagezi-tif-mini "$HAGEZI/tif.mini.txt"
            ;;
        xlarge)
            printf '%s %s\n' adguard-dns "$ADGUARD_DNS_FILTER"
            printf '%s %s\n' hagezi-ultimate "$HAGEZI/ultimate.txt"
            printf '%s %s\n' hagezi-tif "$HAGEZI/tif.txt"
            ;;
    esac
}

lists_label() {
    case $1 in
        default) say "AdGuard DNS filter + HaGeZi Pro + TIF mini" ;;
        large) say "AdGuard DNS filter + HaGeZi Pro++ + TIF mini" ;;
        xlarge) say "AdGuard DNS filter + HaGeZi Ultimate + TIF" ;;
    esac
}

lists_min_ram_mib() {
    case $1 in
        default) say 192 ;;
        large) say 384 ;;
        xlarge) say 768 ;;
    esac
}

choose_lists() {
    ram=$(ram_mib)

    if [ -z "$LISTS" ]; then
        tell ""
        if [ -n "$ram" ]; then
            tell "2) Blocklists (this machine has about $ram MB of RAM)"
        else
            tell "2) Blocklists"
        fi
        tell "   1  AdGuard DNS filter + HaGeZi Pro + TIF mini: about 12 MB (default, fits 256 MB boards)"
        tell "   2  AdGuard DNS filter + HaGeZi Pro++ + TIF mini, larger cache: 25-35 MB (512 MB and up)"
        tell "   3  AdGuard DNS filter + HaGeZi Ultimate + TIF, biggest cache: 60-90 MB (1 GB and up)"
        ask "Choose" 1

        case $ANSWER in
            1) LISTS=default ;;
            2) LISTS=large ;;
            3) LISTS=xlarge ;;
            *) fail "unknown choice: $ANSWER" ;;
        esac
    fi

    case $LISTS in
        default|large|xlarge) ;;
        *) fail "unknown lists '$LISTS' (default, large, xlarge)" ;;
    esac

    needed=$(lists_min_ram_mib "$LISTS")
    if [ -n "$ram" ] && [ "$ram" -lt "$needed" ]; then
        warn "the '$LISTS' lists are meant for $needed MB of RAM or more; this machine has $ram MB"
    fi
}

choose_router() {
    if [ -z "$ROUTER" ]; then
        gateway=$(default_gateway)
        if [ -z "$gateway" ]; then
            gateway=none
        fi

        tell ""
        tell "3) Your router answers names of devices in your network and reverse lookups."
        tell "   Enter its address, or 'none' to skip."
        ask "Router IP" "$gateway"
        ROUTER=$ANSWER
    fi

    if [ "$ROUTER" != none ] && ! is_ipv4 "$ROUTER"; then
        fail "router must be an IPv4 address or 'none': $ROUTER"
    fi
}

random_password() {
    LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

choose_web() {
    if [ -z "$WEB_PORT" ]; then
        tell ""
        tell "4) Status page"
        ask "Status page port" 8080
        WEB_PORT=$ANSWER
    fi

    if ! is_port "$WEB_PORT"; then
        fail "status page port must be a number from 1 to 65535: $WEB_PORT"
    fi

    if [ -z "$WEB_PASSWORD" ]; then
        tell "   Press Enter for a random password, type your own, or type 'none' for no password."
        ask_secret "Status page password for user admin"
        WEB_PASSWORD=$ANSWER
    fi

    case $WEB_PASSWORD in
        none)
            WEB_PASSWORD=
            ;;
        '')
            WEB_PASSWORD=$(random_password)
            PASSWORD_GENERATED=1
            ;;
    esac

    if printf '%s' "$WEB_PASSWORD" | LC_ALL=C grep -q '[[:cntrl:]]'; then
        fail "the status page password must not contain control characters"
    fi
}

run_wizard() {
    if [ "$ASSUME_YES" = 1 ]; then
        say "Using the defaults for every question not given as a flag (--yes)."
    else
        tell ""
        tell "A few questions. Press Enter to take the default."
    fi

    choose_upstream
    choose_lists
    choose_router
    choose_web

    say ""
    say "Your choices:"
    say "  upstream:  $(upstream_label "$UPSTREAM")"
    say "  lists:     $(lists_label "$LISTS")"
    say "  router:    $ROUTER"
    if [ "$PASSWORD_GENERATED" = 1 ]; then
        say "  status:    port $WEB_PORT, user admin, random password"
    elif [ -n "$WEB_PASSWORD" ]; then
        say "  status:    port $WEB_PORT, user admin, password set"
    else
        say "  status:    port $WEB_PORT, no password"
    fi
}

toml_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

write_config() {
    {
        cat <<EOF
# picoguard configuration, written by install.sh on $(date +%Y-%m-%d).
# Settings that are not listed here have their default. All of them:
# https://github.com/$REPO/blob/main/docs/configuration.md
# Check this file with: picoguard --check -c $CONFIG_PATH

[upstream]
# $(upstream_label "$UPSTREAM")
servers = [
EOF
        upstream_servers | while IFS= read -r url; do
            printf '    "%s",\n' "$url"
        done
        printf ']\n'

        if upstream_needs_bootstrap; then
            printf '# Plain DNS servers that resolve the host names above.\nbootstrap = ["9.9.9.9", "1.1.1.1"]\n'
        fi

        if [ "$ROUTER" != none ]; then
            cat <<EOF

[local]
# The router answers reverse lookups of private addresses and the local domains.
resolver = "$ROUTER:53"
domains = ["lan", "home.arpa"]
EOF
        fi

        cat <<EOF

[web]
port = $WEB_PORT
EOF
        if [ -n "$WEB_PASSWORD" ]; then
            printf 'user = "admin"\npassword = "%s"\n' "$(toml_escape "$WEB_PASSWORD")"
        fi

        case $LISTS in
            large)
                printf '\n[cache]\nmax_entries = 30000\nmax_bytes = 12582912\n'
                ;;
            xlarge)
                printf '\n[cache]\nmax_entries = 100000\nmax_bytes = 41943040\n'
                ;;
        esac

        printf '\n# Blocklists: %s\n' "$(lists_label "$LISTS")"
        lists_for "$LISTS" | while read -r name url; do
            printf '[[lists]]\nname = "%s"\nurl = "%s"\nformat = "adblock"\n' "$name" "$url"

            # The full TIF has about 2.1 million rules, over the default cap of 1.5 million.
            case $name in
                hagezi-ultimate|hagezi-tif)
                    printf 'max_rules = 3000000\n'
                    ;;
            esac

            printf '\n'
        done
    } >"$1"
}

stage_config() {
    if [ -f "$CONFIG_PATH" ] && [ "$RECONFIGURE" != 1 ]; then
        say "Keeping the existing config $CONFIG_PATH"

        if [ "$WIZARD_FLAGS_GIVEN" = 1 ]; then
            warn "the answer flags were ignored; use --reconfigure to replace the config"
        fi

        CHECK_PATH=$CONFIG_PATH

        return 0
    fi

    run_wizard
    write_config "$TMP/picoguard.toml"
    WRITE_CONFIG=1
    CHECK_PATH=$TMP/picoguard.toml
}

check_config() {
    if ! output=$("$STAGED" --check -c "$CHECK_PATH" 2>&1); then
        fail "the config $CHECK_PATH is not valid for this picoguard version: $output"
    fi
}

install_config() {
    if [ "$WRITE_CONFIG" != 1 ]; then
        return 0
    fi

    mkdir -p "$CONFIG_DIR"

    if [ -f "$CONFIG_PATH" ]; then
        BACKUP_CONFIG=$CONFIG_PATH.bak.$(date +%Y%m%d%H%M%S)
        cp -p "$CONFIG_PATH" "$BACKUP_CONFIG"
        say "Saved the old config as $BACKUP_CONFIG"
    fi

    install -m 0640 "$TMP/picoguard.toml" "$CONFIG_PATH"
    say "Wrote $CONFIG_PATH"
}

# systemd's DynamicUser makes a "picoguard" user that id finds but /etc/passwd does not hold.
ensure_service_user() {
    if grep -q "^$SERVICE_USER:" /etc/passwd; then
        return 0
    fi

    nologin=$(command -v nologin || say /bin/false)

    if command -v useradd >/dev/null 2>&1; then
        useradd --system --user-group --no-create-home --home-dir "$STATE_DIR" --shell "$nologin" "$SERVICE_USER"
    elif command -v adduser >/dev/null 2>&1; then
        addgroup -S "$SERVICE_USER" 2>/dev/null || true
        adduser -S -D -H -h "$STATE_DIR" -s "$nologin" -G "$SERVICE_USER" "$SERVICE_USER"
    else
        fail "neither useradd nor adduser is available, so the $SERVICE_USER user cannot be created"
    fi

    say "Created the system user $SERVICE_USER"
}

# systemd keeps the state of a DynamicUser service in /var/lib/private/picoguard and links
# /var/lib/picoguard to it. The static user needs a real directory it owns.
migrate_dynamic_state() {
    if [ "$INIT" != systemd ] || [ ! -L "$STATE_DIR" ] || [ ! -d "$OLD_STATE_DIR" ]; then
        return 0
    fi

    say "Moving the state of the old DynamicUser service to $STATE_DIR"
    systemctl stop picoguard 2>/dev/null || true
    rm -f "$STATE_DIR"
    mv "$OLD_STATE_DIR" "$STATE_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"
    chmod 0750 "$STATE_DIR"
}

# The config can hold the status page password: only root and the service may read it.
secure_config_files() {
    if [ ! -d "$CONFIG_DIR" ]; then
        return 0
    fi

    chown "root:$SERVICE_USER" "$CONFIG_DIR"
    chmod 0750 "$CONFIG_DIR"

    for file in "$CONFIG_PATH"*; do
        if [ -f "$file" ]; then
            chown "root:$SERVICE_USER" "$file"
            chmod 0640 "$file"
        fi
    done
}

# Prints "name pid" for each listener on the DNS port, one per line (pid is - when unknown).
port_53_owners() {
    if command -v ss >/dev/null 2>&1; then
        ss -lntup 2>/dev/null | awk -v port="$DNS_PORT" '
            $5 ~ (":" port "$") {
                name = "unknown"
                pid = "-"
                if (match($0, /users:\(\("[^"]*"/)) {
                    name = substr($0, RSTART + 9, RLENGTH - 10)
                }
                if (match($0, /pid=[0-9]+/)) {
                    pid = substr($0, RSTART + 4, RLENGTH - 4)
                }
                print name, pid
            }'
    elif command -v netstat >/dev/null 2>&1; then
        netstat -lntup 2>/dev/null | awk -v port="$DNS_PORT" '
            $4 ~ (":" port "$") {
                name = "unknown"
                pid = "-"
                if ($NF ~ /^[0-9]+\//) {
                    pid = $NF
                    sub(/\/.*/, "", pid)
                    name = $NF
                    sub(/^[0-9]+\//, "", name)
                }
                print name, pid
            }'
    else
        proc_net_port_53_owners
    fi
}

proc_net_port_53_owners() {
    hex_port=$(printf '%04X' "$DNS_PORT")
    inodes=$(awk -v hex_port="$hex_port" '
        FNR > 1 && $2 ~ (":" hex_port "$") && (($4 == "0A" && FILENAME ~ /tcp/) || ($4 == "07" && FILENAME ~ /udp/)) {
            print $10
        }' /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null)

    for inode in $inodes; do
        name=unknown
        pid=-

        for fd in /proc/[0-9]*/fd/*; do
            if [ "$(readlink "$fd" 2>/dev/null)" = "socket:[$inode]" ]; then
                pid=${fd#/proc/}
                pid=${pid%%/*}
                name=$(cat "/proc/$pid/comm" 2>/dev/null || say unknown)
                break
            fi
        done

        say "$name $pid"
    done
}

systemd_unit_of_pid() {
    sed -n 's|.*/\([^/]*\.service\)$|\1|p' "/proc/$1/cgroup" 2>/dev/null | head -n 1
}

# Saves what /etc/resolv.conf is now, so that --uninstall can put it back exactly.
save_resolv_conf() {
    mkdir -p "$CONFIG_DIR"
    rm -f "$RESOLV_SAVED_LINK" "$RESOLV_SAVED_COPY"

    if [ -L /etc/resolv.conf ]; then
        readlink /etc/resolv.conf >"$RESOLV_SAVED_LINK"
    elif [ -f /etc/resolv.conf ]; then
        cp -p /etc/resolv.conf "$RESOLV_SAVED_COPY"
    fi
}

apply_resolved_fix() {
    say "Turning off the systemd-resolved stub listener"
    save_resolv_conf
    mkdir -p "$(dirname "$RESOLVED_DROPIN")"
    cat >"$RESOLVED_DROPIN" <<'EOF'
[Resolve]
DNSStubListener=no
EOF
    RESOLVED_APPLIED=1

    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
}

# Listeners on port 53 that are not picoguard. A root that may not read other users'
# processes (some containers) sees our own running service as "unknown".
foreign_port_53_owners() {
    if service_active; then
        port_53_owners | grep -v -e '^picoguard ' -e '^unknown ' | sort -u || true
    else
        port_53_owners | grep -v '^picoguard ' | sort -u || true
    fi
}

# $1 is a "name pid" line. This script never stops another DNS server.
fail_port_53_busy() {
    name=${1%% *}
    pid=${1#* }
    unit=

    if [ "$INIT" = systemd ] && [ "$pid" != - ]; then
        unit=$(systemd_unit_of_pid "$pid")
    fi

    {
        printf 'error: port %s is used by %s' "$DNS_PORT" "$name"
        if [ "$pid" != - ]; then
            printf ' (pid %s' "$pid"
            if [ -n "$unit" ]; then
                printf ', systemd unit %s' "$unit"
            fi
            printf ')'
        fi
        printf '.\n'
        printf 'picoguard cannot start while it runs, and this script does not stop other DNS servers.\n'
        printf 'Stop or reconfigure it yourself, then run this script again. For example:\n'
        if [ "$INIT" = systemd ]; then
            printf '  systemctl disable --now %s\n' "${unit:-$name.service}"
        else
            printf '  rc-service %s stop && rc-update del %s\n' "$name" "$name"
        fi

        printf 'If another program starts it (NetworkManager with dns=dnsmasq, Pi-hole, AdGuard Home),\n'
        printf 'change that program instead. Or install now without starting: --no-start.\n'
    } >&2

    exit 1
}

ensure_port_53_free() {
    owners=$(foreign_port_53_owners)
    others=$(printf '%s\n' "$owners" | grep -v -e '^systemd-resolve' -e '^$' | head -n 1 || true)

    if [ -n "$others" ]; then
        fail_port_53_busy "$others"
    fi

    if [ -z "$owners" ]; then
        return 0
    fi

    say ""
    say "systemd-resolved listens on port $DNS_PORT."

    if ! confirm "Turn off its stub listener, so picoguard can use port 53?" y; then
        fail "port 53 is busy. Turn off the resolved listener (docs/install.md, 'Free port 53'), or use --no-start."
    fi

    apply_resolved_fix
    sleep 1
    owners=$(foreign_port_53_owners | head -n 1)

    if [ -n "$owners" ]; then
        fail_port_53_busy "$owners"
    fi
}

# The installer sources the same text from /usr/local/lib/picoguard/common.sh.
common_text() {
    cat <<'COMMON'
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
COMMON
}

eval "$(common_text)"

systemd_unit_text() {
    cat <<'SYSTEMD_UNIT'
[Unit]
Description=picoguard DNS ad and malware blocker
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart=/usr/local/bin/picoguard -c /etc/picoguard/picoguard.toml
Restart=on-failure
RestartSec=5
# picoguard drains in-flight work within 10 s of SIGTERM.
TimeoutStopSec=15

# A system user (install.sh creates it; see docs/install.md). State goes to
# /var/lib/picoguard (state.dir). The config is root:picoguard 0640, because it
# can hold the status page password.
User=picoguard
Group=picoguard
StateDirectory=picoguard
StateDirectoryMode=0750
ConfigurationDirectory=picoguard
ConfigurationDirectoryMode=0750
UMask=0077

# Port 53 and nothing else that needs root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
# A user namespace would drop the ambient capability.
PrivateUsers=no

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM

# Steady use is about 16 MB; the limit leaves room for a list refresh.
MemoryMax=64M

[Install]
WantedBy=multi-user.target
SYSTEMD_UNIT
}

openrc_script_text() {
    cat <<'OPENRC_SCRIPT'
#!/sbin/openrc-run

description="picoguard DNS ad and malware blocker"

command=/usr/local/bin/picoguard
command_args="-c /etc/picoguard/picoguard.toml"
# A system user that install.sh creates with adduser -S. State goes to
# /var/lib/picoguard (state.dir).
command_user=picoguard:picoguard
supervisor=supervise-daemon
respawn_delay=5
respawn_max=0

# Port 53 and nothing else that needs root.
capabilities="^cap_net_bind_service"

# Log lines (level warn by default) go to syslog when a logger runs.
error_logger="logger -t picoguard -p daemon.warning"

depend() {
    need net
    use logger
    after firewall
}

start_pre() {
    checkpath --directory --owner picoguard:picoguard --mode 0750 /var/lib/picoguard
}
OPENRC_SCRIPT
}

update_helper_text() {
    cat <<'UPDATE_HELPER'
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
UPDATE_HELPER
}

systemd_update_path_text() {
    cat <<'SYSTEMD_UPDATE_PATH'
[Unit]
Description=Install a picoguard update that the status page staged

[Path]
# A new, a changed and a removed request all start the installer. It acts only on a request
# that is whole and not yet answered, so the extra runs end at once.
PathChanged=/var/lib/picoguard/update/request

[Install]
WantedBy=paths.target
SYSTEMD_UPDATE_PATH
}

systemd_update_service_text() {
    cat <<'SYSTEMD_UPDATE_SERVICE'
[Unit]
Description=Install a picoguard update that the status page staged
# No Requires, BindsTo or PartOf: restarting picoguard must not stop the installer that asks
# for it.
After=picoguard.service
# Every change of the request starts a pass, and a pass is cheap. With systemd's default limit
# (5 starts in 10 seconds) a daemon that rewrites the request over and over would put this
# unit, and the path unit with it, out of action until the next boot.
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/picoguard/update run systemd
TimeoutStartSec=10min

NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/usr/local/bin /var/lib/picoguard-update
ProtectHome=yes
PrivateTmp=yes

[Install]
# Also runs at boot: it finishes an update that a power loss interrupted.
WantedBy=multi-user.target
SYSTEMD_UPDATE_SERVICE
}

openrc_update_text() {
    cat <<'OPENRC_UPDATE_SCRIPT'
#!/sbin/openrc-run

description="Install a picoguard update that the status page staged"

command=/usr/local/lib/picoguard/update
command_args="watch openrc"
supervisor=supervise-daemon
respawn_delay=5
respawn_max=0

# No `need picoguard`: OpenRC restarts the services that need a restarted one, which would
# stop the installer in the middle of the update that restarts picoguard.
depend() {
    after picoguard
    use logger
}
OPENRC_UPDATE_SCRIPT
}

owns_memory_dropin() {
    [ "$(head -n 1 "$SYSTEMD_MEMORY_DROPIN" 2>/dev/null)" = "$MEMORY_DROPIN_MARKER" ]
}

install_systemd_service() {
    systemd_unit_text >"$TMP/picoguard.service"
    install -m 0644 "$TMP/picoguard.service" "$SYSTEMD_UNIT"

    # The biggest lists need more than the 64 MB of the shipped unit.
    if [ "$WRITE_CONFIG" = 1 ]; then
        if [ -f "$SYSTEMD_MEMORY_DROPIN" ] && ! owns_memory_dropin; then
            if [ "$LISTS" = xlarge ]; then
                warn "$SYSTEMD_MEMORY_DROPIN is not from install.sh, so it is left as it is. The xlarge lists need MemoryMax=192M or more in it."
            fi
        elif [ "$LISTS" = xlarge ]; then
            mkdir -p "$SYSTEMD_UNIT_DIR"
            printf '%s\n[Service]\nMemoryMax=192M\n' "$MEMORY_DROPIN_MARKER" >"$SYSTEMD_MEMORY_DROPIN"
        elif [ -f "$SYSTEMD_MEMORY_DROPIN" ]; then
            rm -f "$SYSTEMD_MEMORY_DROPIN"
            rmdir "$SYSTEMD_UNIT_DIR" 2>/dev/null || true
        fi
    fi

    systemd_update_path_text >"$TMP/picoguard-update.path"
    install -m 0644 "$TMP/picoguard-update.path" "$SYSTEMD_UPDATE_PATH"
    systemd_update_service_text >"$TMP/picoguard-update.service"
    install -m 0644 "$TMP/picoguard-update.service" "$SYSTEMD_UPDATE_SERVICE"

    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload
    fi
}

install_openrc_service() {
    mkdir -p "$STATE_DIR"
    chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"
    chmod 0750 "$STATE_DIR"

    mkdir -p "$(dirname "$OPENRC_SCRIPT")"
    openrc_script_text >"$TMP/picoguard.openrc"
    install -m 0755 "$TMP/picoguard.openrc" "$OPENRC_SCRIPT"
    openrc_update_text >"$TMP/picoguard-update.openrc"
    install -m 0755 "$TMP/picoguard-update.openrc" "$OPENRC_UPDATE_SCRIPT"
}

# The root installer of updates from the status page, what it sources, and the directory it
# keeps its lock and its state in. Only root can write any of it: the daemon must not.
install_update_helper() {
    mkdir -p "$UPDATE_HELPER_DIR"
    chown root:root "$UPDATE_HELPER_DIR"
    chmod 0755 "$UPDATE_HELPER_DIR"
    update_helper_text >"$TMP/picoguard-update"
    install -m 0755 "$TMP/picoguard-update" "$UPDATE_HELPER"
    common_text >"$TMP/picoguard-common.sh"
    install -m 0644 "$TMP/picoguard-common.sh" "$UPDATE_COMMON"

    mkdir -p "$UPDATE_DIR"
    chown root:root "$UPDATE_DIR"
    chmod 0755 "$UPDATE_DIR"

    # Never replaced: a pass may hold a lock on this very file. The daemon cannot open it, or
    # it could keep updates and this script waiting.
    if [ ! -e "$UPDATE_DIR/lock" ]; then
        : >"$UPDATE_DIR/lock"
    fi

    chmod 0600 "$UPDATE_DIR/lock"
}

install_service() {
    install_update_helper

    case $INIT in
        systemd) install_systemd_service ;;
        openrc) install_openrc_service ;;
    esac
}

install_binary() {
    mv -f "$STAGED" "$BIN_PATH"
    STAGED=
}

stop_update_installer() {
    case $INIT in
        systemd) systemctl stop picoguard-update.service 9>&- || true ;;
        openrc) rc-service picoguard-update stop 9>&- || true ;;
    esac
}

# Takes the lock the update installer takes for a whole pass, on fd 9 until this script ends,
# so that the two never change the binary, the units or the installer's folder together.
# Every child that can run long closes or keeps it on purpose: the installer's children keep
# it, so it lasts as long as any of them; the services started here close it (9>&-), or
# OpenRC's supervise-daemon would hold it until a reboot.
# Without the folder (a first install, or an upgrade from a version without the installer) no
# installer is running and there is nothing to wait for.
lock_updates() {
    if [ ! -d "$UPDATE_DIR" ]; then
        return 0
    fi

    exec 9>>"$UPDATE_DIR/lock"

    if timeout "$LOCK_WAIT" flock 9; then
        return 0
    fi

    warn "an update is being installed and has not finished in $LOCK_WAIT seconds; stopping it"
    stop_update_installer

    # What the installer left running (a verification it was waiting for) ends within its own
    # limits; until then it still holds the lock, and nothing may change under it.
    if ! timeout "$STOPPED_WAIT" flock 9; then
        warn "the stopped installer still holds the lock; going on anyway"
    fi
}

# On an upgrade, keep what runs now, so that a failed restart can be undone.
backup_previous() {
    if [ ! -x "$BIN_PATH" ]; then
        return 0
    fi

    BACKUP_DIR=$TMP/previous
    mkdir -p "$BACKUP_DIR"
    cp -p "$BIN_PATH" "$BACKUP_DIR/binary"

    if [ -f "$SYSTEMD_UNIT" ]; then
        cp -p "$SYSTEMD_UNIT" "$BACKUP_DIR/unit"
    fi

    if [ -f "$OPENRC_SCRIPT" ]; then
        cp -p "$OPENRC_SCRIPT" "$BACKUP_DIR/initscript"
    fi

    if [ -f "$SYSTEMD_MEMORY_DROPIN" ]; then
        cp -p "$SYSTEMD_MEMORY_DROPIN" "$BACKUP_DIR/memory-dropin"
    fi

    update_files | while read -r name path; do
        if [ -f "$path" ]; then
            cp -p "$path" "$BACKUP_DIR/$name"
        fi
    done

    if [ -d "$UPDATE_DIR" ]; then
        : >"$BACKUP_DIR/had-update-dir"
    fi
}

# The name a file is kept under in the backup, and its path: everything the installer of
# updates puts on the device, except the folder it keeps its state in.
update_files() {
    cat <<LIST
update-helper $UPDATE_HELPER
update-common $UPDATE_COMMON
systemd-update-path $SYSTEMD_UPDATE_PATH
systemd-update-service $SYSTEMD_UPDATE_SERVICE
openrc-update $OPENRC_UPDATE_SCRIPT
LIST
}

# A trigger that this run added is stopped before anything else is put back, or it could
# start an update over the binary that is being restored.
stop_new_update_trigger() {
    case $INIT in
        systemd)
            if [ ! -f "$BACKUP_DIR/systemd-update-path" ]; then
                systemctl disable --now picoguard-update.path picoguard-update.service 9>&- || true
            fi
            ;;
        openrc)
            if [ ! -f "$BACKUP_DIR/openrc-update" ]; then
                rc-service picoguard-update stop 9>&- || true
                rc-update del picoguard-update || true
            fi
            ;;
    esac
}

# Back to what was there before this run: a file that was backed up is copied back, one that
# was not is removed.
restore_or_remove() {
    if [ -f "$BACKUP_DIR/$1" ]; then
        cp -p "$BACKUP_DIR/$1" "$2"
    else
        rm -f "$2"
    fi
}

restore_update_installer() {
    update_files | while read -r name path; do
        restore_or_remove "$name" "$path"
    done

    if [ ! -f "$BACKUP_DIR/had-update-dir" ]; then
        rm -rf "$UPDATE_DIR"
    fi

    rmdir "$UPDATE_HELPER_DIR" 2>/dev/null || true
}

# Starts again the trigger that was there before this run.
restart_old_update_trigger() {
    case $INIT in
        systemd)
            if [ -f "$BACKUP_DIR/systemd-update-path" ]; then
                systemctl restart picoguard-update.path 9>&- || true
                systemctl start --no-block picoguard-update.service 9>&- || true
            fi
            ;;
        openrc)
            if [ -f "$BACKUP_DIR/openrc-update" ]; then
                rc-service picoguard-update restart 9>&- || true
            fi
            ;;
    esac
}

rollback_upgrade() {
    warn "the new version did not start or did not answer; putting $OLD_VERSION back"
    stop_new_update_trigger
    cp -p "$BACKUP_DIR/binary" "$BIN_PATH.old.$$"
    mv -f "$BIN_PATH.old.$$" "$BIN_PATH"

    if [ -f "$BACKUP_DIR/unit" ]; then
        cp -p "$BACKUP_DIR/unit" "$SYSTEMD_UNIT"
    fi

    if [ -f "$BACKUP_DIR/initscript" ]; then
        cp -p "$BACKUP_DIR/initscript" "$OPENRC_SCRIPT"
    fi

    if [ -f "$BACKUP_DIR/memory-dropin" ]; then
        mkdir -p "$SYSTEMD_UNIT_DIR"
        cp -p "$BACKUP_DIR/memory-dropin" "$SYSTEMD_MEMORY_DROPIN"
    elif owns_memory_dropin; then
        rm -f "$SYSTEMD_MEMORY_DROPIN"
        rmdir "$SYSTEMD_UNIT_DIR" 2>/dev/null || true
    fi

    if [ -n "$BACKUP_CONFIG" ] && [ -f "$BACKUP_CONFIG" ]; then
        cp -p "$BACKUP_CONFIG" "$CONFIG_PATH"
        secure_config_files
    fi

    restore_update_installer

    if [ "$INIT" = systemd ]; then
        systemctl daemon-reload
    fi

    restart_service || true
    restart_old_update_trigger

    if service_active; then
        say "The previous version runs again."
    else
        warn "the previous version did not start either. Look at the log."
    fi

    fail "the upgrade failed and was rolled back"
}

start_service() {
    case $INIT in
        systemd)
            # The oneshot is queued, not waited for: it runs once this script has ended, and
            # answers a request that waited (a path unit started over an existing request does
            # not fire).
            systemctl enable picoguard picoguard-update.path picoguard-update.service 9>&- &&
                systemctl restart picoguard 9>&- &&
                systemctl restart picoguard-update.path 9>&- &&
                systemctl start --no-block picoguard-update.service 9>&-
            ;;
        openrc)
            rc-update add picoguard default && rc-update add picoguard-update default &&
                rc-service picoguard restart 9>&- && rc-service picoguard-update restart 9>&-
            ;;
    esac
}

# 0: answered, 1: no answer, 2: no dig or nslookup to ask with.
dns_lookup() {
    if command -v dig >/dev/null 2>&1; then
        if answer=$(dig +time=2 +tries=1 +short -p "$DNS_PORT" "@$DNS_HOST" example.com 2>/dev/null) && [ -n "$answer" ]; then
            return 0
        fi

        return 1
    fi

    if command -v nslookup >/dev/null 2>&1; then
        if [ "$DNS_PORT" = 53 ]; then
            answer=$(nslookup example.com "$DNS_HOST" 2>&1) || answer=
        else
            answer=$(nslookup "-port=$DNS_PORT" example.com "$DNS_HOST" 2>&1) || answer=
        fi

        if [ "$(printf '%s\n' "$answer" | grep -ci '^address')" -ge 2 ]; then
            return 0
        fi

        return 1
    fi

    return 2
}

# Same codes as dns_lookup; 2 also needs picoguard to hold port 53.
wait_for_dns() {
    waited=0

    while [ "$waited" -lt 10 ]; do
        if service_active; then
            status=0
            dns_lookup || status=$?

            case $status in
                0)
                    return 0
                    ;;
                2)
                    if port_53_owners | grep -q -e '^picoguard ' -e '^unknown '; then
                        return 2
                    fi
                    ;;
            esac
        fi

        sleep 1
        waited=$((waited + 1))
    done

    return 1
}

start_and_verify() {
    LOOKUP=failed

    if start_service; then
        status=0
        wait_for_dns || status=$?

        case $status in
            0) LOOKUP=ok ;;
            2) LOOKUP=untested ;;
        esac
    fi

    if [ "$LOOKUP" = failed ] && [ -n "$BACKUP_DIR" ]; then
        rollback_upgrade
    fi
}

device_addresses() {
    if command -v ip >/dev/null 2>&1; then
        ip -4 -o addr show scope global 2>/dev/null | awk '{ split($4, a, "/"); print a[1] }'
    elif command -v hostname >/dev/null 2>&1; then
        hostname -I 2>/dev/null | tr ' ' '\n' | sed '/^$/d' || true
    fi
}

configured_web_port() {
    if [ -f "$CONFIG_PATH" ]; then
        awk '
            /^\[/ { in_web = ($0 == "[web]") }
            in_web && $1 == "port" { print $3; exit }' "$CONFIG_PATH"
    fi
}

print_web_login() {
    if [ "$PASSWORD_GENERATED" = 1 ]; then
        say ""
        say "Status page login (shown once; it is also in $CONFIG_PATH):"
        say "  user: admin"
        say "  password: $WEB_PASSWORD"
    fi
}

report() {
    if [ "$NO_START" = 1 ]; then
        say ""
        say "Installed, not started (--no-start). Start it with:"
        case $INIT in
            systemd) say "  systemctl enable --now picoguard picoguard-update.path picoguard-update.service" ;;
            openrc) say "  rc-update add picoguard default && rc-update add picoguard-update default && rc-service picoguard start && rc-service picoguard-update start" ;;
            *) say "  /usr/local/bin/picoguard -c $CONFIG_PATH" ;;
        esac
        print_web_login

        return 0
    fi

    if ! service_active; then
        case $INIT in
            systemd) fail "picoguard is not running. See: journalctl -u picoguard -e" ;;
            openrc) fail "picoguard is not running. See: rc-service picoguard status, and /var/log/messages" ;;
        esac
    fi

    case $LOOKUP in
        ok)
            say "A test lookup of example.com works."
            ;;
        untested)
            say "picoguard holds port 53. No lookup was tried: neither dig nor nslookup is installed."
            ;;
        *)
            warn "picoguard runs but a test lookup did not answer. The lists may still be loading, or the upstream servers are not reachable."
            ;;
    esac

    port=$(configured_web_port)
    if [ -z "$port" ]; then
        port=8080
    fi

    say ""
    say "picoguard is running."
    for address in $(device_addresses); do
        say "  Device address:  $address"
        say "  Status page:     http://$address:$port/"
    done
    say "  Config:          $CONFIG_PATH"
    print_web_login
    say ""
    say "Next: set this device's address as the DNS server in your router (DHCP settings)."
    say "Give the device a fixed address first, or the whole network loses DNS when it changes."
    say "Details: https://github.com/$REPO/blob/main/docs/install.md#3-point-your-network-at-picoguard"
}

# Puts /etc/resolv.conf back as save_resolv_conf found it, but only while it still is
# what apply_resolved_fix made it.
restore_resolv_conf() {
    if [ "$(readlink /etc/resolv.conf 2>/dev/null)" != /run/systemd/resolve/resolv.conf ]; then
        warn "/etc/resolv.conf was changed after the install; leaving it as it is"
    elif [ -f "$RESOLV_SAVED_LINK" ]; then
        ln -sf "$(cat "$RESOLV_SAVED_LINK")" /etc/resolv.conf
    elif [ -f "$RESOLV_SAVED_COPY" ]; then
        rm -f /etc/resolv.conf
        cp -p "$RESOLV_SAVED_COPY" /etc/resolv.conf
    else
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    fi

    rm -f "$RESOLV_SAVED_LINK" "$RESOLV_SAVED_COPY"
}

undo_resolved_fix() {
    if [ ! -f "$RESOLVED_DROPIN" ]; then
        return 0
    fi

    say "Undoing the systemd-resolved change"
    rm -f "$RESOLVED_DROPIN"
    rmdir "$(dirname "$RESOLVED_DROPIN")" 2>/dev/null || true
    restore_resolv_conf

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl restart systemd-resolved || true
    fi
}

uninstall() {
    say "Removing picoguard"

    # Not while an update is being installed. The lock is kept until the installer's files and
    # folder are gone; a pass that waited for it finds its lock removed and ends.
    lock_updates

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl disable --now picoguard-update.path picoguard-update.service 9>&- 2>/dev/null || true
        systemctl disable --now picoguard 2>/dev/null || true
    fi

    if command -v rc-service >/dev/null 2>&1 && [ -f "$OPENRC_UPDATE_SCRIPT" ]; then
        rc-service picoguard-update stop 9>&- 2>/dev/null || true
        rc-update del picoguard-update 2>/dev/null || true
    fi

    if command -v rc-service >/dev/null 2>&1 && [ -f "$OPENRC_SCRIPT" ]; then
        rc-service picoguard stop 2>/dev/null || true
        rc-update del picoguard 2>/dev/null || true
    fi

    rm -f "$SYSTEMD_UNIT" "$OPENRC_SCRIPT" "$BIN_PATH"
    rm -f "$SYSTEMD_UPDATE_PATH" "$SYSTEMD_UPDATE_SERVICE" "$OPENRC_UPDATE_SCRIPT"
    rm -rf "$UPDATE_HELPER_DIR" "$UPDATE_DIR"

    if [ -f "$SYSTEMD_MEMORY_DROPIN" ]; then
        if owns_memory_dropin; then
            rm -f "$SYSTEMD_MEMORY_DROPIN"
        else
            warn "$SYSTEMD_MEMORY_DROPIN is not from install.sh, so it is left in place"
        fi
    fi

    rmdir "$SYSTEMD_UNIT_DIR" 2>/dev/null || true

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl daemon-reload
    fi

    undo_resolved_fix

    if [ "$PURGE" = 1 ]; then
        rm -rf "$CONFIG_DIR" "$STATE_DIR"

        if grep -q "^$SERVICE_USER:" /etc/passwd; then
            if command -v userdel >/dev/null 2>&1; then
                userdel "$SERVICE_USER" 2>/dev/null || true
            else
                deluser "$SERVICE_USER" 2>/dev/null || true
            fi
        fi

        if command -v delgroup >/dev/null 2>&1; then
            delgroup "$SERVICE_USER" 2>/dev/null || true
        fi

        say "Removed $CONFIG_DIR, $STATE_DIR and the $SERVICE_USER user"
    else
        say "Kept $CONFIG_DIR and $STATE_DIR (add --purge to remove them)"
    fi
}

main() {
    parse_args "$@"
    require_root
    detect_init

    # Nothing below may read what is left of a script that is piped into sh.
    exec </dev/null

    if [ "$UNINSTALL" = 1 ]; then
        uninstall

        return 0
    fi

    if [ "$INIT" = none ]; then
        if [ "$NO_START" = 1 ]; then
            fail "no supported init system found (systemd or OpenRC). Pass --init systemd or --init openrc to install its service file anyway."
        fi

        fail "no supported init system found (systemd or OpenRC). Pass --init to force one."
    fi

    detect_target
    find_script_dir
    setup_terminal

    TMP=$(mktemp -d)
    trap cleanup EXIT
    trap 'exit 1' INT TERM HUP

    fetch_binary
    stage_binary
    stage_config
    check_config
    read_dns_target

    if [ "$NO_START" != 1 ]; then
        ensure_port_53_free
    fi

    ensure_service_user
    migrate_dynamic_state
    lock_updates
    backup_previous
    install_config
    secure_config_files
    install_service
    install_binary

    if [ "$NO_START" != 1 ]; then
        start_and_verify
    fi

    report
    INSTALL_DONE=1
}

main "$@"

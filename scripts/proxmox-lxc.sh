#!/usr/bin/env bash
# Create an unprivileged Alpine LXC on a Proxmox VE host and install picoguard in it.
# Run it as root on the Proxmox host. `bash proxmox-lxc.sh --help` lists the options.
set -euo pipefail

REPO=risan/picoguard
BASE_URL=${PICOGUARD_BASE_URL:-https://github.com/$REPO/releases}
STAGING_DIR=/root/picoguard-install

CTID=
HOSTNAME_CT=
CORES=
MEMORY=
SWAP=
DISK=
STORAGE=
TEMPLATE_STORAGE=
BRIDGE=
IP=
GATEWAY=
NAMESERVER=
BINARY_FILE=
VERSION=latest
UPSTREAM=
UPSTREAM_URLS=()
LISTS=
ROUTER=
WEB_PORT=
ASSUME_YES=0
DRY_RUN=0
HAVE_TTY=0
TMP=
SCRIPT_DIR=
CONTAINER_CREATED=0

usage() {
    cat <<'EOF'
Usage: bash proxmox-lxc.sh [options]

Creates an unprivileged Alpine LXC container on this Proxmox VE host, installs picoguard
in it with install.sh, and prints the address of the status page. Run it as root on the host.
A few questions come first; --yes takes the default for every question. Every question has a flag.

Container:
  --ctid ID              Container ID (default: the next free ID). An existing ID is refused.
  --hostname NAME        Default: picoguard.
  --cores N              Default: 1.
  --memory MB            Default: 128.
  --swap MB              Default: 0.
  --disk GB              Default: 1.
  --storage NAME         Storage for the root disk (default: local-lvm, else the first rootdir storage).
  --template-storage N   Storage for the Alpine template (default: local).
  --bridge NAME          Default: vmbr0.
  --ip CIDR|dhcp         For example 192.168.1.50/24. Default: dhcp. A fixed address is better:
                         this container becomes the DNS server of your network.
  --gateway IP           Gateway for a fixed address (default: the host's gateway).
  --nameserver IP        DNS server of the container itself (default: the host's).

picoguard (passed on to install.sh):
  --binary FILE          Use this binary, unchecked (install.sh gets it with --binary). Otherwise a
                         picoguard-<target> file next to this script (SHA256SUMS must be there too)
                         or the downloaded release is used. A downloaded install.sh is always checked.
  --version vX.Y.Z       Release to download (default: latest).
  --upstream NAME        cloudflare-quad9 (default), cloudflare, quad9, adguard.
  --upstream-url URL     Your own upstream server; repeat for several.
  --lists NAME           default (AdGuard DNS filter + HaGeZi Pro + TIF mini, about 12 MB).
                         large and xlarge need more memory than the 128 MB default.
  --router IP|none       Router for local names (default: the container's gateway).
  --web-port PORT        Status page port (default: 8080).

Other:
  -y, --yes              Take the default for every question.
  --dry-run              Run only commands that read; print every command that would change
                         something (pveam update/download, pct create/start/push/exec).
  -h, --help             Show this help.

The status page gets a random password; it is printed at the end. Change it in
/etc/picoguard/picoguard.toml inside the container.
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

cleanup() {
    local status=$?

    if [ -n "$TMP" ]; then
        rm -rf "$TMP"
    fi

    if [ "$status" -ne 0 ] && [ "$CONTAINER_CREATED" = 1 ]; then
        printf 'The container %s was created and still exists, without a working picoguard.\n' "$CTID" >&2
        printf 'Remove it with: pct stop %s; pct destroy %s\n' "$CTID" "$CTID" >&2
    fi
}

# Runs a command that changes something; with --dry-run it only prints it.
run() {
    if [ "$DRY_RUN" = 1 ]; then
        printf '+'
        printf ' %q' "$@"
        printf '\n'

        return 0
    fi

    "$@"
}

need_value() {
    if [ "$1" -lt 2 ]; then
        fail "$2 needs a value (see --help)"
    fi
}

parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            --ctid)
                need_value $# "$1"
                CTID=$2
                shift 2
                ;;
            --hostname)
                need_value $# "$1"
                HOSTNAME_CT=$2
                shift 2
                ;;
            --cores)
                need_value $# "$1"
                CORES=$2
                shift 2
                ;;
            --memory)
                need_value $# "$1"
                MEMORY=$2
                shift 2
                ;;
            --swap)
                need_value $# "$1"
                SWAP=$2
                shift 2
                ;;
            --disk)
                need_value $# "$1"
                DISK=$2
                shift 2
                ;;
            --storage)
                need_value $# "$1"
                STORAGE=$2
                shift 2
                ;;
            --template-storage)
                need_value $# "$1"
                TEMPLATE_STORAGE=$2
                shift 2
                ;;
            --bridge)
                need_value $# "$1"
                BRIDGE=$2
                shift 2
                ;;
            --ip)
                need_value $# "$1"
                IP=$2
                shift 2
                ;;
            --gateway)
                need_value $# "$1"
                GATEWAY=$2
                shift 2
                ;;
            --nameserver)
                need_value $# "$1"
                NAMESERVER=$2
                shift 2
                ;;
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
            --upstream)
                need_value $# "$1"
                UPSTREAM=$2
                shift 2
                ;;
            --upstream-url)
                need_value $# "$1"
                UPSTREAM_URLS+=("$2")
                shift 2
                ;;
            --lists)
                need_value $# "$1"
                LISTS=$2
                shift 2
                ;;
            --router)
                need_value $# "$1"
                ROUTER=$2
                shift 2
                ;;
            --web-port)
                need_value $# "$1"
                WEB_PORT=$2
                shift 2
                ;;
            -y|--yes)
                ASSUME_YES=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
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
        *)
            VERSION=v$VERSION
            ;;
    esac
}

# prompt VARIABLE "Question" DEFAULT: keeps a value that a flag already set.
prompt() {
    local name=$1 question=$2 default=$3 answer=

    if [ -n "${!name}" ]; then
        return 0
    fi

    if [ "$ASSUME_YES" = 1 ]; then
        printf -v "$name" '%s' "$default"

        return 0
    fi

    if [ "$HAVE_TTY" != 1 ]; then
        fail "cannot ask '$question' without a terminal. Give the matching flag, or use --yes."
    fi

    printf '%s [%s]: ' "$question" "$default" >/dev/tty
    IFS= read -r answer </dev/tty || answer=
    printf -v "$name" '%s' "${answer:-$default}"
}

tell() {
    if [ "$ASSUME_YES" != 1 ] && [ "$HAVE_TTY" = 1 ]; then
        printf '%s\n' "$*" >/dev/tty
    fi
}

check_host() {
    if [ "$(id -u)" != 0 ]; then
        fail "run this script as root on the Proxmox host"
    fi

    local tool

    for tool in pct pveam pvesh pvesm; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fail "$tool not found. This script must run on a Proxmox VE host."
        fi
    done

    if ( : </dev/tty ) 2>/dev/null; then
        HAVE_TTY=1
    fi
}

is_number() {
    [[ $1 =~ ^[0-9]+$ ]]
}

default_storage() {
    local content=$1 preferred=$2 names

    names=$(pvesm status --content "$content" 2>/dev/null | awk 'NR > 1 && $3 == "active" { print $1 }')

    if grep -qx "$preferred" <<<"$names"; then
        printf '%s' "$preferred"
    else
        head -n 1 <<<"$names"
    fi
}

host_nameserver() {
    awk '$1 == "nameserver" && $2 !~ /^127\./ { print $2; exit }' /etc/resolv.conf 2>/dev/null || true
}

host_gateway() {
    ip -4 route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) { if ($i == "via") { print $(i + 1); exit } } }'
}

container_exists() {
    pct status "$1" >/dev/null 2>&1 || ! pvesh get /cluster/nextid --vmid "$1" >/dev/null 2>&1
}

ask_container_settings() {
    local next

    if [ -z "$CTID" ]; then
        next=$(pvesh get /cluster/nextid | tr -d '"[:space:]')
        prompt CTID "Container ID" "$next"
    fi

    if ! is_number "$CTID"; then
        fail "container ID must be a number: $CTID"
    fi

    if container_exists "$CTID"; then
        fail "container (or VM) $CTID already exists. Pick another ID; this script never touches an existing one."
    fi

    prompt HOSTNAME_CT "Hostname" picoguard
    prompt CORES "CPU cores" 1
    prompt MEMORY "Memory in MB" 128
    prompt SWAP "Swap in MB" 0
    prompt DISK "Disk in GB" 1
    prompt STORAGE "Storage for the root disk" "$(default_storage rootdir local-lvm)"
    prompt TEMPLATE_STORAGE "Storage for the Alpine template" "$(default_storage vztmpl local)"
    prompt BRIDGE "Network bridge" vmbr0

    tell ""
    tell "This container becomes the DNS server of your network. A fixed address is much safer"
    tell "than DHCP: if the address changes, the whole network loses DNS."
    prompt IP "IPv4 address as CIDR (for example 192.168.1.50/24) or 'dhcp'" dhcp

    if [ "$IP" != dhcp ]; then
        if [[ ! $IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            fail "--ip must look like 192.168.1.50/24, or be 'dhcp': $IP"
        fi

        prompt GATEWAY "Gateway" "$(host_gateway)"
    else
        warn "DHCP: reserve this container's address in your router, or the DNS server may move."
    fi

    prompt NAMESERVER "DNS server for the container itself" "$(host_nameserver || true)"

    local name

    for name in CORES MEMORY SWAP DISK; do
        if ! is_number "${!name}"; then
            fail "$name must be a number: ${!name}"
        fi
    done

    if [[ ! $HOSTNAME_CT =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]]; then
        fail "invalid hostname: $HOSTNAME_CT"
    fi

    if [ -z "$STORAGE" ] || [ -z "$TEMPLATE_STORAGE" ]; then
        fail "no storage found for the root disk or the template. Pass --storage and --template-storage."
    fi

    if [ -z "$NAMESERVER" ]; then
        NAMESERVER=1.1.1.1
    fi
}

ask_picoguard_settings() {
    tell ""
    tell "picoguard"
    tell "  upstream: cloudflare-quad9 (default), cloudflare, quad9, adguard"

    if [ "${#UPSTREAM_URLS[@]}" -eq 0 ]; then
        prompt UPSTREAM "Upstream DNS" cloudflare-quad9
    fi

    tell "  lists: default (AdGuard DNS filter + HaGeZi Pro + TIF mini), large, xlarge (need more memory)"
    prompt LISTS "Blocklists" default
    prompt WEB_PORT "Status page port" 8080

    # Check everything install.sh will check, before a container exists.
    local url

    if [ "${#UPSTREAM_URLS[@]}" -eq 0 ]; then
        case $UPSTREAM in
            cloudflare-quad9|cloudflare|quad9|adguard) ;;
            *) fail "unknown upstream '$UPSTREAM' (cloudflare-quad9, cloudflare, quad9, adguard)" ;;
        esac
    fi

    for url in "${UPSTREAM_URLS[@]}"; do
        if [[ ! $url =~ ^(https|tls|udp|tcp):// ]]; then
            fail "upstream URL must start with https://, tls://, udp:// or tcp://: $url"
        fi
    done

    case $LISTS in
        default) ;;
        large)
            if [ "$MEMORY" -lt 384 ]; then
                warn "the 'large' lists are meant for 384 MB or more; this container gets $MEMORY MB (--memory)"
            fi
            ;;
        xlarge)
            if [ "$MEMORY" -lt 768 ]; then
                warn "the 'xlarge' lists are meant for 768 MB or more; this container gets $MEMORY MB (--memory)"
            fi
            ;;
        *) fail "unknown lists '$LISTS' (default, large, xlarge)" ;;
    esac

    if ! is_number "$WEB_PORT" || [ "$WEB_PORT" -lt 1 ] || [ "$WEB_PORT" -gt 65535 ]; then
        fail "status page port must be a number from 1 to 65535: $WEB_PORT"
    fi

    if [ -n "$ROUTER" ] && [ "$ROUTER" != none ] && [[ ! $ROUTER =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        fail "router must be an IPv4 address or 'none': $ROUTER"
    fi
}

target_for_host() {
    case $(uname -m) in
        x86_64) printf 'x86_64-unknown-linux-musl' ;;
        aarch64) printf 'aarch64-unknown-linux-musl' ;;
        *)
            fail "unsupported host CPU $(uname -m)
            Proxmox VE runs on x86_64 or aarch64"
            ;;
    esac
}

release_url() {
    if [ "$VERSION" = latest ]; then
        printf '%s/latest/download/%s' "$BASE_URL" "$1"
    else
        printf '%s/download/%s/%s' "$BASE_URL" "$VERSION" "$1"
    fi
}

fetch() {
    local name=$1 url code

    url=$(release_url "$name")
    say "Downloading $url"

    if [ "$DRY_RUN" = 1 ]; then
        say "(dry run: not downloaded)"

        return 0
    fi

    if command -v curl >/dev/null 2>&1; then
        code=$(curl -sSL -o "$TMP/$name" -w '%{http_code}' "$url" || true)
        if [ "$code" = 200 ]; then
            return 0
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q -O "$TMP/$name" "$url"; then
            return 0
        fi
    else
        fail "need curl or wget to download picoguard (or pass --binary and use install.sh next to this script)"
    fi

    {
        printf 'error: could not download %s\n' "$url"
        printf 'Check that the version exists: %s\n' "$BASE_URL"
        printf 'To download the files by hand, then run this script from that folder:\n\n'
        printf '  curl -fsSLO %s\n' "$(release_url "picoguard-$(target_for_host)")"
        printf '  curl -fsSLO %s\n' "$(release_url SHA256SUMS)"
        printf '  curl -fsSLO %s\n' "$(release_url install.sh)"
        printf '  curl -fsSLO %s\n' "$(release_url proxmox-lxc.sh)"
        printf '  bash proxmox-lxc.sh\n'
    } >&2

    exit 1
}

verify_checksum() {
    local file=$1 sums=$2 name=$3 expected actual

    expected=$(awk -v name="$name" '{ n = $2; sub(/^\*/, "", n); if (n == name) { print $1; exit } }' "$sums")

    if [ -z "$expected" ]; then
        fail "SHA256SUMS has no entry for $name"
    fi

    actual=$(sha256sum "$file" | awk '{ print $1 }')

    if [ "$expected" != "$actual" ]; then
        fail "checksum mismatch for $name (expected $expected, got $actual). Not installing."
    fi
}

# Sets BINARY_PATH, SUMS_PATH (may stay empty) and INSTALLER_PATH.
gather_files() {
    local target asset

    target=$(target_for_host)
    asset=picoguard-$target
    BINARY_PATH=
    SUMS_PATH=
    INSTALLER_PATH=

    if [ -n "$BINARY_FILE" ]; then
        if [ ! -f "$BINARY_FILE" ]; then
            fail "--binary: $BINARY_FILE is not a file"
        fi

        BINARY_PATH=$BINARY_FILE
        say "Using $BINARY_PATH (not checked against SHA256SUMS)"
    elif [ -f "$SCRIPT_DIR/$asset" ]; then
        BINARY_PATH=$SCRIPT_DIR/$asset

        if [ ! -f "$SCRIPT_DIR/SHA256SUMS" ]; then
            fail "found $BINARY_PATH but no SHA256SUMS next to it. Download SHA256SUMS from the same release, or pass --binary FILE to skip the check."
        fi

        SUMS_PATH=$SCRIPT_DIR/SHA256SUMS
        verify_checksum "$BINARY_PATH" "$SUMS_PATH" "$asset"
        say "Using $BINARY_PATH (checksum OK)"
    else
        fetch "$asset"
        fetch SHA256SUMS
        BINARY_PATH=$TMP/$asset
        SUMS_PATH=$TMP/SHA256SUMS

        if [ "$DRY_RUN" != 1 ]; then
            verify_checksum "$BINARY_PATH" "$SUMS_PATH" "$asset"
            say "Checksum OK"
        fi
    fi

    if [ -f "$SCRIPT_DIR/install.sh" ]; then
        INSTALLER_PATH=$SCRIPT_DIR/install.sh

        # Release files downloaded together carry a manifest that lists install.sh; a
        # checkout of the repository has none, and its install.sh is the user's own file.
        if [ -f "$SCRIPT_DIR/SHA256SUMS" ] && awk '{ n = $2; sub(/^\*/, "", n); if (n == "install.sh") { found = 1 } } END { exit !found }' "$SCRIPT_DIR/SHA256SUMS"; then
            verify_checksum "$INSTALLER_PATH" "$SCRIPT_DIR/SHA256SUMS" install.sh
            say "install.sh: checksum OK"
        fi
    else
        fetch install.sh
        INSTALLER_PATH=$TMP/install.sh

        # It runs as root in the container, so a downloaded copy is always checked against
        # the manifest of the same release, even when the binary comes from --binary.
        if [ ! -f "$TMP/SHA256SUMS" ]; then
            fetch SHA256SUMS
        fi

        if [ "$DRY_RUN" != 1 ]; then
            verify_checksum "$INSTALLER_PATH" "$TMP/SHA256SUMS" install.sh
            say "install.sh: checksum OK"
        fi
    fi

    BINARY_ASSET=$asset
}

find_template() {
    local arch

    arch=$(dpkg --print-architecture 2>/dev/null || echo amd64)
    pveam available --section system 2>/dev/null |
        awk -v arch="$arch" '$2 ~ /^alpine-3\.[0-9]+-default_/ && index($2, "_" arch ".tar") { print $2 }' |
        sort -V | tail -n 1
}

ensure_template() {
    TEMPLATE=$(find_template)

    if [ -z "$TEMPLATE" ]; then
        say "No Alpine template in the list; updating it"
        run pveam update
        TEMPLATE=$(find_template)
    fi

    if [ -z "$TEMPLATE" ]; then
        fail "no alpine-3.* template found in 'pveam available --section system'"
    fi

    if pveam list "$TEMPLATE_STORAGE" 2>/dev/null | grep -q "$TEMPLATE"; then
        say "Template $TEMPLATE is on $TEMPLATE_STORAGE"
    else
        say "Downloading template $TEMPLATE to $TEMPLATE_STORAGE"
        run pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
    fi
}

create_container() {
    local net="name=eth0,bridge=$BRIDGE"

    if [ "$IP" = dhcp ]; then
        net+=",ip=dhcp"
    else
        net+=",ip=$IP,gw=$GATEWAY"
    fi

    say "Creating container $CTID ($HOSTNAME_CT)"
    run pct create "$CTID" "$TEMPLATE_STORAGE:vztmpl/$TEMPLATE" \
        --hostname "$HOSTNAME_CT" \
        --ostype alpine \
        --unprivileged 1 \
        --cores "$CORES" \
        --memory "$MEMORY" \
        --swap "$SWAP" \
        --rootfs "$STORAGE:$DISK" \
        --net0 "$net" \
        --nameserver "$NAMESERVER" \
        --onboot 1 \
        --tags picoguard
    if [ "$DRY_RUN" != 1 ]; then
        CONTAINER_CREATED=1
    fi

    run pct start "$CTID"
}

container_address() {
    pct exec "$CTID" -- ip -4 -o addr show dev eth0 2>/dev/null | awk '{ split($4, a, "/"); print a[1]; exit }'
}

wait_for_network() {
    local waited=0

    if [ "$DRY_RUN" = 1 ]; then
        return 0
    fi

    while [ "$waited" -lt 60 ]; do
        if [ -n "$(container_address || true)" ]; then
            return 0
        fi

        sleep 1
        waited=$((waited + 1))
    done

    fail "container $CTID got no IPv4 address in 60 seconds. Check the bridge and the address settings."
}

install_in_container() {
    local args=(--yes --web-port "$WEB_PORT" --lists "$LISTS")
    local url

    if [ -n "$BINARY_FILE" ]; then
        args+=(--binary "$STAGING_DIR/$BINARY_ASSET")
    fi

    if [ "${#UPSTREAM_URLS[@]}" -gt 0 ]; then
        for url in "${UPSTREAM_URLS[@]}"; do
            args+=(--upstream-url "$url")
        done
    else
        args+=(--upstream "$UPSTREAM")
    fi

    if [ -n "$ROUTER" ]; then
        args+=(--router "$ROUTER")
    fi

    say "Copying picoguard into the container"
    run pct exec "$CTID" -- mkdir -p "$STAGING_DIR"
    run pct push "$CTID" "$BINARY_PATH" "$STAGING_DIR/$BINARY_ASSET" --perms 0755
    run pct push "$CTID" "$INSTALLER_PATH" "$STAGING_DIR/install.sh" --perms 0755

    if [ -n "$SUMS_PATH" ]; then
        run pct push "$CTID" "$SUMS_PATH" "$STAGING_DIR/SHA256SUMS"
    fi

    say "Running install.sh in the container"

    if [ "$DRY_RUN" = 1 ]; then
        run pct exec "$CTID" -- sh "$STAGING_DIR/install.sh" "${args[@]}"
        run pct exec "$CTID" -- rm -rf "$STAGING_DIR"

        return 0
    fi

    INSTALL_LOG=$TMP/install.log

    if ! pct exec "$CTID" -- sh "$STAGING_DIR/install.sh" "${args[@]}" 2>&1 | tee "$INSTALL_LOG"; then
        fail "install.sh failed in container $CTID (see above)."
    fi

    pct exec "$CTID" -- rm -rf "$STAGING_DIR"
}

report() {
    local address password

    if [ "$DRY_RUN" = 1 ]; then
        address='<container address>'
        password='<random password>'
    else
        address=$(container_address || true)
        password=$(sed -n 's/^  password: //p' "$INSTALL_LOG" | head -n 1)
    fi

    say ""
    say "picoguard runs in container $CTID ($HOSTNAME_CT)."
    say "  Container address:  $address"
    say "  Status page:        http://$address:$WEB_PORT/"

    if [ -n "$password" ]; then
        say "  Login:              admin / $password   (shown once)"
    fi

    say ""
    say "Next: set $address as the DNS server in your router (DHCP settings)."

    if [ "$IP" = dhcp ]; then
        say "The container uses DHCP: give it a fixed address in your router first."
    fi
}

main() {
    parse_args "$@"
    check_host

    # pct would otherwise read the rest of a script that is piped into bash.
    exec </dev/null

    TMP=$(mktemp -d)
    trap cleanup EXIT

    case $0 in
        */*) SCRIPT_DIR=${0%/*} ;;
        *)
            SCRIPT_DIR=.
            ;;
    esac

    if [ ! -f "$0" ]; then
        SCRIPT_DIR=/nonexistent
    fi

    if [ "$DRY_RUN" = 1 ]; then
        say "Dry run: commands that change something are printed, not run."
    fi

    ask_container_settings
    ask_picoguard_settings
    gather_files
    ensure_template
    create_container
    wait_for_network
    install_in_container
    report
}

main "$@"

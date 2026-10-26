# Install picoguard

picoguard is one static program. It needs no other packages. Pick the path that fits your setup.
Each one starts with a quick path of a few commands.

| You have | Path |
|---|---|
| A board (TV box, Orange Pi, Raspberry Pi) or any Linux machine or VM, with systemd or OpenRC | [install.sh](#install-on-a-board-or-vm-with-installsh) |
| A Proxmox VE host | [proxmox-lxc.sh](#install-in-a-proxmox-lxc) |
| A machine that already runs Docker | [Docker](#run-in-docker) |

Part 1 gets a board ready. Part 2 installs picoguard. Part 3 points your network at it. Part 4 makes
the SD card last. Part 5 is for when something goes wrong.

On a 256 MB board, use `install.sh`, not Docker: Docker's own daemon costs tens of MB of RAM.

Release files are named `picoguard-<target>`. Not sure which one fits? Run `uname -m` on the device.
`install.sh` picks the right one by itself.

| Your device | CPU | `uname -m` says | Binary |
|---|---|---|---|
| Used TV box (ZTE B860H, Fiberhome HG680P) with Armbian | ARM64 | `aarch64` | `picoguard-aarch64-unknown-linux-musl` |
| Orange Pi Zero or Zero LTS with Armbian | ARMv7 | `armv7l` | `picoguard-armv7-unknown-linux-musleabihf` |
| Proxmox LXC or any x86_64 Linux | x86_64 | `x86_64` | `picoguard-x86_64-unknown-linux-musl` |

ARMv6 boards (Raspberry Pi 1 and Zero) are not supported.

## 1. Prepare the device

### Used Amlogic TV box (ZTE B860H, Fiberhome HG680P)

These boxes are cheap and common. They have an ARM64 CPU (Amlogic S905X), 1 to 2 GB of RAM and
Ethernet. They do not run Armbian from the factory. You install it from the
[ophub/amlogic-s9xxx-armbian](https://github.com/ophub/amlogic-s9xxx-armbian) project.

**Warning: these images are unofficial.** They are not made by Armbian or by the box maker.
A stranger builds them, and you run them as root on your home network. Download them only from the
project page, read its notes for your model, and do not put anything private on the box. Quality
differs between box versions: some images fail to boot on some boxes. Keep the original firmware
backup if the project tells you to.

Short version:

1. Download the image for your box from the ophub project. Read its README for the right image and
   device settings for your model (ZTE B860H V1 and V2 differ).
2. Write the image to a microSD card (8 GB is enough, 16 GB is nice) with balenaEtcher or
   Raspberry Pi Imager.
3. Put the card in the box, connect Ethernet, power on. The box boots from the card.
4. Log in over SSH. Find the box's address in your router's device list.
5. You can stay on the SD card. Installing to the box's internal eMMC is possible
   (`armbian-install`) and the card then does not wear out. Follow the project's steps.

Check the CPU: `uname -m` must say `aarch64`.

### Orange Pi Zero or Zero LTS

The Zero and the Zero LTS have an Allwinner H2+ (some shops say H3). It is a 32-bit ARMv7 CPU.
Both work the same for picoguard.

1. Download the Armbian image for your board from [armbian.com/orange-pi-zero](https://www.armbian.com/orange-pi-zero/).
   Pick the Debian "minimal" or "server" image, not a desktop image.
2. Write it to a microSD card (8 GB is enough) with balenaEtcher.
3. Connect Ethernet and power (5 V, 1 A or more), and power on.
4. Find the address in your router and log in over SSH. The first login asks you to set a password
   and create a user.

Check the CPU: `uname -m` must say `armv7l`.

### x86_64 Linux or a Proxmox LXC

Use any Linux with systemd (Debian, Ubuntu) or OpenRC (Alpine). On Proxmox, the
[script below](#install-in-a-proxmox-lxc) creates the container for you.

Check the CPU: `uname -m` must say `x86_64`.

## 2. Install picoguard

### Install on a board or VM with install.sh

`scripts/install.sh` does everything in "Manual install" below for you: it picks the binary for
your CPU, checks its checksum, asks four questions, writes the config, frees port 53, installs the
service (systemd or OpenRC) and starts it. Run it as root on the device.

One line downloads the installer, which downloads the binary and checks it:

```sh
curl -fsSL https://github.com/risan/picoguard/releases/latest/download/install.sh | sudo sh
```

To read the script before you run it, download it first. Run it on the device, or on another
computer and copy it over:

```sh
curl -fsSLO https://github.com/risan/picoguard/releases/latest/download/install.sh
sudo sh install.sh
```

Without internet on the device, download `install.sh`, `SHA256SUMS` and the `picoguard-<target>`
file for your CPU (the table at the top) from the
[releases page](https://github.com/risan/picoguard/releases), copy the three files to one
folder on the device and run `sudo sh install.sh` there. `install.sh` uses the
`picoguard-<target>` file next to it and checks it with `SHA256SUMS`, which must be there too.

The four questions (press Enter for the default; every question also has a flag, see
`sh install.sh --help`):

1. **Upstream DNS.** Cloudflare and Quad9 over DoH (default), Cloudflare only, Quad9 only,
   AdGuard DNS unfiltered, or your own URLs.
2. **Blocklists.** The menu shows your RAM. The default is the AdGuard DNS filter plus HaGeZi Pro
   and TIF mini (about 12 MB, fits a 256 MB board). The other rows are the bigger boards of
   [Choose lists for your board](configuration.md#choose-lists-for-your-board).
3. **Router.** Its address (default: this device's gateway) goes into the `[local]` section, so
   names and reverse lookups of your own devices keep working.
4. **Status page.** The port (8080) and a password for the user `admin`. Press Enter and the
   script makes a random 16-character password and shows it once at the end. Type your own, or
   `none` for no password.

`--yes` takes every default and asks nothing (good for scripts).

What the script does about **port 53**: if the systemd-resolved stub listener holds it, the script
offers the fix from "Free port 53" below and applies it when you agree (`--yes` agrees). It saves
what `/etc/resolv.conf` was first, and `--uninstall` puts that back, unless you changed the file
since. If anything else holds the port (AdGuard Home, dnsmasq, Pi-hole, unbound), the script names
the process and its unit, prints what to do, and stops. It never stops another DNS server itself.

When it is done, the script runs a test lookup and prints the device address and the status page
URL. Next, [point your network at picoguard](#3-point-your-network-at-picoguard).

Good to know:

- The service runs as the system user `picoguard`. The config is
  `/etc/picoguard/picoguard.toml`, owned by `root:picoguard` with mode `0640`, because it can hold
  the status page password.
- When you upgrade, the script keeps the previous binary, unit, config and memory drop-in. If the
  restart fails, or the new version does not answer a test lookup, it puts them back, restarts the
  old version and says so. The test lookup goes to an address from `[server] bind` that the device
  can reach (`127.0.0.1` for `0.0.0.0`, `::1` when only IPv6 is bound).
- The xlarge lists (HaGeZi Ultimate and the full TIF) get `max_rules = 3000000` in the config and,
  on systemd, a drop-in `/etc/systemd/system/picoguard.service.d/memory.conf` with `MemoryMax=192M`.
  The script only creates, replaces or removes that drop-in while its first line is
  `# Written by install.sh for the xlarge lists.`. A `memory.conf` of your own is left alone, and
  the script warns when the xlarge lists need a higher limit than it sets.
- If an install fails after the systemd-resolved change, the change is undone.
- An existing config is never overwritten. `--reconfigure` asks the questions again and saves the
  old file as `picoguard.toml.bak.<time>` first.
- `--no-start` installs everything and starts nothing.
- `--binary FILE` installs a binary you built yourself, without a checksum check. `--version vX.Y.Z` picks a release.
- `sh install.sh --uninstall` removes the binary, the service and the systemd-resolved change. It
  keeps a `memory.conf` that it did not write.
  It keeps `/etc/picoguard` and `/var/lib/picoguard` unless you add `--purge`.

### Install in a Proxmox LXC

`scripts/proxmox-lxc.sh` runs on the Proxmox VE host, as root. It creates an unprivileged Alpine
container (1 core, 128 MB RAM, 1 GB disk, start at boot), copies the binary and `install.sh` into
it and runs `install.sh` there. It never touches another container, and it refuses a container ID
that exists.

```sh
curl -fsSL https://github.com/risan/picoguard/releases/latest/download/proxmox-lxc.sh | bash
```

The questions have defaults: the next free container ID, hostname `picoguard`, the root disk on
`local-lvm`, the template on `local`, bridge `vmbr0`, and DHCP. **Give the container a fixed
address instead** (for example `--ip 192.168.1.53/24 --gateway 192.168.1.1`): it becomes the DNS
server of your whole network, so its address must not change. At the end the script prints the
container address, the status page URL and the generated password.

`--yes` takes all defaults, and `--dry-run` shows every `pct` and `pveam` command that would
change something, without running it. `bash proxmox-lxc.sh --help` lists all flags.

The script checks the binary and a downloaded `install.sh` against `SHA256SUMS` and stops when a
checksum is missing or wrong. `--binary FILE` installs a binary you built yourself without a
checksum check; a downloaded `install.sh` is still checked. If the install inside the container
fails, the script leaves the container in place and prints its ID and the `pct stop` and
`pct destroy` commands that remove it.

The container is Alpine with OpenRC, so no systemd sandbox is involved. To update picoguard later,
click the **Update** button on the status page when a newer release exists, or see "Update
picoguard" below.

### Run in Docker

The image is built from source: a static musl binary in an image with nothing else in it, running
as a non-root user. You need the repository.

```sh
git clone https://github.com/risan/picoguard && cd picoguard
cp dist/picoguard.docker.toml picoguard.toml
docker compose up -d --build
```

- Edit `picoguard.toml` for your upstreams, lists and router, then `docker compose restart`.
  It is mounted read-only. The list copies live in the volume `picoguard-state`.
- The container publishes 53/udp, 53/tcp and 8080. Port 53 must be free on the host (see "Free
  port 53" below if systemd-resolved holds it).
- `compose.yaml` runs it with a read-only root file system, no capabilities, `no-new-privileges`
  and a 64 MB memory limit. A non-root user can open port 53 in the container because Docker sets
  `net.ipv4.ip_unprivileged_port_start=0` there.
- The ports are published on IPv4 only (`PICOGUARD_BIND=192.168.1.53 docker compose up -d`
  picks one address). Docker's proxy turns a connection that arrives over IPv6 into one from a
  private bridge address, and picoguard would then let it in. Set `web.user` and `web.password` in
  `picoguard.toml` too.
- The image builds on x86_64 and ARM64. On an ARMv7 board, use `install.sh`.
- Host networking (`network_mode: host`) is the alternative: no NAT, and picoguard sees the real
  address of each client. See the comment in `compose.yaml`.
- Docker's own daemon costs tens of MB of RAM. On a 256 MB board, use `install.sh` instead.

### Update picoguard

#### From the status page

When a newer release exists, the status page says "update available". If you are signed in (set
`web.user` and `web.password`), it also shows a button, **Update to vX.Y.Z**. The button needs a
release binary that `install.sh` installed: `install.sh` also sets up the root program that
installs the update ("the installer" below). A manual install, a Docker image and a build from
source show the command to run instead.

What one click does:

1. picoguard downloads the release binary, `SHA256SUMS` and `SHA256SUMS.sig` from GitHub into
   `/var/lib/picoguard/update/`, through your configured upstream servers.
2. It checks the signature of `SHA256SUMS` against the release key built into the program, and the
   binary against its hash there.
3. The installer, which runs as root, copies the staged files out of that folder (picoguard can
   write there, so nothing in it is trusted), checks all of it again, and runs
   `picoguard --check` of the new version on your config. Anything wrong ends the update here with
   nothing installed.
4. It keeps a copy of the current binary, puts the new one at `/usr/local/bin/picoguard` in one
   step (the file is always the whole old or the whole new binary) and restarts the service.
5. Within 30 seconds the old, trusted binary asks picoguard for `example.com` at the address in
   `[server] bind` (`picoguard dns-check`). A reply of `NOERROR` or `NXDOMAIN` keeps the new
   version. Otherwise the installer puts the previous binary back, restarts it and asks again.

The page shows how it ended:

| The page says | What happened |
|---|---|
| Updated to vX.Y.Z | The new version answers. |
| Rolled back: *reason* | The new version did not start or did not answer within 30 seconds; the reason says which, and whether the previous version answers again. |
| Update failed: *reason* | Nothing was installed. The reason names the step: the signature, the hash, the version, your config with the new version, a disk error, or "the installer did not answer within 10 minutes". |

If the installer is stopped part way (killed, or the power fails), its next run (at boot, or when
you start it) finishes the update first: it keeps the new version when it answers and puts the old
one back when it does not, or reports that it was interrupted when nothing had been installed yet.

What is on the device for this (`install.sh` writes and replaces all of it):

| Path | What |
|---|---|
| `/usr/local/lib/picoguard/update` and `common.sh` | The installer and the shell functions it shares with `install.sh`. Owned by root. |
| `/etc/systemd/system/picoguard-update.path` and `.service` | systemd: the path unit starts the installer when `/var/lib/picoguard/update/request` changes, and the service runs once at boot. |
| `/etc/init.d/picoguard-update` | OpenRC: a root service that looks for a request every 5 seconds (two small processes, under 1 MB of memory together, and no disk writes while idle). |
| `/var/lib/picoguard-update/` | Its lock, the answer (`result`), and while an update runs its record, the previous binary and the verified copy. Owned by root; picoguard cannot write or even open anything in it but `result`. |

The service file of picoguard itself does not change: it still cannot write its binary, `/etc` or
the installer's folder.

Good to know:

- **Disk writes.** One update writes about four copies of the binary (about 4 MB each): the staged
  file, the verified copy, the backup of the old one and the new one at `/usr/local/bin`. The
  extra files are gone when it ends. On an SD card that is nothing next to the list downloads.
- **Only the binary changes.** A page update replaces `/usr/local/bin/picoguard`. The installer,
  its units, the service file and your config change only when you run `install.sh`.
- **`state.dir` must stay `/var/lib/picoguard`.** The installer watches that fixed path. With
  another `state.dir` the page waits 10 minutes and ends with "the installer did not answer".
- **`allow_from` must let the device ask itself.** The check asks from the device. The default
  covers `127.0.0.0/8` and `::1`. If you narrowed `server.allow_from` so that the device's own
  address is out, every update ends rolled back.
- **Turn it off.** `[update] check = false` in the config: no daily check, so no "update
  available" and no button. To also remove the trigger: on systemd,
  `systemctl disable --now picoguard-update.path picoguard-update.service`; on OpenRC,
  `rc-service picoguard-update stop && rc-update del picoguard-update`. `install.sh` brings the
  trigger back the next time you run it, and `install.sh --uninstall` removes it.
- `install.sh` and the installer never change the binary at the same moment: `install.sh` waits
  up to 5 minutes for an update that is running, and an update that starts while `install.sh`
  runs waits until it ends.

#### With install.sh

Run `install.sh` again. It downloads the latest release (or uses the files next to it), replaces
the binary, keeps your config and restarts the service:

```sh
curl -fsSL https://github.com/risan/picoguard/releases/latest/download/install.sh | sudo sh
```

The script checks your config against the new binary first and stops if it does not accept it.
In a Proxmox container, run `pct push` for the new files and `pct exec` for `install.sh --yes`,
or enter the container with `pct enter` and run the commands above. For Docker:
`git pull && docker compose up -d --build`.

### Manual install

These are the steps that `install.sh` automates. Use them when you want to see each one, or when
your system has neither systemd nor OpenRC. Run them as root (`sudo -i`) on the device.

A manual install has no **Update** button: the page offers it only when the installer of "Update
picoguard" is set up as well, and these steps do not set it up. Run `install.sh` once over it to
get the button, or update by hand.

#### Download and check the binary

`SHA256SUMS` lists the checksums of the release files. Replace `TARGET` with the name from the table at the top (for example `aarch64-unknown-linux-musl`).

Download the two files on the board or on another computer:

```sh
cd /tmp
wget "https://github.com/risan/picoguard/releases/download/v0.2.0/picoguard-TARGET"
wget "https://github.com/risan/picoguard/releases/download/v0.2.0/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
```

You must see `picoguard-TARGET: OK`. If you see `FAILED`, do not use the file. Download it again.

#### Check the signature

Releases from v0.3.0 on also carry `SHA256SUMS.sig`, an Ed25519 signature of `SHA256SUMS` made
with the project's release key. The checksum only shows that the files match `SHA256SUMS`; the
signature shows that `SHA256SUMS` itself comes from the release workflow. You need OpenSSL 3.
Take every file from the same version (here `v0.3.0`), in a new folder:

```sh
mkdir signed && cd signed
base="https://github.com/risan/picoguard/releases/download/v0.3.0"
wget "$base/picoguard-TARGET" "$base/SHA256SUMS" "$base/SHA256SUMS.sig"
wget "https://raw.githubusercontent.com/risan/picoguard/main/dist/release-key.der"
sha256sum release-key.der
```

The fingerprint must be

```
5724aad59c1a5c73be060aaffe293b0b56e5092b71ebb0073e19b1c4238656cf
```

the same as in the [README](../README.md#documentation). If it differs, stop: do not trust that
key file. Then check the signature:

```sh
openssl pkeyutl -verify -pubin -inkey release-key.der -keyform DER \
    -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
```

You must see `Signature Verified Successfully`. Anything else means `SHA256SUMS` is not the
one the project signed. Do not use the files. Last, in the same folder, check the binary against
the signed list: `sha256sum -c --ignore-missing SHA256SUMS`.

You can also build the binaries yourself on another computer with `scripts/build-release.sh`
(needs Rust, `cargo-zigbuild` and `zig`). They land in `dist/bin/<target>/picoguard`.

#### Put the files in place

```sh
install -m 0755 picoguard-TARGET /usr/local/bin/picoguard
picoguard --version
```

Create the system user that runs the service. The config can hold the status page password, so
only root and this user may read it:

```sh
# Debian, Ubuntu, Armbian, Raspberry Pi OS
useradd --system --user-group --no-create-home --home-dir /var/lib/picoguard \
    --shell /usr/sbin/nologin picoguard

# Alpine (BusyBox)
addgroup -S picoguard
adduser -S -D -H -h /var/lib/picoguard -s /sbin/nologin -G picoguard picoguard
```

Copy `picoguard.toml` and `picoguard.service` (systemd) or `picoguard.openrc` (Alpine) from the
`dist/` folder of the source to the device. Then:

```sh
install -d -m 0750 -o root -g picoguard /etc/picoguard
install -m 0640 -g picoguard picoguard.toml /etc/picoguard/picoguard.toml
picoguard --check -c /etc/picoguard/picoguard.toml
```

and, with systemd:

```sh
install -m 0644 picoguard.service /etc/systemd/system/picoguard.service
```

or, with OpenRC:

```sh
install -d -m 0750 -o picoguard -g picoguard /var/lib/picoguard
install -m 0755 picoguard.openrc /etc/init.d/picoguard
```

The `--check` command must print `OK`. The default config blocks ads, trackers and malware with the
AdGuard DNS filter, HaGeZi Pro and HaGeZi Threat Intelligence mini, and forwards to Cloudflare and
Quad9 over DoH. To change anything, read [configuration.md](configuration.md).

If your router is at `192.168.1.1`, open the config and uncomment the `[local]` section with
`resolver = "192.168.1.1:53"`. Then names and addresses of devices on your network keep working.

#### Free port 53

picoguard needs port 53. See who has it:

```sh
ss -lunpt 'sport = :53'
```

No output means the port is free. Skip to the next step.

**systemd-resolved** (common on Ubuntu images) listens on `127.0.0.53:53`. Turn off its listener:

```sh
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/picoguard.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
systemctl restart systemd-resolved
```

The `ln` line makes `/etc/resolv.conf` list the real DNS servers instead of `127.0.0.53`.

**dnsmasq** (or another DNS server):

```sh
systemctl disable --now dnsmasq
```

Run `ss -lunpt 'sport = :53'` again. It must show nothing.

#### Start the service

With systemd:

```sh
systemctl daemon-reload
systemctl enable --now picoguard
systemctl status picoguard
```

With OpenRC:

```sh
rc-update add picoguard default
rc-service picoguard start
```

The service runs as the `picoguard` user with almost no rights. It may only open port 53 and
write to `/var/lib/picoguard`.

On the first start picoguard downloads the lists. This takes a few seconds to a minute, depending
on your line. After that, it keeps a copy of each list in `/var/lib/picoguard`, so a restart blocks
again in about a second.

#### Check that it works

Ask it for a normal name:

```sh
dig @127.0.0.1 example.com
```

You should see `status: NOERROR` and an answer. Now test blocking with a rule of your own. Add this
line to `/etc/picoguard/picoguard.toml`, **before** the first `[section]` header:

```toml
rules = ["||picoguard-test.example^"]
```

Restart (`systemctl restart picoguard` or `rc-service picoguard restart`) and ask:

```sh
systemctl restart picoguard
dig @127.0.0.1 picoguard-test.example
```

The answer must be `0.0.0.0`. Remove the line again when you are done.

Next, open the status page in a browser on a computer in your network:

```
http://DEVICE_IP:8080/
```

It shows totals, the share blocked and the state of each list (size, age, errors). A list shows an
error here when its download failed. Until you set `web.user` and `web.password` (see
`docs/configuration.md`), that is all: the top domains, the top clients, the recent queries and the
pause button need the password.

Logs: `journalctl -u picoguard` (systemd) or syslog (OpenRC, when a logger runs). The default level is
`warn`, so the log is empty when all is well.

## 3. Point your network at picoguard

1. Give the device a fixed address. The best way is a DHCP reservation in your router. The
   address must not change, or the whole network loses DNS.
2. In your router, find the DHCP settings and set the **DNS server** that the router hands to
   clients. Put the device's address there.
3. Add a **second** DNS server, so the network keeps working when the device is off or being
   updated. The second server should also block ads. Good choices:
   - a second picoguard on another board (the two can share the same config file);
   - your current AdGuard Home, while you move over.

   Do not use a plain public resolver (such as `1.1.1.1`) as the second server. Most devices use
   both servers, and some of your queries would then skip blocking.
4. Renew the DHCP lease on a client (disconnect and reconnect Wi-Fi) and check
   `dig example.com`. The answer should come from the device's address. On Linux and macOS, `dig`
   shows `SERVER:` at the end.

If your router cannot change the DHCP DNS, set the DNS server by hand on each device, or turn off
the router's own DHCP server and use another one.

## 4. Make the SD card last

An SD card wears out from writes. picoguard already writes almost nothing, but the operating system
does not. These changes cut the rest. Do the ones you want. Reboot at the end.

### What picoguard writes

- **No query log, no statistics file.** The status page and the query log live in memory and are
  lost on restart.
- **List copies.** When a list changes, picoguard writes one copy of it (about 8 bytes per rule, so
  a few MB for all lists) to `/var/lib/picoguard`. It writes to a temporary file and renames it.
  If a list did not change, nothing is written. Normally that means a few writes per day at most.
- **Zero writes.** Set this to stop even those writes:

  ```toml
  [state]
  persist_lists = false
  ```

  The lists then live in memory only, and picoguard downloads them again at every start. If the
  internet is down at boot, there is no blocking until it is back.
- **Check it.** The number of bytes written by picoguard since it started:

  ```sh
  grep write_bytes /proc/$(pidof picoguard)/io
  ```

### Mount options: `noatime` and `commit=600`

Linux writes the "last read" time of every file it reads. Turn that off. In `/etc/fstab`, find the
line of the root file system (`/`) and add the options:

```
UUID=...  /  ext4  defaults,noatime,commit=600  0  1
```

- `noatime` works on every file system.
- `commit=600` is for ext4. It writes pending data every 10 minutes instead of every 5 seconds.
  A power cut can then lose up to 10 minutes of file changes. Since picoguard keeps nearly
  nothing on disk, this is a good deal.

Apply it without a reboot: `mount -o remount /`.

### journald in memory

By default systemd may write the journal to disk. Keep it in RAM:

```sh
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/volatile.conf <<'EOF'
[Journal]
Storage=volatile
RuntimeMaxUse=16M
EOF
systemctl restart systemd-journald
```

After a reboot the old log is gone. That is fine for a DNS box.

### No swap on the SD card

Swap on an SD card is slow and wears the card. Check:

```sh
swapon --show
free -m
```

- Armbian uses **zram** (compressed swap in RAM) by default. That is fine. It never touches the
  card.
- If you see a swap file or a swap partition on the card (`/swapfile`, or `dphys-swapfile` on
  Raspberry Pi OS), turn it off: `swapoff -a`, remove the line from `/etc/fstab`, and delete the
  file. On Raspberry Pi OS also run `systemctl disable --now dphys-swapfile`.

picoguard uses about 16 MB. It does not need swap.

### `/var/log` in RAM (Armbian)

Armbian keeps `/var/log` in RAM with `armbian-ramlog` (called `log2ram` in older images) and writes
it to the card only at shutdown. This is on by default. Check:

```sh
systemctl status armbian-ramlog
```

On other systems you can install `log2ram`. With journald set to `volatile` above, this matters
less.

### Optional: read-only root with overlayroot

With `overlayroot` the root file system is read-only. All changes go to RAM and are lost at reboot.
The card gets no writes at all while running, and it survives power cuts. The tool is available on
Ubuntu-based images; on Debian-based Armbian check `apt search overlayroot` first.

```sh
apt install overlayroot
```

Then in `/etc/overlayroot.conf` set `overlayroot="tmpfs"` and reboot.

Things to know:

- Set `persist_lists = false` in picoguard's config **before** you turn on overlayroot. The state
  directory is then in RAM anyway, and lists download again at each boot.
- To change files later, run `overlayroot-chroot` and edit inside it, or set
  `overlayroot=""` and reboot.
- Make sure the clock works at boot (see "Clock not set" below), because downloads need TLS.

## 5. Troubleshooting

**picoguard does not start: "address already in use" (port 53 busy).**
Something else listens on port 53. Find it with `ss -lunpt 'sport = :53'`. Turn off the
systemd-resolved listener or stop dnsmasq (Part 2, "Free port 53"). Then
`systemctl restart picoguard`. Look at the reason with `journalctl -u picoguard -e`.

**Ads are not blocked, but DNS works.**
The lists may still be downloading, or a download failed. Open the status page and look at the
list section: size 0 or an error means no rules are loaded. Wait a minute after the first start.
If the error stays, check that the device can reach the internet and the list address
(`wget -O /dev/null <list url>`). Also check that your client really uses the device as its DNS
server (`dig example.com` shows `SERVER:`). Many browsers use their own "secure DNS" and skip your
network's DNS. Turn that off in the browser.

**The status page does not open.**
Check `web.allow_from`. By default only private networks may open it. If your computer comes from
another network (a VPN, a different subnet that is not private), add that network. Also check
that:
- you use the right port (`:8080` by default, see `web.port`);
- you open it by IP address, or you added your host name to `web.hostnames`. Other host names get
  an error on purpose, as protection against attacks from web pages;
- `web.enabled` is not `false`.

**Lists never download, and the log says the TLS certificate is not valid (clock not set).**
Small boards have no battery clock. After a boot the time can be years wrong until the network sets
it, and TLS refuses the certificate. Install a time service:

```sh
apt install chrony
```

or enable `systemd-timesyncd` (`systemctl enable --now systemd-timesyncd`). Check with `date`.
Restart picoguard once the time is right: `systemctl restart picoguard`.

**The page says "the installer did not answer within 10 minutes".**
The Update button staged the files, but nothing installed them. Check, in this order:
- the trigger runs: `systemctl status picoguard-update.path` (systemd) or
  `rc-service picoguard-update status` (OpenRC). If it is missing or stopped, run `install.sh`
  again: it installs and starts it;
- `state.dir` is `/var/lib/picoguard`; the installer does not look anywhere else;
- the installer's log: `journalctl -u picoguard-update` (systemd) or `/var/log/messages` (OpenRC,
  when a syslog runs). It logs one line per update, and "the installed picoguard cannot verify
  updates" when the binary in place is too old to be updated from the page; run `install.sh`
  then.

**The page says "Rolled back".**
The new version was installed, but it did not start or did not answer a lookup of `example.com`
within 30 seconds, so the old version is back. The reason on the page says which. Look at
`journalctl -u picoguard` (systemd) or `/var/log/messages` (OpenRC) for what the new version said.
A common cause is a config that the new version accepts but that blocks the device's own lookup:
the installer asks from the device itself, so `server.allow_from` must cover `127.0.0.0/8` (or the
address picoguard listens on). The update stays available: fix the cause, then click again.

**Check the config before a restart.**
`picoguard --check -c /etc/picoguard/picoguard.toml`. It names the first bad key.

**The service does not start in a Debian container: a namespace or sandbox error.**
The unit uses `PrivateDevices`, `ProtectProc` and a system call filter. In a Proxmox container,
turn on the container option "Nesting" (`Options > Features`) and restart the container, or use
the Alpine container from `proxmox-lxc.sh`, which has no sandbox.

**The service is killed (out of memory).**
The unit allows 64 MB (`MemoryMax=64M`). With very large lists, raise it:
`systemctl edit picoguard`, then add

```ini
[Service]
MemoryMax=128M
```

See [configuration.md](configuration.md) for memory per list.


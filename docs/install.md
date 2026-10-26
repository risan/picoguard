# Install picoguard

picoguard is one static program. It needs no other packages. This guide has three targets:

| Your device | CPU | Binary to download |
|---|---|---|
| Used TV box (ZTE B860H, Fiberhome HG680P) with Armbian | ARM64 | `picoguard-aarch64-unknown-linux-musl` |
| Orange Pi Zero or Zero LTS with Armbian | ARMv7 | `picoguard-armv7-unknown-linux-musleabihf` |
| Proxmox LXC or any x86_64 Linux | x86_64 | `picoguard-x86_64-unknown-linux-musl` |

Not sure which one you have? Run `uname -m` on the device.

| `uname -m` says | Use |
|---|---|
| `aarch64` | ARM64 |
| `armv7l` | ARMv7 |
| `x86_64` | x86_64 |

Part 1 gets the device ready. Part 2 is the same for every device. Part 3 points your network at
it. Part 4 makes the SD card last. Part 5 is for when something goes wrong.

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

### Proxmox LXC or any x86_64 Linux

Use any Linux with systemd, for example Debian or Ubuntu. For a Proxmox LXC container:

1. Create a Debian container: 1 core and 256 MB of RAM are enough, and 1 GB of disk.
2. Give it a fixed IP address (or a DHCP reservation in your router).
3. The service unit uses `DynamicUser` and `PrivateDevices`. If the service fails to start with a
   namespace or sandbox error inside the container, turn on the container option "Nesting"
   (`Options > Features`) and restart the container.

Check the CPU: `uname -m` must say `x86_64`.

## 2. Install picoguard

Run these steps as root (`sudo -i`) on the device.

### Download and check the binary

Release files are named `picoguard-<target>`, and `SHA256SUMS` lists their checksums. Replace
`TARGET` with the name from the first table (for example `aarch64-unknown-linux-musl`).

The repository is private for now, so a plain download needs a login. Use the GitHub CLI
(`gh auth login` once), on the board or on another computer:

```sh
cd /tmp
gh release download v0.1.0 -R risan/picoguard -p "picoguard-TARGET" -p SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

When the repository is public, `wget` works without a login:

```sh
cd /tmp
wget "https://github.com/risan/picoguard/releases/download/v0.1.0/picoguard-TARGET"
wget "https://github.com/risan/picoguard/releases/download/v0.1.0/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
```

You must see `picoguard-TARGET: OK`. If you see `FAILED`, do not use the file. Download it again.

You can also build the binaries yourself on another computer with `scripts/build-release.sh`
(needs Rust, `cargo-zigbuild` and `zig`). They land in `dist/bin/<target>/picoguard`.

### Put the files in place

```sh
install -m 0755 picoguard-TARGET /usr/local/bin/picoguard
picoguard --version

mkdir -p /etc/picoguard
```

Copy `picoguard.toml` and `picoguard.service` from the `dist/` folder of the release (or of the
source) to the device. Then:

```sh
install -m 0644 picoguard.toml /etc/picoguard/picoguard.toml
install -m 0644 picoguard.service /etc/systemd/system/picoguard.service
picoguard --check -c /etc/picoguard/picoguard.toml
```

The last command must print `OK`. The default config blocks ads, trackers and malware with HaGeZi
Pro and HaGeZi Threat Intelligence mini, and forwards to Cloudflare and Quad9 over DoH. To change
anything, read [configuration.md](configuration.md).

If your router is at `192.168.1.1`, open the config and uncomment the `[local]` section with
`resolver = "192.168.1.1:53"`. Then names and addresses of devices on your network keep working.

### Free port 53

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

### Start the service

```sh
systemctl daemon-reload
systemctl enable --now picoguard
systemctl status picoguard
```

The service runs as a temporary user with almost no rights. It may only open port 53 and write to
`/var/lib/picoguard`.

On the first start picoguard downloads the lists. This takes a few seconds to a minute, depending
on your line. After that, it keeps a copy of each list in `/var/lib/picoguard`, so a restart blocks
again in about a second.

### Check that it works

Ask it for a normal name:

```sh
dig @127.0.0.1 example.com
```

You should see `status: NOERROR` and an answer. Now test blocking with a rule of your own. Add this
line to `/etc/picoguard/picoguard.toml`, **before** the first `[section]` header:

```toml
rules = ["||picoguard-test.example^"]
```

Restart and ask:

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

Logs: `journalctl -u picoguard`. The default level is `warn`, so the log is empty when all is well.

### Update picoguard

```sh
systemctl stop picoguard
install -m 0755 picoguard-TARGET /usr/local/bin/picoguard
systemctl start picoguard
```

Your config and list copies stay as they are.

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

**Check the config before a restart.**
`picoguard --check -c /etc/picoguard/picoguard.toml`. It names the first bad key.

**The service is killed (out of memory).**
The unit allows 64 MB (`MemoryMax=64M`). With very large lists, raise it:
`systemctl edit picoguard`, then add

```ini
[Service]
MemoryMax=128M
```

See [configuration.md](configuration.md) for memory per list.

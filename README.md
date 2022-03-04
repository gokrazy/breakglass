# breakglass

breakglass is a [gokrazy](https://github.com/gokrazy/gokrazy) package
which provides emergency/debugging access to a gokrazy installation.

It breaks the gokrazy model in that it allows you to run payloads
implemented in any language (e.g. busybox, implemented in C).

To repeat, breakglass’s whole idea is **remote code execution** (via
SSH/SCP, listening only on private network addresss). Hence, it should
usually not be present on your gokrazy installation, but it might be
useful for development/debugging. As a safety measure, breakglass will
not automatically be started on boot, but needs to explicitly be
started via the gokrazy web interface.

## Installation

Please see https://gokrazy.org/quickstart/ if you’re unfamiliar with gokrazy.

First, install your SSH public key(s) as authorized via [package
config](https://gokrazy.org/userguide/package-config/) for the
`github.com/gokrazy/breakglass` package:

```
mkdir -p extrafiles/github.com/gokrazy/breakglass/etc/
# Note: At the moment only ed25519 and ecdsa keys work
cat ~/.ssh/id_*.pub \
  > extrafiles/github.com/gokrazy/breakglass/etc/breakglass.authorized_keys

mkdir -p flags/github.com/gokrazy/breakglass/
echo '-authorized_keys=/etc/breakglass.authorized_keys' \
  > flags/github.com/gokrazy/breakglass/flags.txt
```

Then, add the `github.com/gokrazy/breakglass` and
`github.com/gokrazy/serial-busybox` packages to your `gokr-packer` command,
e.g.:

```
gokr-packer -overwrite=/dev/sdx \
  github.com/gokrazy/hello \
  github.com/gokrazy/serial-busybox \
  github.com/gokrazy/breakglass
```

## Usage

Be sure to install the convenience SSH wrapper tool on the host:

```
go install github.com/gokrazy/breakglass/cmd/breakglass
```

### Start a shell

If you have `github.com/gokrazy/serial-busybox` installed on your gokrazy
installation, you can directly start a shell without having to upload your own
tools. Run:

```
breakglass gokrazy
```

If you prefer, you can also manually start `breakglass` in the gokrazy web
interface and then use `ssh gokrazy` to log in.

### Run your own tools

1. Create a tarball containing your statically linked arm64 binaries
   and any other files you’ll need.
2. SCP that tarball to your gokrazy installation, where breakglass
   will unpack it into a temporary directory.
3. Execute a binary via SSH.

Here’s an example, assuming you unpacked and statically cross-compiled
busybox in `/tmp/busybox-1.22.0` and your gokrazy installation runs on
host `gokrazy`:

```
$ cd /tmp/busybox-1.22.0
$ file busybox
busybox: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked,
for GNU/Linux 3.7.0, BuildID[sha1]=c9e20e9849ed0ca3c2bd058427ac31a27c008efe, stripped
$ ln -s busybox sh
$ tar cf breakglass.tar --dereference sh
$ breakglass -debug_tarball_pattern=debug.tar gokrazy
/tmp/breakglass564067692 # df -h
Filesystem                Size      Used Available Use% Mounted on
/dev/root                60.5M     60.5M         0 100% /
devtmpfs                445.3M         0    445.3M   0% /dev
tmpfs                    50.0M      1.8M     48.2M   4% /tmp
tmpfs                     1.0M      8.0K   1016.0K   1% /etc
/dev/mmcblk0p4           28.2G     44.1M     26.7G   0% /perm
```

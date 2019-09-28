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

Add the `github.com/gokrazy/breakglass` package to your `gokr-packer`
command, e.g.:

```
gokr-packer -overwrite=/dev/sdx \
  github.com/gokrazy/hello \
  github.com/gokrazy/breakglass
```

On the permanent file system of your gokrazy installation, create a
host key and an authorized keys file. Assuming you mounted the
permanent file system at `/media/sdx4`:

```
sudo ssh-keygen -N '' -t rsa -f /media/sdx4/breakglass.host_key
sudo install -m 600 ~/.ssh/id_*.pub /media/sdx4/breakglass.authorized_keys
```

## Usage

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
$ scp breakglass.tar gokrazy:
$ ssh gokrazy
/tmp/breakglass564067692 # df -h
Filesystem                Size      Used Available Use% Mounted on
/dev/root                60.5M     60.5M         0 100% /
devtmpfs                445.3M         0    445.3M   0% /dev
tmpfs                    50.0M      1.8M     48.2M   4% /tmp
tmpfs                     1.0M      8.0K   1016.0K   1% /etc
/dev/mmcblk0p4           28.2G     44.1M     26.7G   0% /perm
```

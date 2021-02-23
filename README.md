# oramfs - ORAM filesystem written in Rust

`oramfs` features:

* ORAM - encrypt files and hide read/write access patterns from remote storage
* Resizable ORAM - extend your ORAM when required!
* **Cloud storage agnostic** - synchronize your files to any remote server that can be mounted as a local directory
* **Filesystem agnostic** - ext4 is used by default. Manual mode let you use the filesystem you like.
* Supports **multiple encryption ciphers** - ChaCha8, AES-CTR
* Supports **multiple ORAM schemes** - PathORAM, etc.
* Written in **Rust** - Avoids memory safety issues, great performance

**DISCLAIMER** `oramfs` is a prototype and may not be ready for production. It may erase some of your data. Make sure to
backup important data before using this software.

# Introduction

On an encrypted filesystem, an ORAM prevents an attacker from knowing whether read or write operations are performed and
which parts of the filesystem are accessed. This privacy comes with a loss of performance.

To setup the ORAM, two inputs are required. A public directory and a private directory.

The public directory can be any local directory, including remote data mounted as a local directory. Hence, hiding
access patterns to a remote SSH directory or to a remote cloud storage is possible. Indeed, these remote storages simply
need to be mounted as a local directory first, and then, that directory can be used as the public directory for `oramfs`
. For example, [Rclone](https://github.com/rclone/rclone) supports mounting a variety of cloud storage providers as
local directories.

The private directory is the one that should be used to access files stored in the ORAM. Any operation performed on the
private directory has an impact on the public directory. And if that public directory is a mounted remote storage, then
it is safely and transparently synchronized to the remote server whenever an operation is performed on the private
directory.

# Getting started

Install Rust using [rustup](https://rustup.rs/) if it is not installed yet.

Note: for best performance, see the "Performance" section below.

First, build `oramfs` using `cargo`:

```
cargo build
```

The `oramfs` binary will be created in the `target/release` directory. For convenience, add it to your `PATH`. Note that
installing the binary can also be performed with `cargo install --path .`. It will be installed in `~/.cargo/bin` by
default.

```
sudo su
export PATH=$PATH:target/release
```

Then, create or mount a public directory to be protected by the ORAM, and a private directory:

```
mkdir public
mkdir private
```

Finally, run the executable and create an ORAM configuration called `myoram`:

```
oramfs add myoram public/ private/
```

Follow the interactive instructions and complete the ORAM setup.

Once the ORAM configuration is setup, the details are saved to `~/.config/oramfs/oramfs.yml`.

Now the ORAM can be mounted and unmounted at any time using this configuration.

```
oramfs mount myoram
```

To unmount the ORAM:

```
oramfs umount myoram
```

To enlarge the ORAM, make sure it is unmounted first, then double its size:

```
oramfs enlarge myoram
```

Then it can be mounted as usual and its size will be larger than before.

# How does it work?

Instead of implementing a full filesystem, `oramfs` only provides a mounted file. Therefore, the user is expected to
create a filesystem on top of that file using a loop device and the filesystem of their choice. Note that such
operations usually require root privileges and therefore `oramfs` should be run as root to work properly.

`oramfs` takes a public directory as input and exposes a single private file, which is a proxy for read and write
operations so that they are privacy-preserving thanks to an ORAM scheme.

The mounted private file can be used to setup a loop device using `losetup`. Then, any filesystem, such as ext4 can be
created on top of that loop device. `oramfs` automates this process, but also lets users do it manually if they want to.

```
+--------------------------------------------------------------+
|                                                              |
|                       ext4 filesystem                        | <---+ or any other FS or your choice
|                                                              |
+--------------------------------------------------------------+
|                                                              |
|                   Loop device (/dev/loop0)                   | <---+ created with losetup
|                                                              |
+--------------------------------------------------------------+
|                                                              |
|                         ORAMFS (FUSE)                        | <---+ Input  : *public* local directory
|                                                              |       Output : *private* single file, 
+-------------------+-----------------+------------------------+                for use with loop device
|                   |                 |                        |
|  Local directory  |  Cloud storage  |  Remote SSH directory  | <---+ Input directory can be anything
|                   |                 |                        |       that appears as a local directory,
+-------------------+-----------------+------------------------+       including mounted remote directories.
                                                                       Examples: SSH, FTP, anything supported 
                                                                       by rclone or similar tools, 
                                                                       any mounted FUSE filesystem, etc.
```

Before using ORAMFS:

```
$ tree
.
├── private  <---+ empty directory
└── public   <---+ this is the directory that the attacker can see ("public" directory)
```

When ORAMFS is in use, every operation done in "mnt" - or directly on the "oram" private file - appears ORAMified in
the "public" directory. In the standard use case, the user does not directly modify the
"oram" private file, but instead uses a higher level abstraction (the filesystem in the "mnt" directory). The user
typically mounts their public cloud storage to the "public" directory before running ORAMFS, so that the public files
are transparently synchronized to the cloud in a privacy-preserving way.

```
$ tree
.
├── mnt
│   └── lost+found
│   └── very_private_document.txt
├── private
│   └── oram
└── public
    └── node_0.oram
    └── node_1.oram
    └── node_2.oram
    └── ...
```

# Building

If performance is not an issue, for a quick build, run:

```
cargo build
```

To get maximum performance, build in release mode and target the native CPU architecture:

```
RUSTFLAGS="-Ctarget-cpu=native" cargo build --release
```

An executable will be produced in `target/release/oramfs`.

# Advanced Usage

Note that `oramfs` requires to be run as root. The reason for this is that this software relies on an external
additional layer, to obtain a working filesystem, such as setting up a loop device and formatting it as ext4.

Run the produced executable directly or run it via cargo with `cargo run --release`.

Show help with `cargo run -- -h`

## Foreground mode

By default, the ORAMFS runs in the background. Use `--foreground` to avoid that.

Note that when ORAMFS runs in the foreground, it implies that manual mode is used.

```
oramfs mount myoram --foreground
```

## Manual mode

For maximum control, manual mode can be used (`--manual`). Mount ORAMFS using Path ORAM (with explicit parameters). The
mounted ORAMFS appears as a file under `private/oram`.

```
mkdir private
mkdir public
mkdir client-data
sudo su
oramfs mount myoram --manual
```

Since manual mode does not automatically mount a file system for you, you must do it yourself. To do so, create an ext4
filesystem on top of the ORAM. Note that `mount` automatically creates a loop device for us:

```
sudo su
mkfs.ext4 private/oram
mkdir mnt
mount -o sync private/oram mnt/
echo "hello oram" > mnt/hello.txt
```

## Encryption key file

It is possible to create an encryption key file instead of using a passphrase to derive a key. Configure the path to the
key file in the ORAMFS configuration file. Depending on the `cipher` used, the key should have a specific size.

For `chacha8`, use a 32 bytes (256 bits) key:

```
dd if=/dev/urandom of=/path/to/client-data/encryption_key bs=32 count=1
```

For `aes-ctr`, use a 16 bytes (128 bits) key:

```
dd if=/dev/urandom of=/path/to/client-data/encryption_key_16 bs=16 count=1
```

## Mounting multiple ORAMs at the same time

When mounting multiple ORAMs at the same time, make sure that the ORAMs use different, public directories, private
directories, mountpoints and client data directories.

## ORAM initialization

**Important**: the first time that an ORAM is mounted, the `--init` option is passed automatically.
`--init` is a destructive operation and it will permanently destroy any data in an existing ORAM. In practice, there
should be little need to manually pass `--init`.

`oramfs` looks at the `init` property in the global oramfs config file to determine whether the ORAM was already
initialized.

## ORAM schemes

This prototype currently only supports PathORAM, but it is built so that more schemes can be added in the future. To
prove this, there is a second scheme named `fakeoram` built-in, but it should not be used in production because it is
not a true ORAM. FakeORAM is a "Hello World" example ORAM scheme that could be useful for developers who want to add new
ORAM schemes to `oramfs`.

# Privacy

The `public` directory can be safely mirrored to the cloud, without the cloud provider knowing which file is being
accessed and whether read or write operations were performed. One scenario would be to mount a remote Google Drive
directory as the `public` directory, and use that `public` directory as the public directory for the ORAMFS.

# Read caching

To avoid read caching, on Linux, clear the kernel cache before reading a file from the ORAM:

```
sync; echo 1 > /proc/sys/vm/drop_caches
```

# Performance

When native CPU instructions can be used, AES-CTR may be faster than ChaCha8. Changing the cipher can be achieved by
passing `--cipher aes-ctr`.

To achieve the best performance, make sure to build or run using `cargo`'s `--release` flag and to pass
the `RUSTFLAGS="-Ctarget-cpu=native"` environment variable.

# Testing

Run tests with `cargo test --release`


# Contributing

Feel free to open an issue or pull request.

Code should be formatted with rustfmt

# License and Copyright

Copyright(c) 2021 Nagravision SA.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.


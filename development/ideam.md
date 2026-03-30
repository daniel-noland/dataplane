# Scratch container test infrastructure

## Status

**In progress.** The nix derivations, protocol constants, container
mount logic, and kernel image build are implemented.
The scratch-mode infrastructure is feature-complete for local
development; CI integration and recipe automation remain.

## Problem

The [n-vm] `#[in_vm]` test infrastructure launches a Docker container
(`ghcr.io/githedgehog/testn/n-vm:v0.0.9`) that bundles a Linux kernel,
cloud-hypervisor, virtiofsd, and the [n-it] init system. The container
image ships its own copy of glibc and libgcc.

Meanwhile, the nix-built test binaries have `rpath` entries pointing
into `/nix/store/{hash}-glibc-X.Y/lib`. If the glibc version inside
the container image drifts from the one in the nix closure — due to a
toolchain bump, a nixpkgs pin update, or a container image rebuild —
the dynamic linker inside the VM fails at runtime with opaque loader
errors.

This is the classic "two sources of truth for the same dynamic linking
contract" problem.

A secondary annoyance: every developer must remember to `docker pull`
the correct version of the pre-built image. Forgetting (or pulling a
stale tag) produces confusing failures that look like test bugs.

## Solution: scratch container with nix store passthrough

Collapse both sources of truth into **one**: the nix store.

### Architecture

The existing multi-tier test pattern is preserved:

1. **Host** — `run_test_in_vm` launches a Docker container.
2. **Container** — boots a VM via cloud-hypervisor (or QEMU), runs
   virtiofsd in `--no-sandbox` mode.
3. **VM guest** — `n-it` (PID 1) spawns the test binary.

What changes is _how the container is constructed_.

#### New nix derivations

Two new entries join the existing [sysroot] and [devroot] symlink family:

- **`testroot`** — container-tier tools.
  A `symlinkJoin` of cloud-hypervisor, virtiofsd, qemu, and a
  `kernel-image` derivation that extracts the `bzImage` from
  `linux-fancy`.
  Subdirectories (`bin/`, `lib/`, `share/`, …) are volume-mounted at
  their standard container paths, and top-level files (`bzImage`) are
  bind-mounted at the container root.

- **`vmroot`** — VM guest root filesystem.
  A custom derivation containing the `n-it` init binary, glibc and
  libgcc runtime libraries, and a critical `/nix → /nix` absolute
  symlink.

Both are built by `just setup-roots` and appear as symlinks in the
project root, just like `sysroot` and `devroot`.

#### Kernel image

The kernel is built entirely inside nix via the `linux-fancy`
derivation in `nix/overlays/dataplane-dev.nix`.
It uses `linuxManualConfig` with a `.config` produced by
`nix/pkgs/linux/merge-config.nix`, which merges 13 Kconfig fragments
on an `allnoconfig` base using the kernel's own `merge_config.sh`.

Fragment ordering (later overrides earlier):

> base → serial-console → kvm-guest → virtio → hugepages →
> cgroups-ns → filesystems → crypto → net-core → net-tc-qos →
> net-virt-devices → mlx5-sriov → disable

A `kernel-image` wrapper derivation in `default.nix` copies only the
`bzImage` out of the full kernel build so that `symlinkJoin` produces
a single top-level file in `testroot` without pulling in modules or
headers.

#### Container layout

Instead of pulling a pre-built image, the test infrastructure uses a
locally-created empty ("scratch") Docker image with careful volume
mounts:

```text
┌──────────────────────────────────────────────────────────┐
│ Scratch container                                        │
│                                                          │
│ /bzImage    ← bind mount from testroot/bzImage (ro)      │
│ /bin        ← bind mount from testroot/bin (read-only)   │
│ /lib        ← bind mount from testroot/lib (read-only)   │
│ /share      ← bind mount from testroot/share (read-only) │
│ /nix/store  ← bind mount from host /nix/store (read-only)│
│ /vm.root    ← bind mount from vmroot (read-only)         │
│ /vm.root/nix/store ← bind mount from host /nix/store (ro)│
│ /vm         ← tmpfs (runtime sockets, logs)              │
│ /dev/hugepages ← bind mount from host hugetlbfs (rw)     │
│ /{bin_dir}  ← bind mount of test binary directory        │
│ /vm.root/test-bin ← same bind mount (VM guest mount pt)  │
│                                                          │
│ Binaries at /bin/cloud-hypervisor, /bin/virtiofsd, etc.  │
│ are symlinks into /nix/store/… which resolves because    │
│ /nix/store is mounted.                                   │
│                                                          │
│ /bzImage is a plain file copied from the linux-fancy     │
│ nix derivation (not a symlink, so no /nix/store dep).    │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ VM guest (root = virtiofs share of /vm.root)             │
│                                                          │
│ /bin/n-it   ← symlink → /nix/store/{hash}/bin/n-it      │
│ /lib/       ← symlinks → /nix/store/{hash}-glibc/lib/…  │
│ /nix/store/ ← real directory (bind-mounted from host)    │
│ /test-bin/  ← test binary directory (bind-mounted)       │
│                                                          │
│ Test binary rpath: /nix/store/{hash}-glibc-X.Y/lib       │
│ This resolves because /nix/store is bind-mounted into    │
│ the vmroot and served by virtiofsd as a real directory.   │
└──────────────────────────────────────────────────────────┘
```

#### How `/nix/store` reaches the VM guest

The container tier bind-mounts the host's `/nix/store` at
`/vm.root/nix/store` (the vmroot derivation pre-creates an empty
`/nix/store` directory as the mount point).  virtiofsd shares
`/vm.root` into the VM, so the guest sees a real `/nix/store`
directory populated with the host's nix store contents.

When the VM guest accesses (e.g.)
`/nix/store/{hash}-glibc/lib/libc.so.6`:

```text
VM: /nix/store/{hash}/lib/libc.so.6
 → virtiofsd serves /vm.root/nix/store/{hash}/lib/libc.so.6
 → /vm.root/nix/store is bind-mounted from host /nix/store
 → file found ✓
```

> **Why not a `/nix → /nix` symlink?**  An earlier design used an
> absolute symlink `ln -s /nix $out/nix` in the vmroot derivation,
> relying on virtiofsd's `--sandbox=none` mode to follow it into the
> container's mount namespace.  This does not work: the FUSE protocol
> returns symlinks to the guest kernel for resolution, and the guest
> kernel sees `/nix → /nix` as a self-referential symlink, producing
> `ELOOP` (error -40) when trying to execute the init binary.

### Root resolution

`ScratchRoots::resolve()` locates `testroot` and `vmroot` automatically:

1. **Environment variables** — if `N_VM_TEST_ROOT` and `N_VM_VM_ROOT`
   are both set, their values are used (useful in CI or non-standard
   layouts).
2. **Working-directory auto-detection** — looks for `testroot` and
   `vmroot` symlinks in the current working directory.

If neither method succeeds, `resolve()` returns an error directing the
developer to run `just setup-roots`.

| Variable         | Description                                       |
| ---------------- | ------------------------------------------------- |
| `N_VM_TEST_ROOT` | Absolute path to the resolved `testroot` symlink. |
| `N_VM_VM_ROOT`   | Absolute path to the resolved `vmroot` symlink.   |

The `just test` and `just coverage` recipes export these variables
automatically when the symlinks exist, so nix-archive test runs find
the roots even though the test binary lives in the nix store.

### Developer workflow

```shell
# One-time (or after nixpkgs pin updates):
just setup-roots

# Run tests — roots are detected automatically:
cargo nextest run          # from workspace root (auto-detects testroot/vmroot)
just test                  # nix-archive path (exports env vars automatically)
```

The `just setup-roots` recipe builds all four roots (`devroot`,
`sysroot`, `testroot`, `vmroot`) via `nix build`.

### What this eliminates

| Before                                                 | After                                        |
| ------------------------------------------------------ | -------------------------------------------- |
| glibc version must match between image and nix closure | Single source of truth (nix store)           |
| `docker pull` of correct image tag required            | No external image; locally built             |
| Image rebuild + push on toolchain bumps                | `just setup-roots` regenerates locally       |
| Runtime loader errors on version drift                 | Structurally impossible (same rpath targets) |

## Remaining work

- [x] Migrate kernel image build into `testroot` (via `linux-fancy`
      and `kernel-image` derivations).
- [x] Auto-detect `testroot`/`vmroot` from the working directory
      (`ScratchRoots::resolve()` with env-var override).
- [x] Wire env vars into `just test` / `just coverage` recipes
      (exported automatically when the symlinks exist).
- [ ] Wire `N_VM_TEST_ROOT` / `N_VM_VM_ROOT` into CI environment.
- [ ] Evaluate whether `vmroot` should include additional tools for
      debugging (e.g. busybox) in a development profile.

## Files changed

- `default.nix` — `testroot`, `vmroot`, and `kernel-image` derivations.
- `justfile` — `setup-roots` extended; `test`/`coverage` export root
  env vars automatically.
- `n-vm-protocol/src/lib.rs` — `ScratchRoots::resolve()` with
  env-var + CWD auto-detection, `ScratchRootError` enum.
- `n-vm/src/container.rs` — scratch-only container mode, mount
  construction (directories **and** top-level files), empty image
  creation.
- `n-vm/src/error.rs` — `ScratchRootResolve`, `ScratchImageCreate` variants.
- `n-vm/src/lib.rs` — updated re-exports.
- `nix/overlays/dataplane-dev.nix` — `linux-fancy` kernel derivation.
- `nix/pkgs/linux/merge-config.nix` — Kconfig fragment merging infrastructure.
- `nix/pkgs/linux/fragments/*.config` — per-subsystem kernel config fragments.

[sysroot]: ../sysroot
[devroot]: ../devroot
[n-vm]: ../n-vm
[n-it]: ../n-it

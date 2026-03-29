# Scratch container test infrastructure

## Status

**In progress.** The nix derivations, protocol constants, and container
mount logic are implemented.  The kernel image is not yet included —
that code is being migrated from an external repository.

## Problem

The `#[in_vm]` test infrastructure launches a Docker container
(`ghcr.io/githedgehog/testn/n-vm:v0.0.9`) that bundles a Linux kernel,
cloud-hypervisor, virtiofsd, and the `n-it` init system.  The container
image ships its own copy of glibc and libgcc.

Meanwhile, the nix-built test binaries have `rpath` entries pointing
into `/nix/store/{hash}-glibc-X.Y/lib`.  If the glibc version inside
the container image drifts from the one in the nix closure — due to a
toolchain bump, a nixpkgs pin update, or a container image rebuild —
the dynamic linker inside the VM fails at runtime with opaque loader
errors.

This is the classic "two sources of truth for the same dynamic linking
contract" problem.

A secondary annoyance: every developer must remember to `docker pull`
the correct version of the pre-built image.  Forgetting (or pulling a
stale tag) produces confusing failures that look like test bugs.

## Solution: scratch container with nix store passthrough

Collapse both sources of truth into **one**: the nix store.

### Architecture

The existing multi-tier test pattern is preserved:

1. **Host** — `run_test_in_vm` launches a Docker container.
2. **Container** — boots a VM via cloud-hypervisor (or QEMU), runs
   virtiofsd in `--no-sandbox` mode.
3. **VM guest** — `n-it` (PID 1) spawns the test binary.

What changes is *how the container is constructed*.

#### New nix derivations

Two new entries join the existing [sysroot] and [devroot] symlink family:

- **`testroot`** — container-tier tools.  A `symlinkJoin` of
  cloud-hypervisor, virtiofsd, qemu, and (eventually) a kernel image.
  Subdirectories (`bin/`, `lib/`, `share/`, …) are volume-mounted at
  their standard container paths.

- **`vmroot`** — VM guest root filesystem.  A custom derivation
  containing the `n-it` init binary, glibc and libgcc runtime
  libraries, and a critical `/nix → /nix` absolute symlink.

Both are built by `just setup-roots` and appear as symlinks in the
project root, just like `sysroot` and `devroot`.

#### Container layout

Instead of pulling a pre-built image, the test infrastructure uses a
locally-created empty ("scratch") Docker image with careful volume
mounts:

```text
┌──────────────────────────────────────────────────────────┐
│ Scratch container                                        │
│                                                          │
│ /bin        ← bind mount from testroot/bin (read-only)   │
│ /lib        ← bind mount from testroot/lib (read-only)   │
│ /share      ← bind mount from testroot/share (read-only) │
│ /nix/store  ← bind mount from host /nix/store (read-only)│
│ /vm.root    ← bind mount from vmroot (read-only)         │
│ /vm         ← tmpfs (runtime sockets, logs)              │
│ /{bin_dir}  ← bind mount of test binary directory        │
│                                                          │
│ Binaries at /bin/cloud-hypervisor, /bin/virtiofsd, etc.  │
│ are symlinks into /nix/store/… which resolves because    │
│ /nix/store is mounted.                                   │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ VM guest (root = virtiofs share of /vm.root)             │
│                                                          │
│ /bin/n-it   ← symlink → /nix/store/{hash}/bin/n-it      │
│ /lib/       ← symlinks → /nix/store/{hash}-glibc/lib/…  │
│ /nix        ← symlink → /nix (host's nix store)         │
│ /{bin_dir}  ← test binary (bind-mounted by container)    │
│                                                          │
│ Test binary rpath: /nix/store/{hash}-glibc-X.Y/lib       │
│ This resolves because /nix → /nix through virtiofsd      │
│ --no-sandbox, which follows symlinks across mount         │
│ boundaries in the container's namespace.                  │
└──────────────────────────────────────────────────────────┘
```

#### Why `--no-sandbox` makes this work

In sandbox mode, virtiofsd performs a `pivot_root` + namespace dance
that restricts path resolution to the shared directory.  In
`--no-sandbox` mode, it simply serves files from its own mount
namespace without restriction.

The container mounts `/nix/store` from the host.  The `vmroot`
derivation contains a `/nix → /nix` symlink.  When the VM guest
accesses (e.g.) `/nix/store/{hash}-glibc/lib/libc.so.6`, virtiofsd
resolves this through the symlink chain:

```text
VM: /nix/store/{hash}/lib/libc.so.6
 → virtiofsd resolves in container namespace:
   /vm.root/nix → /nix → /nix/store/{hash}/lib/libc.so.6
 → container has /nix/store bind-mounted from host
 → file found ✓
```

### Environment variables

Scratch mode is activated by setting two environment variables:

| Variable          | Description                                              |
|-------------------|----------------------------------------------------------|
| `N_VM_TEST_ROOT`  | Absolute path to the resolved `testroot` symlink.        |
| `N_VM_VM_ROOT`    | Absolute path to the resolved `vmroot` symlink.          |

When both are set, `container.rs` switches from the pre-built image to
the scratch container strategy.  When unset, the legacy pre-built image
is used (optionally overridden by `N_VM_CONTAINER_IMAGE`).

### Developer workflow

```shell
# One-time (or after nixpkgs pin updates):
just setup-roots

# Run tests — no docker pull required:
N_VM_TEST_ROOT=$(pwd)/testroot N_VM_VM_ROOT=$(pwd)/vmroot cargo nextest run
```

The `just setup-roots` recipe builds all four roots (`devroot`,
`sysroot`, `testroot`, `vmroot`) via `nix build`.

### What this eliminates

| Before                                        | After                                  |
|-----------------------------------------------|----------------------------------------|
| glibc version must match between image and nix closure | Single source of truth (nix store) |
| `docker pull` of correct image tag required   | No external image; locally built       |
| Image rebuild + push on toolchain bumps       | `just setup-roots` regenerates locally |
| Runtime loader errors on version drift        | Structurally impossible (same rpath targets) |

## Remaining work

- [ ] Migrate kernel image build from external repository into `testroot`.
- [ ] Wire `N_VM_TEST_ROOT` / `N_VM_VM_ROOT` into CI environment.
- [ ] Consider adding the env vars to `just test` / `just coverage` recipes
      automatically (detect presence of `testroot`/`vmroot` symlinks).
- [ ] Evaluate whether `vmroot` should include additional tools for
      debugging (e.g. busybox) in a development profile.

## Files changed

- `default.nix` — `testroot` and `vmroot` derivations, exported.
- `justfile` — `setup-roots` extended.
- `n-vm-protocol/src/lib.rs` — `ScratchRoots`, `container_image()`,
  env var constants.
- `n-vm/src/container.rs` — scratch mode detection, mount construction,
  empty image creation.
- `n-vm/src/error.rs` — `ScratchRootResolve`, `ScratchImageCreate` variants.
- `n-vm/src/lib.rs` — updated re-exports.

[sysroot]: ../sysroot
[devroot]: ../devroot
[n-vm]: ../n-vm
[n-it]: ../n-it
# Plan: Validate DPDK tx/rx Traffic in n-vm Tests

## Goal

Prove that we can initialise DPDK, bind network devices, and transmit
and receive Ethernet frames inside VMs launched by the `#[in_vm]` test
infrastructure across every supported hypervisor × NIC-model
combination:

| Hypervisor       | NIC model    | Notes                                     |
| ---------------- | ------------ | ----------------------------------------- |
| cloud-hypervisor | `virtio_net` | Default backend; only virtio is supported |
| QEMU             | `virtio_net` | Virtio on the QEMU backend                |
| QEMU             | `e1000`      | Intel 82540EM (legacy emulated)           |
| QEMU             | `e1000e`     | Intel 82574L (newer emulated)             |

## Strategy

We adopt a **coarse-to-fine** approach split into two major milestones:

1. **Milestone 1 — "Any traffic at all"** (this plan).
   Validate that DPDK can initialise, bind each NIC type, transmit
   frames without error, and receive _any_ frame — including kernel
   chatter.
   Getting a single frame out of `rx_burst` is a victory: it proves the
   PMD, the virtio/emulated device, the hypervisor's TAP plumbing, and
   the guest's VFIO binding all work end to end.

2. **Milestone 2 — "Precise payload round-trip"** (future plan).
   For tests that need to verify _specific_ frame content, switch the
   virtio cells to vhost-user networking so the kernel never touches the
   data path.
   The e1000/e1000e cells will remain TAP-backed (QEMU's emulated NIC
   models cannot use vhost-user), so those tests will use a custom
   EtherType + rx filter if precise matching is needed.

This plan covers **Milestone 1 only**.

---

## Background

### Current state

- The `n-vm` crate can boot a VM with three TAP-backed network
  interfaces (`mgmt`, `fabric1`, `fabric2`) on both cloud-hypervisor
  and QEMU.
- The `#[in_vm]` macro and its companion attributes (`#[hypervisor]`,
  `#[guest]`, `#[network]`) already select the backend, NIC model,
  IOMMU, host page size, and guest hugepage configuration at compile
  time.
- The `dpdk` crate wraps EAL initialisation, device discovery, memory
  pools, and rx/tx queue operations (`RxQueue::receive`,
  `TxQueue::transmit`).
- Existing `n-vm` integration tests verify that VMs boot, filesystems
  are mounted correctly, hugepage reservations work, and the IOMMU
  path functions — but **no test currently exercises DPDK or network
  I/O inside a VM**.

### Traffic injection from the container tier

The container's kernel owns the TAP interfaces and _may_ inject
link-local chatter (IPv6 ND, RS, etc.), but relying on that for rx
validation would be non-deterministic.
Instead, we inject frames explicitly from the container tier using
`AF_PACKET` sockets bound to the TAP devices.

The project already has the building blocks for this:

- The `net` crate (`dataplane-net`) provides `Eth`, `SourceMac`,
  `DestinationMac`, `EthType`, and the `DeParse` trait for
  serialising headers into byte buffers.
- The kernel driver (`dataplane/src/drivers/kernel`) uses
  `afpacket::tokio::RawPacketStream` for raw frame I/O on
  `AF_PACKET` sockets — the same mechanism works for writing frames
  _into_ a TAP from the container side.

The container-tier test harness can open an `AF_PACKET` / raw socket
on a TAP interface (e.g. `fabric1`), serialise an Ethernet frame
using the `net` crate, and `send()` it.
From the guest's perspective this is indistinguishable from traffic
arriving on a physical wire — the frame traverses the TAP fd into
the hypervisor's virtio (or emulated) NIC backend and appears in
DPDK's rx ring.

This gives us deterministic, on-demand traffic without depending on
kernel chatter or bridges.

---

## Phases

### Phase 0 — Spike: DPDK init in a VM

**Goal:** Confirm that EAL starts and ethdevs are detected inside a
cloud-hypervisor VM with default settings.

**Tasks:**

- [ ] Write a minimal `#[in_vm] #[test]` that calls `dpdk::eal::init`
      with a basic set of EAL arguments.
- [ ] Assert that `Eal` is constructed without panicking and that
      `eal.dev` can enumerate at least one port.
- [ ] Run the test locally and capture any failures.
      Identify the correct EAL arguments and device-bind strategy
      (PCI allow-list vs VFIO no-IOMMU vs IOMMU).

**Open questions to resolve:**

- What PCI addresses do the virtio-net devices appear at inside the
  guest?
  Are they stable across runs for a given backend?
- Does the guest kernel need `vfio-pci` loaded, or is UIO sufficient?
- Do we need to unbind the kernel driver from the NIC before DPDK can
  claim it, or does EAL handle that?

**Outcome:** We understand the EAL arguments and device-bind strategy
that work inside the VM guest for at least one backend.

---

### Phase 1 — In-guest DPDK bootstrap helper

**Goal:** Provide a reusable helper that initialises DPDK inside a VM
guest, binds the requested ethdev ports, creates a mempool, and
configures one rx and one tx queue per port.

**Tasks:**

- [ ] Create a new module (e.g. `n-vm/src/dpdk_guest.rs` or a
      dedicated test-support crate) with a function like:

      ```rust
      pub struct GuestDpdkEnv {
          pub eal: Eal,
          pub ports: Vec<StartedDev>,
          pub pool: Mempool,
      }

      pub fn init_dpdk_in_guest(opts: &GuestDpdkOpts) -> GuestDpdkEnv { … }
      ```

- [ ] The helper must:
  - Detect whether hugepages are available and pass `--no-huge` when
    `GuestHugePageConfig::None` was used.
  - Allow-list the PCI addresses of the fabric ports (or use VFIO
    no-IOMMU / IOMMU depending on `VmConfig::iommu`).
  - Create a packet mempool sized for the test (small is fine —
    e.g. 1024 mbufs).
  - Configure and start each ethdev with 1 rx + 1 tx queue.
- [ ] Add unit tests for the EAL argument builder (property-based
      where possible: e.g. no duplicate flags, no contradictory
      options).

**Outcome:** A single function call boots DPDK inside the VM guest
and returns ready-to-use ports and a mempool.

---

### Phase 2 — "Any traffic" integration tests (the matrix)

**Goal:** One integration test per matrix cell proving that DPDK can
**transmit** and **receive** at least one frame through each NIC type.

#### Tx validation

Allocate an mbuf, fill it with a minimal Ethernet frame (any content),
and call `TxQueue::transmit`.
Success criteria:

- `tx_burst` returns without error.
- The DPDK tx stats counter increments (i.e. the NIC consumed the
  descriptor).

No bridge or receiver is needed — we are only proving the guest → PMD
→ NIC → TAP direction works.

#### Rx validation

From the **container tier**, open an `AF_PACKET` raw socket on the
TAP device (e.g. `fabric1`), build a frame using the `net` crate's
`Eth` + `DeParse`, and `send()` it into the TAP.
Inside the **guest**, enable promiscuous mode on the corresponding
DPDK port and poll `RxQueue::receive` with a timeout.

Success criteria:

- `rx_burst` returns at least one mbuf before the timeout expires.
- The mbuf has a non-zero length.

This requires coordination between the container tier (injector) and
the guest tier (receiver).
The simplest approach for Milestone 1: have the container tier start
a background task that periodically sends a frame into the TAP
_before_ booting the VM, so that frames are already flowing by the
time DPDK comes up in the guest.
Alternatively, use the existing vsock channel to signal the container
to start injection after DPDK init completes.

No bridge is needed — the injector writes directly into the TAP that
backs the guest NIC.

#### Test matrix

##### 2a — cloud-hypervisor + virtio_net (default)

```rust
#[in_vm]
#[test]
fn dpdk_tx_any_frame_virtio_cloud_hypervisor() {
    let env = init_dpdk_in_guest(&GuestDpdkOpts::default());
    let frame = build_minimal_frame(&env.pool);
    env.ports[0].tx_queue(0).transmit(std::iter::once(frame));
    // success: tx_burst did not panic or return an error
}

#[in_vm]
#[test]
fn dpdk_rx_any_frame_virtio_cloud_hypervisor() {
    // Container tier injects frames via AF_PACKET on the TAP.
    let env = init_dpdk_in_guest(&GuestDpdkOpts::default());
    let rx = try_receive_any(&env.ports[0].rx_queue(0), TIMEOUT);
    assert!(rx.is_some(), "expected at least one injected frame");
}
```

##### 2b — QEMU + virtio_net

```rust
#[in_vm(qemu)]
#[test]
fn dpdk_tx_any_frame_virtio_qemu() { /* …same body… */ }

#[in_vm(qemu)]
#[test]
fn dpdk_rx_any_frame_virtio_qemu() { /* …same body… */ }
```

##### 2c — QEMU + e1000

```rust
#[in_vm(qemu)]
#[test]
#[network(nic_model = "e1000")]
fn dpdk_tx_any_frame_e1000() { /* …same body… */ }

#[in_vm(qemu)]
#[test]
#[network(nic_model = "e1000")]
fn dpdk_rx_any_frame_e1000() { /* …same body… */ }
```

##### 2d — QEMU + e1000e

```rust
#[in_vm(qemu)]
#[test]
#[network(nic_model = "e1000e")]
fn dpdk_tx_any_frame_e1000e() { /* …same body… */ }

#[in_vm(qemu)]
#[test]
#[network(nic_model = "e1000e")]
fn dpdk_rx_any_frame_e1000e() { /* …same body… */ }
```

**Tasks:**

- [ ] Implement `build_minimal_frame` (guest side) — allocates an
      mbuf and fills it with a valid (but arbitrary) Ethernet header +
      small payload.
- [ ] Implement `try_receive_any` (guest side) — polls `rx_burst` in
      a loop with a deadline, returns `Some(mbuf)` on the first
      non-empty burst, `None` on timeout.
- [ ] Implement a container-tier frame injector that:
  - Opens an `AF_PACKET` / raw socket on a named TAP interface
    (using `afpacket::RawPacketStream` or equivalent).
  - Builds a minimal Ethernet frame using the `net` crate (`Eth`,
    `SourceMac`, `DestinationMac`, `EthType::IPV4`, `DeParse`).
  - Sends the frame at a low rate (e.g. once per 100 ms) in a
    background task so frames are available when the guest polls.
- [ ] Add the eight tests (tx + rx for each of four cells) to
      `n-vm/tests/dpdk_traffic.rs`.
- [ ] Ensure each test prints the EAL log and ethdev stats on failure
      for debuggability.
- [ ] Run locally and in CI.

**Outcome:** Green tests for all eight (4 tx + 4 rx) tests, proving
end-to-end DPDK data-path functionality on every NIC model.

---

## Future: Milestone 2 — Precise payload round-trip

Once Milestone 1 is complete, the next step is to prove we can transmit
a specific frame and receive that _exact_ frame on another port.
This requires a clean data path free of kernel-injected chatter.

### The TAP chatter problem

The container's kernel owns the TAP interfaces and may inject IPv6
router solicitations, neighbour discovery, and other link-local
traffic.
Milestone 1 already uses AF_PACKET injection so we control what goes
in, but the kernel may _also_ inject frames that the guest receives
alongside our injected ones.
For precise payload matching this means:

- A naïve `try_receive_one` may pick up a kernel frame instead of the
  test frame.
- A burst of chatter could fill the rx ring and cause the real frame to
  be dropped.

### Options for eliminating stray traffic

Three approaches are on the table.
They are not mutually exclusive — we may use different approaches for
different cells, or layer them for defence in depth.

#### Option A — tc flower filters on the TAP (all NIC models)

Attach a `clsact` qdisc to each TAP interface in the container tier,
then install `flower` filters on the **egress** path (egress from the
kernel's perspective = ingress into the hypervisor's TAP fd) that drop
everything _except_ frames matching our test EtherType (`0x88B5`).

Conceptually:

```
# allow our test frames through
tc filter add dev fabric1 egress protocol 0x88B5 \
    flower action pass

# default: drop everything else
tc filter add dev fabric1 egress protocol all prio 9999 \
    flower action drop
```

The `interface-manager` crate (`interface-manager/src/tc/`) already
has Rust bindings for the pieces we need:

- **`qdisc`** — `clsact` qdisc creation.
- **`chain`** — chain management with `flower` templates.
- **`filter`** — `FilterSpec` with `Vec<TcFilterFlowerOption>`
  criteria, including `TcFilterFlowerOption::EthType` matching.
- **`action/gact`** — `GenericActionSpec` with `TcActionType` for
  `drop` / `pass` actions.
- All wired through `rtnetlink` for programmatic CRUD.

This tooling is incomplete but covers the core primitives.
Finishing it for this use case would also benefit the main dataplane
(where tc offload is part of the production path).

|          |                                                                                                                                                                                                                                                                   |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Pros** | Works for **all** NIC models including e1000/e1000e. Kernel-enforced — chatter is dropped before it reaches the hypervisor TAP fd, so no risk of rx ring overflow. Exercises and improves existing tc tooling in the project. No new processes or infrastructure. |
| **Cons** | Requires `NET_ADMIN` in the container (already granted). The existing tc bindings need work to be test-ready. Adds a kernel dependency on the `cls_flower` and `act_gact` modules (both standard, but must be present in the container's kernel).                 |

#### Option B — vhost-user networking (virtio cells only)

Replace the TAP backend with vhost-user sockets for the virtio cells.
Both cloud-hypervisor and QEMU support `vhost-user-net` backends — the
hypervisor presents the same virtio-net device to the guest, but the
backend is a userspace process speaking vhost-user over a Unix socket
instead of going through a kernel TAP.
The container-tier injector writes directly to the vhost-user socket,
giving a fully kernel-free path with no stray traffic.

|          |                                                                                                                                                                                                  |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Pros** | Completely eliminates the kernel from the data path. Hermetic and future-proof.                                                                                                                  |
| **Cons** | Does **not** work for e1000/e1000e (QEMU's emulated NIC models are inherently TAP-backed). Requires implementing or vendoring a vhost-user bridge process. More complex container-tier plumbing. |

#### Option C — sysctls + custom EtherType rx filter

Suppress kernel protocols on the TAPs via sysctls (disable IPv6, ARP)
and use a custom EtherType (`0x88B5`) with a guest-side rx filter that
discards non-matching frames.

|          |                                                                                                                                                                         |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Pros** | No new infrastructure. Works for all NIC models.                                                                                                                        |
| **Cons** | Not hermetic — relies on knowing every protocol the kernel might inject. A burst of unknown chatter could still overflow the rx ring before the guest-side filter runs. |

### Recommended approach

**Option A (tc flower filters)** is the strongest starting point:

1. It works for **all four** matrix cells uniformly — no need to split
   the approach by NIC model.
2. Filtering happens in the kernel at the TAP egress, _before_ frames
   reach the hypervisor — so the rx ring cannot overflow with chatter.
3. It exercises and improves the existing `interface-manager/src/tc/`
   tooling, which benefits the production dataplane too.
4. The container already has `NET_ADMIN` and the required kernel
   modules (`cls_flower`, `act_gact`) are standard in any modern
   kernel.

If tc proves insufficient or too complex for a given scenario, we can
layer Option B (vhost-user) for virtio cells or fall back to Option C
(sysctls + guest-side filter) as a quick workaround.

### Tasks (not yet scheduled)

- [ ] Complete the `interface-manager/src/tc/` bindings enough to
      programmatically install `clsact` + `flower` + `gact drop`
      rules on a TAP interface.
- [ ] Add a container-tier pre-boot hook that installs the tc filters
      on the fabric TAPs before the hypervisor starts.
- [ ] Adopt EtherType `0x88B5` for all test frames; update the
      AF_PACKET injector from Milestone 1 to use it.
- [ ] Add a paired-port round-trip test: tx a frame with `0x88B5` on
      fabric port 0, rx on fabric port 1 (bridged via a Linux bridge
      between the two TAPs), verify exact payload match.
- [ ] _(Stretch)_ Evaluate Option B (vhost-user) for virtio cells if
      tc filtering proves limiting.

---

## Test crate placement

Two options:

1. **Add to `n-vm/tests/`** — keeps all VM integration tests together.
   The tests already depend on `n_vm` (and transitively on `dpdk`
   through the workspace).
2. **New crate `n-vm-dpdk-tests/`** — isolates the DPDK traffic tests
   and their helper code from the core `n-vm` tests.
   Cleaner dependency graph but more workspace boilerplate.

**Recommendation:** Start with option 1 (add a new file
`n-vm/tests/dpdk_traffic.rs`).
Refactor into a dedicated crate later if the helper code grows
substantial enough to warrant its own module.

---

## Risks and mitigations

| Risk                                                                                          | Impact                       | Mitigation                                                                                                                                                           |
| --------------------------------------------------------------------------------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| DPDK EAL fails to init inside the VM (missing kernel modules, wrong VFIO mode)                | Blocks all tests             | Phase 0 spike; inspect dmesg and EAL logs in the init trace                                                                                                          |
| e1000/e1000e PMDs not compiled into the DPDK build                                            | QEMU emulated-NIC tests fail | Check `dpdk-sys` build flags; enable the relevant PMD configs if needed                                                                                              |
| AF_PACKET injector frames don't reach DPDK (e.g. TAP not yet connected to hypervisor backend) | Rx validation fails          | Start the injector loop before VM boot so frames are queued by the time DPDK init completes; use a generous timeout (several seconds); log TAP link state on failure |
| Hugepage exhaustion in CI (no 1G pages available)                                             | Default config fails in CI   | Use `host_pages = "4k"` + `guest(hugepage_size = "2m")` or `"none"` for CI-friendly variants                                                                         |
| Container image missing QEMU binary                                                           | QEMU tests fail              | Verify `ghcr.io/githedgehog/testn/n-vm` image includes `qemu-system-x86_64` at the expected path                                                                     |
| PCI address instability across hypervisors                                                    | Device bind fails            | Enumerate devices by driver/type rather than hardcoded BDF addresses; or use EAL allow-list with discovered addresses                                                |

---

## Definition of done (Milestone 1)

- [ ] All eight tests (4 tx + 4 rx) pass in CI.
- [ ] Each tx test successfully transmits at least one frame via
      `tx_burst` without error.
- [ ] Each rx test successfully receives at least one frame via
      `rx_burst` before the timeout expires.
- [ ] Helper code (`init_dpdk_in_guest`, frame builder, rx poller) is
      documented and reusable for Milestone 2.
- [ ] Failure output includes EAL logs, ethdev stats, and kernel dmesg
      for easy triage.

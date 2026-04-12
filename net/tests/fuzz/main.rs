// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// Force the linker to include dataplane-net's object files.
// Without this, linkme's distributed_slice entries are dropped.
extern crate dataplane_net as _;

fn main() {
    fuzz_list::main();
}

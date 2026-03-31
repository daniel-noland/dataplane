// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[n_vm::in_vm(cloud_hypervisor)]
#[n_vm::network(nic_model = "e1000")]
fn e1000_on_explicit_cloud_hypervisor() {}

fn main() {}
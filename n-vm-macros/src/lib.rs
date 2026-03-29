// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![warn(missing_docs)]

//! Proc macro crate for the `n-vm` test infrastructure.
//!
//! This crate provides the [`in_vm`] attribute macro, which rewrites a test
//! function so that it transparently runs inside an ephemeral virtual machine.
//!
//! # Architecture
//!
//! The `#[in_vm]` macro implements a three-tier dispatch based on environment
//! variables (defined in `n_vm_protocol` and re-exported from `n_vm`):
//!
//! 1. **Host** (no env vars set) -- the default when `cargo test` is invoked.
//!    Delegates to [`n_vm::dispatch::run_host_tier`] which launches a Docker
//!    container with the required devices and capabilities, then re-executes
//!    the same test binary inside it.
//!
//! 2. **Container** (`IN_TEST_CONTAINER=YES`) -- inside the Docker container.
//!    Delegates to [`n_vm::dispatch::run_container_tier`] which boots a VM
//!    using the selected hypervisor backend, shares the test binary into the
//!    guest via virtiofs, and re-executes the test inside the VM.
//!
//! 3. **VM guest** (`IN_VM=YES`) -- inside the virtual machine, running under
//!    the `n-it` init system.  The original test body executes directly.
//!
//! All runtime policy (tokio runtime construction, tracing configuration,
//! error formatting, exit-code interpretation) lives in the
//! [`n_vm::dispatch`] module rather than in `quote!` output, so that
//! changes do not require proc-macro recompilation and the logic is
//! testable and debuggable as normal Rust code.
//!
//! # Backend selection
//!
//! The macro accepts optional arguments to select the hypervisor backend
//! and VM options:
//!
//! | Attribute | Backend | vIOMMU |
//! |-----------|---------|--------|
//! | `#[in_vm]` | [`CloudHypervisor`] (default) | off |
//! | `#[in_vm(cloud_hypervisor)]` | [`CloudHypervisor`] (explicit) | off |
//! | `#[in_vm(qemu)]` | [`Qemu`] | off |
//! | `#[in_vm(iommu)]` | [`CloudHypervisor`] (default) | **on** |
//! | `#[in_vm(qemu, iommu)]` | [`Qemu`] | **on** |
//! | `#[in_vm(cloud_hypervisor, iommu)]` | [`CloudHypervisor`] | **on** |
//!
//! The backend and option identifiers are case-sensitive and must match
//! one of the supported values exactly.
//! Any other identifier produces a compile error listing the valid
//! options.
//!
//! # Usage
//!
//! ```ignore
//! use n_vm::in_vm;
//!
//! #[test]
//! #[in_vm]
//! fn my_test_on_default_backend() {
//!     // This body runs inside an ephemeral VM (cloud-hypervisor).
//!     assert!(std::path::Path::new("/proc").exists());
//! }
//!
//! #[test]
//! #[in_vm(qemu)]
//! fn my_test_on_qemu() {
//!     // This body runs inside an ephemeral VM (QEMU).
//!     assert!(std::path::Path::new("/proc").exists());
//! }
//!
//! #[test]
//! #[in_vm(iommu)]
//! fn my_dpdk_test_with_viommu() {
//!     // Runs on the default backend with a virtual IOMMU device
//!     // presented to the guest, exercising DMA remapping paths.
//!     assert!(std::path::Path::new("/proc").exists());
//! }
//!
//! #[test]
//! #[in_vm(qemu, iommu)]
//! fn my_dpdk_test_on_qemu_with_viommu() {
//!     // Runs on QEMU with Intel IOMMU emulation enabled.
//!     assert!(std::path::Path::new("/proc").exists());
//! }
//! ```
//!
//! The decorated function must be a synchronous `fn()` with no parameters and
//! no return value.

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{ReturnType, parse_macro_input};

/// Recognised backend identifiers and their corresponding type paths.
///
/// Each entry maps a user-facing identifier (the string written inside
/// `#[in_vm(...)]`) to the fully-qualified type path emitted in the
/// generated code.
const KNOWN_BACKENDS: &[(&str, &str)] = &[
    ("cloud_hypervisor", "::n_vm::CloudHypervisor"),
    ("qemu", "::n_vm::Qemu"),
];

/// Recognised option identifiers that are not backend names.
///
/// These are parsed from the comma-separated attribute argument list
/// alongside (or instead of) a backend identifier.
const KNOWN_OPTIONS: &[&str] = &["iommu"];

/// The type path used when no backend is specified (`#[in_vm]`).
const DEFAULT_BACKEND_PATH: &str = "::n_vm::CloudHypervisor";

/// Builds a human-readable list of valid backend identifiers for use in
/// error messages.
fn known_backend_list() -> String {
    KNOWN_BACKENDS
        .iter()
        .map(|(name, _)| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Builds a human-readable list of valid option identifiers for use in
/// error messages.
fn known_option_list() -> String {
    KNOWN_OPTIONS
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolves a backend identifier to the corresponding type path.
///
/// Returns `None` if the identifier is not recognised as a backend.
fn resolve_backend(ident: &str) -> Option<&'static str> {
    KNOWN_BACKENDS
        .iter()
        .find(|(name, _)| *name == ident)
        .map(|(_, path)| *path)
}

/// Returns `true` if `ident` is a recognised option (not a backend).
fn is_known_option(ident: &str) -> bool {
    KNOWN_OPTIONS.contains(&ident)
}

/// Parsed attribute arguments for `#[in_vm(...)]`.
struct InVmArgs {
    /// The resolved backend type path token stream.
    backend_path: proc_macro2::TokenStream,
    /// Whether the `iommu` option was specified.
    iommu: bool,
}

/// Parses a comma-separated list of identifiers from the attribute
/// arguments.
///
/// Accepts zero or more identifiers separated by commas.
/// At most one backend identifier is allowed (and it must appear first
/// if present).
/// The `iommu` option may appear in any position.
///
/// # Errors
///
/// Returns a compile error if:
/// - A non-identifier token is encountered.
/// - An identifier is not a recognised backend or option.
/// - A backend identifier appears after an option.
/// - Multiple backend identifiers are specified.
fn parse_in_vm_args(attr: TokenStream) -> Result<InVmArgs, TokenStream> {
    if attr.is_empty() {
        return Ok(InVmArgs {
            backend_path: DEFAULT_BACKEND_PATH
                .parse()
                .expect("DEFAULT_BACKEND_PATH is a valid token stream"),
            iommu: false,
        });
    }

    // Parse as a punctuated list of identifiers separated by commas.
    // `Punctuated` does not implement `Parse` directly, so we use its
    // `parse_terminated` method via the `Parser` trait.
    use syn::parse::Parser;
    let parser =
        syn::punctuated::Punctuated::<syn::Ident, syn::Token![,]>::parse_terminated;
    let punctuated = match parser.parse(attr) {
        Ok(p) => p,
        Err(_) => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                format!(
                    "#[in_vm] expects a comma-separated list of identifiers; \
                     valid backends are: {}; valid options are: {}",
                    known_backend_list(),
                    known_option_list(),
                ),
            )
            .to_compile_error()
            .into());
        }
    };

    let idents: Vec<syn::Ident> = punctuated.into_iter().collect();

    let mut backend_path: Option<proc_macro2::TokenStream> = None;
    let mut iommu = false;
    let mut backend_seen = false;

    for ident in &idents {
        let ident_str = ident.to_string();

        if let Some(path) = resolve_backend(&ident_str) {
            if backend_seen {
                return Err(syn::Error::new_spanned(
                    ident,
                    "only one backend identifier is allowed in #[in_vm]",
                )
                .to_compile_error()
                .into());
            }
            // A backend identifier must appear before any options so that
            // the attribute reads naturally as `#[in_vm(backend, opts...)]`.
            if iommu {
                return Err(syn::Error::new_spanned(
                    ident,
                    "the backend identifier must appear before options in #[in_vm]; \
                     use e.g. #[in_vm(qemu, iommu)]",
                )
                .to_compile_error()
                .into());
            }
            backend_path = Some(
                path.parse()
                    .expect("KNOWN_BACKENDS paths are valid token streams"),
            );
            backend_seen = true;
        } else if ident_str == "iommu" {
            if iommu {
                return Err(syn::Error::new_spanned(
                    ident,
                    "duplicate `iommu` option in #[in_vm]",
                )
                .to_compile_error()
                .into());
            }
            iommu = true;
        } else if is_known_option(&ident_str) {
            // Future-proofing: if we add more options, handle them here.
            // For now, `iommu` is the only option, so this branch is
            // unreachable.
            unreachable!("unhandled known option: {ident_str}");
        } else {
            return Err(syn::Error::new_spanned(
                ident,
                format!(
                    "unknown #[in_vm] argument `{ident_str}`; \
                     valid backends are: {}; valid options are: {}",
                    known_backend_list(),
                    known_option_list(),
                ),
            )
            .to_compile_error()
            .into());
        }
    }

    Ok(InVmArgs {
        backend_path: backend_path.unwrap_or_else(|| {
            DEFAULT_BACKEND_PATH
                .parse()
                .expect("DEFAULT_BACKEND_PATH is a valid token stream")
        }),
        iommu,
    })
}

/// Attribute macro that rewrites a test function to run inside an ephemeral VM.
///
/// See the [crate-level documentation](crate) for a full description of the
/// three-tier dispatch mechanism, backend selection, and usage examples.
///
/// # Backend selection and options
///
/// Arguments are specified as a comma-separated list of identifiers:
///
/// - `#[in_vm]` -- uses [`CloudHypervisor`](::n_vm::CloudHypervisor)
///   (the default), no vIOMMU.
/// - `#[in_vm(cloud_hypervisor)]` -- same as above, explicitly.
/// - `#[in_vm(qemu)]` -- uses [`Qemu`](::n_vm::Qemu).
/// - `#[in_vm(iommu)]` -- default backend with a virtual IOMMU device.
/// - `#[in_vm(qemu, iommu)]` -- QEMU with a virtual IOMMU device.
/// - `#[in_vm(cloud_hypervisor, iommu)]` -- cloud-hypervisor with a
///   virtual IOMMU device.
///
/// When `iommu` is specified, the backend presents a virtual IOMMU to
/// the guest and places virtio devices behind it.
/// This exercises the same DMA remapping code paths that DPDK/VFIO
/// encounters in production.
///
/// # Compile-time validation
///
/// The macro rejects functions that are:
/// - **`async`** -- the generated code creates its own tokio runtime at the
///   container tier, so the decorated function must be synchronous.
/// - **Parameterised** -- the function is re-invoked by name as `fn()` inside
///   the VM guest, so it cannot accept arguments.
/// - **Non-unit return type** -- the generated dispatch branches use bare
///   `return;` statements, so the function must return `()`.
///
/// The macro also rejects:
/// - **Unrecognised identifiers** -- backend and option names must be one
///   of the supported values.
/// - **Backend after options** -- the backend identifier (if any) must
///   appear before option identifiers.
/// - **Duplicate options** -- each option may appear at most once.
///
/// # Panics
///
/// The generated code panics if:
/// - The Docker container exits with a non-zero code (host tier).
/// - The VM test output indicates failure (container tier).
/// - The tokio runtime cannot be created.
#[proc_macro_attribute]
pub fn in_vm(attr: TokenStream, input: TokenStream) -> TokenStream {
    // ── Parse backend selection and options ───────────────────────────

    let InVmArgs {
        backend_path,
        iommu,
    } = match parse_in_vm_args(attr) {
        Ok(args) => args,
        Err(err) => return err,
    };

    // ── Parse and validate the function ──────────────────────────────

    let func = parse_macro_input!(input as syn::ItemFn);

    if func.sig.asyncness.is_some() {
        return syn::Error::new_spanned(
            func.sig.asyncness,
            "#[in_vm] cannot be applied to async functions; \
             the generated code creates its own tokio runtime at the container tier",
        )
        .to_compile_error()
        .into();
    }

    if !func.sig.inputs.is_empty() {
        return syn::Error::new_spanned(
            &func.sig.inputs,
            "#[in_vm] functions must take no parameters; \
             the function is re-invoked by name as `fn()` inside the VM guest",
        )
        .to_compile_error()
        .into();
    }

    if !matches!(func.sig.output, ReturnType::Default) {
        return syn::Error::new_spanned(
            &func.sig.output,
            "#[in_vm] functions must return `()`; \
             the generated dispatch branches use bare `return;` statements",
        )
        .to_compile_error()
        .into();
    }

    // ── Code generation ──────────────────────────────────────────────

    let block = &func.block;
    let vis = &func.vis;
    let sig = &func.sig;
    let attrs = &func.attrs;
    let ident = &func.sig.ident;

    // The three tiers are dispatched as a flat if chain.
    // Each tier is identified by an environment variable set by the
    // enclosing layer before re-executing the test binary.
    //
    // Only tier 3 (the VM guest) runs the original test body and must
    // therefore be generated inline.  Tiers 1 and 2 delegate to helper
    // functions in `n_vm::dispatch` so that all runtime policy lives in
    // normal, testable Rust code rather than in macro output.
    quote! {
        #(#attrs)*
        #vis #sig {
            // Tier 3: VM guest
            if ::n_vm::is_in_vm() {
                { #block }
                return;
            }

            // Tier 2: Docker container -> VM
            if ::n_vm::is_in_test_container() {
                ::n_vm::run_container_tier::<#backend_path, _>(#ident, #iommu);
                return;
            }

            // Tier 1: Host -> Docker container
            ::n_vm::run_host_tier(#ident);
        }
    }
    .into()
}
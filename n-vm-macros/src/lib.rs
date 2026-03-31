// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![warn(missing_docs)]

//! Proc macro crate for the `n-vm` test infrastructure.
//!
//! This crate provides the [`in_vm`] attribute macro and its companion
//! attributes [`hypervisor`], [`guest`], and [`network`], which together
//! rewrite a
//! test function so that it transparently runs inside an ephemeral
//! virtual machine.
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
//! The `#[in_vm]` attribute accepts an optional backend identifier:
//!
//! | Attribute | Backend |
//! |-----------|---------|
//! | `#[in_vm]` | [`CloudHypervisor`] (default) |
//! | `#[in_vm(cloud_hypervisor)]` | [`CloudHypervisor`] (explicit) |
//! | `#[in_vm(qemu)]` | [`Qemu`] |
//!
//! # VM configuration
//!
//! Three optional companion attributes configure the VM environment.
//! They must appear **below** `#[in_vm]` on the same function so that
//! the `#[in_vm]` proc macro can consume them before the compiler
//! attempts to expand them independently.
//!
//! ## `#[hypervisor(…)]` -- hypervisor configuration
//!
//! | Option | Values | Default | Description |
//! |--------|--------|---------|-------------|
//! | `iommu` | *(flag)* | off | Present a virtual IOMMU device |
//! | `host_pages` | `"4k"`, `"2m"`, `"1g"` | `"1g"` | Page size backing VM memory on the host |
//!
//! ## `#[guest(…)]` -- guest kernel configuration
//!
//! | Option | Values | Default | Description |
//! |--------|--------|---------|-------------|
//! | `hugepage_size` | `"none"`, `"2m"`, `"1g"` | `"1g"` | Guest hugepage reservation size |
//! | `hugepage_count` | integer | `1` | Number of guest hugepages to reserve |
//!
//! When `hugepage_size = "none"`, guest hugepages are disabled entirely
//! (DPDK must use `--no-huge`), and `hugepage_count` must not be
//! specified.
//!
//! ## `#[network(…)]` -- network interface configuration
//!
//! | Option | Values | Default | Description |
//! |--------|--------|---------|-------------|
//! | `nic_model` | `"virtio_net"`, `"e1000"`, `"e1000e"` | `"virtio_net"` | NIC model for all interfaces |
//!
//! The `e1000` and `e1000e` NIC models are only supported with the QEMU
//! backend (`#[in_vm(qemu)]`).  Using them with cloud-hypervisor is a
//! compile-time error.
//!
//! # Usage
//!
//! ```ignore
//! use n_vm::in_vm;
//!
//! // All defaults: cloud-hypervisor, 1G host pages, 1G×1 guest hugepages
//! #[test]
//! #[in_vm]
//! fn test_defaults() {
//!     assert!(std::path::Path::new("/proc").exists());
//! }
//!
//! // QEMU backend, 4K host pages (no hugepages on host), 2M×512 guest
//! // hugepages, virtual IOMMU enabled.
//! #[test]
//! #[in_vm(qemu)]
//! #[hypervisor(iommu, host_pages = "4k")]
//! #[guest(hugepage_size = "2m", hugepage_count = 512)]
//! fn test_dpdk_2m_on_qemu() {
//!     assert!(std::path::Path::new("/proc").exists());
//! }
//!
//! // Default backend, no guest hugepages (DPDK --no-huge mode)
//! #[test]
//! #[in_vm]
//! #[guest(hugepage_size = "none")]
//! fn test_dpdk_no_huge() {
//!     assert!(std::path::Path::new("/proc").exists());
//! }
//!
//! // QEMU backend with e1000 NICs (emulated Intel 82540EM)
//! #[test]
//! #[in_vm(qemu)]
//! #[network(nic_model = "e1000")]
//! fn test_e1000_nics() {
//!     assert!(std::path::Path::new("/proc").exists());
//! }
//!
//! // QEMU backend with e1000e NICs (emulated Intel 82574L)
//! #[test]
//! #[in_vm(qemu)]
//! #[network(nic_model = "e1000e")]
//! fn test_e1000e_nics() {
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

// ── Backend configuration ────────────────────────────────────────────

/// Recognised backend identifiers and their corresponding type paths.
///
/// Each entry maps a user-facing identifier (the string written inside
/// `#[in_vm(...)]`) to the fully-qualified type path emitted in the
/// generated code.
const KNOWN_BACKENDS: &[(&str, &str)] = &[
    ("cloud_hypervisor", "::n_vm::CloudHypervisor"),
    ("qemu", "::n_vm::Qemu"),
];

/// The type path used when no backend is specified (`#[in_vm]`).
const DEFAULT_BACKEND_PATH: &str = "::n_vm::CloudHypervisor";

/// The backend identifier used when no backend is specified (`#[in_vm]`).
const DEFAULT_BACKEND_NAME: &str = "cloud_hypervisor";

/// Recognised option identifiers that have migrated from `#[in_vm]` to
/// companion attributes.
///
/// When one of these appears inside `#[in_vm(…)]`, the macro emits a
/// helpful compile error pointing the user to the new attribute syntax.
const MIGRATED_OPTIONS: &[(&str, &str)] = &[
    ("iommu", "#[hypervisor(iommu)]"),
];

/// Builds a human-readable list of valid backend identifiers for use in
/// error messages.
#[must_use]
fn known_backend_list() -> String {
    KNOWN_BACKENDS
        .iter()
        .map(|(name, _)| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolves a backend identifier to its name and type path.
///
/// Returns `None` if the identifier is not recognised as a backend.
#[must_use]
fn resolve_backend(ident: &str) -> Option<(&'static str, &'static str)> {
    KNOWN_BACKENDS
        .iter()
        .find(|(name, _)| *name == ident)
        .copied()
}

/// If `ident` is a migrated option, returns the migration hint.
#[must_use]
fn migration_hint(ident: &str) -> Option<&'static str> {
    MIGRATED_OPTIONS
        .iter()
        .find(|(name, _)| *name == ident)
        .map(|(_, hint)| *hint)
}

// ── #[in_vm] argument parsing ────────────────────────────────────────

/// Resolved backend from `#[in_vm(…)]` parsing.
struct BackendInfo {
    /// Token stream for the backend type path (e.g. `::n_vm::Qemu`).
    path: proc_macro2::TokenStream,
    /// The backend identifier string (e.g. `"qemu"`, `"cloud_hypervisor"`).
    name: &'static str,
}

/// Parses the `#[in_vm(…)]` attribute arguments, which now contain
/// **only** the backend selector (zero or one identifier).
///
/// Returns a [`BackendInfo`] with the resolved type path and identifier
/// name (used for cross-attribute validation, e.g. rejecting e1000 on
/// cloud-hypervisor).
///
/// # Errors
///
/// Returns a compile error if:
/// - A non-identifier token is encountered.
/// - The identifier is not a recognised backend.
/// - More than one backend identifier is specified.
/// - A migrated option (e.g. `iommu`) is used in `#[in_vm(…)]`.
fn parse_in_vm_backend(attr: TokenStream) -> syn::Result<BackendInfo> {
    if attr.is_empty() {
        return Ok(BackendInfo {
            path: DEFAULT_BACKEND_PATH
                .parse()
                .expect("DEFAULT_BACKEND_PATH is a valid token stream"),
            name: DEFAULT_BACKEND_NAME,
        });
    }

    // Parse as a punctuated list of identifiers separated by commas.
    use syn::parse::Parser;
    let parser = syn::punctuated::Punctuated::<syn::Ident, syn::Token![,]>::parse_terminated;
    let punctuated = parser.parse(attr).map_err(|_| {
        syn::Error::new(
            proc_macro2::Span::call_site(),
            format!(
                "#[in_vm] expects an optional backend identifier; \
                 valid backends are: {}",
                known_backend_list(),
            ),
        )
    })?;

    let idents: Vec<syn::Ident> = punctuated.into_iter().collect();

    if idents.len() > 1 {
        return Err(syn::Error::new_spanned(
            &idents[1],
            "only one backend identifier is allowed in #[in_vm]; \
             VM options have moved to companion attributes \
             (#[hypervisor(…)], #[guest(…)], #[network(…)])",
        ));
    }

    let ident = &idents[0];
    let ident_str = ident.to_string();

    // Check for migrated options with a helpful hint.
    if let Some(hint) = migration_hint(&ident_str) {
        return Err(syn::Error::new_spanned(
            ident,
            format!(
                "`{ident_str}` has moved out of #[in_vm(…)] — \
                 use {hint} instead",
            ),
        ));
    }

    if let Some((name, path)) = resolve_backend(&ident_str) {
        Ok(BackendInfo {
            path: path
                .parse()
                .expect("KNOWN_BACKENDS paths are valid token streams"),
            name,
        })
    } else {
        Err(syn::Error::new_spanned(
            ident,
            format!(
                "unknown #[in_vm] backend `{ident_str}`; \
                 valid backends are: {}",
                known_backend_list(),
            ),
        ))
    }
}

// ── #[hypervisor] argument parsing ───────────────────────────────────

/// Parsed arguments from a `#[hypervisor(…)]` companion attribute.
struct HypervisorArgs {
    /// Whether to present a virtual IOMMU device to the guest.
    iommu: bool,
    /// Host page size as a fully-qualified token stream
    /// (e.g. `::n_vm::HostPageSize::Huge1G`).
    host_page_size: proc_macro2::TokenStream,
}

impl Default for HypervisorArgs {
    fn default() -> Self {
        Self {
            iommu: false,
            host_page_size: quote! { ::n_vm::HostPageSize::Huge1G },
        }
    }
}

/// Parses the content of a `#[hypervisor(…)]` attribute.
///
/// Accepts:
/// - `iommu` -- boolean flag.
/// - `host_pages = "4k" | "2m" | "1g"` -- host page size.
///
/// `#[hypervisor]` (no parentheses) is treated as all-defaults.
fn parse_hypervisor_attr(attr: &syn::Attribute) -> syn::Result<HypervisorArgs> {
    let mut args = HypervisorArgs::default();

    // #[hypervisor] without parentheses → all defaults.
    if matches!(&attr.meta, syn::Meta::Path(_)) {
        return Ok(args);
    }

    let mut iommu_seen = false;
    let mut host_pages_seen = false;

    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("iommu") {
            if iommu_seen {
                return Err(meta.error("duplicate `iommu` option in #[hypervisor]"));
            }
            iommu_seen = true;
            args.iommu = true;
            Ok(())
        } else if meta.path.is_ident("host_pages") {
            if host_pages_seen {
                return Err(meta.error("duplicate `host_pages` option in #[hypervisor]"));
            }
            host_pages_seen = true;
            let value: syn::LitStr = meta.value()?.parse()?;
            args.host_page_size = match value.value().as_str() {
                "4k" => quote! { ::n_vm::HostPageSize::Standard },
                "2m" => quote! { ::n_vm::HostPageSize::Huge2M },
                "1g" => quote! { ::n_vm::HostPageSize::Huge1G },
                other => {
                    return Err(syn::Error::new_spanned(
                        &value,
                        format!(
                            "unknown host page size `{other}` in #[hypervisor]; \
                             valid values are: \"4k\", \"2m\", \"1g\"",
                        ),
                    ));
                }
            };
            Ok(())
        } else {
            let name = meta
                .path
                .get_ident()
                .map(ToString::to_string)
                .unwrap_or_else(|| "<path>".into());
            Err(meta.error(format!(
                "unknown #[hypervisor] option `{name}`; \
                 valid options are: `iommu`, `host_pages`",
            )))
        }
    })?;

    Ok(args)
}

// ── #[guest] argument parsing ────────────────────────────────────────

/// Parsed arguments from a `#[guest(…)]` companion attribute.
struct GuestArgs {
    /// Guest hugepage configuration as a fully-qualified token stream.
    guest_hugepages: proc_macro2::TokenStream,
}

impl Default for GuestArgs {
    fn default() -> Self {
        Self {
            guest_hugepages: quote! {
                ::n_vm::GuestHugePageConfig::Allocate {
                    size: ::n_vm::GuestHugePageSize::Huge1G,
                    count: 1u32,
                }
            },
        }
    }
}

/// Parses the content of a `#[guest(…)]` attribute.
///
/// Accepts:
/// - `hugepage_size = "none" | "2m" | "1g"` -- guest hugepage
///   granularity.
/// - `hugepage_count = N` -- number of hugepages to reserve (integer,
///   defaults to 1, forbidden when `hugepage_size = "none"`).
///
/// `#[guest]` (no parentheses) is treated as all-defaults.
fn parse_guest_attr(attr: &syn::Attribute) -> syn::Result<GuestArgs> {
    // #[guest] without parentheses → all defaults.
    if matches!(&attr.meta, syn::Meta::Path(_)) {
        return Ok(GuestArgs::default());
    }

    let mut hugepage_size_seen = false;
    let mut hugepage_count_seen = false;

    // Intermediate storage: we need to see both options before
    // constructing the final token stream.
    let mut size_is_none = false;
    let mut size_tokens: Option<proc_macro2::TokenStream> = None;
    let mut count: u32 = 1;
    let mut count_span: Option<proc_macro2::Span> = None;

    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("hugepage_size") {
            if hugepage_size_seen {
                return Err(meta.error("duplicate `hugepage_size` option in #[guest]"));
            }
            hugepage_size_seen = true;
            let value: syn::LitStr = meta.value()?.parse()?;
            match value.value().as_str() {
                "none" => {
                    size_is_none = true;
                }
                "2m" => {
                    size_tokens =
                        Some(quote! { ::n_vm::GuestHugePageSize::Huge2M });
                }
                "1g" => {
                    size_tokens =
                        Some(quote! { ::n_vm::GuestHugePageSize::Huge1G });
                }
                other => {
                    return Err(syn::Error::new_spanned(
                        &value,
                        format!(
                            "unknown hugepage size `{other}` in #[guest]; \
                             valid values are: \"none\", \"2m\", \"1g\"",
                        ),
                    ));
                }
            }
            Ok(())
        } else if meta.path.is_ident("hugepage_count") {
            if hugepage_count_seen {
                return Err(meta.error("duplicate `hugepage_count` option in #[guest]"));
            }
            hugepage_count_seen = true;
            let lit: syn::LitInt = meta.value()?.parse()?;
            count_span = Some(lit.span());
            count = lit.base10_parse()?;
            if count == 0 {
                return Err(syn::Error::new(
                    lit.span(),
                    "hugepage_count must be at least 1; \
                     use `hugepage_size = \"none\"` to disable guest hugepages entirely",
                ));
            }
            Ok(())
        } else {
            let name = meta
                .path
                .get_ident()
                .map(ToString::to_string)
                .unwrap_or_else(|| "<path>".into());
            Err(meta.error(format!(
                "unknown #[guest] option `{name}`; \
                 valid options are: `hugepage_size`, `hugepage_count`",
            )))
        }
    })?;

    // Validate cross-field constraints.
    if size_is_none && hugepage_count_seen {
        return Err(syn::Error::new(
            count_span.unwrap_or_else(proc_macro2::Span::call_site),
            "hugepage_count cannot be specified when \
             hugepage_size = \"none\"; hugepages are disabled",
        ));
    }

    // If #[guest(...)] was given but hugepage_size was not specified,
    // that is an error: the attribute is meaningless without it.
    if !hugepage_size_seen && !hugepage_count_seen {
        // Empty #[guest()] — treat as all defaults.
        return Ok(GuestArgs::default());
    }
    if !hugepage_size_seen {
        return Err(syn::Error::new_spanned(
            attr,
            "#[guest] requires `hugepage_size`; e.g. \
             #[guest(hugepage_size = \"2m\", hugepage_count = 512)]",
        ));
    }

    // Build the guest hugepage configuration token stream.
    let guest_hugepages = if size_is_none {
        quote! { ::n_vm::GuestHugePageConfig::None }
    } else {
        let sz = size_tokens.expect("size_tokens set when size_is_none is false");
        quote! {
            ::n_vm::GuestHugePageConfig::Allocate {
                size: #sz,
                count: #count,
            }
        }
    };

    Ok(GuestArgs { guest_hugepages })
}

// ── #[network] argument parsing ──────────────────────────────────────

/// Parsed arguments from a `#[network(…)]` companion attribute.
struct NetworkArgs {
    /// NIC model as a fully-qualified token stream
    /// (e.g. `::n_vm::NicModel::VirtioNet`).
    nic_model: proc_macro2::TokenStream,
    /// Whether this NIC model requires the QEMU backend.
    ///
    /// Set to `true` for models that cloud-hypervisor does not support
    /// (e.g. `e1000`).  Used for cross-attribute validation in
    /// [`in_vm`].
    requires_qemu: bool,
}

impl Default for NetworkArgs {
    fn default() -> Self {
        Self {
            nic_model: quote! { ::n_vm::NicModel::VirtioNet },
            requires_qemu: false,
        }
    }
}

/// Parses the content of a `#[network(…)]` attribute.
///
/// Accepts:
/// - `nic_model = "virtio_net" | "e1000" | "e1000e"` -- NIC model for
///   all interfaces.
///
/// `#[network]` (no parentheses) is treated as all-defaults.
fn parse_network_attr(attr: &syn::Attribute) -> syn::Result<NetworkArgs> {
    let mut args = NetworkArgs::default();

    // #[network] without parentheses → all defaults.
    if matches!(&attr.meta, syn::Meta::Path(_)) {
        return Ok(args);
    }

    let mut nic_model_seen = false;

    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("nic_model") {
            if nic_model_seen {
                return Err(meta.error("duplicate `nic_model` option in #[network]"));
            }
            nic_model_seen = true;
            let value: syn::LitStr = meta.value()?.parse()?;
            match value.value().as_str() {
                "virtio_net" => {
                    args.nic_model = quote! { ::n_vm::NicModel::VirtioNet };
                    args.requires_qemu = false;
                }
                "e1000" => {
                    args.nic_model = quote! { ::n_vm::NicModel::E1000 };
                    args.requires_qemu = true;
                }
                "e1000e" => {
                    args.nic_model = quote! { ::n_vm::NicModel::E1000E };
                    args.requires_qemu = true;
                }
                other => {
                    return Err(syn::Error::new_spanned(
                        &value,
                        format!(
                            "unknown NIC model `{other}` in #[network]; \
                             valid values are: \"virtio_net\", \"e1000\", \"e1000e\"",
                        ),
                    ));
                }
            }
            Ok(())
        } else {
            let name = meta
                .path
                .get_ident()
                .map(ToString::to_string)
                .unwrap_or_else(|| "<path>".into());
            Err(meta.error(format!(
                "unknown #[network] option `{name}`; \
                 valid options are: `nic_model`",
            )))
        }
    })?;

    Ok(args)
}

// ── Companion attribute extraction ───────────────────────────────────

/// Crate path prefixes that may qualify companion attribute paths.
///
/// Users may write `#[n_vm::hypervisor(…)]` (via the re-export in
/// `n_vm`) or `#[n_vm_macros::hypervisor(…)]` (the defining crate).
/// Any other prefix is not ours and should not be consumed.
const KNOWN_ATTR_PREFIXES: &[&str] = &["n_vm", "n_vm_macros"];

/// Returns `true` if the attribute's path matches the given
/// identifier.
///
/// Matches bare `#[name]` and qualified `#[n_vm::name]` /
/// `#[n_vm_macros::name]` forms.
/// Other qualified paths (e.g. `#[other_crate::name]`) do not match.
fn attr_has_name(attr: &syn::Attribute, name: &str) -> bool {
    let path = attr.path();
    if path.is_ident(name) {
        return true;
    }
    let segments: Vec<_> = path.segments.iter().collect();
    segments.len() == 2
        && KNOWN_ATTR_PREFIXES
            .iter()
            .any(|prefix| segments[0].ident == prefix)
        && segments[1].ident == name
}

/// Extracts at most one attribute with the given name from the list,
/// removing it in place.
///
/// Returns an error if more than one attribute with the name is found.
fn extract_unique_attr(
    attrs: &mut Vec<syn::Attribute>,
    name: &str,
) -> syn::Result<Option<syn::Attribute>> {
    // Find the first match.
    let idx = match attrs.iter().position(|a| attr_has_name(a, name)) {
        Some(i) => i,
        None => return Ok(None),
    };
    let attr = attrs.remove(idx);

    // Check for duplicates.
    if let Some(dup) = attrs.iter().find(|a| attr_has_name(a, name)) {
        return Err(syn::Error::new_spanned(
            dup,
            format!("duplicate #[{name}] attribute"),
        ));
    }

    Ok(Some(attr))
}

/// Extracts an optional unique companion attribute by `name`, parses it
/// with `parse`, and falls back to `T::default()` when absent.
///
/// This combines [`extract_unique_attr`] and a parser function into a
/// single step, eliminating nested `match` arms at the call site.
fn extract_and_parse<T: Default>(
    attrs: &mut Vec<syn::Attribute>,
    name: &str,
    parse: impl FnOnce(&syn::Attribute) -> syn::Result<T>,
) -> syn::Result<T> {
    match extract_unique_attr(attrs, name)? {
        Some(attr) => parse(&attr),
        None => Ok(T::default()),
    }
}

// ── Code generation ──────────────────────────────────────────────────

/// Attribute macro that rewrites a test function to run inside an
/// ephemeral VM.
///
/// See the [crate-level documentation](crate) for the three-tier
/// dispatch mechanism and additional examples.
///
/// # Backend selection
///
/// `#[in_vm]` accepts an optional backend identifier:
///
/// | Attribute | Backend |
/// |-----------|---------|
/// | `#[in_vm]` | [`CloudHypervisor`](::n_vm::CloudHypervisor) (default) |
/// | `#[in_vm(cloud_hypervisor)]` | [`CloudHypervisor`](::n_vm::CloudHypervisor) (explicit) |
/// | `#[in_vm(qemu)]` | [`Qemu`](::n_vm::Qemu) |
///
/// # Companion attributes
///
/// Three optional companion attributes configure the VM environment.
/// They must appear **below** `#[in_vm]` on the same function so that
/// the `#[in_vm]` proc macro can consume them before the compiler
/// attempts to expand them independently.
///
/// ## `#[hypervisor(…)]`
///
/// | Option | Values | Default | Description |
/// |--------|--------|---------|-------------|
/// | `iommu` | *(flag)* | off | Present a virtual IOMMU device |
/// | `host_pages` | `"4k"`, `"2m"`, `"1g"` | `"1g"` | Page size backing VM memory on the host |
///
/// ## `#[guest(…)]`
///
/// | Option | Values | Default | Description |
/// |--------|--------|---------|-------------|
/// | `hugepage_size` | `"none"`, `"2m"`, `"1g"` | `"1g"` | Guest hugepage reservation size |
/// | `hugepage_count` | integer | `1` | Number of guest hugepages to reserve |
///
/// When `hugepage_size = "none"`, guest hugepages are disabled entirely
/// (DPDK must use `--no-huge`), and `hugepage_count` must not be
/// specified.
///
/// ## `#[network(…)]`
///
/// | Option | Values | Default | Description |
/// |--------|--------|---------|-------------|
/// | `nic_model` | `"virtio_net"`, `"e1000"`, `"e1000e"` | `"virtio_net"` | NIC model for all interfaces |
///
/// The `e1000` and `e1000e` NIC models are only supported with the
/// QEMU backend (`#[in_vm(qemu)]`).  Using them with cloud-hypervisor
/// is a compile-time error.
///
/// # Compile-time validation
///
/// The macro rejects functions that are:
/// - **`async`** -- the generated code creates its own tokio runtime at
///   the container tier, so the decorated function must be synchronous.
/// - **Parameterised** -- the function is re-invoked by name as `fn()`
///   inside the VM guest, so it cannot accept arguments.
/// - **Non-unit return type** -- the generated dispatch branches use
///   bare `return;` statements, so the function must return `()`.
///
/// The macro also rejects:
/// - **Unrecognised identifiers** in any of the four attributes.
/// - **Duplicate options** within a single attribute.
/// - **Duplicate companion attributes** (e.g. two `#[hypervisor]`
///   blocks).
/// - **Contradictory options** (e.g. `hugepage_count` with
///   `hugepage_size = "none"`).
/// - **Incompatible backend/NIC combinations** -- emulated NIC models
///   (`e1000`, `e1000e`) require `#[in_vm(qemu)]`; using them with the
///   cloud-hypervisor backend is a compile-time error.
///
/// # Panics
///
/// The generated code panics if:
/// - The Docker container exits with a non-zero code (host tier).
/// - The VM test output indicates failure (container tier).
/// - The tokio runtime cannot be created.
#[proc_macro_attribute]
pub fn in_vm(attr: TokenStream, input: TokenStream) -> TokenStream {
    // ── Parse backend selection ──────────────────────────────────────

    let backend = match parse_in_vm_backend(attr) {
        Ok(info) => info,
        Err(err) => return err.to_compile_error().into(),
    };

    // ── Parse and validate the function ──────────────────────────────

    let mut func = parse_macro_input!(input as syn::ItemFn);

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

    // ── Extract and parse companion attributes ───────────────────────

    let hypervisor_args =
        match extract_and_parse(&mut func.attrs, "hypervisor", parse_hypervisor_attr) {
            Ok(args) => args,
            Err(err) => return err.to_compile_error().into(),
        };

    let guest_args = match extract_and_parse(&mut func.attrs, "guest", parse_guest_attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error().into(),
    };

    let network_args = match extract_and_parse(&mut func.attrs, "network", parse_network_attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error().into(),
    };

    // ── Cross-attribute validation ───────────────────────────────────

    // e1000 (and future emulated NIC models) require QEMU -- cloud-
    // hypervisor only supports virtio devices.  Reject the combination
    // at compile time rather than deferring to a runtime panic.
    if network_args.requires_qemu && backend.name != "qemu" {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            format!(
                "the selected NIC model requires the QEMU backend, but the \
                 current backend is `{backend}`; use #[in_vm(qemu)] with \
                 emulated NIC models like e1000 or e1000e",
                backend = backend.name,
            ),
        )
        .to_compile_error()
        .into();
    }

    // ── Code generation ──────────────────────────────────────────────

    let block = &func.block;
    let vis = &func.vis;
    let sig = &func.sig;
    let attrs = &func.attrs; // remaining attrs after companion extraction
    let ident = &func.sig.ident;

    let backend_path = &backend.path;
    let iommu = hypervisor_args.iommu;
    let host_page_size = &hypervisor_args.host_page_size;
    let guest_hugepages = &guest_args.guest_hugepages;
    let nic_model = &network_args.nic_model;

    // The three tiers are dispatched as a flat if-chain.
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
                ::n_vm::run_container_tier::<#backend_path, _>(
                    #ident,
                    ::n_vm::VmConfig {
                        iommu: #iommu,
                        host_page_size: #host_page_size,
                        guest_hugepages: #guest_hugepages,
                        nic_model: #nic_model,
                    },
                );
                return;
            }

            // Tier 1: Host -> Docker container
            ::n_vm::run_host_tier(#ident);
        }
    }
    .into()
}

/// Companion attribute for [`in_vm`] -- hypervisor configuration.
///
/// This attribute is consumed by the `#[in_vm]` proc macro and must
/// appear **below** it on the same function.
/// If it is expanded independently (wrong order or missing `#[in_vm]`),
/// it emits a compile error with a usage hint.
///
/// # Options
///
/// | Option | Values | Default | Description |
/// |--------|--------|---------|-------------|
/// | `iommu` | *(flag)* | off | Present a virtual IOMMU device to the guest |
/// | `host_pages` | `"4k"`, `"2m"`, `"1g"` | `"1g"` | Page size backing VM memory on the host |
///
/// `#[hypervisor]` with no parentheses is accepted and uses all
/// defaults.
///
/// # Example
///
/// ```ignore
/// #[test]
/// #[in_vm(qemu)]
/// #[hypervisor(iommu, host_pages = "4k")]
/// fn my_test() { /* … */ }
/// ```
#[proc_macro_attribute]
pub fn hypervisor(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[hypervisor] must be used together with #[in_vm] and must \
         appear below it on the same function; e.g.\n\n\
         #[in_vm]\n\
         #[hypervisor(iommu, host_pages = \"4k\")]\n\
         fn my_test() { ... }",
    )
    .to_compile_error();

    // Re-emit the original item so that downstream code does not see
    // cascading "not found" errors from the missing function.
    let input2: proc_macro2::TokenStream = input.into();
    quote! {
        #error
        #input2
    }
    .into()
}

/// Companion attribute for [`in_vm`] -- guest kernel configuration.
///
/// This attribute is consumed by the `#[in_vm]` proc macro and must
/// appear **below** it on the same function.
/// If it is expanded independently (wrong order or missing `#[in_vm]`),
/// it emits a compile error with a usage hint.
///
/// # Options
///
/// | Option | Values | Default | Description |
/// |--------|--------|---------|-------------|
/// | `hugepage_size` | `"none"`, `"2m"`, `"1g"` | `"1g"` | Guest hugepage reservation size |
/// | `hugepage_count` | integer | `1` | Number of guest hugepages to reserve |
///
/// When `hugepage_size = "none"`, guest hugepages are disabled entirely
/// (DPDK must use `--no-huge`), and `hugepage_count` must not be
/// specified.
///
/// `#[guest]` with no parentheses is accepted and uses all defaults.
///
/// # Example
///
/// ```ignore
/// #[test]
/// #[in_vm]
/// #[guest(hugepage_size = "2m", hugepage_count = 512)]
/// fn my_test() { /* … */ }
/// ```
#[proc_macro_attribute]
pub fn guest(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[guest] must be used together with #[in_vm] and must \
         appear below it on the same function; e.g.\n\n\
         #[in_vm]\n\
         #[guest(hugepage_size = \"2m\", hugepage_count = 512)]\n\
         fn my_test() { ... }",
    )
    .to_compile_error();

    // Re-emit the original item so that downstream code does not see
    // cascading "not found" errors from the missing function.
    let input2: proc_macro2::TokenStream = input.into();
    quote! {
        #error
        #input2
    }
    .into()
}

/// Companion attribute for [`in_vm`] -- network interface configuration.
///
/// This attribute is consumed by the `#[in_vm]` proc macro and must
/// appear **below** it on the same function.
/// If it is expanded independently (wrong order or missing `#[in_vm]`),
/// it emits a compile error with a usage hint.
///
/// # Options
///
/// | Option | Values | Default | Description |
/// |--------|--------|---------|-------------|
/// | `nic_model` | `"virtio_net"`, `"e1000"`, `"e1000e"` | `"virtio_net"` | NIC model for all interfaces |
///
/// The `e1000` (Intel 82540EM) and `e1000e` (Intel 82574L) models are
/// fully emulated legacy NICs supported by **QEMU only**.  Using them
/// with the cloud-hypervisor backend is a compile-time error.
///
/// `#[network]` with no parentheses is accepted and defaults to
/// `virtio_net`.
///
/// # Example
///
/// ```ignore
/// #[test]
/// #[in_vm(qemu)]
/// #[network(nic_model = "e1000e")]
/// fn my_test() { /* … */ }
/// ```
#[proc_macro_attribute]
pub fn network(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let error = syn::Error::new(
        proc_macro2::Span::call_site(),
        "#[network] must be used together with #[in_vm] and must \
         appear below it on the same function; e.g.\n\n\
         #[in_vm(qemu)]\n\
         #[network(nic_model = \"e1000\")]\n\
         fn my_test() { ... }",
    )
    .to_compile_error();

    // Re-emit the original item so that downstream code does not see
    // cascading "not found" errors from the missing function.
    let input2: proc_macro2::TokenStream = input.into();
    quote! {
        #error
        #input2
    }
    .into()
}
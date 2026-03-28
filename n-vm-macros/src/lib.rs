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
//! 1. **Host** (no env vars set) — the default when `cargo test` is invoked.
//!    Launches a Docker container via [`n_vm::run_test_in_vm`] with the
//!    required devices (`/dev/kvm`, `/dev/vhost-vsock`, etc.) and
//!    capabilities, then re-executes the same test binary inside it.
//!
//! 2. **Container** (`IN_TEST_CONTAINER=YES`) — inside the Docker container.
//!    Boots a cloud-hypervisor VM via [`n_vm::run_in_vm`], sharing the test
//!    binary into the guest via virtiofs, then re-executes the test inside
//!    the VM.
//!
//! 3. **VM guest** (`IN_VM=YES`) — inside the virtual machine, running under
//!    the `n-it` init system.  The original test body executes directly.
//!
//! # Usage
//!
//! ```ignore
//! use n_vm::in_vm;
//!
//! #[test]
//! #[in_vm]
//! fn my_test() {
//!     // This body runs inside an ephemeral VM.
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

/// Attribute macro that rewrites a test function to run inside an ephemeral VM.
///
/// See the [crate-level documentation](crate) for a full description of the
/// three-tier dispatch mechanism and usage examples.
///
/// # Compile-time validation
///
/// The macro rejects functions that are:
/// - **`async`** — the generated code creates its own tokio runtime at the
///   container tier, so the decorated function must be synchronous.
/// - **Parameterised** — the function is re-invoked by name as `fn()` inside
///   the VM guest, so it cannot accept arguments.
/// - **Non-unit return type** — the generated dispatch branches use bare
///   `return;` statements, so the function must return `()`.
///
/// # Panics
///
/// The generated code panics if:
/// - The Docker container exits with a non-zero code (host tier).
/// - The VM test output indicates failure (container tier).
/// - The tokio runtime cannot be created.
#[proc_macro_attribute]
pub fn in_vm(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let func = parse_macro_input!(input as syn::ItemFn);

    // ── Validate function signature ──────────────────────────────────

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

    if let ReturnType::Type(arrow, ref ty) = func.sig.output {
        return syn::Error::new_spanned(
            quote! { #arrow #ty },
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

    quote! {
        #(#attrs)*
        #vis #sig {
            match ::std::env::var(::n_vm::ENV_IN_VM) {
                Ok(var) if var == ::n_vm::ENV_MARKER_VALUE => {
                    {
                        #block
                    }
                    return;
                }
                _ => {
                    if let Ok(val) = ::std::env::var(::n_vm::ENV_IN_TEST_CONTAINER)
                        && val == ::n_vm::ENV_MARKER_VALUE
                    {
                        let runtime = ::tokio::runtime::Builder::new_current_thread()
                            .enable_io()
                            .enable_time()
                            .build()
                            .unwrap();
                        let _guard = runtime.enter();
                        runtime.block_on(async {
                            // Use try_init() to avoid panicking if a subscriber is already set
                            // (e.g. when multiple #[in_vm] tests run in the same binary).
                            let _ = ::tracing_subscriber::fmt()
                                .with_max_level(tracing::Level::INFO)
                                .with_thread_names(true)
                                .without_time()
                                .with_test_writer()
                                .with_line_number(true)
                                .with_target(true)
                                .with_file(true)
                                .try_init();
                            let _init_span = ::tracing::span!(tracing::Level::INFO, "hypervisor");
                            let _guard = _init_span.enter();
                            let output = ::n_vm::run_in_vm(#ident).await;
                            eprintln!("{output}");
                            assert!(output.success);
                        });
                        return;
                    }
                }
            }
            eprintln!("•─────⋅☾☾☾☾BEGIN NESTED TEST ENVIRONMENT☽☽☽☽⋅─────•");
            let container_state = ::n_vm::run_test_in_vm(#ident);
            eprintln!("•─────⋅☾☾☾☾ END NESTED TEST ENVIRONMENT ☽☽☽☽⋅─────•");
            if let Some(code) = container_state.exit_code {
                if code != 0 {
                    panic!("test container exited with code {code}");
                }
            } else {
                panic!("test container not return an exit code");
            }
        }
    }
    .into()
}
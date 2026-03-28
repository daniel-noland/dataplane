extern crate proc_macro;

use quote::quote;
use syn::parse_macro_input;

#[proc_macro_attribute]
pub fn in_vm(
    _attr: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let x = parse_macro_input!(input as syn::ItemFn);
    let block = x.block;
    let vis = x.vis;
    let sig = x.sig.clone();
    let attrs = x.attrs;
    let ident = x.sig.ident.clone();

    quote! {
        #(#attrs)*
        #vis #sig {
            match ::std::env::var(::n_vm_protocol::ENV_IN_VM) {
                Ok(var) if var == ::n_vm_protocol::ENV_MARKER_VALUE => {
                    {
                        #block
                    }
                    return;
                }
                _ => {
                    if let Ok(val) = ::std::env::var(::n_vm_protocol::ENV_IN_TEST_CONTAINER)
                        && val == ::n_vm_protocol::ENV_MARKER_VALUE
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
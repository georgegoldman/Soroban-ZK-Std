//! Procedural macros for [`soroban-zk-std`](https://docs.rs/soroban-zk-std).
//!
//! Use them through `soroban_zk_std` (they are re-exported behind its
//! default-on `macros` feature); the generated code refers to
//! `::soroban_zk_std` and `::soroban_sdk`, so both crates must be direct
//! dependencies of the calling crate.
//!
//! * [`include_snarkjs_vk!`] – embed a SnarkJS `verification_key.json` as a
//!   validated, zero-heap `const Groth16VerifyingKey<'static>`.
//! * [`snarkjs_vk!`] – the same, from an inline JSON string literal.
//! * [`#[zk_verifier]`](macro@zk_verifier) – turn an `impl` block into a
//!   Soroban `#[contractimpl]` exposing typed Groth16 verification entry
//!   points that emit structured events and (optionally) enforce anti-replay.
//!
//! All validation happens at compile time: malformed JSON, non-canonical
//! field elements, off-curve points and G2 points outside the prime-order
//! subgroup are reported as `compile_error!` diagnostics pointing at the macro
//! argument.

mod curve;
mod snarkjs;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, Expr, ExprLit, ItemImpl, Lit, LitStr, MetaNameValue, Token};

/// Embeds a SnarkJS Groth16 `verification_key.json` as a compile-time
/// constant.
///
/// The path is resolved relative to the `CARGO_MANIFEST_DIR` of the crate
/// invoking the macro (like `include_str!` from the crate root). Every G1
/// point is checked to be on BN254 (cofactor 1, so this implies subgroup
/// membership) and every G2 point is checked to be on the twist **and** in the
/// prime-order subgroup (`[r]P == O`). Any problem is a compile error.
///
/// The expansion is a `const`-evaluable expression of type
/// `soroban_zk_std::Groth16VerifyingKey<'static>`, so it can initialise a
/// `const` item and costs no heap allocation or storage read at runtime:
///
/// ```ignore
/// use soroban_zk_std::{include_snarkjs_vk, Groth16VerifyingKey};
///
/// pub const MY_VK: Groth16VerifyingKey<'static> =
///     include_snarkjs_vk!("circuits/verification_key.json");
/// ```
#[proc_macro]
pub fn include_snarkjs_vk(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    let rel = lit.value();
    let base = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => std::path::PathBuf::from(dir),
        Err(_) => {
            return error(
                lit.span(),
                "include_snarkjs_vk!: CARGO_MANIFEST_DIR is not set; build with cargo",
            )
        }
    };
    let path = base.join(&rel);
    let json = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            return error(
                lit.span(),
                &format!("include_snarkjs_vk!: failed to read SnarkJS verifying key `{rel}`: {e}"),
            )
        }
    };
    match snarkjs::parse(&json) {
        Ok(vk) => vk.to_tokens(path.to_str().filter(|p| !p.is_empty())).into(),
        Err(msg) => error(
            lit.span(),
            &format!("include_snarkjs_vk!(\"{rel}\"): {msg}"),
        ),
    }
}

/// Like [`include_snarkjs_vk!`], but takes the SnarkJS verifying-key JSON as
/// an inline string literal (handy for tests and generated code).
///
/// ```ignore
/// const VK: soroban_zk_std::Groth16VerifyingKey<'static> =
///     soroban_zk_std::snarkjs_vk!(r#"{ "protocol": "groth16", ... }"#);
/// ```
#[proc_macro]
pub fn snarkjs_vk(input: TokenStream) -> TokenStream {
    let lit = parse_macro_input!(input as LitStr);
    match snarkjs::parse(&lit.value()) {
        Ok(vk) => vk.to_tokens(None).into(),
        Err(msg) => error(lit.span(), &format!("snarkjs_vk!: {msg}")),
    }
}

fn error(span: Span, msg: &str) -> TokenStream {
    syn::Error::new(span, msg).to_compile_error().into()
}

/// Arguments of `#[zk_verifier(...)]`.
struct VerifierArgs {
    vk: Expr,
    anti_replay: bool,
    method: syn::Ident,
}

impl Parse for VerifierArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let pairs = Punctuated::<MetaNameValue, Token![,]>::parse_terminated(input)?;
        let mut protocol: Option<LitStr> = None;
        let mut vk: Option<Expr> = None;
        let mut anti_replay = false;
        let mut method = format_ident!("verify_proof");

        for nv in pairs {
            let key = nv
                .path
                .get_ident()
                .map(ToString::to_string)
                .unwrap_or_default();
            match key.as_str() {
                "protocol" => protocol = Some(lit_str(&nv.value, "protocol")?),
                "vk" => vk = Some(nv.value),
                "anti_replay" => match &nv.value {
                    Expr::Lit(ExprLit {
                        lit: Lit::Bool(b), ..
                    }) => anti_replay = b.value,
                    other => {
                        return Err(syn::Error::new_spanned(
                            other,
                            "`anti_replay` must be `true` or `false`",
                        ))
                    }
                },
                "method" => {
                    let s = lit_str(&nv.value, "method")?;
                    method = syn::parse_str::<syn::Ident>(&s.value()).map_err(|_| {
                        syn::Error::new(s.span(), "`method` must be a valid Rust identifier")
                    })?;
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        &nv.path,
                        "unknown zk_verifier argument; expected `protocol`, `vk`, `anti_replay` or `method`",
                    ))
                }
            }
        }

        let protocol = protocol.ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "zk_verifier requires `protocol = \"groth16\"`",
            )
        })?;
        if protocol.value() != "groth16" {
            return Err(syn::Error::new(
                protocol.span(),
                format!(
                    "unsupported zk_verifier protocol \"{}\"; only \"groth16\" is supported",
                    protocol.value()
                ),
            ));
        }
        let vk = vk.ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "zk_verifier requires `vk = <const Groth16VerifyingKey>`",
            )
        })?;
        Ok(Self {
            vk,
            anti_replay,
            method,
        })
    }
}

fn lit_str(expr: &Expr, name: &str) -> syn::Result<LitStr> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => Ok(s.clone()),
        other => Err(syn::Error::new_spanned(
            other,
            format!("`{name}` must be a string literal"),
        )),
    }
}

/// Generates typed Soroban verification entry points for a contract.
///
/// Apply it to an inherent `impl` block of a `#[contract]` type **instead of**
/// `#[contractimpl]` (it adds `#[soroban_sdk::contractimpl]` itself, keeping
/// any methods you wrote in the block):
///
/// ```ignore
/// use soroban_sdk::contract;
/// use soroban_zk_std::{include_snarkjs_vk, zk_verifier, Groth16VerifyingKey};
///
/// const MY_VK: Groth16VerifyingKey<'static> = include_snarkjs_vk!("vk.json");
///
/// #[contract]
/// pub struct MyVerifier;
///
/// #[zk_verifier(protocol = "groth16", vk = MY_VK, anti_replay = true)]
/// impl MyVerifier {}
/// ```
///
/// Arguments:
/// * `protocol` – proof system; only `"groth16"` is supported.
/// * `vk` – a `Groth16VerifyingKey<'static>` expression, typically a `const`
///   built by [`include_snarkjs_vk!`].
/// * `anti_replay` (default `false`) – record a nullifier for every accepted
///   proof and reject resubmissions with `ZkContractError::ReplayDetected`.
/// * `method` (default `"verify_proof"`) – name of the generated entry point.
///
/// Generated methods:
/// * `fn <method>(env: Env, proof: BytesN<256>, public_inputs: Vec<U256>) -> Result<bool, ZkContractError>`
///   – decodes `A || B || C`, validates every public input, runs the pairing
///   check against the embedded key and publishes a `ZkVerificationEvent`
///   (see `EVENTS.md`) on success and on every failure stage. Returns
///   `Ok(false)` for a well-formed proof that does not verify.
/// * `fn is_proof_spent(env: Env, proof: BytesN<256>, public_inputs: Vec<U256>) -> bool`
///   – only when `anti_replay = true`.
#[proc_macro_attribute]
pub fn zk_verifier(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as VerifierArgs);
    let mut item = parse_macro_input!(item as ItemImpl);

    if let Some((_, path, _)) = &item.trait_ {
        return syn::Error::new_spanned(
            path,
            "#[zk_verifier] must be applied to an inherent `impl` block, not a trait impl",
        )
        .to_compile_error()
        .into();
    }
    if let Some(attr) = item.attrs.iter().find(|a| {
        a.path()
            .segments
            .last()
            .is_some_and(|s| s.ident == "contractimpl")
    }) {
        return syn::Error::new_spanned(
            attr,
            "#[zk_verifier] already applies #[contractimpl]; remove this attribute",
        )
        .to_compile_error()
        .into();
    }

    let VerifierArgs {
        vk,
        anti_replay,
        method,
    } = args;

    let verify_doc = format!(
        " Verifies a Groth16 proof (`A || B || C`, 256 bytes) against the embedded \
         verifying key and publishes a `ZkVerificationEvent`. Anti-replay: {anti_replay}."
    );
    let verify_fn: syn::ImplItem = syn::parse_quote! {
        #[doc = #verify_doc]
        pub fn #method(
            env: ::soroban_sdk::Env,
            proof: ::soroban_sdk::BytesN<256>,
            public_inputs: ::soroban_sdk::Vec<::soroban_sdk::U256>,
        ) -> ::core::result::Result<bool, ::soroban_zk_std::ZkContractError> {
            const __SOROBAN_ZK_VK: ::soroban_zk_std::Groth16VerifyingKey<'static> = #vk;
            ::soroban_zk_std::verifier::verify_groth16(
                &env,
                &__SOROBAN_ZK_VK,
                &proof,
                &public_inputs,
                #anti_replay,
            )
        }
    };
    item.items.push(verify_fn);

    if anti_replay {
        let spent_fn: syn::ImplItem = syn::parse_quote! {
            /// Returns `true` if this exact proof + public inputs were already
            /// accepted (anti-replay nullifier recorded).
            pub fn is_proof_spent(
                env: ::soroban_sdk::Env,
                proof: ::soroban_sdk::BytesN<256>,
                public_inputs: ::soroban_sdk::Vec<::soroban_sdk::U256>,
            ) -> bool {
                ::soroban_zk_std::verifier::is_proof_spent(&env, &proof, &public_inputs)
            }
        };
        item.items.push(spent_fn);
    }

    quote! {
        #[::soroban_sdk::contractimpl]
        #item
    }
    .into()
}

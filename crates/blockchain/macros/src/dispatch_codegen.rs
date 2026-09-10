//! `#[contract_dispatch]` codegen.
//!
//! Generates an ABI dispatch function and a private `sol!` interface from
//! methods annotated with `#[contract_public("sig")]`. Helper markers
//! `#[contract_view]` and `#[contract_payable]` select the dispatch helper
//! (read-only / caller / caller+value).

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use std::str::FromStr;
use syn::{
    parse_macro_input, spanned::Spanned, FnArg, GenericArgument, ImplItem, ItemImpl, LitStr, Pat,
    PathArguments, ReturnType, Type,
};

pub fn expand_dispatch(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemImpl);
    match generate(input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MethodKind {
    View,
    Mutating,
    Payable,
}

struct DispatchMethod {
    rust_name: syn::Ident,
    kind: MethodKind,
    sig_name: String,
    sig_arg_types: Vec<String>,
    sig_tail: String,
    abi_arg_names: Vec<syn::Ident>,
    returns_unit: bool,
}

fn generate(mut input: ItemImpl) -> syn::Result<TokenStream2> {
    let contract_name = self_type_last_ident(&input.self_ty)?;

    let mut methods: Vec<DispatchMethod> = Vec::new();

    for item in input.items.iter_mut() {
        let ImplItem::Fn(func) = item else { continue };

        let mut sig_str: Option<LitStr> = None;
        let mut is_view = false;
        let mut is_payable = false;
        let mut keep_attrs = Vec::with_capacity(func.attrs.len());

        for attr in std::mem::take(&mut func.attrs) {
            if attr.path().is_ident("contract_public") {
                if sig_str.is_some() {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "duplicate #[contract_public(\"...\")] on method",
                    ));
                }
                sig_str = Some(attr.parse_args()?);
            } else if attr.path().is_ident("contract_view") {
                is_view = true;
            } else if attr.path().is_ident("contract_payable") {
                is_payable = true;
            } else {
                keep_attrs.push(attr);
            }
        }
        func.attrs = keep_attrs;

        let Some(sig_lit) = sig_str else {
            if is_view || is_payable {
                return Err(syn::Error::new_spanned(
                    &func.sig.ident,
                    "#[contract_view] / #[contract_payable] require #[contract_public(\"...\")] on the same method",
                ));
            }
            continue;
        };

        if is_view && is_payable {
            return Err(syn::Error::new_spanned(
                &sig_lit,
                "#[contract_view] and #[contract_payable] are mutually exclusive",
            ));
        }

        let kind = if is_view {
            MethodKind::View
        } else if is_payable {
            MethodKind::Payable
        } else {
            MethodKind::Mutating
        };

        let parsed = parse_signature(&sig_lit)?;
        let abi_arg_names = collect_abi_arg_names(func, kind, &sig_lit)?;

        if abi_arg_names.len() != parsed.arg_types.len() {
            return Err(syn::Error::new_spanned(
                &sig_lit,
                format!(
                    "signature declares {} ABI argument(s) but method has {} non-special argument(s)",
                    parsed.arg_types.len(),
                    abi_arg_names.len()
                ),
            ));
        }

        methods.push(DispatchMethod {
            rust_name: func.sig.ident.clone(),
            kind,
            sig_name: parsed.name,
            sig_arg_types: parsed.arg_types,
            sig_tail: parsed.tail,
            abi_arg_names,
            returns_unit: result_returns_unit(&func.sig.output),
        });
    }

    if methods.is_empty() {
        return Err(syn::Error::new_spanned(
            &input,
            "#[contract_dispatch] requires at least one method annotated with #[contract_public(\"...\")]",
        ));
    }

    let interface_ident = format_ident!("__{}Abi", contract_name);
    let calls_ident = format_ident!("__{}AbiCalls", contract_name);

    let interface_decl = build_sol_interface(&interface_ident, &methods, input.span())?;
    let any_payable = methods.iter().any(|m| m.kind == MethodKind::Payable);
    let arms = methods
        .iter()
        .map(build_match_arm)
        .collect::<syn::Result<Vec<_>>>()?;

    // With no payable method the whole contract refuses value up front. Once one
    // method is payable the boundary credits value to this address, so the
    // contract refuses it for every selector it has not published instead -
    // dropping the check would let every other selector silently accept value it
    // has no accounting for.
    let reject_value = if any_payable {
        quote! {
            ::outbe_primitives::dispatch::reject_value_unless_payable(
                data,
                self::PAYABLE_SELECTORS,
                &value,
            )?;
        }
    } else {
        quote! { ::outbe_primitives::dispatch::reject_value(&value)?; }
    };

    let dispatch_fn = quote! {
        /// ABI dispatch entrypoint generated by `#[contract_dispatch]`.
        pub fn dispatch(
            storage: ::outbe_primitives::storage::StorageHandle,
            data: &[u8],
            caller: ::alloy_primitives::Address,
            value: ::alloy_primitives::U256,
        ) -> ::outbe_primitives::error::Result<::alloy_primitives::Bytes> {
            #reject_value
            ::outbe_primitives::dispatch::dispatch_call(
                data,
                <#interface_ident::#calls_ident as ::alloy_sol_types::SolInterface>::abi_decode,
                |call| {
                    let mut contract = #contract_name::new(storage);
                    let _ = caller;
                    let _ = value;
                    use #interface_ident::#calls_ident::*;
                    match call {
                        #(#arms),*
                    }
                },
            )
        }
    };

    Ok(quote! {
        #input
        #interface_decl
        #dispatch_fn
    })
}

fn build_match_arm(m: &DispatchMethod) -> syn::Result<TokenStream2> {
    let variant = syn::Ident::new(&m.sig_name, Span::call_site());
    let rust_name = &m.rust_name;
    let abi_arg_names = &m.abi_arg_names;
    let field_accesses: Vec<TokenStream2> = abi_arg_names.iter().map(|n| quote! { c.#n }).collect();

    Ok(match m.kind {
        MethodKind::View => quote! {
            #variant(c) => ::outbe_primitives::dispatch::view(
                c,
                |c| contract.#rust_name(#(#field_accesses),*),
            )
        },
        MethodKind::Mutating => {
            if m.returns_unit {
                quote! {
                    #variant(c) => ::outbe_primitives::dispatch::mutate_void(
                        c,
                        caller,
                        |sender, c| contract.#rust_name(sender, #(#field_accesses),*),
                    )
                }
            } else {
                quote! {
                    #variant(c) => ::outbe_primitives::dispatch::mutate(
                        c,
                        caller,
                        |sender, c| contract.#rust_name(sender, #(#field_accesses),*),
                    )
                }
            }
        }
        MethodKind::Payable => {
            if !m.returns_unit {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "#[contract_payable] on `{}` requires return type `Result<()>` (no `mutate_payable` helper yet)",
                        m.rust_name
                    ),
                ));
            }
            quote! {
                #variant(c) => ::outbe_primitives::dispatch::mutate_void_payable(
                    c,
                    self::PAYABLE_SELECTORS,
                    caller,
                    value,
                    |sender, c, v| contract.#rust_name(sender, v, #(#field_accesses),*),
                )
            }
        }
    })
}

fn build_sol_interface(
    interface_ident: &syn::Ident,
    methods: &[DispatchMethod],
    err_span: Span,
) -> syn::Result<TokenStream2> {
    let mut body = String::new();
    for m in methods {
        let typed_args: Vec<String> = m
            .sig_arg_types
            .iter()
            .zip(m.abi_arg_names.iter())
            .map(|(ty, name)| format!("{} {}", ty, name))
            .collect();
        let tail = if m.sig_tail.is_empty() {
            String::new()
        } else {
            format!(" {}", m.sig_tail)
        };
        body.push_str(&format!(
            "function {}({}) external{};\n",
            m.sig_name,
            typed_args.join(", "),
            tail,
        ));
    }

    let solidity = format!("interface {} {{\n{}}}", interface_ident, body);
    let body_tokens = TokenStream2::from_str(&solidity).map_err(|e| {
        syn::Error::new(
            err_span,
            format!("internal: failed to lex generated sol! interface: {e}"),
        )
    })?;

    Ok(quote! {
        #[allow(non_snake_case, non_camel_case_types, dead_code)]
        ::alloy_sol_types::sol! {
            #body_tokens
        }
    })
}

struct ParsedSig {
    name: String,
    arg_types: Vec<String>,
    tail: String,
}

fn parse_signature(lit: &LitStr) -> syn::Result<ParsedSig> {
    let raw = lit.value();
    let raw = raw.trim();

    let open = raw.find('(').ok_or_else(|| {
        syn::Error::new_spanned(lit, "signature missing '(' - expected `name(types) ...`")
    })?;
    let name = raw[..open].trim().to_string();
    if name.is_empty() || !is_valid_sol_ident(&name) {
        return Err(syn::Error::new_spanned(
            lit,
            format!("signature has invalid or empty function name: `{}`", name),
        ));
    }

    let mut depth = 1i32;
    let mut close = None;
    for (i, ch) in raw[open + 1..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + 1 + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let close =
        close.ok_or_else(|| syn::Error::new_spanned(lit, "signature missing matching ')'"))?;

    let inner = &raw[open + 1..close];
    let arg_types = if inner.trim().is_empty() {
        Vec::new()
    } else {
        split_top_level(inner)
    };

    let tail = raw[close + 1..].trim().to_string();

    Ok(ParsedSig {
        name,
        arg_types,
        tail,
    })
}

fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut depth = 0i32;
    for ch in s.chars() {
        match ch {
            '(' | '[' => {
                depth += 1;
                buf.push(ch);
            }
            ')' | ']' => {
                depth -= 1;
                buf.push(ch);
            }
            ',' if depth == 0 => {
                let trimmed = buf.trim();
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
                buf.clear();
            }
            _ => buf.push(ch),
        }
    }
    let trimmed = buf.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
    out
}

fn is_valid_sol_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn collect_abi_arg_names(
    func: &syn::ImplItemFn,
    kind: MethodKind,
    sig_lit: &LitStr,
) -> syn::Result<Vec<syn::Ident>> {
    let mut iter = func.sig.inputs.iter();
    let first = iter.next().ok_or_else(|| {
        syn::Error::new_spanned(
            &func.sig,
            "method must take a receiver (`&self` or `&mut self`)",
        )
    })?;
    if !matches!(first, FnArg::Receiver(_)) {
        return Err(syn::Error::new_spanned(
            first,
            "first parameter must be a receiver (`&self` or `&mut self`)",
        ));
    }

    let remaining: Vec<&FnArg> = iter.collect();

    let abi_args = match kind {
        MethodKind::View => &remaining[..],
        MethodKind::Mutating => {
            let caller = remaining.first().ok_or_else(|| {
                syn::Error::new_spanned(
                    sig_lit,
                    "mutating (default) method must take `caller: Address` as first parameter after `&mut self`",
                )
            })?;
            check_arg_type(caller, "Address")?;
            &remaining[1..]
        }
        MethodKind::Payable => {
            if remaining.len() < 2 {
                return Err(syn::Error::new_spanned(
                    sig_lit,
                    "#[contract_payable] method must take `caller: Address, value: U256` as first two parameters after `&mut self`",
                ));
            }
            check_arg_type(remaining[0], "Address")?;
            check_arg_type(remaining[1], "U256")?;
            &remaining[2..]
        }
    };

    abi_args.iter().map(|a| arg_ident(a)).collect()
}

fn arg_ident(arg: &FnArg) -> syn::Result<syn::Ident> {
    let FnArg::Typed(pat) = arg else {
        return Err(syn::Error::new_spanned(
            arg,
            "expected named typed argument",
        ));
    };
    let Pat::Ident(pi) = &*pat.pat else {
        return Err(syn::Error::new_spanned(
            arg,
            "argument must be a plain identifier (no patterns)",
        ));
    };
    Ok(pi.ident.clone())
}

fn check_arg_type(arg: &FnArg, expected: &str) -> syn::Result<()> {
    let FnArg::Typed(pat) = arg else {
        return Err(syn::Error::new_spanned(
            arg,
            format!("expected typed argument of type `{}`", expected),
        ));
    };
    let actual = type_last_ident(&pat.ty).unwrap_or_default();
    if actual != expected {
        return Err(syn::Error::new_spanned(
            &pat.ty,
            format!("expected `{}`, found `{}`", expected, actual),
        ));
    }
    Ok(())
}

fn type_last_ident(ty: &Type) -> Option<String> {
    if let Type::Path(p) = ty {
        return Some(p.path.segments.last()?.ident.to_string());
    }
    None
}

fn self_type_last_ident(ty: &Type) -> syn::Result<syn::Ident> {
    if let Type::Path(p) = ty {
        if let Some(seg) = p.path.segments.last() {
            return Ok(seg.ident.clone());
        }
    }
    Err(syn::Error::new_spanned(
        ty,
        "#[contract_dispatch] expects `impl <ContractTypeName>` (a path type)",
    ))
}

fn result_returns_unit(out: &ReturnType) -> bool {
    let ReturnType::Type(_, ty) = out else {
        return true;
    };
    let Type::Path(p) = &**ty else { return false };
    let Some(seg) = p.path.segments.last() else {
        return false;
    };
    if seg.ident != "Result" {
        return false;
    }
    let PathArguments::AngleBracketed(args) = &seg.arguments else {
        return false;
    };
    let Some(GenericArgument::Type(inner)) = args.args.first() else {
        return false;
    };
    matches!(inner, Type::Tuple(t) if t.elems.is_empty())
}

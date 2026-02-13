use quote::ToTokens;
use syn::{Attribute, ItemFn, ItemStruct};

pub struct AnchorExtractor;

impl AnchorExtractor {
    pub fn is_anchor_account(s: &ItemStruct) -> bool {
        Self::has_macro_attribute(&s.attrs, "account")
    }

    pub fn is_instruction_context(s: &ItemStruct) -> bool {
        // Often #[derive(Accounts)]
        s.attrs.iter().any(|attr| {
            if attr.path().is_ident("derive") {
                let code = attr.to_token_stream().to_string();
                code.contains("Accounts")
            } else {
                false
            }
        })
    }

    pub fn is_program_module(_f: &ItemFn) -> bool {
        // Not trivial on ItemFn, but placeholder logic
        // Use _f to suppress unused variable warning
        false
    }

    fn has_macro_attribute(attrs: &[Attribute], name: &str) -> bool {
        attrs.iter().any(|attr| attr.path().is_ident(name))
    }
}

use std::fs;
use std::path::Path;
use syn::{parse_file, File, Item, ItemFn, ItemStruct};

pub struct AstParser;

impl AstParser {
    pub fn parse_file(path: &Path) -> Result<File, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let syntax = parse_file(&content)?;
        Ok(syntax)
    }

    pub fn find_functions(file: &File) -> Vec<&ItemFn> {
        file.items
            .iter()
            .filter_map(|item| {
                if let Item::Fn(f) = item {
                    Some(f)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn find_structs(file: &File) -> Vec<&ItemStruct> {
        file.items
            .iter()
            .filter_map(|item| {
                if let Item::Struct(s) = item {
                    Some(s)
                } else {
                    None
                }
            })
            .collect()
    }
}

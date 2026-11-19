use crate::types::{
    sha256_prefixed, ByteSpan, CstEdit, DynamicSite, Language, MdeError, MdeResult, Zone,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use tree_sitter::{Node, Parser, Tree};

#[derive(Debug, Clone)]
pub struct ParsedSymbol {
    pub symbol: String,
    pub kind: String,
    pub zone: Zone,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
    pub span_sha256: String,
}

#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub language: Language,
    pub cst_root_sha256: String,
    pub dominant_zone: Zone,
    pub zone_bytes: BTreeMap<String, usize>,
    pub symbols: Vec<ParsedSymbol>,
    pub error_spans: Vec<ByteSpan>,
    pub macro_opaque_spans: Vec<ByteSpan>,
    pub dynamic_sites: Vec<DynamicSite>,
}

pub fn detect_language(path: &str) -> Language {
    let ext = Path::new(path)
        .extension()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "rs" => Language::Rust,
        "py" => Language::Python,
        "c" | "h" => Language::C,
        "ts" | "mts" | "cts" => Language::Typescript,
        "tsx" | "jsx" => Language::Tsx,
        "md" | "markdown" | "txt" | "rst" => Language::Markdown,
        "lean" => Language::Lean,
        "css" | "scss" | "html" | "htm" | "svg" | "svelte" | "vue" => Language::UiText,
        "json" | "jsonl" | "toml" | "yaml" | "yml" => Language::Json,
        _ => Language::Plain,
    }
}

fn ts_language(lang: Language) -> Option<tree_sitter::Language> {
    match lang {
        Language::Rust => Some(tree_sitter_rust::LANGUAGE.into()),
        Language::Python => Some(tree_sitter_python::LANGUAGE.into()),
        Language::C => Some(tree_sitter_c::LANGUAGE.into()),
        Language::Typescript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        Language::Tsx => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        _ => None,
    }
}

pub fn parse_tree(lang: Language, source: &[u8]) -> MdeResult<Option<Tree>> {
    let Some(ts_lang) = ts_language(lang) else {
        return Ok(None);
    };
    let mut parser = Parser::new();
    parser
        .set_language(&ts_lang)
        .map_err(|e| MdeError::new("ERR_PARSER_INIT", format!("language load failed: {e}")))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| MdeError::new("ERR_PARSE_FAILED", "tree-sitter returned no tree"))?;
    Ok(Some(tree))
}

pub fn analyze_file(path: &str, source: &[u8]) -> MdeResult<ParsedFile> {
    let language = detect_language(path);
    let mut zone_bytes: BTreeMap<String, usize> = BTreeMap::new();
    zone_bytes.insert("prose".to_string(), 0);
    zone_bytes.insert("code".to_string(), 0);
    zone_bytes.insert("formal_proof".to_string(), 0);
    zone_bytes.insert("ui_module".to_string(), 0);
    zone_bytes.insert("condensed_json".to_string(), 0);

    let Some(tree) = parse_tree(language, source)? else {
        let zone = default_zone_for_language(language, source);
        zone_bytes.insert(zone.as_str().to_string(), source.len());
        return Ok(ParsedFile {
            language,
            cst_root_sha256: sha256_prefixed(source),
            dominant_zone: zone,
            zone_bytes,
            symbols: Vec::new(),
            error_spans: Vec::new(),
            macro_opaque_spans: Vec::new(),
            dynamic_sites: Vec::new(),
        });
    };

    let root = tree.root_node();
    let cst_root_sha256 = sha256_prefixed(root.to_sexp().as_bytes());
    let mut symbols = Vec::new();
    let mut error_spans = Vec::new();
    let mut macro_opaque_spans = Vec::new();
    let mut dynamic_sites = Vec::new();

    walk_cst(
        root,
        path,
        language,
        source,
        &mut symbols,
        &mut error_spans,
        &mut macro_opaque_spans,
        &mut dynamic_sites,
        &mut zone_bytes,
    );

    let dominant_zone = compute_dominant_zone(language, &zone_bytes, source);

    Ok(ParsedFile {
        language,
        cst_root_sha256,
        dominant_zone,
        zone_bytes,
        symbols,
        error_spans,
        macro_opaque_spans,
        dynamic_sites,
    })
}

fn default_zone_for_language(language: Language, source: &[u8]) -> Zone {
    match language {
        Language::Lean => Zone::FormalProof,
        Language::Json => Zone::CondensedJson,
        Language::Markdown | Language::Plain => {
            let text = String::from_utf8_lossy(source);
            if text.contains("```lean") || text.contains("@formal-proof") || text.contains("data-eido-skip") {
                Zone::FormalProof
            } else {
                Zone::Prose
            }
        }
        Language::UiText | Language::Tsx => Zone::UiModule,
        _ => Zone::Code,
    }
}

fn compute_dominant_zone(
    language: Language,
    zone_bytes: &BTreeMap<String, usize>,
    source: &[u8],
) -> Zone {
    let mut best_zone = default_zone_for_language(language, source);
    let mut best_count = 0usize;
    for (name, count) in zone_bytes {
        if *count > best_count {
            best_count = *count;
            best_zone = match name.as_str() {
                "prose" => Zone::Prose,
                "formal_proof" => Zone::FormalProof,
                "ui_module" => Zone::UiModule,
                "condensed_json" => Zone::CondensedJson,
                _ => Zone::Code,
            };
        }
    }
    best_zone
}

#[allow(clippy::too_many_arguments)]
fn walk_cst(
    node: Node,
    path: &str,
    language: Language,
    source: &[u8],
    symbols: &mut Vec<ParsedSymbol>,
    error_spans: &mut Vec<ByteSpan>,
    macro_opaque_spans: &mut Vec<ByteSpan>,
    dynamic_sites: &mut Vec<DynamicSite>,
    zone_bytes: &mut BTreeMap<String, usize>,
) {
    let kind = node.kind();
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    let start_line = node.start_position().row + 1;
    let end_line = node.end_position().row + 1;

    if node.is_error() || node.is_missing() {
        error_spans.push(ByteSpan {
            start_byte,
            end_byte,
            start_line,
            end_line,
            kind: if node.is_missing() {
                format!("MISSING:{kind}")
            } else {
                "ERROR".to_string()
            },
        });
    }

    if is_macro_opaque_node(language, kind) {
        macro_opaque_spans.push(ByteSpan {
            start_byte,
            end_byte,
            start_line,
            end_line,
            kind: kind.to_string(),
        });
    }

    if let Some(dyn_kind) = detect_dynamic_site(language, node, source) {
        let slice = &source[start_byte..end_byte.min(source.len())];
        let snippet = String::from_utf8_lossy(slice)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .chars()
            .take(80)
            .collect();
        dynamic_sites.push(DynamicSite {
            path: path.to_string(),
            line: start_line,
            kind: dyn_kind,
            snippet,
        });
    }

    if let Some((sym_name, zone)) = extract_symbol_and_zone(language, node, source) {
        let slice = &source[start_byte..end_byte.min(source.len())];
        let entry = zone_bytes.entry(zone.as_str().to_string()).or_insert(0);
        *entry += slice.len();
        symbols.push(ParsedSymbol {
            symbol: sym_name,
            kind: kind.to_string(),
            zone,
            start_byte,
            end_byte,
            start_line,
            end_line,
            span_sha256: sha256_prefixed(slice),
        });
    } else if is_doc_or_ui_leaf(language, node, source) {
        let zone = classify_node_zone(language, node, source);
        let len = end_byte.saturating_sub(start_byte);
        let entry = zone_bytes.entry(zone.as_str().to_string()).or_insert(0);
        *entry += len;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_cst(
            child,
            path,
            language,
            source,
            symbols,
            error_spans,
            macro_opaque_spans,
            dynamic_sites,
            zone_bytes,
        );
    }
}

fn is_macro_opaque_node(language: Language, kind: &str) -> bool {
    match language {
        Language::C => matches!(
            kind,
            "preproc_if"
                | "preproc_ifdef"
                | "preproc_elif"
                | "preproc_else"
                | "preproc_def"
                | "preproc_function_def"
        ),
        Language::Rust => matches!(kind, "macro_definition" | "macro_invocation" | "macro_rule"),
        _ => false,
    }
}

fn detect_dynamic_site(language: Language, node: Node, source: &[u8]) -> Option<String> {
    let kind = node.kind();
    let text = node_text(node, source);
    match language {
        Language::Rust => {
            if kind == "unsafe_block" {
                return Some("rust_unsafe_block".to_string());
            }
            if kind == "foreign_mod_item" {
                return Some("rust_extern_ffi".to_string());
            }
            None
        }
        Language::Python => {
            if kind == "call" {
                if let Some(func) = node.child_by_field_name("function") {
                    let fname = node_text(func, source);
                    if matches!(fname, "getattr" | "setattr" | "eval" | "exec" | "__import__") {
                        return Some(format!("python_dynamic_{fname}"));
                    }
                }
            }
            None
        }
        Language::C => {
            if kind == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let fname = node_text(func, source);
                    if fname == "dlsym" || func.kind() == "parenthesized_expression" {
                        return Some("c_indirect_or_dlsym_call".to_string());
                    }
                }
            }
            None
        }
        Language::Typescript | Language::Tsx => {
            if kind == "call_expression" {
                if let Some(func) = node.child_by_field_name("function") {
                    let fname = node_text(func, source);
                    if matches!(fname, "eval" | "import" | "Function") {
                        return Some(format!("ts_dynamic_{fname}"));
                    }
                }
            }
            if kind == "new_expression" && text.starts_with("new Function") {
                return Some("ts_dynamic_Function".to_string());
            }
            None
        }
        _ => None,
    }
}

fn is_doc_or_ui_leaf(language: Language, node: Node, source: &[u8]) -> bool {
    let kind = node.kind();
    match language {
        Language::Rust => {
            if matches!(kind, "line_comment" | "block_comment") {
                let t = node_text(node, source);
                return t.starts_with("///") || t.starts_with("//!") || t.starts_with("/**");
            }
            false
        }
        Language::Python => kind == "comment",
        Language::C => kind == "comment",
        Language::Tsx | Language::Typescript => {
            matches!(kind, "jsx_element" | "jsx_self_closing_element" | "comment")
        }
        _ => false,
    }
}

fn classify_node_zone(language: Language, node: Node, source: &[u8]) -> Zone {
    let text = node_text(node, source);
    if text.contains("@formal-proof")
        || text.contains("data-eido-skip")
        || text.contains("theorem ")
        || text.contains("lemma ")
    {
        return Zone::FormalProof;
    }
    if text.contains("@ui-module")
        || matches!(
            node.kind(),
            "jsx_element" | "jsx_self_closing_element" | "jsx_fragment"
        )
        || (language == Language::Tsx && (text.contains('<') && text.contains("/>")))
    {
        return Zone::UiModule;
    }
    if matches!(
        node.kind(),
        "line_comment" | "block_comment" | "comment" | "string"
    ) {
        return Zone::Prose;
    }
    if language == Language::Tsx && has_jsx_descendant(node) {
        return Zone::UiModule;
    }
    Zone::Code
}

fn has_jsx_descendant(node: Node) -> bool {
    if matches!(
        node.kind(),
        "jsx_element" | "jsx_self_closing_element" | "jsx_fragment"
    ) {
        return true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if has_jsx_descendant(child) {
            return true;
        }
    }
    false
}

fn extract_symbol_and_zone(
    language: Language,
    node: Node,
    source: &[u8],
) -> Option<(String, Zone)> {
    let kind = node.kind();
    let is_decl = match language {
        Language::Rust => matches!(
            kind,
            "function_item" | "struct_item" | "enum_item" | "trait_item" | "impl_item" | "mod_item"
        ),
        Language::Python => matches!(kind, "function_definition" | "class_definition"),
        Language::C => matches!(
            kind,
            "function_definition" | "struct_specifier" | "enum_specifier" | "type_definition"
        ),
        Language::Typescript | Language::Tsx => matches!(
            kind,
            "function_declaration"
                | "class_declaration"
                | "method_definition"
                | "interface_declaration"
                | "type_alias_declaration"
        ),
        _ => false,
    };

    if !is_decl {
        // Also expose Rust doc comments & Python docstrings as Prose spans.
        if language == Language::Rust && matches!(kind, "line_comment" | "block_comment") {
            let t = node_text(node, source);
            if t.starts_with("///") || t.starts_with("//!") || t.starts_with("/**") {
                let line = node.start_position().row + 1;
                return Some((format!("doc@L{line}"), classify_node_zone(language, node, source)));
            }
        }
        return None;
    }

    let name = extract_decl_name(language, node, source)
        .unwrap_or_else(|| format!("anonymous_{kind}@L{}", node.start_position().row + 1));
    let zone = classify_node_zone(language, node, source);
    Some((name, zone))
}

fn extract_decl_name(language: Language, node: Node, source: &[u8]) -> Option<String> {
    if let Some(name_node) = node.child_by_field_name("name") {
        return Some(node_text(name_node, source).trim().to_string());
    }
    if language == Language::C && node.kind() == "function_definition" {
        if let Some(decl) = node.child_by_field_name("declarator") {
            return find_first_identifier(decl, source);
        }
    }
    if language == Language::Rust && node.kind() == "impl_item" {
        if let Some(ty) = node.child_by_field_name("type") {
            return Some(format!("impl {}", node_text(ty, source).trim()));
        }
    }
    None
}

fn find_first_identifier(node: Node, source: &[u8]) -> Option<String> {
    if matches!(node.kind(), "identifier" | "type_identifier") {
        return Some(node_text(node, source).to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(id) = find_first_identifier(child, source) {
            return Some(id);
        }
    }
    None
}

fn node_text<'a>(node: Node, source: &'a [u8]) -> &'a str {
    let start = node.start_byte().min(source.len());
    let end = node.end_byte().min(source.len());
    std::str::from_utf8(&source[start..end]).unwrap_or("")
}

fn spans_intersect(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    if a_start == a_end {
        return a_start >= b_start && a_start <= b_end;
    }
    if b_start == b_end {
        return b_start >= a_start && b_start <= a_end;
    }
    a_start < b_end && b_start < a_end
}

/// Apply raw byte-span CST edits cleanly without AST pretty-printing.
/// Guarantees 0-byte identity when `edits` is empty (G1.1), preserves untouched bytes (G1.2),
/// refuses edits inside ERROR/MISSING regions (G1.3) or macro-opaque regions (G1.4),
/// and re-parses the patched output to ensure zero newly introduced syntax errors.
pub fn apply_byte_span_edits(
    path: &str,
    original: &[u8],
    edits: &[CstEdit],
) -> MdeResult<Vec<u8>> {
    if edits.is_empty() {
        return Ok(original.to_vec());
    }

    let parsed_before = analyze_file(path, original)?;

    // Check every edit span for bounds, old-bytes SHA-256 match, syntax errors, and macros.
    for edit in edits {
        if edit.start_byte > edit.end_byte || edit.end_byte > original.len() {
            return Err(MdeError::with_detail(
                "ERR_INVALID_SPAN",
                format!(
                    "edit span {}..{} out of bounds for {} ({} bytes)",
                    edit.start_byte,
                    edit.end_byte,
                    path,
                    original.len()
                ),
                json!({"path": path, "start_byte": edit.start_byte, "end_byte": edit.end_byte}),
            ));
        }

        let actual_old = sha256_prefixed(&original[edit.start_byte..edit.end_byte]);
        if actual_old != edit.expected_old_sha256 {
            return Err(MdeError::with_detail(
                "ERR_STALE_SPAN",
                format!("span content mismatch in {path}"),
                json!({
                    "expected_old_sha256": edit.expected_old_sha256,
                    "actual_old_sha256": actual_old
                }),
            ));
        }

        // Gate G1.3: hard refusal if target span intersects or sits inside ERROR/MISSING.
        for err_span in &parsed_before.error_spans {
            if spans_intersect(
                edit.start_byte,
                edit.end_byte,
                err_span.start_byte,
                err_span.end_byte,
            ) {
                return Err(MdeError::with_detail(
                    "ERR_SYNTAX_ERROR_REGION",
                    format!(
                        "refusing splice inside broken syntax region {}..{}",
                        err_span.start_byte, err_span.end_byte
                    ),
                    json!({"damaged_span": err_span}),
                ));
            }
        }

        // Also check Tree-sitter ancestor chain directly for ERROR/MISSING ancestors.
        if let Some(tree) = parse_tree(parsed_before.language, original)? {
            let root = tree.root_node();
            if root.has_error() {
                if let Some(mut cur) =
                    root.descendant_for_byte_range(edit.start_byte, edit.end_byte.max(edit.start_byte))
                {
                    let mut is_target = true;
                    loop {
                        let tainted = if is_target {
                            cur.is_error() || cur.is_missing() || cur.has_error()
                        } else {
                            cur.is_error() || cur.is_missing()
                        };
                        if tainted {
                            return Err(MdeError::with_detail(
                                "ERR_SYNTAX_ERROR_REGION",
                                format!(
                                    "refusing splice under ERROR-tainted CST node ({} {}..{})",
                                    cur.kind(),
                                    cur.start_byte(),
                                    cur.end_byte()
                                ),
                                json!({
                                    "damaged_span": {
                                        "start_byte": cur.start_byte(),
                                        "end_byte": cur.end_byte(),
                                        "kind": cur.kind()
                                    }
                                }),
                            ));
                        }
                        is_target = false;
                        match cur.parent() {
                            Some(p) => cur = p,
                            None => break,
                        }
                    }
                }
            }
        }

        // Gate G1.4: hard refusal on macro/preprocessor opaque spans.
        for macro_span in &parsed_before.macro_opaque_spans {
            if spans_intersect(
                edit.start_byte,
                edit.end_byte,
                macro_span.start_byte,
                macro_span.end_byte,
            ) {
                return Err(MdeError::with_detail(
                    "ERR_MACRO_OPAQUE",
                    format!(
                        "refusing splice intersecting macro-opaque region {} ({}..{})",
                        macro_span.kind, macro_span.start_byte, macro_span.end_byte
                    ),
                    json!({"macro_span": macro_span}),
                ));
            }
        }
    }

    // Sort edits by start_byte ascending to detect overlaps, then apply in reverse order.
    let mut ordered: Vec<&CstEdit> = edits.iter().collect();
    ordered.sort_by_key(|e| (e.start_byte, e.end_byte));
    for win in ordered.windows(2) {
        if win[0].end_byte > win[1].start_byte {
            return Err(MdeError::new(
                "ERR_OVERLAPPING_SPANS",
                format!(
                    "overlapping edit spans {}..{} and {}..{}",
                    win[0].start_byte, win[0].end_byte, win[1].start_byte, win[1].end_byte
                ),
            ));
        }
    }

    let mut result = original.to_vec();
    for edit in ordered.into_iter().rev() {
        let mut next = Vec::with_capacity(
            result.len() - (edit.end_byte - edit.start_byte) + edit.replacement_utf8.len(),
        );
        next.extend_from_slice(&result[..edit.start_byte]);
        next.extend_from_slice(edit.replacement_utf8.as_bytes());
        next.extend_from_slice(&result[edit.end_byte..]);
        result = next;
    }

    // Re-parse patched bytes to ensure zero newly introduced syntax errors.
    let parsed_after = analyze_file(path, &result)?;
    if parsed_after.error_spans.len() > parsed_before.error_spans.len() {
        return Err(MdeError::with_detail(
            "ERR_PATCH_INTRODUCED_SYNTAX_ERROR",
            "patched bytes introduced Tree-sitter ERROR or MISSING nodes",
            json!({"error_spans": parsed_after.error_spans}),
        ));
    }

    Ok(result)
}

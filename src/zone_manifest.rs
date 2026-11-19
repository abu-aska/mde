use crate::types::{canonical_json_sha256, MdeError, MdeResult, Zone, MDE_VERSION};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const ZONE_MANIFEST_SCHEMA: &str = "zone-manifest/v0.1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneProtectionFlags {
    pub protect_axioms: bool,
    pub protect_sha_digests: bool,
    pub protect_exact_keys: bool,
    pub respect_data_eido_skip: bool,
    pub preserve_sibling_comments: bool,
    pub enforce_prose_guard: bool,
    pub prose_rewrite_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZoneRule {
    pub zone: Zone,
    pub l1_bank_tag: u8,
    pub file_extensions: Vec<String>,
    pub tree_sitter_languages: Vec<String>,
    pub cst_node_kinds: Vec<String>,
    pub inline_markers: Vec<String>,
    pub protection_flags: ZoneProtectionFlags,
    pub default_l2_scales: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZoneManifest {
    pub schema: String,
    pub manifest_id: String,
    pub mde_version: String,
    pub precedence_order: Vec<Zone>,
    pub zones: Vec<ZoneRule>,
}

fn scales(corpus: f64, weft_eido: f64, formal: f64) -> BTreeMap<String, f64> {
    let mut map = BTreeMap::new();
    map.insert("corpus".to_string(), corpus);
    map.insert("weft-eido".to_string(), weft_eido);
    map.insert("formal-verification".to_string(), formal);
    map
}

/// Build the canonical, SHA-256 content-addressed L5-to-L2 Vertical Zone Manifest.
pub fn build_zone_manifest() -> MdeResult<ZoneManifest> {
    let zones = vec![
        ZoneRule {
            zone: Zone::FormalProof,
            l1_bank_tag: 3,
            file_extensions: vec!["lean".to_string()],
            tree_sitter_languages: vec![
                "rust".to_string(),
                "python".to_string(),
                "c".to_string(),
                "typescript".to_string(),
            ],
            cst_node_kinds: vec![
                "function_item".to_string(),
                "function_definition".to_string(),
                "line_comment".to_string(),
                "block_comment".to_string(),
            ],
            inline_markers: vec![
                "@formal-proof".to_string(),
                "data-eido-skip".to_string(),
                "theorem ".to_string(),
                "lemma ".to_string(),
                "```lean".to_string(),
            ],
            protection_flags: ZoneProtectionFlags {
                protect_axioms: true,
                protect_sha_digests: true,
                protect_exact_keys: true,
                respect_data_eido_skip: true,
                preserve_sibling_comments: true,
                enforce_prose_guard: false,
                prose_rewrite_allowed: false,
            },
            default_l2_scales: scales(0.0, 0.0, 1.0),
        },
        ZoneRule {
            zone: Zone::CondensedJson,
            l1_bank_tag: 4,
            file_extensions: vec![
                "json".to_string(),
                "jsonl".to_string(),
                "toml".to_string(),
                "yaml".to_string(),
                "yml".to_string(),
            ],
            tree_sitter_languages: Vec::new(),
            cst_node_kinds: Vec::new(),
            inline_markers: Vec::new(),
            protection_flags: ZoneProtectionFlags {
                protect_axioms: false,
                protect_sha_digests: true,
                protect_exact_keys: true,
                respect_data_eido_skip: true,
                preserve_sibling_comments: false,
                enforce_prose_guard: false,
                prose_rewrite_allowed: false,
            },
            default_l2_scales: scales(0.0, 0.0, 0.0),
        },
        ZoneRule {
            zone: Zone::UiModule,
            l1_bank_tag: 2,
            file_extensions: vec![
                "tsx".to_string(),
                "jsx".to_string(),
                "css".to_string(),
                "scss".to_string(),
                "html".to_string(),
                "htm".to_string(),
                "svg".to_string(),
                "svelte".to_string(),
                "vue".to_string(),
            ],
            tree_sitter_languages: vec!["tsx".to_string(), "typescript".to_string()],
            cst_node_kinds: vec![
                "jsx_element".to_string(),
                "jsx_self_closing_element".to_string(),
                "jsx_fragment".to_string(),
            ],
            inline_markers: vec!["@ui-module".to_string()],
            protection_flags: ZoneProtectionFlags {
                protect_axioms: false,
                protect_sha_digests: true,
                protect_exact_keys: false,
                respect_data_eido_skip: true,
                preserve_sibling_comments: true,
                enforce_prose_guard: false,
                prose_rewrite_allowed: false,
            },
            default_l2_scales: scales(0.2, 1.0, 0.0),
        },
        ZoneRule {
            zone: Zone::Code,
            l1_bank_tag: 1,
            file_extensions: vec![
                "rs".to_string(),
                "py".to_string(),
                "c".to_string(),
                "h".to_string(),
                "ts".to_string(),
                "mts".to_string(),
                "cts".to_string(),
            ],
            tree_sitter_languages: vec![
                "rust".to_string(),
                "python".to_string(),
                "c".to_string(),
                "typescript".to_string(),
            ],
            cst_node_kinds: vec![
                "function_item".to_string(),
                "struct_item".to_string(),
                "enum_item".to_string(),
                "trait_item".to_string(),
                "impl_item".to_string(),
                "function_definition".to_string(),
                "class_definition".to_string(),
                "function_declaration".to_string(),
                "class_declaration".to_string(),
                "method_definition".to_string(),
                "interface_declaration".to_string(),
                "type_alias_declaration".to_string(),
            ],
            inline_markers: Vec::new(),
            protection_flags: ZoneProtectionFlags {
                protect_axioms: false,
                protect_sha_digests: true,
                protect_exact_keys: false,
                respect_data_eido_skip: true,
                preserve_sibling_comments: true,
                enforce_prose_guard: false,
                prose_rewrite_allowed: false,
            },
            default_l2_scales: scales(0.4, 0.0, 0.5),
        },
        ZoneRule {
            zone: Zone::Prose,
            l1_bank_tag: 0,
            file_extensions: vec![
                "md".to_string(),
                "markdown".to_string(),
                "txt".to_string(),
                "rst".to_string(),
            ],
            tree_sitter_languages: vec![
                "rust".to_string(),
                "python".to_string(),
                "c".to_string(),
                "typescript".to_string(),
            ],
            cst_node_kinds: vec![
                "line_comment".to_string(),
                "block_comment".to_string(),
                "comment".to_string(),
                "string".to_string(),
            ],
            inline_markers: vec!["///".to_string(), "//!".to_string(), "/**".to_string()],
            protection_flags: ZoneProtectionFlags {
                protect_axioms: false,
                protect_sha_digests: true,
                protect_exact_keys: false,
                respect_data_eido_skip: false,
                preserve_sibling_comments: true,
                enforce_prose_guard: true,
                prose_rewrite_allowed: true,
            },
            default_l2_scales: scales(1.0, 0.0, 0.0),
        },
    ];

    let mut manifest = ZoneManifest {
        schema: ZONE_MANIFEST_SCHEMA.to_string(),
        manifest_id: String::new(),
        mde_version: MDE_VERSION.to_string(),
        precedence_order: vec![
            Zone::FormalProof,
            Zone::CondensedJson,
            Zone::UiModule,
            Zone::Code,
            Zone::Prose,
        ],
        zones,
    };
    manifest.manifest_id = canonical_json_sha256(&manifest, Some("manifest_id"))?;
    Ok(manifest)
}

pub fn verify_zone_manifest_file(path: &Path) -> MdeResult<ZoneManifest> {
    let raw_text = fs::read_to_string(path).map_err(|e| {
        MdeError::new(
            "ERR_IO",
            format!("failed to read zone manifest {}: {e}", path.display()),
        )
    })?;
    let on_disk: ZoneManifest = serde_json::from_str(&raw_text)
        .map_err(|e| MdeError::new("ERR_SERIALIZE", format!("invalid zone manifest json: {e}")))?;
    let recomputed = canonical_json_sha256(&on_disk, Some("manifest_id"))?;
    if recomputed != on_disk.manifest_id {
        return Err(MdeError::with_detail(
            "ERR_TAMPERED_MANIFEST",
            "zone manifest_id does not match canonical JSON digest",
            json!({"stored": on_disk.manifest_id, "computed": recomputed}),
        ));
    }
    let expected = build_zone_manifest()?;
    if on_disk != expected {
        return Err(MdeError::with_detail(
            "ERR_MANIFEST_DRIFT",
            "on-disk zone manifest differs from compiled mde zone rules",
            json!({"expected_id": expected.manifest_id, "actual_id": on_disk.manifest_id}),
        ));
    }
    Ok(on_disk)
}

//! AI-readable page snapshots using accessibility tree representation.
//!
//! Converts CDP `Accessibility.getFullAXTree` JSON responses into a compact
//! text representation suitable for language model consumption. Each interactive
//! element is tagged with an ID (`[1]`, `[2]`, etc.) that can be resolved back
//! to a CDP backend node for programmatic interaction.
//!
//! Security properties:
//! - Password fields are redacted by default (role-based detection).
//! - Sensitive ARIA labels (credit card, SSN patterns) are redacted.
//! - Control characters are stripped from all output.
//! - Per-node value length is capped (default 200 chars).
//! - Total snapshot size is capped with intelligent truncation.
//! - No raw HTML appears in output.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Controls how accessibility tree snapshots are rendered and sanitized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Maximum characters in the rendered text representation.
    pub max_chars: usize,
    /// Include node values in the text output.
    pub include_values: bool,
    /// Replace password field values with a redaction marker.
    pub redact_passwords: bool,
    /// Maximum character length for any single node value.
    pub max_value_len: usize,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            max_chars: 8000,
            include_values: true,
            redact_passwords: true,
            max_value_len: 200,
        }
    }
}

// ---------------------------------------------------------------------------
// Node types
// ---------------------------------------------------------------------------

/// A single node in the accessibility tree snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotNode {
    /// Display ID shown as `[id]` in the text representation.
    pub id: u32,
    /// ARIA role (e.g. "heading", "link", "textbox").
    pub role: String,
    /// Accessible name (label text, button text, etc.).
    pub name: String,
    /// Accessible value (text input contents, slider value, etc.).
    pub value: Option<String>,
    /// Child nodes.
    pub children: Vec<SnapshotNode>,
    /// Depth in the tree (0 = root).
    pub depth: usize,
    /// Whether this node is interactive (button, link, textbox, etc.).
    pub interactive: bool,
    /// Checked state for checkboxes/radio buttons.
    pub checked: Option<bool>,
    /// Whether the element is disabled.
    pub disabled: bool,
    /// Expanded state for collapsible elements.
    pub expanded: Option<bool>,
    /// CDP backend node ID for resolving back to DOM.
    pub backend_node_id: Option<i64>,
}

/// Lightweight reference to a node, used in the ID-to-node mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRef {
    /// Display ID (`[1]`, `[2]`, etc.).
    pub node_id: u32,
    /// CDP backend node ID for DOM operations.
    pub backend_node_id: Option<i64>,
    /// ARIA role.
    pub role: String,
    /// Accessible name.
    pub name: String,
}

/// Complete page snapshot with text representation and node mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageSnapshot {
    /// Flat list of all snapshot nodes (pre-order traversal).
    pub nodes: Vec<SnapshotNode>,
    /// Maps display IDs to node references for action resolution.
    pub node_map: HashMap<u32, NodeRef>,
    /// Rendered text representation of the accessibility tree.
    pub text_representation: String,
    /// Whether the text was truncated to fit within `max_chars`.
    pub truncated: bool,
    /// URL of the page at snapshot time.
    pub page_url: String,
    /// Title of the page at snapshot time.
    pub page_title: String,
}

// ---------------------------------------------------------------------------
// Interactive role detection
// ---------------------------------------------------------------------------

/// Roles that represent interactive elements the AI can act on.
const INTERACTIVE_ROLES: &[&str] = &[
    "button",
    "link",
    "textbox",
    "checkbox",
    "radio",
    "combobox",
    "listbox",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "option",
    "searchbox",
    "slider",
    "spinbutton",
    "switch",
    "tab",
    "treeitem",
];

/// Roles that are purely structural/invisible and should be skipped.
const SKIP_ROLES: &[&str] = &["none", "presentation"];

fn is_interactive_role(role: &str) -> bool {
    let lower = role.to_ascii_lowercase();
    INTERACTIVE_ROLES.iter().any(|r| *r == lower)
}

fn should_skip_node(node: &SnapshotNode) -> bool {
    let lower = node.role.to_ascii_lowercase();
    // Skip "none" and "presentation" roles unconditionally.
    if SKIP_ROLES.iter().any(|r| *r == lower) {
        return true;
    }
    // Skip "generic" nodes that have no name (purely structural wrappers).
    if lower == "generic" && node.name.is_empty() {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Security: redaction
// ---------------------------------------------------------------------------

const REDACTION_MARKER: &str = "***REDACTED***";

/// Patterns in node names/roles that indicate sensitive fields.
const SENSITIVE_NAME_PATTERNS: &[&str] = &[
    "password",
    "credit card",
    "card number",
    "cvv",
    "cvc",
    "social security",
    "ssn",
    "secret",
];

/// Returns true if a node's value should be redacted for security.
fn should_redact(node: &SnapshotNode, config: &SnapshotConfig) -> bool {
    if !config.redact_passwords {
        return false;
    }
    let role_lower = node.role.to_ascii_lowercase();
    let name_lower = node.name.to_ascii_lowercase();

    // Redact if role contains "password".
    if role_lower.contains("password") {
        return true;
    }

    // Redact textbox-like inputs whose name matches sensitive patterns.
    if role_lower == "textbox" || role_lower == "searchbox" || role_lower == "combobox" {
        for pattern in SENSITIVE_NAME_PATTERNS {
            if name_lower.contains(pattern) {
                return true;
            }
        }
    }

    // Redact any node whose name matches sensitive patterns (belt and suspenders).
    for pattern in SENSITIVE_NAME_PATTERNS {
        if name_lower.contains(pattern) {
            return true;
        }
    }

    false
}

/// Strip control characters from a string (except newline and tab).
fn sanitize_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// Truncate a string to `max_len` characters, appending "..." if truncated.
fn truncate_value(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
    format!("{truncated}...")
}

// ---------------------------------------------------------------------------
// Tree rendering
// ---------------------------------------------------------------------------

/// Render an accessibility tree to a compact text representation.
///
/// Format:
/// ```text
/// [1] heading 'Page Title'
///   [2] link 'Click here'
///   [3] textbox 'Search...'
/// ```
///
/// Nodes with `role = "none"`, `"presentation"`, or `"generic"` (with no name)
/// are skipped. Password and sensitive fields are redacted.
pub fn render_ax_tree(nodes: &[SnapshotNode], config: &SnapshotConfig) -> String {
    let mut output = String::new();
    for node in nodes {
        render_node(node, config, &mut output);
    }
    output
}

fn render_node(node: &SnapshotNode, config: &SnapshotConfig, output: &mut String) {
    if !should_skip_node(node) {
        let indent = "  ".repeat(node.depth);
        let mut line = format!("{indent}[{}] {}", node.id, sanitize_text(&node.role));

        // Name.
        if !node.name.is_empty() {
            let name = sanitize_text(&node.name);
            let name = truncate_value(&name, config.max_value_len);
            line.push_str(&format!(" '{name}'"));
        }

        // Value (with redaction).
        if config.include_values {
            if let Some(ref val) = node.value {
                if should_redact(node, config) {
                    line.push_str(&format!(" value={REDACTION_MARKER}"));
                } else {
                    let val = sanitize_text(val);
                    let val = truncate_value(&val, config.max_value_len);
                    line.push_str(&format!(" value='{val}'"));
                }
            } else if should_redact(node, config) && node.name.to_ascii_lowercase().contains("password") {
                // Even if value is None, mark the field as redacted so the AI
                // knows not to attempt reading it.
            }
        }

        // Boolean attributes -- only render when present.
        if let Some(checked) = node.checked {
            line.push_str(if checked { " checked" } else { " unchecked" });
        }
        if node.disabled {
            line.push_str(" disabled");
        }
        if let Some(expanded) = node.expanded {
            line.push_str(if expanded {
                " expanded"
            } else {
                " collapsed"
            });
        }

        line.push('\n');
        output.push_str(&line);
    }

    // Recurse into children.
    for child in &node.children {
        render_node(child, config, output);
    }
}

// ---------------------------------------------------------------------------
// Truncation
// ---------------------------------------------------------------------------

/// Apply truncation to fit within `max_chars`.
///
/// Strategy (in order):
/// 1. Remove non-interactive nodes.
/// 2. Remove deepest nodes first.
/// 3. Append `[...truncated]` marker.
pub fn truncate_snapshot(nodes: &[SnapshotNode], config: &SnapshotConfig) -> (String, bool) {
    // First pass: full render.
    let full = render_ax_tree(nodes, config);
    if full.len() <= config.max_chars {
        return (full, false);
    }

    // Second pass: interactive-only.
    let interactive_text = render_interactive_only(nodes, config);
    if interactive_text.len() <= config.max_chars.saturating_sub(TRUNCATION_MARKER.len()) {
        return (format!("{interactive_text}{TRUNCATION_MARKER}\n"), true);
    }

    // Third pass: interactive nodes, shallowest first, up to max_chars.
    let mut interactive_nodes = collect_interactive_flat(nodes);
    interactive_nodes.sort_by_key(|n| n.depth);

    let mut output = String::new();
    for node in &interactive_nodes {
        let line = render_single_node(node, config);
        if output.len() + line.len() + TRUNCATION_MARKER.len() + 1 > config.max_chars {
            break;
        }
        output.push_str(&line);
    }

    output.push_str(TRUNCATION_MARKER);
    output.push('\n');
    (output, true)
}

const TRUNCATION_MARKER: &str = "[...truncated]";

/// Render only interactive nodes from the tree.
fn render_interactive_only(nodes: &[SnapshotNode], config: &SnapshotConfig) -> String {
    let mut output = String::new();
    for node in nodes {
        render_interactive_node(node, config, &mut output);
    }
    output
}

fn render_interactive_node(node: &SnapshotNode, config: &SnapshotConfig, output: &mut String) {
    if node.interactive && !should_skip_node(node) {
        let line = render_single_node(node, config);
        output.push_str(&line);
    }
    for child in &node.children {
        render_interactive_node(child, config, output);
    }
}

/// Render a single node to one line (with indent and newline).
fn render_single_node(node: &SnapshotNode, config: &SnapshotConfig) -> String {
    let indent = "  ".repeat(node.depth);
    let mut line = format!("{indent}[{}] {}", node.id, sanitize_text(&node.role));

    if !node.name.is_empty() {
        let name = sanitize_text(&node.name);
        let name = truncate_value(&name, config.max_value_len);
        line.push_str(&format!(" '{name}'"));
    }

    if config.include_values {
        if let Some(ref val) = node.value {
            if should_redact(node, config) {
                line.push_str(&format!(" value={REDACTION_MARKER}"));
            } else {
                let val = sanitize_text(val);
                let val = truncate_value(&val, config.max_value_len);
                line.push_str(&format!(" value='{val}'"));
            }
        }
    }

    if let Some(checked) = node.checked {
        line.push_str(if checked { " checked" } else { " unchecked" });
    }
    if node.disabled {
        line.push_str(" disabled");
    }
    if let Some(expanded) = node.expanded {
        line.push_str(if expanded {
            " expanded"
        } else {
            " collapsed"
        });
    }

    line.push('\n');
    line
}

/// Collect all interactive nodes into a flat list.
fn collect_interactive_flat(nodes: &[SnapshotNode]) -> Vec<SnapshotNode> {
    let mut result = Vec::new();
    for node in nodes {
        collect_interactive_recurse(node, &mut result);
    }
    result
}

fn collect_interactive_recurse(node: &SnapshotNode, result: &mut Vec<SnapshotNode>) {
    if node.interactive {
        // Clone without children to avoid duplication.
        let mut leaf = node.clone();
        leaf.children = Vec::new();
        result.push(leaf);
    }
    for child in &node.children {
        collect_interactive_recurse(child, result);
    }
}

/// Filter nodes to keep only interactive ones (used externally if needed).
pub fn preserve_interactive(nodes: &[SnapshotNode]) -> Vec<SnapshotNode> {
    collect_interactive_flat(nodes)
}

// ---------------------------------------------------------------------------
// Node ID mapping
// ---------------------------------------------------------------------------

/// Build a mapping from display IDs to node references.
///
/// When the AI says "click [3]", this map resolves `3` to a [`NodeRef`]
/// containing the CDP `backend_node_id` needed to target the DOM element.
pub fn build_node_map(nodes: &[SnapshotNode]) -> HashMap<u32, NodeRef> {
    let mut map = HashMap::new();
    for node in nodes {
        build_node_map_recurse(node, &mut map);
    }
    map
}

fn build_node_map_recurse(node: &SnapshotNode, map: &mut HashMap<u32, NodeRef>) {
    map.insert(
        node.id,
        NodeRef {
            node_id: node.id,
            backend_node_id: node.backend_node_id,
            role: node.role.clone(),
            name: node.name.clone(),
        },
    );
    for child in &node.children {
        build_node_map_recurse(child, map);
    }
}

// ---------------------------------------------------------------------------
// CDP JSON parsing
// ---------------------------------------------------------------------------

/// Build a complete page snapshot from a CDP `Accessibility.getFullAXTree` response.
///
/// The `ax_tree_json` value should be the parsed JSON body of the CDP response,
/// which contains a top-level `"nodes"` array. Each node has fields like
/// `"nodeId"`, `"role"`, `"name"`, `"value"`, `"childIds"`, `"backendDOMNodeId"`,
/// and various properties.
///
/// This function:
/// 1. Parses the flat node list from CDP format.
/// 2. Builds a tree structure from parent-child relationships.
/// 3. Assigns sequential display IDs.
/// 4. Generates the text representation (with truncation if needed).
/// 5. Builds the node ID map.
pub fn build_snapshot(
    ax_tree_json: &serde_json::Value,
    config: &SnapshotConfig,
    page_url: &str,
    page_title: &str,
) -> Result<PageSnapshot, SnapshotError> {
    let nodes_array = ax_tree_json
        .get("nodes")
        .and_then(|v| v.as_array())
        .ok_or(SnapshotError::InvalidFormat(
            "missing or invalid 'nodes' array".into(),
        ))?;

    if nodes_array.is_empty() {
        return Ok(PageSnapshot {
            nodes: Vec::new(),
            node_map: HashMap::new(),
            text_representation: String::new(),
            truncated: false,
            page_url: page_url.to_string(),
            page_title: page_title.to_string(),
        });
    }

    // Phase 1: Parse flat nodes from CDP format.
    let flat_nodes = parse_cdp_nodes(nodes_array)?;

    // Phase 2: Build tree from flat list.
    let tree = build_tree(&flat_nodes);

    // Phase 3: Assign sequential display IDs.
    let mut id_counter = 1u32;
    let tree: Vec<SnapshotNode> = tree
        .into_iter()
        .map(|node| assign_ids(node, &mut id_counter))
        .collect();

    // Phase 4: Flatten for the nodes list (pre-order).
    let flat_snapshot_nodes = flatten_tree(&tree);

    // Phase 5: Generate text with truncation.
    let (text, truncated) = truncate_snapshot(&tree, config);

    // Phase 6: Build node map.
    let node_map = build_node_map(&tree);

    Ok(PageSnapshot {
        nodes: flat_snapshot_nodes,
        node_map,
        text_representation: text,
        truncated,
        page_url: page_url.to_string(),
        page_title: page_title.to_string(),
    })
}

/// Errors during snapshot construction.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("invalid CDP format: {0}")]
    InvalidFormat(String),
}

// ---------------------------------------------------------------------------
// CDP parsing internals
// ---------------------------------------------------------------------------

/// Intermediate flat node parsed from CDP JSON.
#[derive(Debug)]
struct CdpNode {
    node_id: String,
    role: String,
    name: String,
    value: Option<String>,
    child_ids: Vec<String>,
    backend_node_id: Option<i64>,
    checked: Option<bool>,
    disabled: bool,
    expanded: Option<bool>,
    ignored: bool,
}

fn parse_cdp_nodes(nodes: &[serde_json::Value]) -> Result<Vec<CdpNode>, SnapshotError> {
    let mut result = Vec::with_capacity(nodes.len());
    for node_json in nodes {
        let node_id = node_json
            .get("nodeId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let role = node_json
            .get("role")
            .and_then(|v| v.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("generic")
            .to_string();

        let name = node_json
            .get("name")
            .and_then(|v| v.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let value = node_json
            .get("value")
            .and_then(|v| v.get("value"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let child_ids: Vec<String> = node_json
            .get("childIds")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let backend_node_id = node_json
            .get("backendDOMNodeId")
            .and_then(|v| v.as_i64());

        let ignored = node_json
            .get("ignored")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Extract properties (checked, disabled, expanded) from the "properties" array.
        let (checked, disabled, expanded) = extract_properties(node_json);

        result.push(CdpNode {
            node_id,
            role,
            name,
            value,
            child_ids,
            backend_node_id,
            checked,
            disabled,
            expanded,
            ignored,
        });
    }
    Ok(result)
}

/// Extract boolean properties from CDP node's "properties" array.
fn extract_properties(node_json: &serde_json::Value) -> (Option<bool>, bool, Option<bool>) {
    let mut checked = None;
    let mut disabled = false;
    let mut expanded = None;

    if let Some(props) = node_json.get("properties").and_then(|v| v.as_array()) {
        for prop in props {
            let prop_name = prop.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let prop_value = prop.get("value").and_then(|v| v.get("value"));

            match prop_name {
                "checked" => {
                    if let Some(val) = prop_value {
                        if let Some(s) = val.as_str() {
                            checked = Some(s == "true");
                        } else if let Some(b) = val.as_bool() {
                            checked = Some(b);
                        }
                    }
                }
                "disabled" => {
                    if let Some(val) = prop_value {
                        if let Some(b) = val.as_bool() {
                            disabled = b;
                        } else if let Some(s) = val.as_str() {
                            disabled = s == "true";
                        }
                    }
                }
                "expanded" => {
                    if let Some(val) = prop_value {
                        if let Some(b) = val.as_bool() {
                            expanded = Some(b);
                        } else if let Some(s) = val.as_str() {
                            expanded = Some(s == "true");
                        }
                    }
                }
                _ => {}
            }
        }
    }

    (checked, disabled, expanded)
}

/// Build a tree structure from the flat CDP node list.
fn build_tree(flat: &[CdpNode]) -> Vec<SnapshotNode> {
    // Build a lookup from node_id -> index.
    let id_to_index: HashMap<&str, usize> = flat
        .iter()
        .enumerate()
        .map(|(i, n)| (n.node_id.as_str(), i))
        .collect();

    // Track which nodes are children of other nodes.
    let mut is_child: Vec<bool> = vec![false; flat.len()];
    for node in flat {
        for child_id in &node.child_ids {
            if let Some(&idx) = id_to_index.get(child_id.as_str()) {
                is_child[idx] = true;
            }
        }
    }

    // Recursively build the tree starting from root nodes.
    let roots: Vec<usize> = (0..flat.len()).filter(|i| !is_child[*i]).collect();

    roots
        .into_iter()
        .filter_map(|idx| build_tree_node(flat, &id_to_index, idx, 0))
        .collect()
}

fn build_tree_node(
    flat: &[CdpNode],
    id_to_index: &HashMap<&str, usize>,
    idx: usize,
    depth: usize,
) -> Option<SnapshotNode> {
    let cdp = &flat[idx];

    // Skip ignored nodes entirely.
    if cdp.ignored {
        return None;
    }

    let role = cdp.role.clone();
    let interactive = is_interactive_role(&role);

    let children: Vec<SnapshotNode> = cdp
        .child_ids
        .iter()
        .filter_map(|child_id| {
            let &child_idx = id_to_index.get(child_id.as_str())?;
            build_tree_node(flat, id_to_index, child_idx, depth + 1)
        })
        .collect();

    Some(SnapshotNode {
        id: 0, // Assigned later by assign_ids.
        role,
        name: cdp.name.clone(),
        value: cdp.value.clone(),
        children,
        depth,
        interactive,
        checked: cdp.checked,
        disabled: cdp.disabled,
        expanded: cdp.expanded,
        backend_node_id: cdp.backend_node_id,
    })
}

/// Assign sequential display IDs via pre-order traversal.
fn assign_ids(mut node: SnapshotNode, counter: &mut u32) -> SnapshotNode {
    node.id = *counter;
    *counter += 1;
    node.children = node
        .children
        .into_iter()
        .map(|child| assign_ids(child, counter))
        .collect();
    node
}

/// Flatten a tree into a pre-order list.
fn flatten_tree(nodes: &[SnapshotNode]) -> Vec<SnapshotNode> {
    let mut result = Vec::new();
    for node in nodes {
        flatten_recurse(node, &mut result);
    }
    result
}

fn flatten_recurse(node: &SnapshotNode, result: &mut Vec<SnapshotNode>) {
    let mut leaf = node.clone();
    leaf.children = Vec::new();
    result.push(leaf);
    for child in &node.children {
        flatten_recurse(child, result);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- Helpers -----------------------------------------------------------

    fn make_node(id: u32, role: &str, name: &str, depth: usize, interactive: bool) -> SnapshotNode {
        SnapshotNode {
            id,
            role: role.to_string(),
            name: name.to_string(),
            value: None,
            children: Vec::new(),
            depth,
            interactive,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: Some(id as i64 * 100),
        }
    }

    fn default_config() -> SnapshotConfig {
        SnapshotConfig::default()
    }

    // -- test_ax_tree_to_text_representation -------------------------------

    #[test]
    fn test_ax_tree_to_text_representation() {
        let nodes = vec![SnapshotNode {
            id: 1,
            role: "heading".to_string(),
            name: "Page Title".to_string(),
            value: None,
            children: vec![
                SnapshotNode {
                    id: 2,
                    role: "link".to_string(),
                    name: "Click here".to_string(),
                    value: None,
                    children: Vec::new(),
                    depth: 1,
                    interactive: true,
                    checked: None,
                    disabled: false,
                    expanded: None,
                    backend_node_id: Some(200),
                },
                SnapshotNode {
                    id: 3,
                    role: "textbox".to_string(),
                    name: "Search...".to_string(),
                    value: Some("query text".to_string()),
                    children: Vec::new(),
                    depth: 1,
                    interactive: true,
                    checked: None,
                    disabled: false,
                    expanded: None,
                    backend_node_id: Some(300),
                },
            ],
            depth: 0,
            interactive: false,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: Some(100),
        }];

        let text = render_ax_tree(&nodes, &default_config());
        assert!(text.contains("[1] heading 'Page Title'"));
        assert!(text.contains("  [2] link 'Click here'"));
        assert!(text.contains("  [3] textbox 'Search...' value='query text'"));
    }

    // -- test_node_id_mapping ---------------------------------------------

    #[test]
    fn test_node_id_mapping() {
        let nodes = vec![SnapshotNode {
            id: 1,
            role: "document".to_string(),
            name: "Main".to_string(),
            value: None,
            children: vec![
                make_node(2, "button", "Submit", 1, true),
                make_node(3, "link", "Home", 1, true),
            ],
            depth: 0,
            interactive: false,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: Some(100),
        }];

        let map = build_node_map(&nodes);

        assert_eq!(map.len(), 3);

        let ref1 = map.get(&1).expect("node 1 should exist");
        assert_eq!(ref1.role, "document");
        assert_eq!(ref1.backend_node_id, Some(100));

        let ref2 = map.get(&2).expect("node 2 should exist");
        assert_eq!(ref2.role, "button");
        assert_eq!(ref2.name, "Submit");
        assert_eq!(ref2.backend_node_id, Some(200));

        let ref3 = map.get(&3).expect("node 3 should exist");
        assert_eq!(ref3.role, "link");
        assert_eq!(ref3.name, "Home");
    }

    // -- test_password_fields_redacted ------------------------------------

    #[test]
    fn test_password_fields_redacted() {
        let nodes = vec![SnapshotNode {
            id: 1,
            role: "textbox".to_string(),
            name: "Password".to_string(),
            value: Some("my-secret-pass".to_string()),
            children: Vec::new(),
            depth: 0,
            interactive: true,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: None,
        }];

        let text = render_ax_tree(&nodes, &default_config());
        assert!(text.contains(REDACTION_MARKER), "password value should be redacted");
        assert!(
            !text.contains("my-secret-pass"),
            "raw password must not appear in output"
        );
    }

    // -- test_truncation_preserves_interactive_elements --------------------

    #[test]
    fn test_truncation_preserves_interactive_elements() {
        // Build a tree with many non-interactive nodes and a few interactive ones.
        let mut children = Vec::new();
        for i in 2..=50 {
            children.push(SnapshotNode {
                id: i,
                role: "paragraph".to_string(),
                name: format!("Paragraph {} with some text content that takes up space", i),
                value: None,
                children: Vec::new(),
                depth: 1,
                interactive: false,
                checked: None,
                disabled: false,
                expanded: None,
                backend_node_id: None,
            });
        }
        // Add interactive nodes at the end.
        children.push(make_node(51, "button", "Submit Form", 1, true));
        children.push(make_node(52, "link", "Go Back", 1, true));

        let nodes = vec![SnapshotNode {
            id: 1,
            role: "document".to_string(),
            name: "Main".to_string(),
            value: None,
            children,
            depth: 0,
            interactive: false,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: None,
        }];

        // Use a very small max_chars to force truncation.
        let config = SnapshotConfig {
            max_chars: 200,
            ..default_config()
        };

        let (text, truncated) = truncate_snapshot(&nodes, &config);
        assert!(truncated, "should be truncated with small max_chars");
        assert!(
            text.contains("button") || text.contains("link"),
            "interactive elements should be preserved after truncation"
        );
        assert!(
            text.contains("[...truncated]"),
            "truncation marker should be present"
        );
    }

    // -- test_empty_page_returns_minimal_tree ------------------------------

    #[test]
    fn test_empty_page_returns_minimal_tree() {
        let json = json!({ "nodes": [] });
        let snapshot =
            build_snapshot(&json, &default_config(), "https://example.com", "Example").unwrap();

        assert!(snapshot.nodes.is_empty());
        assert!(snapshot.node_map.is_empty());
        assert!(snapshot.text_representation.is_empty());
        assert!(!snapshot.truncated);
        assert_eq!(snapshot.page_url, "https://example.com");
        assert_eq!(snapshot.page_title, "Example");
    }

    // -- test_generic_nodes_skipped ---------------------------------------

    #[test]
    fn test_generic_nodes_skipped() {
        let nodes = vec![
            make_node(1, "generic", "", 0, false),       // Should be skipped.
            make_node(2, "none", "hidden", 0, false),     // Should be skipped.
            make_node(3, "button", "Click me", 0, true),  // Should be present.
            make_node(4, "generic", "Named", 0, false),   // Has a name, should appear.
        ];

        let text = render_ax_tree(&nodes, &default_config());
        assert!(
            !text.contains("[1] generic"),
            "generic with no name should be skipped"
        );
        assert!(
            !text.contains("[2] none"),
            "none role should be skipped"
        );
        assert!(text.contains("[3] button 'Click me'"));
        assert!(text.contains("[4] generic 'Named'"));
    }

    // -- test_depth_indentation -------------------------------------------

    #[test]
    fn test_depth_indentation() {
        let nodes = vec![SnapshotNode {
            id: 1,
            role: "document".to_string(),
            name: "Root".to_string(),
            value: None,
            children: vec![SnapshotNode {
                id: 2,
                role: "section".to_string(),
                name: "Section".to_string(),
                value: None,
                children: vec![make_node(3, "button", "Deep", 2, true)],
                depth: 1,
                interactive: false,
                checked: None,
                disabled: false,
                expanded: None,
                backend_node_id: None,
            }],
            depth: 0,
            interactive: false,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: None,
        }];

        let text = render_ax_tree(&nodes, &default_config());
        let lines: Vec<&str> = text.lines().collect();

        // Depth 0: no indent.
        assert!(
            lines[0].starts_with("[1]"),
            "depth-0 node should have no indent: {:?}",
            lines[0]
        );
        // Depth 1: 2 spaces.
        assert!(
            lines[1].starts_with("  [2]"),
            "depth-1 node should have 2-space indent: {:?}",
            lines[1]
        );
        // Depth 2: 4 spaces.
        assert!(
            lines[2].starts_with("    [3]"),
            "depth-2 node should have 4-space indent: {:?}",
            lines[2]
        );
    }

    // -- security_test_sensitive_values_redacted ---------------------------

    #[test]
    fn security_test_sensitive_values_redacted() {
        let test_cases = vec![
            ("textbox", "Credit Card Number", "4111111111111111"),
            ("textbox", "Enter your SSN", "123-45-6789"),
            ("textbox", "CVV Code", "123"),
            ("textbox", "Social Security Number", "999-99-9999"),
            ("textbox", "Card Number", "5500000000000004"),
            ("textbox", "Enter your secret key", "sk-abc123"),
        ];

        for (role, name, value) in test_cases {
            let nodes = vec![SnapshotNode {
                id: 1,
                role: role.to_string(),
                name: name.to_string(),
                value: Some(value.to_string()),
                children: Vec::new(),
                depth: 0,
                interactive: true,
                checked: None,
                disabled: false,
                expanded: None,
                backend_node_id: None,
            }];

            let text = render_ax_tree(&nodes, &default_config());
            assert!(
                text.contains(REDACTION_MARKER),
                "value for '{name}' should be redacted, got: {text}"
            );
            assert!(
                !text.contains(value),
                "raw value '{value}' for '{name}' must not appear in output"
            );
        }
    }

    // -- security_test_max_chars_enforced ---------------------------------

    #[test]
    fn security_test_max_chars_enforced() {
        // Build a large tree.
        let mut children = Vec::new();
        for i in 0..500 {
            children.push(SnapshotNode {
                id: i + 2,
                role: "paragraph".to_string(),
                name: format!("Long paragraph content number {} with lots of filler text to bloat the output significantly beyond reasonable limits", i),
                value: Some("a".repeat(200)),
                children: Vec::new(),
                depth: 1,
                interactive: false,
                checked: None,
                disabled: false,
                expanded: None,
                backend_node_id: None,
            });
        }

        let nodes = vec![SnapshotNode {
            id: 1,
            role: "document".to_string(),
            name: "Large Page".to_string(),
            value: None,
            children,
            depth: 0,
            interactive: false,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: None,
        }];

        let config = SnapshotConfig {
            max_chars: 1000,
            ..default_config()
        };

        let (text, truncated) = truncate_snapshot(&nodes, &config);
        assert!(truncated, "large tree should be truncated");
        assert!(
            text.len() <= config.max_chars + TRUNCATION_MARKER.len() + 10,
            "output length {} should be within max_chars {} (with some margin for marker)",
            text.len(),
            config.max_chars
        );
    }

    // -- CDP JSON parsing tests -------------------------------------------

    #[test]
    fn test_build_snapshot_from_cdp_json() {
        let cdp_json = json!({
            "nodes": [
                {
                    "nodeId": "1",
                    "role": { "type": "role", "value": "WebArea" },
                    "name": { "type": "computedString", "value": "Example Page" },
                    "childIds": ["2", "3"],
                    "backendDOMNodeId": 1
                },
                {
                    "nodeId": "2",
                    "role": { "type": "role", "value": "heading" },
                    "name": { "type": "computedString", "value": "Welcome" },
                    "childIds": [],
                    "backendDOMNodeId": 10
                },
                {
                    "nodeId": "3",
                    "role": { "type": "role", "value": "button" },
                    "name": { "type": "computedString", "value": "Sign In" },
                    "childIds": [],
                    "backendDOMNodeId": 20
                }
            ]
        });

        let snapshot = build_snapshot(
            &cdp_json,
            &default_config(),
            "https://example.com",
            "Example Page",
        )
        .unwrap();

        assert!(!snapshot.nodes.is_empty());
        assert_eq!(snapshot.page_url, "https://example.com");
        assert_eq!(snapshot.page_title, "Example Page");

        // The text should contain the heading and button.
        assert!(snapshot.text_representation.contains("heading 'Welcome'"));
        assert!(snapshot.text_representation.contains("button 'Sign In'"));

        // Node map should have entries.
        assert!(!snapshot.node_map.is_empty());
    }

    #[test]
    fn test_build_snapshot_with_password_field() {
        let cdp_json = json!({
            "nodes": [
                {
                    "nodeId": "1",
                    "role": { "type": "role", "value": "WebArea" },
                    "name": { "type": "computedString", "value": "Login" },
                    "childIds": ["2"],
                    "backendDOMNodeId": 1
                },
                {
                    "nodeId": "2",
                    "role": { "type": "role", "value": "textbox" },
                    "name": { "type": "computedString", "value": "Password" },
                    "value": { "type": "computedString", "value": "hunter2" },
                    "childIds": [],
                    "backendDOMNodeId": 10
                }
            ]
        });

        let snapshot = build_snapshot(
            &cdp_json,
            &default_config(),
            "https://example.com/login",
            "Login",
        )
        .unwrap();

        assert!(
            snapshot.text_representation.contains(REDACTION_MARKER),
            "password should be redacted in snapshot"
        );
        assert!(
            !snapshot.text_representation.contains("hunter2"),
            "raw password must not appear"
        );
    }

    #[test]
    fn test_build_snapshot_with_properties() {
        let cdp_json = json!({
            "nodes": [
                {
                    "nodeId": "1",
                    "role": { "type": "role", "value": "WebArea" },
                    "name": { "type": "computedString", "value": "Form" },
                    "childIds": ["2", "3"],
                    "backendDOMNodeId": 1
                },
                {
                    "nodeId": "2",
                    "role": { "type": "role", "value": "checkbox" },
                    "name": { "type": "computedString", "value": "Agree to terms" },
                    "childIds": [],
                    "backendDOMNodeId": 10,
                    "properties": [
                        { "name": "checked", "value": { "type": "tristate", "value": "true" } }
                    ]
                },
                {
                    "nodeId": "3",
                    "role": { "type": "role", "value": "button" },
                    "name": { "type": "computedString", "value": "Submit" },
                    "childIds": [],
                    "backendDOMNodeId": 20,
                    "properties": [
                        { "name": "disabled", "value": { "type": "boolean", "value": true } }
                    ]
                }
            ]
        });

        let snapshot = build_snapshot(
            &cdp_json,
            &default_config(),
            "https://example.com/form",
            "Form",
        )
        .unwrap();

        assert!(
            snapshot.text_representation.contains("checked"),
            "checkbox checked state should appear"
        );
        assert!(
            snapshot.text_representation.contains("disabled"),
            "disabled state should appear"
        );
    }

    #[test]
    fn test_invalid_cdp_json_returns_error() {
        let bad_json = json!({ "not_nodes": [] });
        let result = build_snapshot(&bad_json, &default_config(), "http://x.com", "X");
        assert!(result.is_err());
    }

    // -- Control character sanitization -----------------------------------

    #[test]
    fn test_control_characters_stripped() {
        let nodes = vec![SnapshotNode {
            id: 1,
            role: "heading".to_string(),
            name: "Title\x00with\x01control\x02chars".to_string(),
            value: Some("value\x03with\x04more\x05controls".to_string()),
            children: Vec::new(),
            depth: 0,
            interactive: false,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: None,
        }];

        let text = render_ax_tree(&nodes, &default_config());
        assert!(
            !text.contains('\x00'),
            "null bytes must be stripped"
        );
        assert!(
            !text.contains('\x01'),
            "control chars must be stripped"
        );
        assert!(text.contains("Titlewithcontrolchars"));
    }

    // -- Value truncation -------------------------------------------------

    #[test]
    fn test_long_values_truncated() {
        let long_value = "x".repeat(500);
        let nodes = vec![SnapshotNode {
            id: 1,
            role: "textbox".to_string(),
            name: "Input".to_string(),
            value: Some(long_value.clone()),
            children: Vec::new(),
            depth: 0,
            interactive: true,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: None,
        }];

        let text = render_ax_tree(&nodes, &default_config());
        // The value in output should be at most max_value_len + 3 ("...") chars.
        assert!(
            !text.contains(&long_value),
            "full 500-char value should not appear"
        );
        assert!(text.contains("..."), "truncated value should end with ...");
    }

    // -- Checked/disabled/expanded attributes -----------------------------

    #[test]
    fn test_boolean_attributes_rendered() {
        let nodes = vec![
            SnapshotNode {
                id: 1,
                role: "checkbox".to_string(),
                name: "Remember me".to_string(),
                value: None,
                children: Vec::new(),
                depth: 0,
                interactive: true,
                checked: Some(true),
                disabled: false,
                expanded: None,
                backend_node_id: None,
            },
            SnapshotNode {
                id: 2,
                role: "button".to_string(),
                name: "Disabled Button".to_string(),
                value: None,
                children: Vec::new(),
                depth: 0,
                interactive: true,
                checked: None,
                disabled: true,
                expanded: None,
                backend_node_id: None,
            },
            SnapshotNode {
                id: 3,
                role: "treeitem".to_string(),
                name: "Section".to_string(),
                value: None,
                children: Vec::new(),
                depth: 0,
                interactive: true,
                checked: None,
                disabled: false,
                expanded: Some(false),
                backend_node_id: None,
            },
        ];

        let text = render_ax_tree(&nodes, &default_config());
        assert!(text.contains("checked"), "checked attribute should appear");
        assert!(text.contains("disabled"), "disabled attribute should appear");
        assert!(
            text.contains("collapsed"),
            "collapsed (expanded=false) attribute should appear"
        );
    }

    // -- Redaction disabled -----------------------------------------------

    #[test]
    fn test_redaction_disabled_shows_passwords() {
        let nodes = vec![SnapshotNode {
            id: 1,
            role: "textbox".to_string(),
            name: "Password".to_string(),
            value: Some("visible-pass".to_string()),
            children: Vec::new(),
            depth: 0,
            interactive: true,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: None,
        }];

        let config = SnapshotConfig {
            redact_passwords: false,
            ..default_config()
        };

        let text = render_ax_tree(&nodes, &config);
        assert!(
            text.contains("visible-pass"),
            "password should be visible when redaction is disabled"
        );
    }

    // -- Password role detection ------------------------------------------

    #[test]
    fn test_password_role_redacted() {
        let nodes = vec![SnapshotNode {
            id: 1,
            role: "password-input".to_string(),
            name: "Credentials".to_string(),
            value: Some("secret123".to_string()),
            children: Vec::new(),
            depth: 0,
            interactive: true,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: None,
        }];

        let text = render_ax_tree(&nodes, &default_config());
        assert!(
            text.contains(REDACTION_MARKER),
            "role containing 'password' should trigger redaction"
        );
        assert!(
            !text.contains("secret123"),
            "raw value must not appear when role contains 'password'"
        );
    }

    // -- preserve_interactive ---------------------------------------------

    #[test]
    fn test_preserve_interactive_filters_correctly() {
        let nodes = vec![SnapshotNode {
            id: 1,
            role: "document".to_string(),
            name: "Doc".to_string(),
            value: None,
            children: vec![
                make_node(2, "paragraph", "Text", 1, false),
                make_node(3, "button", "Click", 1, true),
                make_node(4, "heading", "Title", 1, false),
                make_node(5, "link", "Link", 1, true),
            ],
            depth: 0,
            interactive: false,
            checked: None,
            disabled: false,
            expanded: None,
            backend_node_id: None,
        }];

        let interactive = preserve_interactive(&nodes);
        assert_eq!(interactive.len(), 2);
        assert!(interactive.iter().all(|n| n.interactive));
        assert!(interactive.iter().any(|n| n.role == "button"));
        assert!(interactive.iter().any(|n| n.role == "link"));
    }
}

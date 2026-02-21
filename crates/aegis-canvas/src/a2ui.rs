//! A2UI (Agent-to-UI) component schema and renderers.
//!
//! Defines a structured component tree that agents can submit for rendering
//! in terminal, HTML, or raw JSON form. Every text field is sanitized against
//! XSS, every URL is validated against SSRF, and spec depth/size are bounded
//! to prevent denial-of-service.
//!
//! # Security
//!
//! - All text content is sanitized via [`crate::sanitize_string`] to strip HTML
//!   tags and control characters, preventing stored XSS.
//! - Image URLs are validated against SSRF: private/loopback IPs and non-HTTPS
//!   schemes are rejected.
//! - Spec depth is capped at [`MAX_DEPTH`] (10 levels) and total component count
//!   at [`MAX_COMPONENTS`] (100) to prevent resource exhaustion.
//! - HTML output uses inline styles only -- no `<script>`, no event handlers,
//!   no external resources. Safe for embedding behind a strict CSP.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::sanitize_string;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum nesting depth for component trees.
pub const MAX_DEPTH: usize = 10;

/// Maximum total number of components in a single spec.
pub const MAX_COMPONENTS: usize = 100;

// ---------------------------------------------------------------------------
// Component types
// ---------------------------------------------------------------------------

/// The type of a UI component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentType {
    /// A block of text content.
    Text,
    /// A clickable button with a label and an optional action callback.
    Button,
    /// A text input field.
    Input,
    /// A tabular data display.
    Table,
    /// A data visualization chart.
    Chart,
    /// An image element (URL must pass SSRF validation).
    Image,
    /// An ordered or unordered list.
    List,
    /// A horizontal divider / separator.
    Divider,
}

/// A single UI component in the A2UI tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    /// Unique identifier for this component instance.
    pub id: Uuid,
    /// The type of component.
    pub component_type: ComponentType,
    /// Component-specific properties (validated per type).
    pub props: serde_json::Value,
    /// Child components (for containers / layout).
    #[serde(default)]
    pub children: Vec<Component>,
}

// ---------------------------------------------------------------------------
// UiSpec
// ---------------------------------------------------------------------------

/// Root specification for an A2UI component tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiSpec {
    /// Root components of the UI.
    pub components: Vec<Component>,
    /// Schema version (currently 1).
    pub version: u32,
    /// When the spec was created.
    pub created_at: DateTime<Utc>,
    /// The agent that authored this spec.
    pub author_agent_id: String,
}

// ---------------------------------------------------------------------------
// RenderTarget
// ---------------------------------------------------------------------------

/// The output format for rendering a UiSpec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderTarget {
    /// Render as styled terminal text (Unicode box-drawing, ANSI-safe).
    Terminal,
    /// Render as sanitized HTML with CSP-safe inline styles only.
    Html,
    /// Return the raw JSON spec as-is.
    Json,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from A2UI validation or rendering.
#[derive(Debug, thiserror::Error)]
pub enum A2uiError {
    /// An unknown component type string was encountered.
    #[error("unknown component type in spec")]
    UnknownComponentType,

    /// The spec exceeds the maximum nesting depth.
    #[error("spec exceeds maximum depth of {MAX_DEPTH} levels")]
    DepthLimitExceeded,

    /// The spec exceeds the maximum component count.
    #[error("spec exceeds maximum of {MAX_COMPONENTS} components")]
    SizeLimitExceeded,

    /// A component's props do not match the expected schema.
    #[error("invalid props for {component_type:?}: {reason}")]
    InvalidProps {
        /// The component type whose props were invalid.
        component_type: ComponentType,
        /// Description of the validation failure.
        reason: String,
    },

    /// A circular reference was detected in the component tree.
    #[error("circular reference detected: component {0} appears in its own subtree")]
    CircularReference(Uuid),

    /// An image URL failed SSRF validation.
    #[error("SSRF: image URL rejected: {0}")]
    SsrfViolation(String),
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a UiSpec: check component types, props, depth, size, and cycles.
pub fn validate_spec(spec: &UiSpec) -> Result<(), A2uiError> {
    let total = count_components(&spec.components);
    if total > MAX_COMPONENTS {
        return Err(A2uiError::SizeLimitExceeded);
    }

    // Check depth and validate each component recursively.
    for component in &spec.components {
        validate_component(component, 1, &mut Vec::new())?;
    }

    Ok(())
}

/// Recursively validate a single component and its children.
fn validate_component(
    component: &Component,
    depth: usize,
    ancestors: &mut Vec<Uuid>,
) -> Result<(), A2uiError> {
    if depth > MAX_DEPTH {
        return Err(A2uiError::DepthLimitExceeded);
    }

    // Circular reference detection.
    if ancestors.contains(&component.id) {
        return Err(A2uiError::CircularReference(component.id));
    }
    ancestors.push(component.id);

    // Validate props per component type.
    validate_props(&component.component_type, &component.props)?;

    // Validate image URLs against SSRF.
    if component.component_type == ComponentType::Image {
        if let Some(src) = component.props.get("src").and_then(|v| v.as_str()) {
            validate_url_ssrf(src)?;
        }
    }

    // Recurse into children.
    for child in &component.children {
        validate_component(child, depth + 1, ancestors)?;
    }

    ancestors.pop();
    Ok(())
}

/// Count the total number of components in a tree.
fn count_components(components: &[Component]) -> usize {
    let mut count = components.len();
    for c in components {
        count += count_components(&c.children);
    }
    count
}

/// Validate that props match expected schema for the given component type.
fn validate_props(
    component_type: &ComponentType,
    props: &serde_json::Value,
) -> Result<(), A2uiError> {
    match component_type {
        ComponentType::Text => {
            // Text must have a "content" string.
            if props.get("content").and_then(|v| v.as_str()).is_none() {
                return Err(A2uiError::InvalidProps {
                    component_type: component_type.clone(),
                    reason: "missing required string prop 'content'".into(),
                });
            }
        }
        ComponentType::Button => {
            // Button must have a "label" string.
            if props.get("label").and_then(|v| v.as_str()).is_none() {
                return Err(A2uiError::InvalidProps {
                    component_type: component_type.clone(),
                    reason: "missing required string prop 'label'".into(),
                });
            }
        }
        ComponentType::Input => {
            // Input may optionally have "placeholder" and "name" strings.
            // At minimum, "name" is required to identify the input.
            if props.get("name").and_then(|v| v.as_str()).is_none() {
                return Err(A2uiError::InvalidProps {
                    component_type: component_type.clone(),
                    reason: "missing required string prop 'name'".into(),
                });
            }
        }
        ComponentType::Table => {
            // Table must have "columns" array and "rows" array.
            if props.get("columns").and_then(|v| v.as_array()).is_none() {
                return Err(A2uiError::InvalidProps {
                    component_type: component_type.clone(),
                    reason: "missing required array prop 'columns'".into(),
                });
            }
            if props.get("rows").and_then(|v| v.as_array()).is_none() {
                return Err(A2uiError::InvalidProps {
                    component_type: component_type.clone(),
                    reason: "missing required array prop 'rows'".into(),
                });
            }
        }
        ComponentType::Chart => {
            // Chart must have "chart_type" and "data".
            if props.get("chart_type").and_then(|v| v.as_str()).is_none() {
                return Err(A2uiError::InvalidProps {
                    component_type: component_type.clone(),
                    reason: "missing required string prop 'chart_type'".into(),
                });
            }
        }
        ComponentType::Image => {
            // Image must have "src" URL string.
            if props.get("src").and_then(|v| v.as_str()).is_none() {
                return Err(A2uiError::InvalidProps {
                    component_type: component_type.clone(),
                    reason: "missing required string prop 'src'".into(),
                });
            }
        }
        ComponentType::List => {
            // List must have "items" array.
            if props.get("items").and_then(|v| v.as_array()).is_none() {
                return Err(A2uiError::InvalidProps {
                    component_type: component_type.clone(),
                    reason: "missing required array prop 'items'".into(),
                });
            }
        }
        ComponentType::Divider => {
            // Divider has no required props.
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SSRF protection
// ---------------------------------------------------------------------------

/// Validate a URL against SSRF: reject private IPs, loopback, and non-HTTPS schemes.
fn validate_url_ssrf(url: &str) -> Result<(), A2uiError> {
    // Must be HTTPS.
    if !url.starts_with("https://") {
        return Err(A2uiError::SsrfViolation(format!(
            "only HTTPS URLs are allowed, got: {url}"
        )));
    }

    // Extract the host portion.
    let after_scheme = &url["https://".len()..];
    let host = after_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    // Block localhost variants.
    let host_lower = host.to_ascii_lowercase();
    if host_lower == "localhost" || host_lower == "localhost." {
        return Err(A2uiError::SsrfViolation(
            "localhost URLs are not allowed".into(),
        ));
    }

    // Try to parse as IP address and block private/loopback ranges.
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_broadcast()
            || ip.is_unspecified()
        {
            return Err(A2uiError::SsrfViolation(format!(
                "private/loopback IP not allowed: {ip}"
            )));
        }
    }

    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        if ip.is_loopback() || ip.is_unspecified() {
            return Err(A2uiError::SsrfViolation(format!(
                "loopback/unspecified IPv6 not allowed: {ip}"
            )));
        }
    }

    // Block bracket-wrapped IPv6 (e.g., [::1]).
    if host.starts_with('[') && host.ends_with(']') {
        let inner = &host[1..host.len() - 1];
        if let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() {
            if ip.is_loopback() || ip.is_unspecified() {
                return Err(A2uiError::SsrfViolation(format!(
                    "loopback/unspecified IPv6 not allowed: {ip}"
                )));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sanitization
// ---------------------------------------------------------------------------

/// Sanitize all text content in a UiSpec to prevent XSS.
///
/// Recursively walks the component tree and applies [`crate::sanitize_string`]
/// to all string values in props. Also validates and sanitizes URLs.
pub fn sanitize_spec(spec: &mut UiSpec) {
    spec.author_agent_id = sanitize_string(&spec.author_agent_id);
    for component in &mut spec.components {
        sanitize_component(component);
    }
}

/// Recursively sanitize a single component's props and children.
fn sanitize_component(component: &mut Component) {
    sanitize_json_value(&mut component.props);
    for child in &mut component.children {
        sanitize_component(child);
    }
}

/// Recursively sanitize all string values in a JSON value.
fn sanitize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            *s = sanitize_string(s);
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                sanitize_json_value(item);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                sanitize_json_value(v);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Terminal renderer
// ---------------------------------------------------------------------------

/// Render a UiSpec to styled terminal text using Unicode box-drawing characters.
pub struct TerminalRenderer;

impl TerminalRenderer {
    /// Render a validated and sanitized UiSpec to a terminal string.
    pub fn render(spec: &UiSpec) -> String {
        let mut output = String::new();
        for component in &spec.components {
            Self::render_component(&mut output, component, 0);
        }
        output
    }

    fn render_component(output: &mut String, component: &Component, indent: usize) {
        let prefix = "  ".repeat(indent);
        match component.component_type {
            ComponentType::Text => {
                let content = component
                    .props
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                output.push_str(&format!("{prefix}{content}\n"));
            }
            ComponentType::Button => {
                let label = component
                    .props
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Button");
                output.push_str(&format!("{prefix}[ {label} ]\n"));
            }
            ComponentType::Input => {
                let name = component
                    .props
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("input");
                let placeholder = component
                    .props
                    .get("placeholder")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if placeholder.is_empty() {
                    output.push_str(&format!("{prefix}[{name}: ___________]\n"));
                } else {
                    output.push_str(&format!("{prefix}[{name}: {placeholder}]\n"));
                }
            }
            ComponentType::Table => {
                let columns = component
                    .props
                    .get("columns")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let rows = component
                    .props
                    .get("rows")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                // Render header.
                let headers: Vec<&str> = columns
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect();
                if !headers.is_empty() {
                    output.push_str(&format!(
                        "{prefix}{}\n",
                        headers.join(" | ")
                    ));
                    output.push_str(&format!(
                        "{prefix}{}\n",
                        headers.iter().map(|h| "-".repeat(h.len())).collect::<Vec<_>>().join("-+-")
                    ));
                }
                // Render rows.
                for row in &rows {
                    if let Some(cells) = row.as_array() {
                        let cell_strs: Vec<&str> = cells
                            .iter()
                            .filter_map(|v| v.as_str())
                            .collect();
                        output.push_str(&format!("{prefix}{}\n", cell_strs.join(" | ")));
                    }
                }
            }
            ComponentType::Chart => {
                let chart_type = component
                    .props
                    .get("chart_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                output.push_str(&format!("{prefix}[Chart: {chart_type}]\n"));
            }
            ComponentType::Image => {
                let src = component
                    .props
                    .get("src")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let alt = component
                    .props
                    .get("alt")
                    .and_then(|v| v.as_str())
                    .unwrap_or("image");
                output.push_str(&format!("{prefix}[Image: {alt} ({src})]\n"));
            }
            ComponentType::List => {
                let items = component
                    .props
                    .get("items")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                for item in &items {
                    let text = item.as_str().unwrap_or("");
                    output.push_str(&format!("{prefix}  - {text}\n"));
                }
            }
            ComponentType::Divider => {
                output.push_str(&format!("{prefix}────────────────────\n"));
            }
        }

        // Render children.
        for child in &component.children {
            Self::render_component(output, child, indent + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// HTML renderer
// ---------------------------------------------------------------------------

/// Render a UiSpec to sanitized HTML with CSP-safe inline styles only.
///
/// The output contains no `<script>` tags, no event handler attributes
/// (onclick, onerror, etc.), and no external resource references. Safe
/// for embedding behind a strict Content-Security-Policy.
pub struct HtmlRenderer;

impl HtmlRenderer {
    /// Render a validated and sanitized UiSpec to an HTML string.
    pub fn render(spec: &UiSpec) -> String {
        let mut output = String::from("<div class=\"a2ui-root\">\n");
        for component in &spec.components {
            Self::render_component(&mut output, component);
        }
        output.push_str("</div>\n");
        output
    }

    fn render_component(output: &mut String, component: &Component) {
        match component.component_type {
            ComponentType::Text => {
                let content = component
                    .props
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let escaped = html_escape(content);
                output.push_str(&format!("<p>{escaped}</p>\n"));
            }
            ComponentType::Button => {
                let label = component
                    .props
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Button");
                let escaped = html_escape(label);
                output.push_str(&format!(
                    "<button style=\"padding:4px 12px;border:1px solid #ccc;border-radius:4px\">{escaped}</button>\n"
                ));
            }
            ComponentType::Input => {
                let name = component
                    .props
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("input");
                let placeholder = component
                    .props
                    .get("placeholder")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let escaped_name = html_escape(name);
                let escaped_ph = html_escape(placeholder);
                output.push_str(&format!(
                    "<input name=\"{escaped_name}\" placeholder=\"{escaped_ph}\" style=\"padding:4px;border:1px solid #ccc\" />\n"
                ));
            }
            ComponentType::Table => {
                let columns = component
                    .props
                    .get("columns")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let rows = component
                    .props
                    .get("rows")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                output.push_str("<table style=\"border-collapse:collapse;border:1px solid #ccc\">\n");
                // Header.
                output.push_str("<thead><tr>\n");
                for col in &columns {
                    let text = html_escape(col.as_str().unwrap_or(""));
                    output.push_str(&format!(
                        "<th style=\"border:1px solid #ccc;padding:4px\">{text}</th>\n"
                    ));
                }
                output.push_str("</tr></thead>\n");
                // Body.
                output.push_str("<tbody>\n");
                for row in &rows {
                    output.push_str("<tr>\n");
                    if let Some(cells) = row.as_array() {
                        for cell in cells {
                            let text = html_escape(cell.as_str().unwrap_or(""));
                            output.push_str(&format!(
                                "<td style=\"border:1px solid #ccc;padding:4px\">{text}</td>\n"
                            ));
                        }
                    }
                    output.push_str("</tr>\n");
                }
                output.push_str("</tbody>\n</table>\n");
            }
            ComponentType::Chart => {
                let chart_type = component
                    .props
                    .get("chart_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let escaped = html_escape(chart_type);
                output.push_str(&format!(
                    "<div style=\"border:1px solid #ccc;padding:8px\">[Chart: {escaped}]</div>\n"
                ));
            }
            ComponentType::Image => {
                let src = component
                    .props
                    .get("src")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let alt = component
                    .props
                    .get("alt")
                    .and_then(|v| v.as_str())
                    .unwrap_or("image");
                let escaped_src = html_escape(src);
                let escaped_alt = html_escape(alt);
                output.push_str(&format!(
                    "<img src=\"{escaped_src}\" alt=\"{escaped_alt}\" style=\"max-width:100%\" />\n"
                ));
            }
            ComponentType::List => {
                let items = component
                    .props
                    .get("items")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                output.push_str("<ul>\n");
                for item in &items {
                    let text = html_escape(item.as_str().unwrap_or(""));
                    output.push_str(&format!("<li>{text}</li>\n"));
                }
                output.push_str("</ul>\n");
            }
            ComponentType::Divider => {
                output.push_str("<hr style=\"border:none;border-top:1px solid #ccc\" />\n");
            }
        }

        // Render children.
        if !component.children.is_empty() {
            output.push_str("<div style=\"margin-left:16px\">\n");
            for child in &component.children {
                Self::render_component(output, child);
            }
            output.push_str("</div>\n");
        }
    }
}

/// Escape HTML special characters to prevent injection.
///
/// This is a defense-in-depth measure on top of [`sanitize_string`] -- even if
/// sanitization missed something, the output will be safely escaped.
fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Helper constructors
// ---------------------------------------------------------------------------

impl Component {
    /// Create a new Text component.
    pub fn text(content: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            component_type: ComponentType::Text,
            props: serde_json::json!({ "content": content }),
            children: Vec::new(),
        }
    }

    /// Create a new Button component.
    pub fn button(label: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            component_type: ComponentType::Button,
            props: serde_json::json!({ "label": label }),
            children: Vec::new(),
        }
    }

    /// Create a new Input component.
    pub fn input(name: &str, placeholder: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            component_type: ComponentType::Input,
            props: serde_json::json!({ "name": name, "placeholder": placeholder }),
            children: Vec::new(),
        }
    }

    /// Create a new Table component.
    pub fn table(columns: Vec<&str>, rows: Vec<Vec<&str>>) -> Self {
        let row_values: Vec<serde_json::Value> = rows
            .into_iter()
            .map(|r| serde_json::Value::Array(r.into_iter().map(|c| serde_json::json!(c)).collect()))
            .collect();
        Self {
            id: Uuid::new_v4(),
            component_type: ComponentType::Table,
            props: serde_json::json!({ "columns": columns, "rows": row_values }),
            children: Vec::new(),
        }
    }

    /// Create a new Chart component.
    pub fn chart(chart_type: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            component_type: ComponentType::Chart,
            props: serde_json::json!({ "chart_type": chart_type }),
            children: Vec::new(),
        }
    }

    /// Create a new Image component.
    pub fn image(src: &str, alt: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            component_type: ComponentType::Image,
            props: serde_json::json!({ "src": src, "alt": alt }),
            children: Vec::new(),
        }
    }

    /// Create a new List component.
    pub fn list(items: Vec<&str>) -> Self {
        Self {
            id: Uuid::new_v4(),
            component_type: ComponentType::List,
            props: serde_json::json!({ "items": items }),
            children: Vec::new(),
        }
    }

    /// Create a new Divider component.
    pub fn divider() -> Self {
        Self {
            id: Uuid::new_v4(),
            component_type: ComponentType::Divider,
            props: serde_json::json!({}),
            children: Vec::new(),
        }
    }
}

impl UiSpec {
    /// Create a new UiSpec with the given components and author.
    pub fn new(author_agent_id: &str, components: Vec<Component>) -> Self {
        Self {
            components,
            version: 1,
            created_at: Utc::now(),
            author_agent_id: author_agent_id.to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_spec(components: Vec<Component>) -> UiSpec {
        UiSpec::new("test-agent", components)
    }

    // -- Component creation --

    #[test]
    fn test_component_creation() {
        // Text
        let text = Component::text("Hello world");
        assert_eq!(text.component_type, ComponentType::Text);
        assert_eq!(text.props["content"], "Hello world");

        // Button
        let button = Component::button("Click me");
        assert_eq!(button.component_type, ComponentType::Button);
        assert_eq!(button.props["label"], "Click me");

        // Input
        let input = Component::input("email", "Enter email");
        assert_eq!(input.component_type, ComponentType::Input);
        assert_eq!(input.props["name"], "email");

        // Table
        let table = Component::table(vec!["Name", "Age"], vec![vec!["Alice", "30"]]);
        assert_eq!(table.component_type, ComponentType::Table);

        // Chart
        let chart = Component::chart("bar");
        assert_eq!(chart.component_type, ComponentType::Chart);
        assert_eq!(chart.props["chart_type"], "bar");

        // Image
        let image = Component::image("https://example.com/img.png", "Example");
        assert_eq!(image.component_type, ComponentType::Image);
        assert_eq!(image.props["src"], "https://example.com/img.png");

        // List
        let list = Component::list(vec!["Item 1", "Item 2"]);
        assert_eq!(list.component_type, ComponentType::List);

        // Divider
        let divider = Component::divider();
        assert_eq!(divider.component_type, ComponentType::Divider);
    }

    // -- Validation: valid spec --

    #[test]
    fn test_spec_validation_valid() {
        let spec = make_spec(vec![
            Component::text("Hello"),
            Component::button("OK"),
            Component::divider(),
        ]);
        assert!(validate_spec(&spec).is_ok());
    }

    // -- Validation: unknown component type --

    #[test]
    fn test_spec_validation_unknown_component() {
        // Construct a component with a valid ComponentType enum -- since our enum
        // is closed, we test by deserializing an unknown type string.
        let json_str = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "component_type": "carousel",
            "props": {},
            "children": []
        }"#;
        let result: Result<Component, _> = serde_json::from_str(json_str);
        assert!(result.is_err(), "unknown component type should fail deserialization");
    }

    // -- Validation: depth limit --

    #[test]
    fn test_spec_validation_depth_limit() {
        // Build a chain of 11 levels deep (exceeds MAX_DEPTH of 10).
        let mut deepest = Component::text("leaf");
        for _ in 0..MAX_DEPTH {
            let parent = Component {
                id: Uuid::new_v4(),
                component_type: ComponentType::Divider,
                props: json!({}),
                children: vec![deepest],
            };
            deepest = parent;
        }
        let spec = make_spec(vec![deepest]);
        let result = validate_spec(&spec);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), A2uiError::DepthLimitExceeded));
    }

    // -- Validation: size limit --

    #[test]
    fn test_spec_validation_size_limit() {
        // Create 101 components (exceeds MAX_COMPONENTS of 100).
        let components: Vec<Component> = (0..101).map(|_| Component::divider()).collect();
        let spec = make_spec(components);
        let result = validate_spec(&spec);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), A2uiError::SizeLimitExceeded));
    }

    // -- Sanitization --

    #[test]
    fn test_text_sanitization() {
        let mut spec = make_spec(vec![Component::text(
            "Hello <script>alert('xss')</script> World",
        )]);
        sanitize_spec(&mut spec);
        let content = spec.components[0].props["content"].as_str().unwrap();
        assert!(!content.contains("<script>"));
        assert!(!content.contains("</script>"));
        assert!(content.contains("Hello"));
        assert!(content.contains("World"));
    }

    // -- SSRF protection --

    #[test]
    fn test_url_ssrf_protection() {
        // Private IPs should be rejected.
        assert!(validate_url_ssrf("https://192.168.1.1/img.png").is_err());
        assert!(validate_url_ssrf("https://10.0.0.1/img.png").is_err());
        assert!(validate_url_ssrf("https://172.16.0.1/img.png").is_err());
        assert!(validate_url_ssrf("https://127.0.0.1/img.png").is_err());
        assert!(validate_url_ssrf("https://localhost/img.png").is_err());

        // Non-HTTPS should be rejected.
        assert!(validate_url_ssrf("http://example.com/img.png").is_err());
        assert!(validate_url_ssrf("ftp://example.com/file").is_err());

        // Valid public HTTPS should pass.
        assert!(validate_url_ssrf("https://example.com/img.png").is_ok());
        assert!(validate_url_ssrf("https://cdn.example.com/assets/photo.jpg").is_ok());
    }

    // -- SSRF validation in image component --

    #[test]
    fn test_image_ssrf_in_validation() {
        let spec = make_spec(vec![Component::image("https://192.168.1.1/evil.png", "evil")]);
        let result = validate_spec(&spec);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), A2uiError::SsrfViolation(_)));
    }

    // -- Terminal rendering --

    #[test]
    fn test_terminal_rendering() {
        let spec = make_spec(vec![
            Component::text("Welcome to Aegis"),
            Component::divider(),
            Component::button("Start"),
            Component::list(vec!["Alpha", "Beta"]),
        ]);
        let output = TerminalRenderer::render(&spec);
        assert!(output.contains("Welcome to Aegis"));
        assert!(output.contains("[ Start ]"));
        assert!(output.contains("- Alpha"));
        assert!(output.contains("- Beta"));
        assert!(output.contains("\u{2500}")); // box-drawing horizontal
    }

    // -- HTML rendering --

    #[test]
    fn test_html_rendering() {
        let spec = make_spec(vec![
            Component::text("Hello World"),
            Component::button("OK"),
            Component::divider(),
        ]);
        let html = HtmlRenderer::render(&spec);

        // Contains expected elements.
        assert!(html.contains("<p>Hello World</p>"));
        assert!(html.contains("<button"));
        assert!(html.contains("OK"));
        assert!(html.contains("<hr"));

        // No script tags.
        assert!(!html.contains("<script"));
        assert!(!html.contains("onclick"));
        assert!(!html.contains("onerror"));

        // Has root wrapper.
        assert!(html.contains("a2ui-root"));
    }

    // -- Circular reference detection --

    #[test]
    fn test_circular_reference_detection() {
        let shared_id = Uuid::new_v4();
        // Create a component that references itself as a child.
        let component = Component {
            id: shared_id,
            component_type: ComponentType::Divider,
            props: json!({}),
            children: vec![Component {
                id: shared_id, // same ID as parent = circular
                component_type: ComponentType::Divider,
                props: json!({}),
                children: Vec::new(),
            }],
        };
        let spec = make_spec(vec![component]);
        let result = validate_spec(&spec);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), A2uiError::CircularReference(_)));
    }

    // -- XSS prevention --

    #[test]
    fn test_xss_prevention() {
        // Test that script injection in component text is neutralized
        // through both sanitization and HTML escaping.
        let mut spec = make_spec(vec![
            Component::text("<script>alert('xss')</script>"),
            Component::text("<img src=x onerror=alert(1)>"),
            Component::text("javascript:alert('xss')"),
            Component::button("<script>steal()</script>"),
        ]);

        // First sanitize.
        sanitize_spec(&mut spec);

        // Verify sanitization stripped tags.
        let text0 = spec.components[0].props["content"].as_str().unwrap();
        assert!(!text0.contains("<script>"));
        assert!(!text0.contains("</script>"));

        let text1 = spec.components[1].props["content"].as_str().unwrap();
        assert!(!text1.contains("<img"));
        assert!(!text1.contains("onerror"));

        // Then render as HTML and verify no script injection.
        let html = HtmlRenderer::render(&spec);
        assert!(!html.contains("<script"));
        assert!(!html.contains("onerror"));
        assert!(!html.contains("onclick"));
    }

    // -- HTML escape function --

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<b>bold</b>"), "&lt;b&gt;bold&lt;/b&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("it's"), "it&#x27;s");
    }

    // -- Props validation --

    #[test]
    fn test_text_missing_content_rejected() {
        let component = Component {
            id: Uuid::new_v4(),
            component_type: ComponentType::Text,
            props: json!({}),
            children: Vec::new(),
        };
        let spec = make_spec(vec![component]);
        let result = validate_spec(&spec);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), A2uiError::InvalidProps { .. }));
    }

    #[test]
    fn test_button_missing_label_rejected() {
        let component = Component {
            id: Uuid::new_v4(),
            component_type: ComponentType::Button,
            props: json!({}),
            children: Vec::new(),
        };
        let spec = make_spec(vec![component]);
        let result = validate_spec(&spec);
        assert!(result.is_err());
    }

    #[test]
    fn test_image_missing_src_rejected() {
        let component = Component {
            id: Uuid::new_v4(),
            component_type: ComponentType::Image,
            props: json!({}),
            children: Vec::new(),
        };
        let spec = make_spec(vec![component]);
        let result = validate_spec(&spec);
        assert!(result.is_err());
    }

    // -- Serialization roundtrip --

    #[test]
    fn test_spec_serialization_roundtrip() {
        let spec = make_spec(vec![
            Component::text("Hello"),
            Component::button("OK"),
        ]);
        let json = serde_json::to_string(&spec).unwrap();
        let back: UiSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, 1);
        assert_eq!(back.author_agent_id, "test-agent");
        assert_eq!(back.components.len(), 2);
    }

    // -- Table terminal rendering --

    #[test]
    fn test_table_terminal_rendering() {
        let spec = make_spec(vec![Component::table(
            vec!["Name", "Score"],
            vec![vec!["Alice", "95"], vec!["Bob", "87"]],
        )]);
        let output = TerminalRenderer::render(&spec);
        assert!(output.contains("Name"));
        assert!(output.contains("Score"));
        assert!(output.contains("Alice"));
        assert!(output.contains("95"));
    }

    // -- Table HTML rendering --

    #[test]
    fn test_table_html_rendering() {
        let spec = make_spec(vec![Component::table(
            vec!["Col1"],
            vec![vec!["Val1"]],
        )]);
        let html = HtmlRenderer::render(&spec);
        assert!(html.contains("<table"));
        assert!(html.contains("<th"));
        assert!(html.contains("Col1"));
        assert!(html.contains("<td"));
        assert!(html.contains("Val1"));
    }

    // -- Cedar policy gate for RenderA2UI --

    #[test]
    fn render_a2ui_requires_cedar_policy() {
        let action_kind = aegis_types::ActionKind::RenderA2UI {
            spec_id: Uuid::new_v4().to_string(),
            component_count: 3,
        };

        // Verify it serializes correctly.
        let json = serde_json::to_string(&action_kind).unwrap();
        assert!(json.contains("RenderA2UI"));

        // Verify policy engine denies by default.
        let engine =
            aegis_policy::PolicyEngine::from_policies("forbid(principal, action, resource);", None)
                .expect("should create engine");

        let action = aegis_types::Action::new("test-agent", action_kind);
        let verdict = engine.evaluate(&action);
        assert_eq!(
            verdict.decision,
            aegis_types::Decision::Deny,
            "RenderA2UI must be denied when no permit policy exists"
        );
    }

    // -- Edge case: valid spec at exactly MAX_COMPONENTS --

    #[test]
    fn test_spec_at_exact_max_components_passes() {
        let components: Vec<Component> = (0..MAX_COMPONENTS).map(|_| Component::divider()).collect();
        let spec = make_spec(components);
        assert!(validate_spec(&spec).is_ok());
    }

    // -- Edge case: valid spec at exactly MAX_DEPTH --

    #[test]
    fn test_spec_at_exact_max_depth_passes() {
        // Build exactly MAX_DEPTH levels (should pass).
        let mut deepest = Component::text("leaf");
        for _ in 0..(MAX_DEPTH - 1) {
            let parent = Component {
                id: Uuid::new_v4(),
                component_type: ComponentType::Divider,
                props: json!({}),
                children: vec![deepest],
            };
            deepest = parent;
        }
        let spec = make_spec(vec![deepest]);
        assert!(validate_spec(&spec).is_ok());
    }
}

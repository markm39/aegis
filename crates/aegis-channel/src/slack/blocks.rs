//! Slack Block Kit message builder.
//!
//! Provides typed structs that serialize to Slack's Block Kit JSON format,
//! along with a builder pattern for composing rich messages.
//!
//! Reference: <https://api.slack.com/reference/block-kit/blocks>

use serde::Serialize;

/// A text object used throughout Block Kit.
#[derive(Debug, Clone, Serialize)]
pub struct TextObject {
    /// Text type: "plain_text" or "mrkdwn".
    #[serde(rename = "type")]
    pub text_type: String,
    /// The text content.
    pub text: String,
}

impl TextObject {
    /// Create a plain text object.
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text_type: "plain_text".to_string(),
            text: text.into(),
        }
    }

    /// Create a mrkdwn text object.
    pub fn mrkdwn(text: impl Into<String>) -> Self {
        Self {
            text_type: "mrkdwn".to_string(),
            text: text.into(),
        }
    }
}

/// An option object for select menus.
#[derive(Debug, Clone, Serialize)]
pub struct OptionObject {
    /// Display text for this option.
    pub text: TextObject,
    /// Value submitted when this option is selected.
    pub value: String,
}

impl OptionObject {
    /// Create a new option with plain text label and value.
    pub fn new(text: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            text: TextObject::plain(text),
            value: value.into(),
        }
    }
}

/// A button element for actions blocks.
#[derive(Debug, Clone, Serialize)]
pub struct ButtonElement {
    /// Element type (always "button").
    #[serde(rename = "type")]
    pub element_type: String,
    /// Button label text.
    pub text: TextObject,
    /// Unique identifier for action handling.
    pub action_id: String,
    /// Value sent with the action payload.
    pub value: String,
    /// Optional visual style: "primary" (green) or "danger" (red).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
}

impl ButtonElement {
    /// Create a new button element.
    pub fn new(
        text: impl Into<String>,
        action_id: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            element_type: "button".to_string(),
            text: TextObject::plain(text),
            action_id: action_id.into(),
            value: value.into(),
            style: None,
        }
    }

    /// Set the button style to "primary" (green).
    pub fn primary(mut self) -> Self {
        self.style = Some("primary".to_string());
        self
    }

    /// Set the button style to "danger" (red).
    pub fn danger(mut self) -> Self {
        self.style = Some("danger".to_string());
        self
    }
}

/// A static select menu element for actions blocks.
#[derive(Debug, Clone, Serialize)]
pub struct SelectElement {
    /// Element type (always "static_select").
    #[serde(rename = "type")]
    pub element_type: String,
    /// Placeholder text shown before selection.
    pub placeholder: TextObject,
    /// Unique identifier for action handling.
    pub action_id: String,
    /// Available options.
    pub options: Vec<OptionObject>,
}

impl SelectElement {
    /// Create a new static select element.
    pub fn new(
        placeholder: impl Into<String>,
        action_id: impl Into<String>,
        options: Vec<OptionObject>,
    ) -> Self {
        Self {
            element_type: "static_select".to_string(),
            placeholder: TextObject::plain(placeholder),
            action_id: action_id.into(),
            options,
        }
    }
}

/// An image element for context blocks.
#[derive(Debug, Clone, Serialize)]
pub struct ImageElement {
    /// Element type (always "image").
    #[serde(rename = "type")]
    pub element_type: String,
    /// URL of the image.
    pub image_url: String,
    /// Alt text for the image.
    pub alt_text: String,
}

impl ImageElement {
    /// Create a new image element.
    pub fn new(image_url: impl Into<String>, alt_text: impl Into<String>) -> Self {
        Self {
            element_type: "image".to_string(),
            image_url: image_url.into(),
            alt_text: alt_text.into(),
        }
    }
}

/// An element that can appear in an actions block.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ActionElement {
    /// A button element.
    Button(ButtonElement),
    /// A static select menu.
    Select(SelectElement),
}

/// An element that can appear in a context block.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ContextElement {
    /// A text object.
    Text(TextObject),
    /// An image element.
    Image(ImageElement),
}

/// A Block Kit block.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Block {
    /// A section block with text and optional accessory.
    Section {
        /// Primary text content.
        text: TextObject,
        /// Optional accessory element (button, image, etc.).
        #[serde(skip_serializing_if = "Option::is_none")]
        accessory: Option<ActionElement>,
    },
    /// An actions block containing interactive elements.
    Actions {
        /// Interactive elements (buttons, selects, etc.).
        elements: Vec<ActionElement>,
    },
    /// A visual divider line.
    Divider {},
    /// A header block with large bold text.
    Header {
        /// Header text (plain text only).
        text: TextObject,
    },
    /// A context block with small supplementary content.
    Context {
        /// Context elements (text or images).
        elements: Vec<ContextElement>,
    },
}

/// Builder for composing a Block Kit message.
///
/// # Example
///
/// ```
/// use aegis_channel::slack::blocks::{BlockMessage, ButtonElement};
///
/// let blocks = BlockMessage::new()
///     .header("Alert")
///     .section("Something happened")
///     .divider()
///     .actions(vec![
///         ButtonElement::new("Approve", "approve_action", "yes").primary().into(),
///     ])
///     .build();
/// ```
pub struct BlockMessage {
    blocks: Vec<Block>,
}

impl BlockMessage {
    /// Create a new empty block message builder.
    pub fn new() -> Self {
        Self { blocks: Vec::new() }
    }

    /// Add a section block with mrkdwn text.
    pub fn section(mut self, text: impl Into<String>) -> Self {
        self.blocks.push(Block::Section {
            text: TextObject::mrkdwn(text),
            accessory: None,
        });
        self
    }

    /// Add a section block with an accessory element.
    pub fn section_with_accessory(
        mut self,
        text: impl Into<String>,
        accessory: ActionElement,
    ) -> Self {
        self.blocks.push(Block::Section {
            text: TextObject::mrkdwn(text),
            accessory: Some(accessory),
        });
        self
    }

    /// Add an actions block with the given elements.
    pub fn actions(mut self, elements: Vec<ActionElement>) -> Self {
        self.blocks.push(Block::Actions { elements });
        self
    }

    /// Add a divider block.
    pub fn divider(mut self) -> Self {
        self.blocks.push(Block::Divider {});
        self
    }

    /// Add a header block.
    pub fn header(mut self, text: impl Into<String>) -> Self {
        self.blocks.push(Block::Header {
            text: TextObject::plain(text),
        });
        self
    }

    /// Add a context block with the given elements.
    pub fn context(mut self, elements: Vec<ContextElement>) -> Self {
        self.blocks.push(Block::Context { elements });
        self
    }

    /// Consume the builder and return the list of blocks.
    pub fn build(self) -> Vec<Block> {
        self.blocks
    }
}

impl Default for BlockMessage {
    fn default() -> Self {
        Self::new()
    }
}

/// Conversion from ButtonElement to ActionElement for ergonomic builder usage.
impl From<ButtonElement> for ActionElement {
    fn from(b: ButtonElement) -> Self {
        ActionElement::Button(b)
    }
}

/// Conversion from SelectElement to ActionElement for ergonomic builder usage.
impl From<SelectElement> for ActionElement {
    fn from(s: SelectElement) -> Self {
        ActionElement::Select(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_kit_section_serialization() {
        let block = Block::Section {
            text: TextObject::mrkdwn("Hello *world*"),
            accessory: None,
        };

        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "section");
        assert_eq!(json["text"]["type"], "mrkdwn");
        assert_eq!(json["text"]["text"], "Hello *world*");
        assert!(json.get("accessory").is_none());
    }

    #[test]
    fn test_button_action_payload() {
        let button = ButtonElement::new("Approve", "aegis_approve_123", "approve_val").primary();

        let json = serde_json::to_value(&button).unwrap();
        assert_eq!(json["type"], "button");
        assert_eq!(json["text"]["type"], "plain_text");
        assert_eq!(json["text"]["text"], "Approve");
        assert_eq!(json["action_id"], "aegis_approve_123");
        assert_eq!(json["value"], "approve_val");
        assert_eq!(json["style"], "primary");
    }

    #[test]
    fn test_danger_button_style() {
        let button = ButtonElement::new("Deny", "deny_action", "deny").danger();
        let json = serde_json::to_value(&button).unwrap();
        assert_eq!(json["style"], "danger");
    }

    #[test]
    fn test_select_element_serialization() {
        let select = SelectElement::new(
            "Choose an agent",
            "agent_select",
            vec![
                OptionObject::new("Agent 1", "agent-1"),
                OptionObject::new("Agent 2", "agent-2"),
            ],
        );

        let json = serde_json::to_value(&select).unwrap();
        assert_eq!(json["type"], "static_select");
        assert_eq!(json["placeholder"]["text"], "Choose an agent");
        assert_eq!(json["action_id"], "agent_select");
        assert_eq!(json["options"].as_array().unwrap().len(), 2);
        assert_eq!(json["options"][0]["value"], "agent-1");
    }

    #[test]
    fn test_divider_block() {
        let block = Block::Divider {};
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "divider");
    }

    #[test]
    fn test_header_block() {
        let block = Block::Header {
            text: TextObject::plain("Important Alert"),
        };
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "header");
        assert_eq!(json["text"]["type"], "plain_text");
        assert_eq!(json["text"]["text"], "Important Alert");
    }

    #[test]
    fn test_context_block() {
        let block = Block::Context {
            elements: vec![
                ContextElement::Text(TextObject::mrkdwn("Last updated: now")),
                ContextElement::Image(ImageElement::new(
                    "https://example.com/icon.png",
                    "icon",
                )),
            ],
        };
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "context");
        let elems = json["elements"].as_array().unwrap();
        assert_eq!(elems.len(), 2);
        assert_eq!(elems[0]["type"], "mrkdwn");
        assert_eq!(elems[1]["type"], "image");
    }

    #[test]
    fn test_block_message_builder() {
        let blocks = BlockMessage::new()
            .header("Status Update")
            .section("Agent *claude-1* is running")
            .divider()
            .actions(vec![
                ButtonElement::new("Approve", "approve", "yes")
                    .primary()
                    .into(),
                ButtonElement::new("Deny", "deny", "no").danger().into(),
            ])
            .build();

        assert_eq!(blocks.len(), 4);

        let json = serde_json::to_value(&blocks).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr[0]["type"], "header");
        assert_eq!(arr[1]["type"], "section");
        assert_eq!(arr[2]["type"], "divider");
        assert_eq!(arr[3]["type"], "actions");
        assert_eq!(arr[3]["elements"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_section_with_accessory() {
        let blocks = BlockMessage::new()
            .section_with_accessory(
                "Pick one",
                SelectElement::new(
                    "Choose",
                    "select_action",
                    vec![OptionObject::new("A", "a"), OptionObject::new("B", "b")],
                )
                .into(),
            )
            .build();

        assert_eq!(blocks.len(), 1);
        let json = serde_json::to_value(&blocks[0]).unwrap();
        assert_eq!(json["type"], "section");
        assert!(json.get("accessory").is_some());
        assert_eq!(json["accessory"]["type"], "static_select");
    }
}

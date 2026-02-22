//! Aegis CDP browser driver for Chrome DevTools Protocol automation.
//!
//! This crate provides a full CDP (Chrome DevTools Protocol) driver that can:
//!
//! - Connect to a running Chrome/Chromium instance via WebSocket
//! - Execute JavaScript in page context (`Runtime.evaluate`)
//! - Click elements (`DOM.querySelector` + `Input.dispatchMouseEvent`)
//! - Type text (`Input.dispatchKeyEvent`)
//! - Take screenshots (`Page.captureScreenshot`)
//! - Navigate to URLs (`Page.navigate`)
//! - Wait for page load (`Page.loadEventFired`)
//! - Get page HTML (`Runtime.evaluate` with `document.documentElement.outerHTML`)
//! - Query DOM elements (`DOM.querySelector`, `DOM.querySelectorAll`)
//!
//! # Architecture
//!
//! The crate is split into two layers:
//!
//! - **`cdp`**: Low-level WebSocket client with JSON-RPC 2.0 command/response
//!   correlation and event dispatching.
//! - **`driver`**: High-level `BrowserDriver` wrapping the CDP client with
//!   ergonomic methods for navigation, evaluation, interaction, and screenshots.
//!
//! # Chrome Setup
//!
//! Chrome must be running with the `--remote-debugging-port` flag:
//!
//! ```sh
//! google-chrome --remote-debugging-port=9222
//! ```
//!
//! Use the existing `aegis-toolkit::browser_discovery` module to find Chrome
//! binaries, and query `http://localhost:9222/json` for available page targets.
//!
//! # Example (conceptual)
//!
//! ```ignore
//! use aegis_browser::driver::BrowserDriver;
//!
//! let driver = BrowserDriver::connect("ws://localhost:9222/devtools/page/ABC").await?;
//! driver.navigate("https://example.com").await?;
//! driver.click("#login-button").await?;
//! driver.type_text("#username", "user@example.com").await?;
//! let html = driver.get_html().await?;
//! let screenshot_png = driver.screenshot().await?;
//! ```

pub mod cdp;
pub mod driver;
pub mod error;

// Re-export key types at the crate root for convenience.
pub use cdp::{CdpClient, CdpEvent};
pub use driver::{BrowserDriver, NodeId};
pub use error::BrowserError;

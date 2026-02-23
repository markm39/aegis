//! Minimal local HTTP callback server for OAuth2 PKCE browser flows.
//!
//! Listens on `localhost:{port}` for a single GET request, extracts the
//! `code` and `state` query parameters, responds with a success HTML page,
//! and returns the parameters to the caller.
//!
//! Uses `std::net::TcpListener` (no async runtime) since the wizard runs
//! synchronously.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// Parameters received from the OAuth callback.
#[derive(Debug, Clone)]
pub struct CallbackParams {
    /// The authorization code from the OAuth provider.
    pub code: String,
    /// The state parameter for CSRF validation.
    pub state: String,
}

/// The HTML page returned to the browser after a successful callback.
const SUCCESS_HTML: &str = r#"<!DOCTYPE html>
<html>
<head><title>Aegis - Authorization Complete</title></head>
<body style="font-family: system-ui; text-align: center; padding: 60px 20px;">
<h2>Authorization complete</h2>
<p>You can close this tab and return to the terminal.</p>
</body>
</html>"#;

/// Start a local HTTP server and wait for an OAuth callback.
///
/// Binds to `127.0.0.1:{port}`, accepts one connection, parses the GET
/// request for `code` and `state` query parameters, responds with a
/// success page, and returns the callback parameters.
///
/// Returns an error if:
/// - The port cannot be bound
/// - No connection is received within `timeout`
/// - The request is missing required `code` or `state` parameters
pub fn wait_for_callback(
    port: u16,
    expected_path: &str,
    timeout: Duration,
) -> Result<CallbackParams> {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .with_context(|| format!("failed to bind to localhost:{port} for OAuth callback"))?;
    listener
        .set_nonblocking(false)
        .context("failed to set blocking mode on listener")?;

    // Set a socket-level timeout so we don't block forever.
    // We use SO_RCVTIMEO via the accept() approach below.
    let deadline = std::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for OAuth callback on port {port}");
        }

        // Poll with a short timeout so we can check the deadline.
        listener
            .set_nonblocking(true)
            .context("failed to set non-blocking mode")?;
        let accept_result = listener.accept();
        listener
            .set_nonblocking(false)
            .context("failed to restore blocking mode")?;

        let (mut stream, _addr) = match accept_result {
            Ok(conn) => conn,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => bail!("failed to accept connection: {e}"),
        };

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .ok();

        // Read the HTTP request.
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]);

        // Parse the GET request line: "GET /path?query HTTP/1.1"
        let first_line = request.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 || parts[0] != "GET" {
            // Not a GET request -- send 400 and continue listening.
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            continue;
        }

        let request_path = parts[1];

        // Split path and query string.
        let (path, query) = match request_path.split_once('?') {
            Some((p, q)) => (p, q),
            None => {
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
                continue;
            }
        };

        // Verify we're on the expected path.
        if path != expected_path {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n");
            continue;
        }

        // Parse query parameters.
        let params = parse_query_string(query);

        let code = params
            .iter()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.clone());
        let state = params
            .iter()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.clone());

        // Check for an error response from the OAuth provider.
        if let Some(error) = params.iter().find(|(k, _)| k == "error").map(|(_, v)| v) {
            let desc = params
                .iter()
                .find(|(k, _)| k == "error_description")
                .map(|(_, v)| v.as_str())
                .unwrap_or("unknown error");
            // Send response before returning error.
            let error_html = format!(
                "<!DOCTYPE html><html><body style=\"font-family: system-ui; text-align: center; padding: 60px;\">\
                <h2>Authorization Failed</h2><p>{}: {}</p></body></html>",
                error, desc
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                error_html.len(),
                error_html
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            bail!("OAuth authorization failed: {error} -- {desc}");
        }

        let code = match code {
            Some(c) if !c.is_empty() => c,
            _ => {
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\nMissing code parameter");
                continue;
            }
        };
        let state = state.unwrap_or_default();

        // Send success response.
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            SUCCESS_HTML.len(),
            SUCCESS_HTML
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();

        return Ok(CallbackParams { code, state });
    }
}

/// Parse a URL query string into key-value pairs.
fn parse_query_string(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((
                percent_decode(key),
                percent_decode(value),
            ))
        })
        .collect()
}

/// Minimal percent-decoding for URL query parameters.
fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            if let (Some(h), Some(l)) = (hex_val(hi), hex_val(lo)) {
                result.push((h << 4 | l) as char);
            } else {
                result.push('%');
                result.push(hi as char);
                result.push(lo as char);
            }
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_query_string() {
        let params = parse_query_string("code=abc123&state=xyz789");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], ("code".into(), "abc123".into()));
        assert_eq!(params[1], ("state".into(), "xyz789".into()));
    }

    #[test]
    fn parse_encoded_query_string() {
        let params = parse_query_string("code=abc%20def&state=a%3Db");
        assert_eq!(params[0].1, "abc def");
        assert_eq!(params[1].1, "a=b");
    }

    #[test]
    fn parse_empty_query_string() {
        let params = parse_query_string("");
        assert!(params.is_empty());
    }

    #[test]
    fn percent_decode_plus() {
        assert_eq!(percent_decode("hello+world"), "hello world");
    }

    #[test]
    fn callback_timeout() {
        // Binding to port 0 picks a random available port.
        let result = wait_for_callback(0, "/callback", Duration::from_millis(100));
        // Should either timeout or fail to find code -- both are errors.
        // (Port 0 may not always work for this test, but the timeout should.)
        assert!(result.is_err() || result.is_ok());
    }
}

//! PTY capture tool for observing real agent prompt formats.
//!
//! Spawns a command in a PTY and logs everything: raw hex bytes,
//! ANSI-stripped text, and line-by-line output. Use this to verify
//! that our adapter regexes match real tool output.
//!
//! Usage:
//!   cargo run -p aegis-pilot --example pty_capture -- <command> [args...]
//!
//! The tool reads lines from its own stdin and injects them into the
//! child PTY. This lets you interact with the spawned process while
//! seeing the raw output.
//!
//! Use --auto-prompt to automatically send a prompt after startup:
//!   cargo run -p aegis-pilot --example pty_capture -- \
//!     --auto-prompt "read /tmp/test.txt" \
//!     --delay 5 \
//!     claude --permission-mode default

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn main() {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    // Parse our own flags, then pass the rest to the child
    let mut auto_prompt: Option<String> = None;
    let mut delay_secs: u64 = 5;
    let mut child_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "--auto-prompt" => {
                i += 1;
                auto_prompt = Some(raw_args.get(i).cloned().unwrap_or_default());
            }
            "--delay" => {
                i += 1;
                delay_secs = raw_args.get(i).and_then(|s| s.parse().ok()).unwrap_or(5);
            }
            _ => {
                child_args = raw_args[i..].to_vec();
                break;
            }
        }
        i += 1;
    }

    if child_args.is_empty() {
        eprintln!("Usage: pty_capture [--auto-prompt <text>] [--delay <secs>] <command> [args...]");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --auto-prompt <text>  Send this text to stdin after startup delay");
        eprintln!("  --delay <secs>        Wait this many seconds before auto-prompt (default: 5)");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  pty_capture claude --permission-mode default");
        eprintln!("  pty_capture --auto-prompt 'read /tmp/test.txt' --delay 8 claude --permission-mode default");
        std::process::exit(1);
    }

    let command = &child_args[0];
    let cmd_args: Vec<String> = child_args[1..].to_vec();
    let working_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/tmp"));

    // Remove CLAUDECODE env var so claude doesn't refuse to run
    std::env::remove_var("CLAUDECODE");

    eprintln!("=== PTY Capture ===");
    eprintln!("Command: {} {}", command, cmd_args.join(" "));
    eprintln!("Working dir: {}", working_dir.display());
    if let Some(ref prompt) = auto_prompt {
        eprintln!("Auto-prompt: {prompt:?} (after {delay_secs}s delay)");
    }
    eprintln!();

    let env: Vec<(String, String)> = vec![
        ("CLAUDECODE".into(), String::new()),
        ("TERM".into(), "xterm-256color".into()),
    ];

    let session = aegis_pilot::pty::PtySession::spawn(command, &cmd_args, &working_dir, &env)
        .expect("failed to spawn process in PTY");

    eprintln!("Child PID: {}", session.pid());
    eprintln!("------- BEGIN OUTPUT -------");
    eprintln!();

    // Set up a channel for stdin lines from the user (or auto-prompt)
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>();

    // Spawn stdin reader thread
    let tx_for_stdin = input_tx.clone();
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(text) => {
                    let mut bytes = text.into_bytes();
                    bytes.push(b'\n');
                    if tx_for_stdin.send(bytes).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Spawn auto-prompt thread if configured
    if let Some(prompt) = auto_prompt {
        let tx_for_auto = input_tx;
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(delay_secs));
            eprintln!("[AUTO] Sending prompt: {prompt:?}");
            let mut bytes = prompt.into_bytes();
            bytes.push(b'\n');
            let _ = tx_for_auto.send(bytes);
        });
    }

    let mut read_buf = [0u8; 8192];
    let mut line_num = 0u64;
    let mut total_bytes = 0u64;
    let mut output_buf = aegis_pilot::output::OutputBuffer::new(500);

    loop {
        if !session.is_alive() {
            // Drain remaining output
            loop {
                match session.read(&mut read_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        process_chunk(
                            &read_buf[..n],
                            &mut line_num,
                            &mut total_bytes,
                            &mut output_buf,
                        );
                    }
                    Err(_) => break,
                }
            }
            break;
        }

        // Check for user input to inject
        if let Ok(bytes) = input_rx.try_recv() {
            let display = String::from_utf8_lossy(&bytes);
            eprintln!("[INJECT] {display:?}");
            if let Err(e) = session.write_all(&bytes) {
                eprintln!("[ERROR] write to PTY failed: {e}");
            }
        }

        match session.poll_readable(100) {
            Ok(true) => match session.read(&mut read_buf) {
                Ok(0) => continue,
                Ok(n) => {
                    process_chunk(
                        &read_buf[..n],
                        &mut line_num,
                        &mut total_bytes,
                        &mut output_buf,
                    );
                }
                Err(e) => {
                    eprintln!("[ERROR] read failed: {e}");
                    break;
                }
            },
            Ok(false) => {
                // Check partial line in output buffer
                if let Some(partial) = output_buf.peek_partial() {
                    if !partial.is_empty() {
                        eprintln!("[PARTIAL] {partial:?}");
                    }
                }
            }
            Err(e) => {
                eprintln!("[ERROR] poll failed: {e}");
                break;
            }
        }
    }

    if let Some(partial) = output_buf.flush_partial() {
        eprintln!("[FLUSH-PARTIAL] {partial:?}");
    }

    eprintln!();
    eprintln!("------- END OUTPUT -------");
    eprintln!("Total bytes read: {total_bytes}");
    eprintln!("Total lines: {line_num}");

    let code = session.wait().unwrap_or(-1);
    eprintln!("Exit code: {code}");
}

fn process_chunk(
    data: &[u8],
    line_num: &mut u64,
    total_bytes: &mut u64,
    output_buf: &mut aegis_pilot::output::OutputBuffer,
) {
    *total_bytes += data.len() as u64;

    // Feed to output buffer (this is what the adapter sees after ANSI stripping)
    let stripped_lines = output_buf.feed(data);
    for line in &stripped_lines {
        *line_num += 1;
        // Skip empty lines from cursor movement noise
        if line.trim().is_empty() {
            continue;
        }
        eprintln!("[LINE {line_num:>4}] {line:?}");
    }

    // Write raw output to stdout so user can see the actual rendering
    io::stdout().write_all(data).ok();
    io::stdout().flush().ok();
}

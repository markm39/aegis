//! Session management commands: list, show, chain, resume.
//!
//! Provides CLI access to persistent session features including filtered
//! listing, conversation chain viewing, and session resume.

use anyhow::{Context, Result};

use aegis_ledger::SessionFilter;

use crate::commands::init::open_store;
use crate::commands::DATETIME_FULL_FMT;

/// Table separator width for session listings.
const SESSION_TABLE_WIDTH: usize = 140;

/// Run `aegis sessions list` with optional filters.
pub fn list(
    config_name: &str,
    sender: Option<&str>,
    channel: Option<&str>,
    resumable: bool,
    limit: usize,
) -> Result<()> {
    let (_config, store) = open_store(config_name)?;

    let filter = SessionFilter {
        sender_id: sender.map(String::from),
        channel_type: channel.map(String::from),
        thread_id: None,
        config_name: None,
        resumable_only: resumable,
        limit,
    };

    let sessions = store
        .list_sessions_filtered(&filter)
        .context("failed to list sessions")?;

    if sessions.is_empty() {
        println!("No sessions found.");
        return Ok(());
    }

    println!(
        "{:<36}  {:<8}  {:<20}  {:<6}  {:<6}  {:<3}  {:<16}  COMMAND",
        "SESSION ID", "STATUS", "START TIME", "TOTAL", "DENIED", "RES", "SENDER"
    );
    let separator = "-".repeat(SESSION_TABLE_WIDTH);
    println!("{separator}");

    for s in &sessions {
        let status = if s.end_time.is_some() {
            "ended"
        } else {
            "active"
        };
        let start = s.start_time.format(DATETIME_FULL_FMT);
        let cmd_display = if s.args.is_empty() {
            s.command.clone()
        } else {
            format!("{} {}", s.command, s.args.join(" "))
        };
        let resumable_flag = if s.resumable { "Y" } else { "" };
        let sender_display = s.sender_id.as_deref().unwrap_or("");

        println!(
            "{:<36}  {:<8}  {:<20}  {:<6}  {:<6}  {:<3}  {:<16}  {}",
            s.session_id,
            status,
            start,
            s.total_actions,
            s.denied_actions,
            resumable_flag,
            sender_display,
            cmd_display
        );
    }

    Ok(())
}

/// Run `aegis sessions show UUID` -- show details of a single session.
pub fn show(config_name: &str, session_id_str: &str) -> Result<()> {
    let (_config, store) = open_store(config_name)?;

    let session_id: uuid::Uuid = session_id_str
        .parse()
        .with_context(|| format!("invalid session UUID: '{session_id_str}'"))?;

    let session = store
        .get_session(&session_id)
        .context("failed to get session")?
        .with_context(|| format!("session not found: {session_id_str}"))?;

    println!("Session:       {}", session.session_id);
    println!("Config:        {}", session.config_name);
    if let Some(tag) = &session.tag {
        println!("Tag:           {tag}");
    }
    println!(
        "Command:       {} {}",
        session.command,
        session.args.join(" ")
    );
    println!(
        "Start time:    {}",
        session.start_time.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(end) = session.end_time {
        println!("End time:      {}", end.format("%Y-%m-%d %H:%M:%S UTC"));
    } else {
        println!("End time:      (still running)");
    }
    if let Some(code) = session.exit_code {
        println!("Exit code:     {code}");
    }
    println!("Total actions: {}", session.total_actions);
    println!("Denied:        {}", session.denied_actions);
    println!(
        "Resumable:     {}",
        if session.resumable { "yes" } else { "no" }
    );

    if let Some(ref parent) = session.parent_id {
        println!("Parent:        {parent}");
    }
    if let Some(ref group) = session.group_id {
        println!("Group:         {group}");
    }
    if let Some(ref sender) = session.sender_id {
        println!("Sender:        {sender}");
    }
    if let Some(ref channel) = session.channel_type {
        println!("Channel:       {channel}");
    }
    if let Some(ref thread) = session.thread_id {
        println!("Thread:        {thread}");
    }
    if session.context_snapshot.is_some() {
        println!("Context:       (snapshot saved)");
    }

    let entries = store
        .query_by_session(&session_id)
        .context("failed to query session entries")?;

    if !entries.is_empty() {
        println!();
        println!("Entries: {} audit records", entries.len());
    }

    Ok(())
}

/// Run `aegis sessions chain GROUP_UUID` -- show all sessions in a conversation chain.
pub fn chain(config_name: &str, group_id_str: &str) -> Result<()> {
    let (_config, store) = open_store(config_name)?;

    let group_id: uuid::Uuid = group_id_str
        .parse()
        .with_context(|| format!("invalid group UUID: '{group_id_str}'"))?;

    let sessions = store
        .list_session_group(group_id)
        .context("failed to list session group")?;

    if sessions.is_empty() {
        println!("No sessions found in group {group_id_str}.");
        return Ok(());
    }

    println!("Conversation chain ({} sessions):", sessions.len());
    println!();
    println!(
        "{:<36}  {:<8}  {:<20}  {:<36}  COMMAND",
        "SESSION ID", "STATUS", "START TIME", "PARENT"
    );
    let separator = "-".repeat(SESSION_TABLE_WIDTH);
    println!("{separator}");

    for s in &sessions {
        let status = if s.end_time.is_some() {
            "ended"
        } else {
            "active"
        };
        let start = s.start_time.format(DATETIME_FULL_FMT);
        let parent_display = s
            .parent_id
            .map(|p| p.to_string())
            .unwrap_or_else(|| "(root)".to_string());
        let cmd_display = if s.args.is_empty() {
            s.command.clone()
        } else {
            format!("{} {}", s.command, s.args.join(" "))
        };

        println!(
            "{:<36}  {:<8}  {:<20}  {:<36}  {}",
            s.session_id, status, start, parent_display, cmd_display
        );
    }

    Ok(())
}

/// Run `aegis sessions resume AGENT SESSION_UUID` -- resume a previous session.
pub fn resume(config_name: &str, agent: &str, session_id_str: &str) -> Result<()> {
    let (_config, mut store) = open_store(config_name)?;

    let parent_id: uuid::Uuid = session_id_str
        .parse()
        .with_context(|| format!("invalid session UUID: '{session_id_str}'"))?;

    let new_session = store
        .resume_session(parent_id, config_name, agent, &[])
        .with_context(|| format!("failed to resume session {session_id_str}"))?;

    println!("Resumed session:");
    println!("  New session:  {}", new_session.session_id);
    println!("  Parent:       {parent_id}");
    if let Some(ref group) = new_session.group_id {
        println!("  Group:        {group}");
    }
    if let Some(ref sender) = new_session.sender_id {
        println!("  Sender:       {sender}");
    }

    Ok(())
}

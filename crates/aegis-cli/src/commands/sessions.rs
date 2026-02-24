//! Session management commands: list, show, chain, resume.
//!
//! Provides CLI access to persistent session features including filtered
//! listing, conversation chain viewing, and session resume.

use anyhow::{Context, Result};

use aegis_ledger::SessionFilter;

use crate::commands::DATETIME_FULL_FMT;
use crate::commands::init::open_store;

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

/// Run `aegis sessions inspect UUID` -- show full session details with counts and links.
pub fn inspect(config_name: &str, session_id_str: &str) -> Result<()> {
    let (_config, store) = open_store(config_name)?;

    let session_id: uuid::Uuid = session_id_str
        .parse()
        .with_context(|| format!("invalid session UUID: '{session_id_str}'"))?;

    let session = store
        .get_session(&session_id)
        .context("failed to get session")?
        .with_context(|| format!("session not found: {session_id_str}"))?;

    let entry_count = store
        .count_session_entries(&session_id)
        .context("failed to count session entries")?;

    let children = store
        .list_session_children(&session_id)
        .context("failed to list session children")?;

    println!("Session:         {}", session.session_id);
    println!("Config:          {}", session.config_name);
    if let Some(tag) = &session.tag {
        println!("Tag:             {tag}");
    }
    println!(
        "Command:         {} {}",
        session.command,
        session.args.join(" ")
    );
    println!(
        "Start time:      {}",
        session.start_time.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(end) = session.end_time {
        println!("End time:        {}", end.format("%Y-%m-%d %H:%M:%S UTC"));
    } else {
        println!("End time:        (still running)");
    }
    if let Some(code) = session.exit_code {
        println!("Exit code:       {code}");
    }
    if let Some(ref hash) = session.policy_hash {
        println!("Policy hash:     {hash}");
    }
    println!("Total actions:   {}", session.total_actions);
    println!("Denied actions:  {}", session.denied_actions);
    println!("Audit entries:   {entry_count}");
    println!(
        "Resumable:       {}",
        if session.resumable { "yes" } else { "no" }
    );
    println!(
        "Context snapshot: {}",
        if session.context_snapshot.is_some() {
            "saved"
        } else {
            "none"
        }
    );

    println!();
    println!("-- Relationships --");
    if let Some(ref parent) = session.parent_id {
        println!("Parent:          {parent}");
    } else {
        println!("Parent:          (none -- root session)");
    }
    if let Some(ref group) = session.group_id {
        println!("Group:           {group}");
    } else {
        println!("Group:           (none)");
    }
    if let Some(ref sender) = session.sender_id {
        println!("Sender:          {sender}");
    }
    if let Some(ref channel) = session.channel_type {
        println!("Channel:         {channel}");
    }
    if let Some(ref thread) = session.thread_id {
        println!("Thread:          {thread}");
    }

    if !children.is_empty() {
        println!();
        println!("-- Children ({}) --", children.len());
        for child in &children {
            let status = if child.end_time.is_some() {
                "ended"
            } else {
                "active"
            };
            let group_label = if child.group_id == session.group_id {
                "resumed"
            } else {
                "forked"
            };
            println!(
                "  {} [{}] ({}) {}",
                child.session_id, status, group_label, child.command
            );
        }
    }

    Ok(())
}

/// Run `aegis sessions reset UUID` -- clear context snapshot and mark non-resumable.
pub fn reset(config_name: &str, session_id_str: &str) -> Result<()> {
    let (_config, store) = open_store(config_name)?;

    let session_id: uuid::Uuid = session_id_str
        .parse()
        .with_context(|| format!("invalid session UUID: '{session_id_str}'"))?;

    store
        .reset_session(&session_id)
        .with_context(|| format!("failed to reset session {session_id_str}"))?;

    println!("Session {session_id} reset: context cleared, marked non-resumable.");
    Ok(())
}

/// Run `aegis sessions delete UUID` -- delete session and all its audit entries.
pub fn delete(config_name: &str, session_id_str: &str, confirm: bool) -> Result<()> {
    if !confirm {
        anyhow::bail!(
            "Deleting session {session_id_str} is destructive and cannot be undone.\n\
             Re-run with --confirm to proceed."
        );
    }

    let (_config, mut store) = open_store(config_name)?;

    let session_id: uuid::Uuid = session_id_str
        .parse()
        .with_context(|| format!("invalid session UUID: '{session_id_str}'"))?;

    // Show what will be deleted
    let entry_count = store
        .count_session_entries(&session_id)
        .context("failed to count session entries")?;

    store
        .delete_session(&session_id)
        .with_context(|| format!("failed to delete session {session_id_str}"))?;

    println!("Deleted session {session_id} and {entry_count} audit entries.");
    Ok(())
}

/// Run `aegis sessions fork UUID` -- fork a session, creating a branch point.
pub fn fork(config_name: &str, session_id_str: &str) -> Result<()> {
    let (_config, mut store) = open_store(config_name)?;

    let parent_id: uuid::Uuid = session_id_str
        .parse()
        .with_context(|| format!("invalid session UUID: '{session_id_str}'"))?;

    let forked = store
        .fork_session(parent_id, config_name, "fork", &[])
        .with_context(|| format!("failed to fork session {session_id_str}"))?;

    println!("Forked session (new conversation tree):");
    println!("  New session:  {}", forked.session_id);
    println!("  Parent:       {parent_id}");
    if let Some(ref group) = forked.group_id {
        println!("  Group:        {group}");
    }
    if let Some(ref sender) = forked.sender_id {
        println!("  Sender:       {sender}");
    }

    Ok(())
}

/// Run `aegis sessions tree UUID` -- display the session tree from a root session.
pub fn tree(config_name: &str, session_id_str: &str) -> Result<()> {
    let (_config, store) = open_store(config_name)?;

    let root_id: uuid::Uuid = session_id_str
        .parse()
        .with_context(|| format!("invalid session UUID: '{session_id_str}'"))?;

    let flat_nodes = store
        .list_session_tree(&root_id)
        .context("failed to list session tree")?;

    if flat_nodes.is_empty() {
        println!("No sessions found for root {session_id_str}.");
        return Ok(());
    }

    let built_tree = aegis_ledger::build_session_tree(&flat_nodes);

    println!(
        "Session tree from {} ({} nodes):",
        session_id_str,
        flat_nodes.len()
    );
    println!();

    for root in &built_tree {
        print_tree_node(root, "");
    }

    Ok(())
}

/// Recursively print a session tree node with indentation.
fn print_tree_node(node: &aegis_ledger::SessionTreeNode, prefix: &str) {
    let status = if node.session.end_time.is_some() {
        "ended"
    } else {
        "active"
    };
    let cmd = if node.session.args.is_empty() {
        node.session.command.clone()
    } else {
        format!("{} {}", node.session.command, node.session.args.join(" "))
    };
    let start = node.session.start_time.format(DATETIME_FULL_FMT);
    let resumable = if node.session.resumable {
        " [resumable]"
    } else {
        ""
    };

    println!(
        "{prefix}{} [{status}] {start} {cmd}{resumable}",
        node.session.session_id,
    );

    for (i, child) in node.children.iter().enumerate() {
        let is_last = i == node.children.len() - 1;
        let connector = if is_last { "`-- " } else { "|-- " };
        let child_prefix = if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}|   ")
        };
        print!("{prefix}{connector}");
        // Print the child inline (without the prefix, since we already printed the connector)
        let child_status = if child.session.end_time.is_some() {
            "ended"
        } else {
            "active"
        };
        let child_cmd = if child.session.args.is_empty() {
            child.session.command.clone()
        } else {
            format!("{} {}", child.session.command, child.session.args.join(" "))
        };
        let child_start = child.session.start_time.format(DATETIME_FULL_FMT);
        let child_resumable = if child.session.resumable {
            " [resumable]"
        } else {
            ""
        };
        println!(
            "{} [{child_status}] {child_start} {child_cmd}{child_resumable}",
            child.session.session_id,
        );
        // Print grandchildren with updated prefix
        for (j, grandchild) in child.children.iter().enumerate() {
            let gc_is_last = j == child.children.len() - 1;
            let gc_connector = if gc_is_last { "`-- " } else { "|-- " };
            let gc_prefix = if gc_is_last {
                format!("{child_prefix}    ")
            } else {
                format!("{child_prefix}|   ")
            };
            print!("{child_prefix}{gc_connector}");
            print_tree_node_inline(grandchild, &gc_prefix);
        }
    }
}

/// Print a tree node inline (after a connector was already printed).
fn print_tree_node_inline(node: &aegis_ledger::SessionTreeNode, prefix: &str) {
    let status = if node.session.end_time.is_some() {
        "ended"
    } else {
        "active"
    };
    let cmd = if node.session.args.is_empty() {
        node.session.command.clone()
    } else {
        format!("{} {}", node.session.command, node.session.args.join(" "))
    };
    let start = node.session.start_time.format(DATETIME_FULL_FMT);
    let resumable = if node.session.resumable {
        " [resumable]"
    } else {
        ""
    };

    println!(
        "{} [{status}] {start} {cmd}{resumable}",
        node.session.session_id,
    );

    for (i, child) in node.children.iter().enumerate() {
        let is_last = i == node.children.len() - 1;
        let connector = if is_last { "`-- " } else { "|-- " };
        let child_prefix = if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}|   ")
        };
        print!("{prefix}{connector}");
        print_tree_node_inline(child, &child_prefix);
    }
}

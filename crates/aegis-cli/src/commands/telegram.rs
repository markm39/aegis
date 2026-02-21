//! Interactive Telegram setup wizard.
//!
//! Guides the user through creating a Telegram bot, validating the token,
//! auto-discovering the chat ID, and writing the config to `daemon.toml`.
//! Modeled after OpenClaw's onboarding flow.

use std::io::{self, BufRead, Write};
use std::time::Duration;

use anyhow::{bail, Context};

use aegis_channel::telegram::api::TelegramApi;
use aegis_types::config::{ChannelConfig, TelegramConfig};
use aegis_types::daemon::{daemon_config_path, daemon_dir, DaemonConfig};

/// Entry point: create a tokio runtime and run the async wizard.
pub fn run() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create tokio runtime")?;
    rt.block_on(run_setup())
}

async fn run_setup() -> anyhow::Result<()> {
    println!("Telegram Setup");
    println!("==============");
    println!();
    println!("Step 1: Create a bot");
    println!("  1. Open Telegram and search for @BotFather");
    println!("  2. Send /newbot and follow the prompts");
    println!("  3. Copy the bot token (looks like 123456:ABC-DEF...)");
    println!();

    // Get and validate bot token
    let token = prompt_token()?;
    let user = validate_token(&token).await?;

    let bot_username = user.username.as_deref().unwrap_or("your_bot");
    println!("  Connected to bot @{bot_username} ({})", user.first_name);
    println!();

    // Auto-discover chat ID
    let api = TelegramApi::new(&token);
    let chat_id = discover_chat_id(&api, bot_username).await?;

    // Send confirmation message
    let confirm_text = format!(
        "Aegis connected! This chat will receive agent notifications.\n\
         Chat ID: {chat_id}"
    );
    api.send_message(chat_id, &confirm_text, None, None, false)
        .await
        .context("failed to send confirmation message")?;
    println!("  Sent confirmation message to Telegram");
    println!();

    // Write config
    write_config(&token, chat_id)?;

    // Print summary
    let config_path = daemon_config_path();
    println!("Setup complete!");
    println!("  Bot:     @{bot_username}");
    println!("  Chat ID: {chat_id}");
    println!("  Config:  {}", config_path.display());
    println!();
    println!("The daemon will send Telegram notifications when started.");
    println!("Run `aegis daemon run` or `aegis daemon start` to begin.");

    Ok(())
}

/// Read the bot token from `$AEGIS_TELEGRAM_BOT_TOKEN` or stdin.
pub(crate) fn prompt_token() -> anyhow::Result<String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    // Check env var first
    if let Ok(env_token) = std::env::var("AEGIS_TELEGRAM_BOT_TOKEN") {
        let env_token = env_token.trim().to_string();
        if !env_token.is_empty() {
            print!("Found token in $AEGIS_TELEGRAM_BOT_TOKEN. Use it? [Y/n] ");
            stdout.flush()?;
            let mut answer = String::new();
            stdin.lock().read_line(&mut answer)?;
            let answer = answer.trim().to_lowercase();
            if answer.is_empty() || answer == "y" || answer == "yes" {
                return Ok(env_token);
            }
        }
    }

    print!("Paste your bot token: ");
    stdout.flush()?;
    let mut token = String::new();
    stdin.lock().read_line(&mut token)?;
    let token = token.trim().to_string();

    if token.is_empty() {
        bail!("no token provided");
    }

    Ok(token)
}

/// Validate a bot token by calling `getMe`.
pub(crate) async fn validate_token(
    token: &str,
) -> anyhow::Result<aegis_channel::telegram::types::User> {
    let api = TelegramApi::new(token);
    print!("  Validating token... ");
    io::stdout().flush()?;

    match api.get_me().await {
        Ok(user) => {
            println!("ok");
            Ok(user)
        }
        Err(e) => {
            println!("failed");
            bail!("invalid bot token: {e}\n  Check the token and try again.");
        }
    }
}

/// Poll `getUpdates` until a message arrives, then return the chat ID.
///
/// Pure polling logic with no I/O. Safe to call from both CLI and TUI contexts.
/// Uses 5-second long-poll intervals with the given timeout.
pub(crate) async fn poll_for_chat_id(api: &TelegramApi, timeout_secs: u64) -> anyhow::Result<i64> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut offset: Option<i64> = None;

    // Drain any old updates first so we only detect fresh messages
    loop {
        let updates = api.get_updates(offset, 0).await?;
        match updates.last() {
            Some(last) => offset = Some(last.update_id + 1),
            None => break,
        }
    }

    // Now poll for the user's message
    while tokio::time::Instant::now() < deadline {
        let updates = api.get_updates(offset, 5).await?;

        for update in &updates {
            offset = Some(update.update_id + 1);

            if let Some(ref msg) = update.message {
                return Ok(msg.chat.id);
            }
        }
    }

    bail!("timed out waiting for a Telegram message");
}

/// Poll `getUpdates` until a message arrives, then return the chat ID.
///
/// CLI wrapper that prints progress to stdout.
/// Uses 5-second long-poll intervals with a 60-second total timeout.
pub(crate) async fn discover_chat_id(api: &TelegramApi, bot_username: &str) -> anyhow::Result<i64> {
    println!("Step 2: Send any message to @{bot_username} on Telegram");
    println!("  Waiting for your message (60s timeout)...");

    let chat_id = poll_for_chat_id(api, 60).await?;
    println!("  Found chat: {chat_id}");
    Ok(chat_id)
}

/// Show current Telegram configuration status.
pub fn status() -> anyhow::Result<()> {
    let config_path = daemon_config_path();
    if !config_path.exists() {
        println!("No daemon config found. Run `aegis` to set up.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config = DaemonConfig::from_toml(&content)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;

    match &config.channel {
        Some(ChannelConfig::Telegram(tg)) => {
            println!("Telegram: configured");
            // Don't print the full token for security
            let token_preview = crate::tui_utils::truncate_str(&tg.bot_token, 13);
            println!("  Bot token:       {token_preview}");
            println!("  Chat ID:         {}", tg.chat_id);
            println!("  Poll timeout:    {}s", tg.poll_timeout_secs);
            println!(
                "  Group commands:  {}",
                if tg.allow_group_commands {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!();
            println!("To reconfigure: aegis telegram setup");
            println!("To disable:     aegis telegram disable");
        }
        Some(ChannelConfig::Slack(slack)) => {
            println!("Telegram: not configured (Slack channel active)");
            println!("  Slack channel: {}", slack.channel_id);
            println!();
            println!("To set up Telegram: aegis telegram setup");
        }
        Some(_) => {
            println!("Telegram: not configured (other channel type active)");
            println!();
            println!("To set up Telegram: aegis telegram setup");
        }
        None => {
            println!("Telegram: not configured");
            println!();
            println!("To set up: aegis telegram setup");
        }
    }

    Ok(())
}

/// Remove Telegram configuration from daemon.toml.
pub fn disable() -> anyhow::Result<()> {
    let config_path = daemon_config_path();
    if !config_path.exists() {
        anyhow::bail!("no daemon config found -- nothing to disable");
    }

    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let mut config = DaemonConfig::from_toml(&content)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;

    if config.channel.is_none() {
        anyhow::bail!("Telegram is not configured -- nothing to disable");
    }

    config.channel = None;
    let toml_str = config.to_toml().context("failed to serialize config")?;
    std::fs::write(&config_path, &toml_str)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    println!("Telegram notifications disabled.");
    println!("Run 'aegis daemon reload' to apply changes.");

    Ok(())
}

/// Remove Telegram configuration without printing to stdout.
///
/// Returns a message describing what happened. Used by TUI.
pub(crate) fn disable_quiet() -> anyhow::Result<String> {
    let config_path = daemon_config_path();
    if !config_path.exists() {
        anyhow::bail!("no daemon config found -- nothing to disable");
    }

    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let mut config = DaemonConfig::from_toml(&content)
        .with_context(|| format!("failed to parse {}", config_path.display()))?;

    if config.channel.is_none() {
        anyhow::bail!("Telegram is not configured -- nothing to disable");
    }

    config.channel = None;
    let toml_str = config.to_toml().context("failed to serialize config")?;
    std::fs::write(&config_path, &toml_str)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    Ok("Telegram notifications disabled. Run :daemon reload to apply.".to_string())
}

/// Write the Telegram config into `daemon.toml`, merging with existing config.
pub(crate) fn write_config(bot_token: &str, chat_id: i64) -> anyhow::Result<()> {
    let dir = daemon_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let config_path = daemon_config_path();

    // Load existing config or create default
    let mut config = if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?;
        DaemonConfig::from_toml(&content)
            .with_context(|| format!("failed to parse {}", config_path.display()))?
    } else {
        DaemonConfig::from_toml("").context("failed to create default config")?
    };

    config.channel = Some(ChannelConfig::Telegram(TelegramConfig {
        bot_token: bot_token.to_string(),
        chat_id,
        poll_timeout_secs: 30,
        allow_group_commands: false,
        active_hours: None,
        webhook_mode: false,
        webhook_port: None,
        webhook_url: None,
        webhook_secret: None,
        inline_queries_enabled: false,
    }));

    let toml_str = config.to_toml().context("failed to serialize config")?;
    std::fs::write(&config_path, &toml_str)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    println!("  Wrote config to {}", config_path.display());

    Ok(())
}

//! Channel-specific setup wizard definitions.
//!
//! Each public function returns a `GenericChannelWizard` pre-configured
//! with the instructions, fields, and builder for that channel type.

use aegis_types::config::*;

use super::generic::{field, optional_field, GenericChannelWizard};

// ── Slack ───────────────────────────────────────────────────────────────────

pub fn slack() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Slack Setup",
        &[
            "1. Go to api.slack.com/apps and create or select an app",
            "2. Under OAuth & Permissions, install to workspace",
            "3. Copy the Bot User OAuth Token (xoxb-...)",
            "4. Invite the bot to a channel; copy the Channel ID",
        ],
        vec![
            field("bot_token", "Bot Token (xoxb-...):", true),
            field("channel_id", "Channel ID:", false),
        ],
        |v| {
            ChannelConfig::Slack(SlackConfig {
                bot_token: v[0].clone(),
                channel_id: v[1].clone(),
                recipient_team_id: None,
                recipient_user_id: None,
                streaming: false,
                active_hours: None,
                signing_secret: None,
                oauth_client_id: None,
                interactive_endpoint_port: None,
            })
        },
    )
}

// ── Discord ─────────────────────────────────────────────────────────────────

pub fn discord() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Discord Setup",
        &[
            "1. Go to discord.com/developers/applications",
            "2. Create or select a bot application",
            "3. Under Webhooks, create a webhook for your channel",
            "4. Copy the Webhook URL",
        ],
        vec![field("webhook_url", "Webhook URL:", false)],
        |v| {
            ChannelConfig::Discord(DiscordChannelConfig {
                webhook_url: v[0].clone(),
                bot_token: None,
                channel_id: None,
                guild_id: None,
                application_id: None,
                public_key: None,
                authorized_user_ids: Vec::new(),
                command_channel_id: None,
                active_hours: None,
            })
        },
    )
}

// ── WhatsApp ────────────────────────────────────────────────────────────────

pub fn whatsapp() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "WhatsApp Setup",
        &[
            "1. Go to developers.facebook.com and create a WhatsApp app",
            "2. Copy the API URL, Access Token, and Phone Number ID",
            "   from the WhatsApp > API Setup page",
        ],
        vec![
            field("api_url", "API URL:", false),
            field("access_token", "Access Token:", true),
            field("phone_number_id", "Phone Number ID:", false),
        ],
        |v| {
            ChannelConfig::Whatsapp(WhatsappChannelConfig {
                api_url: v[0].clone(),
                access_token: v[1].clone(),
                phone_number_id: v[2].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Signal ──────────────────────────────────────────────────────────────────

pub fn signal() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Signal Setup",
        &[
            "Requires signal-cli REST API running locally or remotely.",
            "1. Set up signal-cli with a registered phone number",
            "2. Start the REST API (signal-cli-rest-api)",
            "3. Enter the API URL and your registered phone number",
        ],
        vec![
            field("api_url", "Signal REST API URL:", false),
            field("phone_number", "Phone Number (E.164, e.g. +1234567890):", false),
        ],
        |v| {
            ChannelConfig::Signal(SignalChannelConfig {
                api_url: v[0].clone(),
                phone_number: v[1].clone(),
                recipients: Vec::new(),
                active_hours: None,
            })
        },
    )
}

// ── Matrix ──────────────────────────────────────────────────────────────────

pub fn matrix() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Matrix Setup",
        &[
            "1. Create a bot account on your Matrix homeserver",
            "2. Generate an access token for the bot",
            "3. Invite the bot to a room and copy the Room ID",
        ],
        vec![
            field("homeserver_url", "Homeserver URL:", false),
            field("access_token", "Access Token:", true),
            field("room_id", "Room ID (!room:server):", false),
        ],
        |v| {
            ChannelConfig::Matrix(MatrixChannelConfig {
                homeserver_url: v[0].clone(),
                access_token: v[1].clone(),
                room_id: v[2].clone(),
                active_hours: None,
            })
        },
    )
}

// ── iMessage ────────────────────────────────────────────────────────────────

pub fn imessage() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "iMessage Setup",
        &[
            "Requires macOS with Full Disk Access enabled for Aegis.",
            "Uses an API bridge to send/receive iMessages.",
            "1. Set up the iMessage API bridge (e.g., pypush or similar)",
            "2. Enter the bridge API URL and recipient",
        ],
        vec![
            field("api_url", "API Bridge URL:", false),
            field("recipient", "Recipient (phone or email):", false),
        ],
        |v| {
            ChannelConfig::Imessage(ImessageChannelConfig {
                api_url: v[0].clone(),
                recipient: v[1].clone(),
                active_hours: None,
            })
        },
    )
}

// ── IRC ─────────────────────────────────────────────────────────────────────

pub fn irc() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "IRC Setup",
        &[
            "Connect to an IRC server via an HTTP bridge.",
            "1. Enter the IRC server hostname",
            "2. Enter the channel to join (e.g., #aegis)",
            "3. Choose a bot nickname",
        ],
        vec![
            field("server", "IRC Server:", false),
            field("channel", "Channel (e.g., #aegis):", false),
            field("nick", "Bot Nickname:", false),
        ],
        |v| {
            ChannelConfig::Irc(IrcChannelConfig {
                server: v[0].clone(),
                channel: v[1].clone(),
                nick: v[2].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Microsoft Teams ─────────────────────────────────────────────────────────

pub fn msteams() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Microsoft Teams Setup",
        &[
            "1. In Teams, go to the channel > Manage channel",
            "2. Under Connectors, add 'Incoming Webhook'",
            "3. Name the webhook and copy the URL",
        ],
        vec![field("webhook_url", "Webhook URL:", false)],
        |v| {
            ChannelConfig::Msteams(MsteamsChannelConfig {
                webhook_url: v[0].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Google Chat ─────────────────────────────────────────────────────────────

pub fn googlechat() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Google Chat Setup",
        &[
            "1. Open a Google Chat space",
            "2. Go to Space settings > Integrations > Webhooks",
            "3. Create a webhook and copy the URL",
        ],
        vec![field("webhook_url", "Webhook URL:", false)],
        |v| {
            ChannelConfig::Googlechat(GooglechatChannelConfig {
                webhook_url: v[0].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Feishu (Lark) ───────────────────────────────────────────────────────────

pub fn feishu() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Feishu (Lark) Setup",
        &[
            "1. In Feishu, create a custom bot in your group",
            "2. Copy the webhook URL",
            "3. Optionally set a signing secret for verification",
        ],
        vec![
            field("webhook_url", "Webhook URL:", false),
            optional_field("secret", "Signing Secret (optional, Enter to skip):", true),
        ],
        |v| {
            let secret = if v[1].is_empty() { None } else { Some(v[1].clone()) };
            ChannelConfig::Feishu(FeishuChannelConfig {
                webhook_url: v[0].clone(),
                secret,
                active_hours: None,
            })
        },
    )
}

// ── LINE ────────────────────────────────────────────────────────────────────

pub fn line() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "LINE Setup",
        &[
            "1. Go to developers.line.biz and create a Messaging API channel",
            "2. Issue a long-lived Channel Access Token",
            "3. Copy the target User ID from the LINE developer console",
        ],
        vec![
            field("channel_access_token", "Channel Access Token:", true),
            field("user_id", "User ID:", false),
        ],
        |v| {
            ChannelConfig::Line(LineChannelConfig {
                channel_access_token: v[0].clone(),
                user_id: v[1].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Nostr ───────────────────────────────────────────────────────────────────

pub fn nostr() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Nostr Setup",
        &[
            "1. Choose a Nostr relay (e.g., wss://relay.damus.io)",
            "2. Generate or provide a private key in hex format",
            "   (use a dedicated key for the bot, not your main key)",
        ],
        vec![
            field("relay_url", "Relay URL (wss://...):", false),
            field("private_key_hex", "Private Key (hex):", true),
        ],
        |v| {
            ChannelConfig::Nostr(NostrChannelConfig {
                relay_url: v[0].clone(),
                private_key_hex: v[1].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Mattermost ──────────────────────────────────────────────────────────────

pub fn mattermost() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Mattermost Setup",
        &[
            "1. In Mattermost, go to Integrations > Incoming Webhooks",
            "2. Create a webhook and copy the URL",
        ],
        vec![field("webhook_url", "Webhook URL:", false)],
        |v| {
            ChannelConfig::Mattermost(MattermostChannelConfig {
                webhook_url: v[0].clone(),
                channel_id: None,
                active_hours: None,
            })
        },
    )
}

// ── Voice Call ──────────────────────────────────────────────────────────────

pub fn voicecall() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Voice Call Setup",
        &[
            "Requires a telephony API (Twilio, Vonage, etc.).",
            "1. Set up a telephony provider and get API credentials",
            "2. Enter the API endpoint, caller, and recipient numbers",
        ],
        vec![
            field("api_url", "Telephony API URL:", false),
            field("from_number", "From Number (E.164):", false),
            field("to_number", "To Number (E.164):", false),
        ],
        |v| {
            ChannelConfig::VoiceCall(VoiceCallChannelConfig {
                api_url: v[0].clone(),
                from_number: v[1].clone(),
                to_number: v[2].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Twitch ──────────────────────────────────────────────────────────────────

pub fn twitch() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Twitch Setup",
        &[
            "1. Go to dev.twitch.tv/console and register an application",
            "2. Generate an OAuth token for your bot account",
            "3. Enter the channel name and bot username",
        ],
        vec![
            field("oauth_token", "OAuth Token:", true),
            field("channel_name", "Channel Name:", false),
            field("bot_username", "Bot Username:", false),
        ],
        |v| {
            ChannelConfig::Twitch(TwitchChannelConfig {
                oauth_token: v[0].clone(),
                channel_name: v[1].clone(),
                bot_username: v[2].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Nextcloud ───────────────────────────────────────────────────────────────

pub fn nextcloud() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Nextcloud Talk Setup",
        &[
            "1. Log in to your Nextcloud instance",
            "2. Create an App Password under Settings > Security",
            "3. Open a Talk conversation and copy the room token from the URL",
        ],
        vec![
            field("server_url", "Server URL (https://...):", false),
            field("username", "Username:", false),
            field("app_password", "App Password:", true),
            field("room_token", "Room Token:", false),
        ],
        |v| {
            ChannelConfig::Nextcloud(NextcloudChannelConfig {
                server_url: v[0].clone(),
                username: v[1].clone(),
                app_password: v[2].clone(),
                room_token: v[3].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Zalo ────────────────────────────────────────────────────────────────────

pub fn zalo() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Zalo Official Account Setup",
        &[
            "1. Create a Zalo Official Account at oa.zalo.me",
            "2. Copy your OA ID, Access Token, and Secret Key",
        ],
        vec![
            field("oa_id", "Official Account ID:", false),
            field("access_token", "Access Token:", true),
            field("secret_key", "Secret Key:", true),
        ],
        |v| {
            ChannelConfig::Zalo(ZaloChannelConfig {
                oa_id: v[0].clone(),
                access_token: v[1].clone(),
                secret_key: v[2].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Tlon (Urbit) ────────────────────────────────────────────────────────────

pub fn tlon() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Tlon (Urbit) Setup",
        &[
            "1. Ensure your Urbit ship is running and accessible",
            "2. Enter the ship's API URL and ship name",
        ],
        vec![
            field("ship_url", "Ship API URL:", false),
            field("ship_name", "Ship Name (e.g., ~zod):", false),
        ],
        |v| {
            ChannelConfig::Tlon(TlonChannelConfig {
                ship_url: v[0].clone(),
                ship_name: v[1].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Lobster ─────────────────────────────────────────────────────────────────

pub fn lobster() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Lobster Setup",
        &[
            "1. Set up your Lobster instance",
            "2. Generate an API key and copy the API URL",
        ],
        vec![
            field("api_url", "API URL:", false),
            field("api_key", "API Key:", true),
        ],
        |v| {
            ChannelConfig::Lobster(LobsterChannelConfig {
                api_url: v[0].clone(),
                api_key: v[1].clone(),
                active_hours: None,
            })
        },
    )
}

// ── Gmail ───────────────────────────────────────────────────────────────────

pub fn gmail() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Gmail Setup",
        &[
            "1. Go to console.cloud.google.com",
            "2. Enable the Gmail API for your project",
            "3. Create OAuth2 credentials (Desktop application)",
            "4. Copy the Client ID",
            "5. Set the client secret in an environment variable",
        ],
        vec![
            field("client_id", "OAuth2 Client ID:", false),
            field(
                "client_secret_env",
                "Env var name holding client secret:",
                false,
            ),
        ],
        |v| {
            ChannelConfig::Gmail(GmailChannelConfig {
                client_id: v[0].clone(),
                client_secret_env: v[1].clone(),
                project_id: None,
                watch_labels: vec!["INBOX".to_string()],
                token_path: None,
                active_hours: None,
            })
        },
    )
}

// ── Generic Webhook ─────────────────────────────────────────────────────────

pub fn webhook() -> GenericChannelWizard {
    GenericChannelWizard::new(
        "Webhook Setup",
        &[
            "Set up a generic outbound webhook.",
            "Messages will be POSTed as JSON to the URL you provide.",
        ],
        vec![
            field("name", "Channel Name:", false),
            field("outbound_url", "Outbound URL:", false),
        ],
        |v| {
            ChannelConfig::Webhook(WebhookChannelConfig {
                name: v[0].clone(),
                outbound_url: v[1].clone(),
                inbound_url: None,
                auth_header: None,
                payload_template: r#"{"text":"{text}"}"#.to_string(),
                active_hours: None,
            })
        },
    )
}

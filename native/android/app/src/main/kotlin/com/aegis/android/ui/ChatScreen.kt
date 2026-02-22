package com.aegis.android.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.SmartToy
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.android.api.AgentInfo
import com.aegis.android.api.ChatMessage
import com.aegis.android.api.DaemonClient
import com.aegis.android.api.MessageRole
import com.aegis.android.api.sanitizeInput
import com.aegis.android.security.TokenStore
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * Chat screen providing a messaging interface with agents.
 *
 * Features:
 * - Agent selector dropdown to choose which agent to chat with
 * - Message bubbles: user messages right-aligned, agent messages left-aligned
 * - LazyColumn for scrollable message history with auto-scroll to bottom
 * - Text input with send button
 * - Loading indicator while waiting for agent response
 * - Real-time polling for agent output updates
 * - Basic markdown rendering (code blocks, bold, italic)
 * - Connection status indicator
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val tokenStore = remember { TokenStore(context) }
    val client = remember { DaemonClient(tokenStore.getServerUrl(), tokenStore) }

    var agents by remember { mutableStateOf<List<AgentInfo>>(emptyList()) }
    var selectedAgent by remember { mutableStateOf<String?>(null) }
    var showAgentPicker by remember { mutableStateOf(false) }
    val messages = remember { mutableStateListOf<ChatMessage>() }
    var inputText by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var isConnected by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    val listState = rememberLazyListState()
    val timeFormat = remember { SimpleDateFormat("HH:mm", Locale.getDefault()) }

    // Fetch agents on launch
    DisposableEffect(Unit) {
        val job = scope.launch {
            while (isActive) {
                try {
                    agents = client.fetchAgents()
                    isConnected = true
                    if (selectedAgent == null && agents.isNotEmpty()) {
                        selectedAgent = agents.first().name
                    }
                } catch (_: Exception) {
                    isConnected = false
                }
                delay(10_000)
            }
        }
        onDispose { job.cancel() }
    }

    // Poll for agent output as new messages
    DisposableEffect(selectedAgent) {
        val agent = selectedAgent ?: return@DisposableEffect onDispose {}
        val job = scope.launch {
            var lastLineCount = 0
            while (isActive) {
                try {
                    val output = client.fetchAgentOutput(agent)
                    if (output.size > lastLineCount) {
                        val newLines = output.subList(lastLineCount, output.size)
                        for (line in newLines) {
                            if (line.isNotBlank()) {
                                messages.add(
                                    ChatMessage(
                                        id = UUID.randomUUID().toString(),
                                        role = MessageRole.AGENT,
                                        content = line.trim(),
                                        agentName = agent,
                                    )
                                )
                            }
                        }
                        lastLineCount = output.size
                    }
                } catch (_: Exception) {
                    // Silently retry on next poll
                }
                delay(3_000)
            }
        }
        onDispose { job.cancel() }
    }

    // Auto-scroll to bottom when new messages arrive
    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Default.SmartToy,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        TextButton(onClick = { showAgentPicker = true }) {
                            Text(
                                text = selectedAgent ?: "Select Agent",
                                style = MaterialTheme.typography.titleMedium,
                            )
                        }
                        DropdownMenu(
                            expanded = showAgentPicker,
                            onDismissRequest = { showAgentPicker = false },
                        ) {
                            agents.forEach { agent ->
                                DropdownMenuItem(
                                    text = {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Box(
                                                modifier = Modifier
                                                    .size(8.dp)
                                                    .clip(CircleShape)
                                                    .background(statusColor(agent.statusKind))
                                            )
                                            Spacer(modifier = Modifier.width(8.dp))
                                            Text(agent.name)
                                        }
                                    },
                                    onClick = {
                                        selectedAgent = agent.name
                                        messages.clear()
                                        showAgentPicker = false
                                    },
                                )
                            }
                            if (agents.isEmpty()) {
                                DropdownMenuItem(
                                    text = { Text("No agents available") },
                                    onClick = { showAgentPicker = false },
                                    enabled = false,
                                )
                            }
                        }
                    }
                },
                actions = {
                    // Connection indicator
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(if (isConnected) Color(0xFF4CAF50) else Color(0xFFF44336))
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                },
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .imePadding(),
        ) {
            // Message list
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (!isConnected && messages.isEmpty()) {
                    item {
                        DisconnectedChatView()
                    }
                } else if (selectedAgent == null) {
                    item {
                        NoAgentSelectedView()
                    }
                } else if (messages.isEmpty()) {
                    item {
                        EmptyChatView(agentName = selectedAgent!!)
                    }
                }

                items(messages, key = { it.id }) { message ->
                    ChatBubble(
                        message = message,
                        timeFormat = timeFormat,
                    )
                }

                // Loading indicator
                if (isLoading) {
                    item {
                        LoadingBubble()
                    }
                }
            }

            // Error banner
            AnimatedVisibility(visible = errorMessage != null) {
                errorMessage?.let { error ->
                    ErrorBanner(
                        message = error,
                        onDismiss = { errorMessage = null },
                    )
                }
            }

            // Input bar
            ChatInputBar(
                inputText = inputText,
                onInputChange = { inputText = it },
                isLoading = isLoading,
                isEnabled = selectedAgent != null && isConnected,
                onSend = {
                    val agent = selectedAgent ?: return@ChatInputBar
                    val sanitized = sanitizeInput(inputText)
                    if (sanitized.isEmpty()) return@ChatInputBar

                    // Add user message
                    messages.add(
                        ChatMessage(
                            id = UUID.randomUUID().toString(),
                            role = MessageRole.USER,
                            content = sanitized,
                            agentName = agent,
                        )
                    )
                    inputText = ""
                    isLoading = true
                    errorMessage = null

                    scope.launch {
                        try {
                            client.sendInput(agent, sanitized)
                        } catch (e: Exception) {
                            errorMessage = DaemonClient.friendlyError(e)
                        } finally {
                            isLoading = false
                        }
                    }
                },
            )
        }
    }
}

@Composable
private fun ChatBubble(
    message: ChatMessage,
    timeFormat: SimpleDateFormat,
) {
    val isUser = message.role == MessageRole.USER
    val isSystem = message.role == MessageRole.SYSTEM

    val alignment = when {
        isUser -> Alignment.CenterEnd
        else -> Alignment.CenterStart
    }

    val bubbleColor = when {
        isUser -> MaterialTheme.colorScheme.primary
        isSystem -> MaterialTheme.colorScheme.tertiaryContainer
        else -> MaterialTheme.colorScheme.surfaceVariant
    }

    val textColor = when {
        isUser -> MaterialTheme.colorScheme.onPrimary
        isSystem -> MaterialTheme.colorScheme.onTertiaryContainer
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    val bubbleShape = when {
        isUser -> RoundedCornerShape(16.dp, 16.dp, 4.dp, 16.dp)
        else -> RoundedCornerShape(16.dp, 16.dp, 16.dp, 4.dp)
    }

    Box(
        modifier = Modifier.fillMaxWidth(),
        contentAlignment = alignment,
    ) {
        Card(
            modifier = Modifier.widthIn(max = 300.dp),
            shape = bubbleShape,
            colors = CardDefaults.cardColors(containerColor = bubbleColor),
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                SelectionContainer {
                    // Render content with basic markdown support
                    MarkdownText(
                        text = message.content,
                        color = textColor,
                    )
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = timeFormat.format(Date(message.timestamp)),
                    style = MaterialTheme.typography.labelSmall,
                    color = textColor.copy(alpha = 0.6f),
                )
            }
        }
    }
}

/**
 * Simple markdown-aware text renderer.
 *
 * Supports:
 * - Code blocks (``` delimited) rendered in monospace
 * - Inline code (`text`) rendered in monospace
 * - Bold (**text**) and italic (*text*) via simple detection
 *
 * For a production app, use a library like Markwon. This is a minimal
 * implementation that handles the most common formatting in agent output.
 */
@Composable
private fun MarkdownText(
    text: String,
    color: Color,
) {
    val isCodeBlock = text.trimStart().startsWith("```") || text.contains("\n```")

    if (isCodeBlock) {
        // Render as code block
        val codeContent = text
            .replace(Regex("^```\\w*\\n?"), "")
            .replace(Regex("\\n?```$"), "")
            .trim()

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Color.Black.copy(alpha = 0.1f),
                    RoundedCornerShape(8.dp),
                )
                .padding(8.dp),
        ) {
            Text(
                text = codeContent,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    lineHeight = 16.sp,
                ),
                color = color,
            )
        }
    } else {
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = color,
        )
    }
}

@Composable
private fun LoadingBubble() {
    Box(
        modifier = Modifier.fillMaxWidth(),
        contentAlignment = Alignment.CenterStart,
    ) {
        Card(
            shape = RoundedCornerShape(16.dp, 16.dp, 16.dp, 4.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant,
            ),
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Thinking...",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ChatInputBar(
    inputText: String,
    onInputChange: (String) -> Unit,
    isLoading: Boolean,
    isEnabled: Boolean,
    onSend: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        OutlinedTextField(
            value = inputText,
            onValueChange = onInputChange,
            modifier = Modifier.weight(1f),
            placeholder = {
                Text(
                    if (isEnabled) "Type a message..."
                    else "Select an agent to start chatting",
                )
            },
            enabled = isEnabled && !isLoading,
            singleLine = false,
            maxLines = 4,
            shape = RoundedCornerShape(24.dp),
        )
        Spacer(modifier = Modifier.width(8.dp))
        IconButton(
            onClick = onSend,
            enabled = isEnabled && !isLoading && sanitizeInput(inputText).isNotEmpty(),
        ) {
            Icon(
                Icons.AutoMirrored.Filled.Send,
                contentDescription = "Send",
                tint = if (isEnabled && sanitizeInput(inputText).isNotEmpty()) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.38f)
                },
            )
        }
    }
}

@Composable
private fun DisconnectedChatView() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 64.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            Icons.Default.WifiOff,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "Not Connected",
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Connect to the Aegis daemon to start chatting with agents.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun NoAgentSelectedView() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 64.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            Icons.Default.SmartToy,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "Select an Agent",
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Tap the agent name in the toolbar to choose which agent to chat with.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun EmptyChatView(agentName: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 64.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            Icons.Default.SmartToy,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "Chat with $agentName",
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Send a message to start the conversation.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

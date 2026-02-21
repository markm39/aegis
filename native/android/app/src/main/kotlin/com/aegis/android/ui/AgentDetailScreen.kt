package com.aegis.android.ui

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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aegis.android.api.AgentInfo
import com.aegis.android.api.AgentStatusKind
import com.aegis.android.api.DaemonClient
import com.aegis.android.api.PendingRequest
import com.aegis.android.api.RiskLevel
import com.aegis.android.api.sanitizeInput
import com.aegis.android.security.TokenStore
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Detail view for a single agent.
 *
 * Sections:
 * - Agent info: name, status, tool, working directory, restart count
 * - Output log: monospace LazyColumn with auto-scroll to bottom
 * - Pending approvals: approve/deny buttons with confirmation dialog
 * - Input: text field for sending text to the agent
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AgentDetailScreen(
    agentName: String,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val tokenStore = remember { TokenStore(context) }
    val client = remember { DaemonClient(tokenStore.getServerUrl(), tokenStore) }

    var agent by remember { mutableStateOf<AgentInfo?>(null) }
    var outputLines by remember { mutableStateOf<List<String>>(emptyList()) }
    var pendingPrompts by remember { mutableStateOf<List<PendingRequest>>(emptyList()) }
    var inputText by remember { mutableStateOf("") }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    // Confirmation dialog state
    var showApproveDialog by remember { mutableStateOf(false) }
    var showDenyDialog by remember { mutableStateOf(false) }
    var selectedRequestId by remember { mutableStateOf<String?>(null) }
    var denyReason by remember { mutableStateOf("") }

    val outputListState = rememberLazyListState()

    // Auto-refresh agent data and output
    DisposableEffect(agentName) {
        val job = scope.launch {
            while (isActive) {
                try {
                    val agents = client.fetchAgents()
                    agent = agents.find { it.name == agentName }

                    val output = client.fetchAgentOutput(agentName)
                    outputLines = output

                    if (agent != null && agent!!.pendingCount > 0) {
                        pendingPrompts = client.listPending(agentName)
                    } else {
                        pendingPrompts = emptyList()
                    }
                    errorMessage = null
                } catch (e: Exception) {
                    errorMessage = e.message
                }
                delay(3_000)
            }
        }
        onDispose { job.cancel() }
    }

    // Auto-scroll output to bottom
    LaunchedEffect(outputLines.size) {
        if (outputLines.isNotEmpty()) {
            outputListState.animateScrollToItem(outputLines.size - 1)
        }
    }

    // Approve confirmation dialog
    if (showApproveDialog && selectedRequestId != null) {
        AlertDialog(
            onDismissRequest = { showApproveDialog = false },
            title = { Text("Confirm Approval") },
            text = { Text("Are you sure you want to approve this request?") },
            confirmButton = {
                Button(onClick = {
                    val reqId = selectedRequestId!!
                    showApproveDialog = false
                    scope.launch {
                        try {
                            client.approveRequest(reqId, agentName)
                            errorMessage = null
                        } catch (e: Exception) {
                            errorMessage = e.message
                        }
                    }
                }) {
                    Text("Approve")
                }
            },
            dismissButton = {
                TextButton(onClick = { showApproveDialog = false }) {
                    Text("Cancel")
                }
            },
        )
    }

    // Deny confirmation dialog
    if (showDenyDialog && selectedRequestId != null) {
        AlertDialog(
            onDismissRequest = { showDenyDialog = false },
            title = { Text("Deny Request") },
            text = {
                Column {
                    Text("Provide an optional reason for denying this request.")
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = denyReason,
                        onValueChange = { denyReason = it },
                        label = { Text("Reason (optional)") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val reqId = selectedRequestId!!
                        val reason = denyReason.ifBlank { null }
                        showDenyDialog = false
                        denyReason = ""
                        scope.launch {
                            try {
                                client.denyRequest(reqId, agentName, reason)
                                errorMessage = null
                            } catch (e: Exception) {
                                errorMessage = e.message
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                    ),
                ) {
                    Text("Deny")
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    showDenyDialog = false
                    denyReason = ""
                }) {
                    Text("Cancel")
                }
            },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(agentName) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Agent info section
            item {
                agent?.let { AgentInfoCard(it) }
            }

            // Output log section
            item {
                OutputLogCard(
                    outputLines = outputLines,
                    listState = outputListState,
                )
            }

            // Pending approvals section
            if (pendingPrompts.isNotEmpty()) {
                item {
                    PendingApprovalsCard(
                        prompts = pendingPrompts,
                        onApprove = { requestId ->
                            selectedRequestId = requestId
                            showApproveDialog = true
                        },
                        onDeny = { requestId ->
                            selectedRequestId = requestId
                            showDenyDialog = true
                        },
                    )
                }
            }

            // Input section
            item {
                InputCard(
                    inputText = inputText,
                    onInputChange = { inputText = it },
                    onSend = {
                        val sanitized = sanitizeInput(inputText)
                        if (sanitized.isNotEmpty()) {
                            inputText = ""
                            scope.launch {
                                try {
                                    client.sendInput(agentName, sanitized)
                                    errorMessage = null
                                } catch (e: Exception) {
                                    errorMessage = e.message
                                }
                            }
                        }
                    },
                )
            }

            // Error banner
            errorMessage?.let { error ->
                item {
                    ErrorBanner(
                        message = error,
                        onDismiss = { errorMessage = null },
                    )
                }
            }
        }
    }
}

@Composable
private fun AgentInfoCard(agent: AgentInfo) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Agent Info",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(modifier = Modifier.height(12.dp))

            InfoRow("Status", agent.statusKind.displayName, statusColor(agent.statusKind))
            InfoRow("Tool", agent.tool)
            InfoRow("Working Dir", agent.workingDir)
            agent.role?.let { InfoRow("Role", it) }
            InfoRow("Restarts", "${agent.restartCount}")
            InfoRow("Pending", "${agent.pendingCount}")
            InfoRow("Orchestrator", if (agent.isOrchestrator) "Yes" else "No")

            if (agent.attentionNeeded) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = "!",
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFFFC107),
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = "Attention needed",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                    )
                }
            }
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String, color: Color? = null) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(100.dp),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = color ?: MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun OutputLogCard(
    outputLines: List<String>,
    listState: androidx.compose.foundation.lazy.LazyListState,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Output",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(modifier = Modifier.height(8.dp))

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(200.dp)
                    .background(
                        MaterialTheme.colorScheme.surface,
                        RoundedCornerShape(8.dp)
                    )
                    .padding(8.dp),
            ) {
                if (outputLines.isEmpty()) {
                    Text(
                        text = "No output available",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    LazyColumn(state = listState) {
                        items(outputLines) { line ->
                            Text(
                                text = line,
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp,
                                    lineHeight = 14.sp,
                                ),
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PendingApprovalsCard(
    prompts: List<PendingRequest>,
    onApprove: (String) -> Unit,
    onDeny: (String) -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Pending Approvals (${prompts.size})",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(modifier = Modifier.height(12.dp))

            prompts.forEach { prompt ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFFFF9800).copy(alpha = 0.05f),
                    ),
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        // Prompt text
                        Text(
                            text = prompt.rawPrompt,
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace,
                            ),
                            maxLines = 6,
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        // Risk badge and actions
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                RiskBadge(prompt.riskLevel)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "${prompt.ageSecs}s ago",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }

                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(
                                    onClick = { onApprove(prompt.requestId) },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = Color(0xFF4CAF50),
                                    ),
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                                ) {
                                    Icon(
                                        Icons.Default.CheckCircle,
                                        contentDescription = null,
                                        modifier = Modifier.size(16.dp),
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Approve", style = MaterialTheme.typography.labelSmall)
                                }
                                OutlinedButton(
                                    onClick = { onDeny(prompt.requestId) },
                                    colors = ButtonDefaults.outlinedButtonColors(
                                        contentColor = MaterialTheme.colorScheme.error,
                                    ),
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                                ) {
                                    Icon(
                                        Icons.Default.Cancel,
                                        contentDescription = null,
                                        modifier = Modifier.size(16.dp),
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Deny", style = MaterialTheme.typography.labelSmall)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun InputCard(
    inputText: String,
    onInputChange: (String) -> Unit,
    onSend: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "Input",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(modifier = Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = inputText,
                    onValueChange = onInputChange,
                    label = { Text("Send input to agent...") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                )
                Spacer(modifier = Modifier.width(8.dp))
                IconButton(
                    onClick = onSend,
                    enabled = sanitizeInput(inputText).isNotEmpty(),
                ) {
                    Icon(
                        Icons.AutoMirrored.Filled.Send,
                        contentDescription = "Send",
                        tint = if (sanitizeInput(inputText).isNotEmpty()) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                    )
                }
            }
        }
    }
}

@Composable
internal fun RiskBadge(risk: RiskLevel) {
    val color = when (risk) {
        RiskLevel.LOW -> Color(0xFF4CAF50)
        RiskLevel.MEDIUM -> Color(0xFFFFC107)
        RiskLevel.HIGH -> Color(0xFFF44336)
    }

    Text(
        text = risk.displayName,
        style = MaterialTheme.typography.labelSmall,
        fontWeight = FontWeight.SemiBold,
        color = color,
        modifier = Modifier
            .background(color.copy(alpha = 0.15f), RoundedCornerShape(12.dp))
            .padding(horizontal = 8.dp, vertical = 3.dp),
    )
}

@Composable
internal fun ErrorBanner(
    message: String,
    onDismiss: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = message,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onDismiss) {
                Text("Dismiss", style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

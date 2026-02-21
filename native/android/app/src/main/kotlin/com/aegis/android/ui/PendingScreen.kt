package com.aegis.android.ui

import androidx.compose.animation.animateColorAsState
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.aegis.android.api.DaemonClient
import com.aegis.android.api.PendingRequest
import com.aegis.android.api.RiskLevel
import com.aegis.android.security.TokenStore
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * View showing all pending approval requests across all agents.
 *
 * Features:
 * - List of pending requests grouped by risk level (high first)
 * - Each row: agent name, action description, risk level chip, age
 * - Swipe-to-dismiss: right = approve, left = deny
 * - Confirmation dialog before every approve/deny action
 * - Pull-to-refresh for manual reload
 * - Auto-refresh every 5 seconds
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PendingScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val tokenStore = remember { TokenStore(context) }
    val client = remember { DaemonClient(tokenStore.getServerUrl(), tokenStore) }

    var pendingRequests by remember { mutableStateOf<List<PendingRequest>>(emptyList()) }
    var isRefreshing by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    // Dialog state
    var showApproveDialog by remember { mutableStateOf(false) }
    var showDenyDialog by remember { mutableStateOf(false) }
    var selectedRequest by remember { mutableStateOf<PendingRequest?>(null) }
    var denyReason by remember { mutableStateOf("") }

    val refresh: suspend () -> Unit = {
        try {
            pendingRequests = client.fetchPendingRequests()
            errorMessage = null
        } catch (e: Exception) {
            errorMessage = e.message
        }
    }

    // Auto-refresh every 5 seconds
    DisposableEffect(Unit) {
        val job = scope.launch {
            while (isActive) {
                refresh()
                delay(5_000)
            }
        }
        onDispose { job.cancel() }
    }

    // Approve confirmation dialog
    if (showApproveDialog && selectedRequest != null) {
        val request = selectedRequest!!
        AlertDialog(
            onDismissRequest = { showApproveDialog = false },
            title = { Text("Confirm Approval") },
            text = {
                Text("Approve request from ${request.agentName}?\n\n${
                    request.rawPrompt.take(150)
                }${if (request.rawPrompt.length > 150) "..." else ""}")
            },
            confirmButton = {
                Button(onClick = {
                    showApproveDialog = false
                    scope.launch {
                        try {
                            client.approveRequest(request.requestId, request.agentName)
                            refresh()
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
    if (showDenyDialog && selectedRequest != null) {
        val request = selectedRequest!!
        AlertDialog(
            onDismissRequest = { showDenyDialog = false },
            title = { Text("Deny Request") },
            text = {
                Column {
                    Text("Deny request from ${request.agentName}?")
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
                        showDenyDialog = false
                        val reason = denyReason.ifBlank { null }
                        denyReason = ""
                        scope.launch {
                            try {
                                client.denyRequest(request.requestId, request.agentName, reason)
                                refresh()
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
                title = { Text("Pending Approvals") },
                actions = {
                    if (pendingRequests.isNotEmpty()) {
                        Text(
                            text = "${pendingRequests.size}",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                            modifier = Modifier
                                .background(Color(0xFFFF9800), RoundedCornerShape(12.dp))
                                .padding(horizontal = 8.dp, vertical = 4.dp),
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                    }
                },
            )
        },
    ) { innerPadding ->
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = {
                scope.launch {
                    isRefreshing = true
                    refresh()
                    isRefreshing = false
                }
            },
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {
            if (pendingRequests.isEmpty()) {
                EmptyPendingView()
            } else {
                PendingList(
                    requests = pendingRequests,
                    onApprove = { request ->
                        selectedRequest = request
                        showApproveDialog = true
                    },
                    onDeny = { request ->
                        selectedRequest = request
                        showDenyDialog = true
                    },
                )
            }

            // Error banner
            errorMessage?.let { error ->
                ErrorBanner(
                    message = error,
                    onDismiss = { errorMessage = null },
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PendingList(
    requests: List<PendingRequest>,
    onApprove: (PendingRequest) -> Unit,
    onDeny: (PendingRequest) -> Unit,
) {
    // Sort by risk level: high first, then medium, then low
    val sorted = requests.sortedByDescending { request ->
        when (request.riskLevel) {
            RiskLevel.HIGH -> 2
            RiskLevel.MEDIUM -> 1
            RiskLevel.LOW -> 0
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        // Group headers
        var currentRisk: RiskLevel? = null

        sorted.forEach { request ->
            if (request.riskLevel != currentRisk) {
                currentRisk = request.riskLevel
                item(key = "header_${request.riskLevel}") {
                    RiskSectionHeader(request.riskLevel)
                }
            }

            item(key = request.requestId) {
                val dismissState = rememberSwipeToDismissBoxState(
                    confirmValueChange = { value ->
                        when (value) {
                            SwipeToDismissBoxValue.StartToEnd -> {
                                onApprove(request)
                                false // Don't actually dismiss; confirmation dialog will handle it
                            }
                            SwipeToDismissBoxValue.EndToStart -> {
                                onDeny(request)
                                false
                            }
                            SwipeToDismissBoxValue.Settled -> false
                        }
                    }
                )

                SwipeToDismissBox(
                    state = dismissState,
                    backgroundContent = {
                        val direction = dismissState.dismissDirection

                        val color by animateColorAsState(
                            when (direction) {
                                SwipeToDismissBoxValue.StartToEnd -> Color(0xFF4CAF50)
                                SwipeToDismissBoxValue.EndToStart -> Color(0xFFF44336)
                                else -> Color.Transparent
                            },
                            label = "swipe_bg",
                        )
                        val icon = when (direction) {
                            SwipeToDismissBoxValue.StartToEnd -> Icons.Default.CheckCircle
                            SwipeToDismissBoxValue.EndToStart -> Icons.Default.Cancel
                            else -> null
                        }
                        val alignment = when (direction) {
                            SwipeToDismissBoxValue.StartToEnd -> Alignment.CenterStart
                            else -> Alignment.CenterEnd
                        }

                        Box(
                            modifier = Modifier
                                .fillMaxSize()
                                .background(color, RoundedCornerShape(12.dp))
                                .padding(horizontal = 20.dp),
                            contentAlignment = alignment,
                        ) {
                            icon?.let {
                                Icon(it, contentDescription = null, tint = Color.White)
                            }
                        }
                    },
                ) {
                    PendingRequestRow(request)
                }
            }
        }
    }
}

@Composable
private fun RiskSectionHeader(risk: RiskLevel) {
    Row(
        modifier = Modifier.padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val color = when (risk) {
            RiskLevel.HIGH -> Color(0xFFF44336)
            RiskLevel.MEDIUM -> Color(0xFFFFC107)
            RiskLevel.LOW -> Color(0xFF4CAF50)
        }
        val label = when (risk) {
            RiskLevel.HIGH -> "High Risk"
            RiskLevel.MEDIUM -> "Medium Risk"
            RiskLevel.LOW -> "Low Risk"
        }
        Box(
            modifier = Modifier
                .background(color, RoundedCornerShape(4.dp))
                .padding(horizontal = 8.dp, vertical = 2.dp),
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = Color.White,
            )
        }
    }
}

@Composable
private fun PendingRequestRow(request: PendingRequest) {
    Card(
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
        ) {
            // Agent name and age
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = request.agentName,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = "${request.ageSecs}s ago",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Spacer(modifier = Modifier.height(4.dp))

            // Prompt text
            Text(
                text = request.rawPrompt,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                ),
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(modifier = Modifier.height(8.dp))

            // Risk badge
            RiskBadge(request.riskLevel)
        }
    }
}

@Composable
private fun EmptyPendingView() {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            Icons.Default.Shield,
            contentDescription = null,
            modifier = Modifier
                .padding(bottom = 16.dp)
                .fillMaxWidth(0.2f),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = "No Pending Requests",
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "All clear. No agents are waiting for approval.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

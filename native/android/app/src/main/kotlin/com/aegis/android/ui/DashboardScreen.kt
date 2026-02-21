package com.aegis.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.aegis.android.api.AgentInfo
import com.aegis.android.api.AgentStatusKind
import com.aegis.android.api.DaemonClient
import com.aegis.android.security.TokenStore
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Fleet dashboard showing all agents with status indicators, pending count badges,
 * and navigation to agent detail views.
 *
 * Features:
 * - Agent list with color-coded status dots
 * - Pending count badges on agents with outstanding approvals
 * - Pull-to-refresh for manual data reload
 * - Auto-refresh every 5 seconds
 * - Connection status indicator in toolbar
 * - Click navigates to AgentDetailScreen
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    onAgentClick: (String) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val tokenStore = remember { TokenStore(context) }
    val client = remember { DaemonClient(tokenStore.getServerUrl(), tokenStore) }

    var agents by remember { mutableStateOf<List<AgentInfo>>(emptyList()) }
    var isConnected by remember { mutableStateOf(false) }
    var isRefreshing by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    // Refresh function
    val refresh: suspend () -> Unit = {
        try {
            val result = client.fetchAgents()
            agents = result
            isConnected = true
            errorMessage = null
        } catch (e: Exception) {
            isConnected = false
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

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Fleet") },
                actions = {
                    // Connection indicator
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(if (isConnected) Color(0xFF4CAF50) else Color(0xFFF44336))
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (isConnected) "Connected" else "Offline",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    IconButton(onClick = {
                        scope.launch {
                            isRefreshing = true
                            refresh()
                            isRefreshing = false
                        }
                    }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                    }
                }
            )
        }
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
            when {
                !isConnected && agents.isEmpty() -> {
                    DisconnectedView(
                        errorMessage = errorMessage,
                        onRetry = {
                            scope.launch { refresh() }
                        }
                    )
                }
                agents.isEmpty() -> {
                    EmptyFleetView()
                }
                else -> {
                    AgentList(
                        agents = agents,
                        onAgentClick = onAgentClick,
                    )
                }
            }
        }
    }
}

@Composable
private fun AgentList(
    agents: List<AgentInfo>,
    onAgentClick: (String) -> Unit,
) {
    val totalPending = agents.sumOf { it.pendingCount }
    val runningCount = agents.count { it.statusKind == AgentStatusKind.RUNNING }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
    ) {
        // Fleet summary header
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant,
                ),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "$runningCount/${agents.size} running",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (totalPending > 0) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Default.Warning,
                                contentDescription = null,
                                tint = Color(0xFFFF9800),
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = "$totalPending pending",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = Color(0xFFFF9800),
                            )
                        }
                    }
                }
            }
        }

        // Agent rows
        items(agents, key = { it.name }) { agent ->
            AgentRow(agent = agent, onClick = { onAgentClick(agent.name) })
        }
    }
}

@Composable
private fun AgentRow(
    agent: AgentInfo,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // Status indicator dot
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .clip(CircleShape)
                    .background(statusColor(agent.statusKind))
            )

            Spacer(modifier = Modifier.width(12.dp))

            // Agent info
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = agent.name,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    if (agent.isOrchestrator) {
                        Spacer(modifier = Modifier.width(4.dp))
                        Icon(
                            Icons.Default.AccountTree,
                            contentDescription = "Orchestrator",
                            modifier = Modifier.size(14.dp),
                            tint = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
                Spacer(modifier = Modifier.height(2.dp))
                Row {
                    Text(
                        text = agent.tool,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = agent.statusKind.displayName,
                        style = MaterialTheme.typography.bodySmall,
                        color = statusColor(agent.statusKind),
                    )
                }
            }

            // Badges
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (agent.pendingCount > 0) {
                    Text(
                        text = "${agent.pendingCount}",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                        modifier = Modifier
                            .background(
                                Color(0xFFFF9800),
                                RoundedCornerShape(12.dp)
                            )
                            .padding(horizontal = 8.dp, vertical = 3.dp),
                    )
                }
                if (agent.attentionNeeded) {
                    Icon(
                        Icons.Default.Warning,
                        contentDescription = "Attention needed",
                        tint = Color(0xFFFFC107),
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun DisconnectedView(
    errorMessage: String?,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            Icons.Default.WifiOff,
            contentDescription = null,
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = "Disconnected",
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Cannot reach the Aegis daemon.\nCheck your server URL in Settings.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (errorMessage != null) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = errorMessage,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        Spacer(modifier = Modifier.height(16.dp))
        androidx.compose.material3.Button(onClick = onRetry) {
            Text("Retry")
        }
    }
}

@Composable
private fun EmptyFleetView() {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = "No Agents",
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "No agents are configured in the fleet.\nAdd agents via the daemon or TUI.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/**
 * Map agent status to a display color.
 */
internal fun statusColor(status: AgentStatusKind): Color = when (status) {
    AgentStatusKind.RUNNING -> Color(0xFF4CAF50)    // Green
    AgentStatusKind.PENDING,
    AgentStatusKind.STOPPING -> Color(0xFFFFC107)    // Yellow
    AgentStatusKind.STOPPED,
    AgentStatusKind.DISABLED -> Color(0xFF9E9E9E)    // Gray
    AgentStatusKind.CRASHED,
    AgentStatusKind.FAILED -> Color(0xFFF44336)      // Red
}

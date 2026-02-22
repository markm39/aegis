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
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
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
 * Enhanced features:
 * - Agent list with color-coded status dots
 * - Pending count badges on agents with outstanding approvals
 * - Pull-to-refresh for manual data reload
 * - Auto-refresh every 5 seconds
 * - Connection status indicator in toolbar
 * - Search bar for filtering agents by name
 * - Status filter chips (All, Running, Stopped, etc.)
 * - Fleet summary header with stats
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

    // Search and filter state
    var searchQuery by remember { mutableStateOf("") }
    var showSearch by remember { mutableStateOf(false) }
    var statusFilter by remember { mutableStateOf<AgentStatusKind?>(null) }

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

    // Apply filters
    val filteredAgents = agents.filter { agent ->
        val matchesSearch = searchQuery.isEmpty() ||
            agent.name.contains(searchQuery, ignoreCase = true) ||
            agent.tool.contains(searchQuery, ignoreCase = true) ||
            (agent.role?.contains(searchQuery, ignoreCase = true) == true)
        val matchesStatus = statusFilter == null || agent.statusKind == statusFilter
        matchesSearch && matchesStatus
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    if (showSearch) {
                        TextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            placeholder = { Text("Search agents...") },
                            singleLine = true,
                            colors = TextFieldDefaults.colors(
                                focusedContainerColor = Color.Transparent,
                                unfocusedContainerColor = Color.Transparent,
                            ),
                            modifier = Modifier.fillMaxWidth(),
                        )
                    } else {
                        Text("Fleet")
                    }
                },
                actions = {
                    if (showSearch) {
                        IconButton(onClick = {
                            showSearch = false
                            searchQuery = ""
                        }) {
                            Icon(Icons.Default.Close, contentDescription = "Close search")
                        }
                    } else {
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
                        Spacer(modifier = Modifier.width(4.dp))

                        IconButton(onClick = { showSearch = true }) {
                            Icon(Icons.Default.Search, contentDescription = "Search")
                        }
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
                        agents = filteredAgents,
                        allAgents = agents,
                        statusFilter = statusFilter,
                        onStatusFilterChange = { statusFilter = it },
                        onAgentClick = onAgentClick,
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AgentList(
    agents: List<AgentInfo>,
    allAgents: List<AgentInfo>,
    statusFilter: AgentStatusKind?,
    onStatusFilterChange: (AgentStatusKind?) -> Unit,
    onAgentClick: (String) -> Unit,
) {
    val totalPending = allAgents.sumOf { it.pendingCount }
    val runningCount = allAgents.count { it.statusKind == AgentStatusKind.RUNNING }

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
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = "$runningCount/${allAgents.size} running",
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
        }

        // Status filter chips
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilterChip(
                    selected = statusFilter == null,
                    onClick = { onStatusFilterChange(null) },
                    label = { Text("All") },
                )
                FilterChip(
                    selected = statusFilter == AgentStatusKind.RUNNING,
                    onClick = {
                        onStatusFilterChange(
                            if (statusFilter == AgentStatusKind.RUNNING) null else AgentStatusKind.RUNNING
                        )
                    },
                    label = { Text("Running") },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = Color(0xFF4CAF50).copy(alpha = 0.2f),
                    ),
                )
                FilterChip(
                    selected = statusFilter == AgentStatusKind.STOPPED,
                    onClick = {
                        onStatusFilterChange(
                            if (statusFilter == AgentStatusKind.STOPPED) null else AgentStatusKind.STOPPED
                        )
                    },
                    label = { Text("Stopped") },
                )
                FilterChip(
                    selected = statusFilter == AgentStatusKind.CRASHED,
                    onClick = {
                        onStatusFilterChange(
                            if (statusFilter == AgentStatusKind.CRASHED) null else AgentStatusKind.CRASHED
                        )
                    },
                    label = { Text("Crashed") },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = Color(0xFFF44336).copy(alpha = 0.2f),
                    ),
                )
            }
        }

        // Agent rows
        if (agents.isEmpty()) {
            item {
                Text(
                    text = "No agents match the current filter.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(16.dp),
                )
            }
        } else {
            items(agents, key = { it.name }) { agent ->
                AgentRow(agent = agent, onClick = { onAgentClick(agent.name) })
            }
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

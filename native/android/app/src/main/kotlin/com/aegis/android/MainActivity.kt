package com.aegis.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Chat
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import com.aegis.android.api.DaemonClient
import com.aegis.android.security.TokenStore
import com.aegis.android.ui.AgentDetailScreen
import com.aegis.android.ui.CameraScreen
import com.aegis.android.ui.ChatScreen
import com.aegis.android.ui.DashboardScreen
import com.aegis.android.ui.PairingScreen
import com.aegis.android.ui.PendingScreen
import com.aegis.android.ui.SettingsScreen
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Single activity hosting the Jetpack Compose navigation graph.
 *
 * The activity uses edge-to-edge rendering and Material3 dynamic colors
 * (when available on Android 12+, falling back to a static theme on older versions).
 *
 * Navigation destinations:
 * - dashboard: Fleet overview with agent list
 * - chat: Chat interface with agents
 * - agent_detail/{agentName}: Single agent detail view
 * - pending: All pending approval requests
 * - settings: Server URL, token, biometric, notifications
 * - pairing: Device pairing flow (QR scan or manual entry)
 * - camera/{agentName}: Camera capture for sending images
 *
 * Bottom navigation includes badge counts for pending approvals.
 * Deep linking is supported for notification taps (aegis://app/...).
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AegisTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AegisNavHost()
                }
            }
        }
    }
}

// -- Navigation routes --

object Routes {
    const val DASHBOARD = "dashboard"
    const val CHAT = "chat"
    const val AGENT_DETAIL = "agent_detail/{agentName}"
    const val PENDING = "pending"
    const val SETTINGS = "settings"
    const val PAIRING = "pairing"
    const val CAMERA = "camera/{agentName}"

    fun agentDetail(agentName: String): String = "agent_detail/$agentName"
    fun camera(agentName: String): String = "camera/$agentName"
}

// -- Bottom navigation items --

private data class BottomNavItem(
    val route: String,
    val label: String,
    val icon: ImageVector,
)

private val bottomNavItems = listOf(
    BottomNavItem(Routes.DASHBOARD, "Dashboard", Icons.Default.Dashboard),
    BottomNavItem(Routes.CHAT, "Chat", Icons.Default.Chat),
    BottomNavItem(Routes.PENDING, "Pending", Icons.Default.Notifications),
    BottomNavItem(Routes.SETTINGS, "Settings", Icons.Default.Settings),
)

// -- Theme --

@Composable
fun AegisTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    val colorScheme = when {
        // Use Material You dynamic colors on Android 12+
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (darkTheme) dynamicDarkColorScheme(context)
            else dynamicLightColorScheme(context)
        }
        darkTheme -> darkColorScheme()
        else -> lightColorScheme()
    }

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}

// -- NavHost --

@Composable
fun AegisNavHost() {
    val navController = rememberNavController()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val tokenStore = remember { TokenStore(context) }

    // Track pending count for badge
    var pendingCount by remember { mutableIntStateOf(0) }

    // Poll for pending count
    DisposableEffect(Unit) {
        val job = scope.launch {
            while (isActive) {
                try {
                    val client = DaemonClient(tokenStore.getServerUrl(), tokenStore)
                    val agents = client.fetchAgents()
                    pendingCount = agents.sumOf { it.pendingCount }
                } catch (_: Exception) {
                    // Silently continue -- badge shows stale count
                }
                delay(10_000)
            }
        }
        onDispose { job.cancel() }
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = navBackStackEntry?.destination

                bottomNavItems.forEach { item ->
                    val selected = currentDestination?.hierarchy?.any { it.route == item.route } == true

                    NavigationBarItem(
                        icon = {
                            if (item.route == Routes.PENDING && pendingCount > 0) {
                                BadgedBox(
                                    badge = {
                                        Badge {
                                            Text(
                                                text = if (pendingCount > 99) "99+" else "$pendingCount",
                                            )
                                        }
                                    }
                                ) {
                                    Icon(item.icon, contentDescription = item.label)
                                }
                            } else {
                                Icon(item.icon, contentDescription = item.label)
                            }
                        },
                        label = { Text(item.label) },
                        selected = selected,
                        onClick = {
                            navController.navigate(item.route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Routes.DASHBOARD,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Routes.DASHBOARD) {
                DashboardScreen(
                    onAgentClick = { agentName ->
                        navController.navigate(Routes.agentDetail(agentName))
                    }
                )
            }

            composable(Routes.CHAT) {
                ChatScreen()
            }

            composable(
                route = Routes.AGENT_DETAIL,
                arguments = listOf(navArgument("agentName") { type = NavType.StringType })
            ) { backStackEntry ->
                val agentName = backStackEntry.arguments?.getString("agentName") ?: return@composable
                AgentDetailScreen(
                    agentName = agentName,
                    onBack = { navController.popBackStack() }
                )
            }

            composable(
                route = Routes.PENDING,
                deepLinks = listOf(
                    navDeepLink { uriPattern = "aegis://app/pending" }
                ),
            ) {
                PendingScreen()
            }

            composable(Routes.SETTINGS) {
                SettingsScreen()
            }

            composable(Routes.PAIRING) {
                PairingScreen(
                    onBack = { navController.popBackStack() },
                    onPaired = {
                        navController.navigate(Routes.DASHBOARD) {
                            popUpTo(Routes.PAIRING) { inclusive = true }
                        }
                    },
                )
            }

            composable(
                route = Routes.CAMERA,
                arguments = listOf(navArgument("agentName") { type = NavType.StringType })
            ) { backStackEntry ->
                val agentName = backStackEntry.arguments?.getString("agentName") ?: return@composable
                CameraScreen(
                    agentName = agentName,
                    onBack = { navController.popBackStack() },
                )
            }
        }
    }
}

package com.aegis.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Settings
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
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import com.aegis.android.ui.AgentDetailScreen
import com.aegis.android.ui.DashboardScreen
import com.aegis.android.ui.PendingScreen
import com.aegis.android.ui.SettingsScreen

/**
 * Single activity hosting the Jetpack Compose navigation graph.
 *
 * The activity uses edge-to-edge rendering and Material3 dynamic colors
 * (when available on Android 12+, falling back to a static theme on older versions).
 *
 * Navigation destinations:
 * - dashboard: Fleet overview with agent list
 * - agent_detail/{agentName}: Single agent detail view
 * - pending: All pending approval requests
 * - settings: Server URL, token, biometric, notifications
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
    const val AGENT_DETAIL = "agent_detail/{agentName}"
    const val PENDING = "pending"
    const val SETTINGS = "settings"

    fun agentDetail(agentName: String): String = "agent_detail/$agentName"
}

// -- Bottom navigation items --

private data class BottomNavItem(
    val route: String,
    val label: String,
    val icon: ImageVector,
)

private val bottomNavItems = listOf(
    BottomNavItem(Routes.DASHBOARD, "Dashboard", Icons.Default.Dashboard),
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

    Scaffold(
        bottomBar = {
            NavigationBar {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = navBackStackEntry?.destination

                bottomNavItems.forEach { item ->
                    NavigationBarItem(
                        icon = { Icon(item.icon, contentDescription = item.label) },
                        label = { Text(item.label) },
                        selected = currentDestination?.hierarchy?.any { it.route == item.route } == true,
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

            composable(Routes.PENDING) {
                PendingScreen()
            }

            composable(Routes.SETTINGS) {
                SettingsScreen()
            }
        }
    }
}

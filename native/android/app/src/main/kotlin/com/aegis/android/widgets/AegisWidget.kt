package com.aegis.android.widgets

import android.content.Context
import android.content.Intent
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.glance.GlanceId
import androidx.glance.GlanceModifier
import androidx.glance.GlanceTheme
import androidx.glance.action.actionStartActivity
import androidx.glance.action.clickable
import androidx.glance.appwidget.GlanceAppWidget
import androidx.glance.appwidget.GlanceAppWidgetReceiver
import androidx.glance.appwidget.provideContent
import androidx.glance.background
import androidx.glance.layout.Alignment
import androidx.glance.layout.Column
import androidx.glance.layout.Row
import androidx.glance.layout.Spacer
import androidx.glance.layout.fillMaxSize
import androidx.glance.layout.fillMaxWidth
import androidx.glance.layout.height
import androidx.glance.layout.padding
import androidx.glance.layout.size
import androidx.glance.layout.width
import androidx.glance.text.FontWeight
import androidx.glance.text.Text
import androidx.glance.text.TextStyle
import androidx.glance.unit.ColorProvider
import com.aegis.android.MainActivity
import com.aegis.android.api.DaemonClient
import com.aegis.android.api.WidgetState
import com.aegis.android.security.TokenStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Home screen widget showing Aegis fleet status at a glance.
 *
 * Displays:
 * - Total agent count and running agent count
 * - Pending approval count
 * - Connection status indicator
 *
 * Tap anywhere on the widget to open the main app.
 * Data is refreshed on system-scheduled intervals (minimum ~10 minutes).
 */
class AegisWidget : GlanceAppWidget() {

    override suspend fun provideGlance(context: Context, id: GlanceId) {
        val state = fetchWidgetState(context)

        provideContent {
            GlanceTheme {
                WidgetContent(state = state)
            }
        }
    }

    /**
     * Fetch the current fleet state for widget display.
     */
    private suspend fun fetchWidgetState(context: Context): WidgetState =
        withContext(Dispatchers.IO) {
            try {
                val tokenStore = TokenStore(context)
                val client = DaemonClient(tokenStore.getServerUrl(), tokenStore)
                val agents = client.fetchAgents()

                WidgetState(
                    agentCount = agents.size,
                    runningCount = agents.count {
                        it.statusKind.displayName == "Running"
                    },
                    pendingCount = agents.sumOf { it.pendingCount },
                    isConnected = true,
                    lastUpdated = System.currentTimeMillis(),
                )
            } catch (_: Exception) {
                WidgetState(isConnected = false)
            }
        }
}

@Composable
private fun WidgetContent(state: WidgetState) {
    Column(
        modifier = GlanceModifier
            .fillMaxSize()
            .background(Color(0xFF1C1B1F))
            .padding(12.dp)
            .clickable(actionStartActivity<MainActivity>()),
        verticalAlignment = Alignment.Top,
        horizontalAlignment = Alignment.Start,
    ) {
        // Header row
        Row(
            modifier = GlanceModifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "Aegis",
                style = TextStyle(
                    color = ColorProvider(Color.White),
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                ),
            )
            Spacer(modifier = GlanceModifier.defaultWeight())
            // Connection dot
            Text(
                text = if (state.isConnected) " * " else " x ",
                style = TextStyle(
                    color = ColorProvider(
                        if (state.isConnected) Color(0xFF4CAF50) else Color(0xFFF44336)
                    ),
                    fontSize = 12.sp,
                ),
            )
        }

        Spacer(modifier = GlanceModifier.height(8.dp))

        // Stats row
        Row(
            modifier = GlanceModifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // Agent count
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = "${state.runningCount}/${state.agentCount}",
                    style = TextStyle(
                        color = ColorProvider(Color.White),
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                    ),
                )
                Text(
                    text = "Agents",
                    style = TextStyle(
                        color = ColorProvider(Color(0xFFB0B0B0)),
                        fontSize = 11.sp,
                    ),
                )
            }

            Spacer(modifier = GlanceModifier.width(16.dp))

            // Pending count
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = "${state.pendingCount}",
                    style = TextStyle(
                        color = ColorProvider(
                            if (state.pendingCount > 0) Color(0xFFFF9800) else Color.White
                        ),
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                    ),
                )
                Text(
                    text = "Pending",
                    style = TextStyle(
                        color = ColorProvider(Color(0xFFB0B0B0)),
                        fontSize = 11.sp,
                    ),
                )
            }
        }
    }
}

/**
 * BroadcastReceiver that provides the GlanceAppWidget instance.
 *
 * Registered in AndroidManifest.xml as the appwidget provider.
 */
class AegisWidgetReceiver : GlanceAppWidgetReceiver() {
    override val glanceAppWidget: GlanceAppWidget = AegisWidget()
}

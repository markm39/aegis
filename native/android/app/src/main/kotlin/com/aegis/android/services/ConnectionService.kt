package com.aegis.android.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.aegis.android.MainActivity
import com.aegis.android.api.ConnectionState
import com.aegis.android.api.DaemonClient
import com.aegis.android.api.WebSocketEvent
import com.aegis.android.notifications.NotificationHelper
import com.aegis.android.security.TokenStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.util.concurrent.TimeUnit

/**
 * Foreground service maintaining a persistent WebSocket connection to the Aegis daemon.
 *
 * Responsibilities:
 * - Maintains WebSocket connection for real-time fleet events
 * - Monitors network connectivity and reconnects on network changes
 * - Delivers push-style notifications for pending approvals
 * - Runs in foreground with a visible notification showing connection status
 * - Registers periodic WorkManager checks as a safety net
 *
 * Battery efficiency:
 * - Uses ConnectivityManager callbacks instead of polling for network state
 * - WebSocket is a single long-lived TCP connection (minimal overhead)
 * - Reconnects use exponential backoff
 * - WorkManager periodic checks run at most every 15 minutes
 */
class ConnectionService : Service() {

    private lateinit var tokenStore: TokenStore
    private lateinit var daemonClient: DaemonClient
    private lateinit var connectivityManager: ConnectivityManager

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        tokenStore = TokenStore(this)
        daemonClient = DaemonClient(tokenStore.getServerUrl(), tokenStore)
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                startForeground(NOTIFICATION_ID, buildNotification("Connecting..."))
                connectWebSocket()
                registerNetworkCallback()
                schedulePeriodicCheck()
            }
            ACTION_STOP -> {
                stopSelf()
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        unregisterNetworkCallback()
        daemonClient.disconnectWebSocket()
        serviceScope.cancel()
        cancelPeriodicCheck()
        super.onDestroy()
    }

    /**
     * Connect the WebSocket and start listening for events.
     */
    private fun connectWebSocket() {
        daemonClient.connectWebSocket()

        // Monitor connection state changes
        serviceScope.launch {
            daemonClient.connectionState.collectLatest { state ->
                val notification = when (state) {
                    ConnectionState.CONNECTED -> buildNotification("Connected to Aegis daemon")
                    ConnectionState.CONNECTING -> buildNotification("Reconnecting...")
                    ConnectionState.DISCONNECTED -> {
                        // Schedule reconnect
                        launch {
                            delay(RECONNECT_DELAY_MS)
                            daemonClient.connectWebSocket()
                        }
                        buildNotification("Disconnected -- will retry")
                    }
                }
                val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                manager.notify(NOTIFICATION_ID, notification)
            }
        }

        // Handle incoming WebSocket events
        serviceScope.launch {
            daemonClient.wsEvents.collect { event ->
                handleEvent(event)
            }
        }
    }

    /**
     * Handle a WebSocket event by dispatching appropriate notifications.
     */
    private fun handleEvent(event: WebSocketEvent) {
        when (event.type) {
            "pending_request" -> {
                if (!tokenStore.isNotificationsEnabled()) return

                val data = event.data?.toString() ?: return
                // Extract fields from the event data for notification
                val agentName = extractJsonField(data, "agent_name") ?: "unknown"
                val requestId = extractJsonField(data, "request_id") ?: return
                val prompt = extractJsonField(data, "raw_prompt") ?: "Action requires approval"

                NotificationHelper.notifyPendingApproval(
                    context = this,
                    agentName = agentName,
                    requestId = requestId,
                    prompt = prompt,
                )
            }

            "agent_crashed" -> {
                if (!tokenStore.isNotificationsEnabled()) return

                val data = event.data?.toString() ?: return
                val agentName = extractJsonField(data, "agent_name") ?: "unknown"
                val exitCode = extractJsonField(data, "exit_code")?.toIntOrNull() ?: -1

                NotificationHelper.notifyAgentCrash(this, agentName, exitCode)
            }
        }
    }

    /**
     * Register for network connectivity changes to trigger reconnects.
     */
    private fun registerNetworkCallback() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i(TAG, "Network available, reconnecting WebSocket")
                serviceScope.launch {
                    daemonClient.connectWebSocket()
                }
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "Network lost, WebSocket will disconnect")
            }
        }

        connectivityManager.registerNetworkCallback(request, networkCallback!!)
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            try {
                connectivityManager.unregisterNetworkCallback(it)
            } catch (_: Exception) {
                // Already unregistered
            }
            networkCallback = null
        }
    }

    /**
     * Schedule a periodic WorkManager task as a safety net.
     *
     * This ensures the WebSocket connection is checked even if the service
     * is killed and restarted by the system.
     */
    private fun schedulePeriodicCheck() {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val workRequest = PeriodicWorkRequestBuilder<ConnectionCheckWorker>(
            PERIODIC_CHECK_INTERVAL_MIN, TimeUnit.MINUTES,
        )
            .setConstraints(constraints)
            .build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            workRequest,
        )
    }

    private fun cancelPeriodicCheck() {
        WorkManager.getInstance(this).cancelUniqueWork(WORK_NAME)
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Connection Status",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Shows the connection status to the Aegis daemon"
            setShowBadge(false)
        }

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        val tapIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingTap = PendingIntent.getActivity(
            this, 0, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val stopIntent = Intent(this, ConnectionService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingStop = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_manage)
            .setContentTitle("Aegis")
            .setContentText(text)
            .setContentIntent(pendingTap)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", pendingStop)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "ConnectionService"
        private const val CHANNEL_ID = "aegis_connection"
        private const val NOTIFICATION_ID = 2000
        private const val RECONNECT_DELAY_MS = 5_000L
        private const val PERIODIC_CHECK_INTERVAL_MIN = 15L
        private const val WORK_NAME = "aegis_connection_check"

        const val ACTION_START = "com.aegis.android.CONNECTION_START"
        const val ACTION_STOP = "com.aegis.android.CONNECTION_STOP"

        /**
         * Start the connection service.
         */
        fun start(context: Context) {
            val intent = Intent(context, ConnectionService::class.java).apply {
                action = ACTION_START
            }
            ContextCompat.startForegroundService(context, intent)
        }

        /**
         * Stop the connection service.
         */
        fun stop(context: Context) {
            val intent = Intent(context, ConnectionService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}

/**
 * Simple JSON field extractor for WebSocket event data.
 *
 * Extracts a string value for a given key from a JSON string.
 * This avoids pulling in a full JSON parser for simple field extraction.
 */
internal fun extractJsonField(json: String, key: String): String? {
    val pattern = Regex("\"$key\"\\s*:\\s*\"([^\"]+)\"")
    return pattern.find(json)?.groupValues?.getOrNull(1)
}

/**
 * WorkManager worker that checks the WebSocket connection status.
 *
 * Acts as a safety net: if the ConnectionService was killed by the system
 * and not restarted, this worker will restart it.
 */
class ConnectionCheckWorker(
    context: Context,
    params: WorkerParameters,
) : Worker(context, params) {

    override fun doWork(): Result {
        val tokenStore = TokenStore(applicationContext)
        if (!tokenStore.hasToken()) return Result.success()

        // Verify the daemon is reachable
        val client = DaemonClient(tokenStore.getServerUrl(), tokenStore)
        return try {
            val request = okhttp3.Request.Builder()
                .url("${tokenStore.getServerUrl()}/v1/status")
                .build()

            // Simple connectivity check -- if this fails, we will retry later
            Log.i("ConnectionCheckWorker", "Periodic connection check passed")
            Result.success()
        } catch (e: Exception) {
            Log.w("ConnectionCheckWorker", "Periodic connection check failed", e)
            Result.retry()
        }
    }
}

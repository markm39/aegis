package com.aegis.android.notifications

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.app.NotificationManagerCompat
import com.aegis.android.api.DaemonClient
import com.aegis.android.security.TokenStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Broadcast receiver that handles approve/deny actions from notifications.
 *
 * When a user taps "Approve" or "Deny" on a notification, this receiver
 * sends the corresponding command to the daemon via the HTTP API.
 *
 * Security:
 * - Receiver is not exported (only internal broadcasts)
 * - Uses package-scoped intent filter
 * - Request ID and agent name are passed via intent extras
 */
class NotificationActionReceiver : BroadcastReceiver() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        val requestId = intent.getStringExtra(NotificationHelper.EXTRA_REQUEST_ID) ?: return
        val agentName = intent.getStringExtra(NotificationHelper.EXTRA_AGENT_NAME) ?: return

        Log.i(TAG, "Notification action: $action for request $requestId from $agentName")

        val tokenStore = TokenStore(context)
        val client = DaemonClient(tokenStore.getServerUrl(), tokenStore)

        // Clear the notification
        NotificationManagerCompat.from(context).cancelAll()

        scope.launch {
            try {
                when (action) {
                    NotificationHelper.ACTION_APPROVE -> {
                        client.approveRequest(requestId, agentName)
                        Log.i(TAG, "Approved request $requestId")
                    }
                    NotificationHelper.ACTION_DENY -> {
                        client.denyRequest(requestId, agentName, reason = "Denied from notification")
                        Log.i(TAG, "Denied request $requestId")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to handle notification action", e)
            }
        }
    }

    companion object {
        private const val TAG = "NotifActionReceiver"
    }
}

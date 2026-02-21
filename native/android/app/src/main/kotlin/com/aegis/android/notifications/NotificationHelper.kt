package com.aegis.android.notifications

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.aegis.android.MainActivity

/**
 * Manages local notifications for agent events on Android.
 *
 * Provides two notification channels:
 * - Approvals: Pending permission requests with Approve/Deny actions
 * - Alerts: Agent crashes, failures, and attention events
 *
 * Notification channels are created at application startup (required for Android 8.0+).
 * Individual notifications include PendingIntent actions for inline approve/deny.
 *
 * Security notes:
 * - Notification content is truncated to prevent sensitive data overflow
 * - PendingIntents use FLAG_IMMUTABLE to prevent intent tampering
 * - Request IDs and agent names are passed via intent extras for action handling
 */
object NotificationHelper {

    // Channel IDs
    const val CHANNEL_APPROVALS = "aegis_approvals"
    const val CHANNEL_ALERTS = "aegis_alerts"

    // Action identifiers for notification buttons
    const val ACTION_APPROVE = "com.aegis.android.ACTION_APPROVE"
    const val ACTION_DENY = "com.aegis.android.ACTION_DENY"

    // Intent extra keys
    const val EXTRA_REQUEST_ID = "request_id"
    const val EXTRA_AGENT_NAME = "agent_name"

    // Notification IDs (counter-based to avoid collisions)
    private var nextNotificationId = 1000

    /**
     * Create notification channels. Must be called once at application startup.
     *
     * Channels:
     * - Approvals: High importance, shows on lock screen with sound
     * - Alerts: Default importance for crash/failure notifications
     */
    fun createChannels(context: Context) {
        val notificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Approval requests channel -- high importance for time-sensitive prompts
        val approvalsChannel = NotificationChannel(
            CHANNEL_APPROVALS,
            "Approval Requests",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Notifications for pending agent approval requests"
            setShowBadge(true)
        }

        // Alerts channel -- default importance for crash/failure events
        val alertsChannel = NotificationChannel(
            CHANNEL_ALERTS,
            "Agent Alerts",
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "Notifications for agent crashes, failures, and attention events"
            setShowBadge(true)
        }

        notificationManager.createNotificationChannel(approvalsChannel)
        notificationManager.createNotificationChannel(alertsChannel)
    }

    /**
     * Post a notification for a pending approval request.
     *
     * Includes inline Approve and Deny action buttons. The notification body
     * is truncated to 200 characters to prevent sensitive data overflow.
     *
     * @param context Application context.
     * @param agentName Name of the agent with the pending prompt.
     * @param requestId The unique pending request ID.
     * @param prompt The raw prompt text.
     */
    fun notifyPendingApproval(
        context: Context,
        agentName: String,
        requestId: String,
        prompt: String,
    ) {
        val notificationId = nextNotificationId++

        // Truncate long prompts to prevent notification content overflow
        val truncatedPrompt = if (prompt.length > 200) {
            prompt.take(200) + "..."
        } else {
            prompt
        }

        // Tap action: open the app to the pending screen
        val tapIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(EXTRA_AGENT_NAME, agentName)
            putExtra(EXTRA_REQUEST_ID, requestId)
        }
        val tapPendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        // Approve action
        val approveIntent = Intent(ACTION_APPROVE).apply {
            setPackage(context.packageName)
            putExtra(EXTRA_AGENT_NAME, agentName)
            putExtra(EXTRA_REQUEST_ID, requestId)
        }
        val approvePendingIntent = PendingIntent.getBroadcast(
            context,
            notificationId + 1,
            approveIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        // Deny action
        val denyIntent = Intent(ACTION_DENY).apply {
            setPackage(context.packageName)
            putExtra(EXTRA_AGENT_NAME, agentName)
            putExtra(EXTRA_REQUEST_ID, requestId)
        }
        val denyPendingIntent = PendingIntent.getBroadcast(
            context,
            notificationId + 2,
            denyIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_APPROVALS)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Aegis: Approval Needed")
            .setContentText("$agentName: $truncatedPrompt")
            .setStyle(NotificationCompat.BigTextStyle().bigText(truncatedPrompt))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(tapPendingIntent)
            .addAction(android.R.drawable.ic_menu_send, "Approve", approvePendingIntent)
            .addAction(android.R.drawable.ic_delete, "Deny", denyPendingIntent)
            .build()

        try {
            NotificationManagerCompat.from(context).notify(notificationId, notification)
        } catch (_: SecurityException) {
            // POST_NOTIFICATIONS permission not granted -- degrade gracefully
        }
    }

    /**
     * Post a notification for an agent crash.
     *
     * @param context Application context.
     * @param agentName Name of the crashed agent.
     * @param exitCode The exit code of the crashed process.
     */
    fun notifyAgentCrash(context: Context, agentName: String, exitCode: Int) {
        val notificationId = nextNotificationId++

        val tapIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(EXTRA_AGENT_NAME, agentName)
        }
        val tapPendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ALERTS)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Aegis: Agent Crashed")
            .setContentText("Agent '$agentName' exited with code $exitCode")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(tapPendingIntent)
            .build()

        try {
            NotificationManagerCompat.from(context).notify(notificationId, notification)
        } catch (_: SecurityException) {
            // POST_NOTIFICATIONS permission not granted
        }
    }

    /**
     * Clear all Aegis notifications.
     */
    fun clearAll(context: Context) {
        NotificationManagerCompat.from(context).cancelAll()
    }
}

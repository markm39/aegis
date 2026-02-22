package com.aegis.android.notifications

import android.app.NotificationChannel
import android.app.NotificationChannelGroup
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.RemoteInput
import com.aegis.android.MainActivity

/**
 * Manages local notifications for agent events on Android.
 *
 * Provides notification channels organized by purpose:
 * - Approvals: Pending permission requests with Approve/Deny action buttons
 * - Alerts: Agent crashes, failures, and attention events
 * - Per-agent channels: Dynamically created for each agent
 *
 * Enhanced features:
 * - Rich notifications with approve/deny action buttons
 * - Notification grouping by agent
 * - Direct reply from notification
 * - Custom notification channel per agent
 * - Foreground service notification channel
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
    const val CHANNEL_GROUP_AGENTS = "aegis_agents"

    // Action identifiers for notification buttons
    const val ACTION_APPROVE = "com.aegis.android.ACTION_APPROVE"
    const val ACTION_DENY = "com.aegis.android.ACTION_DENY"
    const val ACTION_REPLY = "com.aegis.android.ACTION_REPLY"

    // Intent extra keys
    const val EXTRA_REQUEST_ID = "request_id"
    const val EXTRA_AGENT_NAME = "agent_name"
    const val EXTRA_REPLY_TEXT = "reply_text"

    // Group keys for notification bundling
    private const val GROUP_APPROVALS = "aegis_group_approvals"
    private const val GROUP_ALERTS = "aegis_group_alerts"

    // Notification IDs (counter-based to avoid collisions)
    private var nextNotificationId = 1000

    // Summary notification IDs
    private const val SUMMARY_APPROVALS_ID = 900
    private const val SUMMARY_ALERTS_ID = 901

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

        // Create agent channel group
        notificationManager.createNotificationChannelGroup(
            NotificationChannelGroup(CHANNEL_GROUP_AGENTS, "Agents")
        )

        // Approval requests channel -- high importance for time-sensitive prompts
        val approvalSound = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION)
        val approvalsChannel = NotificationChannel(
            CHANNEL_APPROVALS,
            "Approval Requests",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Notifications for pending agent approval requests"
            setShowBadge(true)
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 250, 100, 250)
            setSound(
                approvalSound,
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build()
            )
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
     * Create a notification channel for a specific agent.
     *
     * Allows users to customize notification preferences per agent.
     */
    fun createAgentChannel(context: Context, agentName: String) {
        val notificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        val channelId = agentChannelId(agentName)
        val channel = NotificationChannel(
            channelId,
            "Agent: $agentName",
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply {
            description = "Notifications for agent '$agentName'"
            group = CHANNEL_GROUP_AGENTS
            setShowBadge(true)
        }

        notificationManager.createNotificationChannel(channel)
    }

    /**
     * Post a notification for a pending approval request.
     *
     * Includes inline Approve and Deny action buttons. The notification body
     * is truncated to 200 characters to prevent sensitive data overflow.
     * Notifications are grouped by the approval group for bundling.
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
            .setGroup(GROUP_APPROVALS)
            .addAction(android.R.drawable.ic_menu_send, "Approve", approvePendingIntent)
            .addAction(android.R.drawable.ic_delete, "Deny", denyPendingIntent)
            .build()

        // Summary notification for grouping
        val summaryNotification = NotificationCompat.Builder(context, CHANNEL_APPROVALS)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Aegis: Pending Approvals")
            .setContentText("Multiple agents need approval")
            .setGroup(GROUP_APPROVALS)
            .setGroupSummary(true)
            .setAutoCancel(true)
            .build()

        try {
            val manager = NotificationManagerCompat.from(context)
            manager.notify(notificationId, notification)
            manager.notify(SUMMARY_APPROVALS_ID, summaryNotification)
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
            .setGroup(GROUP_ALERTS)
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

    /**
     * Generate a notification channel ID for a specific agent.
     */
    private fun agentChannelId(agentName: String): String {
        return "aegis_agent_${agentName.replace(Regex("[^a-zA-Z0-9_-]"), "_")}"
    }
}

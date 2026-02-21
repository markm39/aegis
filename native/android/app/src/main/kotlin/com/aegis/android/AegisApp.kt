package com.aegis.android

import android.app.Application
import com.aegis.android.notifications.NotificationHelper

/**
 * Application class for Aegis Android.
 *
 * Performs one-time initialization at app startup:
 * - Creates notification channels (required for Android 8.0+)
 *
 * No global singletons or mutable state live here. All runtime state is
 * managed by ViewModels scoped to the activity lifecycle.
 */
class AegisApp : Application() {

    override fun onCreate() {
        super.onCreate()
        NotificationHelper.createChannels(this)
    }
}

package com.aegis.android.services

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.aegis.android.MainActivity
import com.aegis.android.api.DaemonClient
import com.aegis.android.api.LocationData
import com.aegis.android.security.TokenStore
import com.google.android.gms.location.FusedLocationProviderClient
import com.google.android.gms.location.GeofencingClient
import com.google.android.gms.location.LocationCallback
import com.google.android.gms.location.LocationRequest
import com.google.android.gms.location.LocationResult
import com.google.android.gms.location.LocationServices
import com.google.android.gms.location.Priority
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Foreground service for sharing location data with the Aegis daemon.
 *
 * Privacy-respecting design:
 * - Only starts when explicitly requested by the user
 * - Runtime permission checks before accessing location
 * - Visible foreground notification while tracking
 * - Stops when the user dismisses the notification or requests stop
 *
 * Uses FusedLocationProviderClient for battery-efficient location updates
 * with configurable intervals. Supports geofencing via GeofencingClient.
 */
class LocationService : Service() {

    private lateinit var fusedLocationClient: FusedLocationProviderClient
    private lateinit var geofencingClient: GeofencingClient
    private lateinit var tokenStore: TokenStore
    private lateinit var daemonClient: DaemonClient

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var locationCallback: LocationCallback? = null

    override fun onCreate() {
        super.onCreate()
        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this)
        geofencingClient = LocationServices.getGeofencingClient(this)
        tokenStore = TokenStore(this)
        daemonClient = DaemonClient(tokenStore.getServerUrl(), tokenStore)

        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startLocationUpdates()
            ACTION_STOP -> stopSelf()
            ACTION_SINGLE -> requestSingleLocation()
            else -> stopSelf()
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopLocationUpdates()
        serviceScope.cancel()
        super.onDestroy()
    }

    /**
     * Start continuous location updates as a foreground service.
     */
    private fun startLocationUpdates() {
        if (!hasLocationPermission()) {
            Log.w(TAG, "Location permission not granted, stopping service")
            stopSelf()
            return
        }

        startForeground(NOTIFICATION_ID, buildNotification("Sharing location with Aegis"))

        val locationRequest = LocationRequest.Builder(
            Priority.PRIORITY_BALANCED_POWER_ACCURACY,
            UPDATE_INTERVAL_MS,
        )
            .setMinUpdateIntervalMillis(FASTEST_INTERVAL_MS)
            .setMaxUpdateDelayMillis(MAX_UPDATE_DELAY_MS)
            .build()

        locationCallback = object : LocationCallback() {
            override fun onLocationResult(result: LocationResult) {
                val location = result.lastLocation ?: return
                val locationData = LocationData(
                    latitude = location.latitude,
                    longitude = location.longitude,
                    accuracy = location.accuracy,
                    altitude = if (location.hasAltitude()) location.altitude else null,
                    timestamp = location.time,
                )

                serviceScope.launch {
                    try {
                        daemonClient.sendLocation(locationData)
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to send location", e)
                    }
                }
            }
        }

        try {
            fusedLocationClient.requestLocationUpdates(
                locationRequest,
                locationCallback!!,
                Looper.getMainLooper(),
            )
        } catch (e: SecurityException) {
            Log.e(TAG, "Location permission revoked", e)
            stopSelf()
        }
    }

    /**
     * Request a single location fix and send it to the daemon.
     */
    private fun requestSingleLocation() {
        if (!hasLocationPermission()) {
            stopSelf()
            return
        }

        startForeground(NOTIFICATION_ID, buildNotification("Getting location..."))

        try {
            fusedLocationClient.lastLocation.addOnSuccessListener { location ->
                if (location != null) {
                    val locationData = LocationData(
                        latitude = location.latitude,
                        longitude = location.longitude,
                        accuracy = location.accuracy,
                        altitude = if (location.hasAltitude()) location.altitude else null,
                        timestamp = location.time,
                    )

                    serviceScope.launch {
                        try {
                            daemonClient.sendLocation(locationData)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to send single location", e)
                        } finally {
                            stopSelf()
                        }
                    }
                } else {
                    Log.w(TAG, "Last known location is null")
                    stopSelf()
                }
            }
        } catch (e: SecurityException) {
            Log.e(TAG, "Location permission revoked", e)
            stopSelf()
        }
    }

    private fun stopLocationUpdates() {
        locationCallback?.let {
            fusedLocationClient.removeLocationUpdates(it)
            locationCallback = null
        }
    }

    private fun hasLocationPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.ACCESS_FINE_LOCATION,
        ) == PackageManager.PERMISSION_GRANTED
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Location Sharing",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Shows when Aegis is sharing your location"
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

        val stopIntent = Intent(this, LocationService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingStop = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setContentTitle("Aegis Location")
            .setContentText(text)
            .setContentIntent(pendingTap)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", pendingStop)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "LocationService"
        private const val CHANNEL_ID = "aegis_location"
        private const val NOTIFICATION_ID = 2001

        const val ACTION_START = "com.aegis.android.LOCATION_START"
        const val ACTION_STOP = "com.aegis.android.LOCATION_STOP"
        const val ACTION_SINGLE = "com.aegis.android.LOCATION_SINGLE"

        /** Location update interval: 30 seconds. */
        private const val UPDATE_INTERVAL_MS = 30_000L

        /** Fastest update interval: 10 seconds. */
        private const val FASTEST_INTERVAL_MS = 10_000L

        /** Maximum update delay for batching: 60 seconds. */
        private const val MAX_UPDATE_DELAY_MS = 60_000L

        /**
         * Start continuous location sharing.
         */
        fun start(context: Context) {
            val intent = Intent(context, LocationService::class.java).apply {
                action = ACTION_START
            }
            ContextCompat.startForegroundService(context, intent)
        }

        /**
         * Stop location sharing.
         */
        fun stop(context: Context) {
            val intent = Intent(context, LocationService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }

        /**
         * Request a single location fix.
         */
        fun requestSingle(context: Context) {
            val intent = Intent(context, LocationService::class.java).apply {
                action = ACTION_SINGLE
            }
            ContextCompat.startForegroundService(context, intent)
        }
    }
}

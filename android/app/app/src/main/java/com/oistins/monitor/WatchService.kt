package com.oistins.monitor

import android.Manifest
import android.app.Notification
import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.IBinder

/** Keeps Oistins checking in the background, with a permanent notification. */
class WatchService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Alarm.channels(this)
        val n = Notification.Builder(this, Alarm.CH_WATCH)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle("Oistins is watching")
            .setContentText("Monitoring your connection, Wi-Fi and cell towers")
            .setOngoing(true)
            .setContentIntent(Alarm.openAppIntent(this))
            .build()
        val hasLocation = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
            checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
        try {
            if (hasLocation) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
            else startForeground(1, n)
        } catch (e: Exception) {
            // Android refused (e.g. permission revoked); stop quietly.
            stopSelf()
            return START_NOT_STICKY
        }
        Monitor.start(this)
        return START_STICKY
    }
}

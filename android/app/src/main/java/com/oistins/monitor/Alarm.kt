package com.oistins.monitor

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioManager
import android.media.ToneGenerator
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator

/** Siren, vibration and notifications for alerts. */
object Alarm {
    const val CH_ALERT = "oistins_alerts"
    const val CH_WATCH = "oistins_watch"
    @Volatile private var lastSiren = 0L

    fun channels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        val alerts = NotificationChannel(CH_ALERT, "Security alerts", NotificationManager.IMPORTANCE_HIGH).apply {
            description = "Warnings about your connection, Wi-Fi and cell towers"
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 400, 200, 400)
        }
        val watch = NotificationChannel(CH_WATCH, "Background watch", NotificationManager.IMPORTANCE_LOW).apply {
            description = "Shown while Oistins monitors in the background"
        }
        nm.createNotificationChannel(alerts)
        nm.createNotificationChannel(watch)
    }

    fun openAppIntent(ctx: Context): PendingIntent = PendingIntent.getActivity(
        ctx, 0,
        Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )

    fun onAlert(ctx: Context, a: Alert) {
        if (a.level == "info") return
        notify(ctx, a)
        if (!Monitor.store.bool("sound", true)) return
        if (a.level == "crit") siren(ctx, 4_000) else beep()
        vibrate(ctx, a.level == "crit")
    }

    fun siren(ctx: Context, minGapMs: Long) {
        val now = System.currentTimeMillis()
        if (now - lastSiren < minGapMs) return
        lastSiren = now
        Thread {
            try {
                val tg = ToneGenerator(AudioManager.STREAM_ALARM, 100)
                repeat(3) {
                    tg.startTone(ToneGenerator.TONE_CDMA_HIGH_L, 450)
                    Thread.sleep(500)
                    tg.startTone(ToneGenerator.TONE_CDMA_LOW_L, 450)
                    Thread.sleep(500)
                }
                tg.release()
            } catch (e: Exception) {
                // audio unavailable
            }
        }.start()
        vibrate(ctx, true)
    }

    private fun beep() {
        Thread {
            try {
                val tg = ToneGenerator(AudioManager.STREAM_NOTIFICATION, 90)
                tg.startTone(ToneGenerator.TONE_PROP_BEEP2, 400)
                Thread.sleep(500)
                tg.release()
            } catch (e: Exception) {
                // audio unavailable
            }
        }.start()
    }

    private fun vibrate(ctx: Context, strong: Boolean) {
        try {
            @Suppress("DEPRECATION")
            val v = ctx.getSystemService(Vibrator::class.java) ?: return
            val pattern = if (strong) longArrayOf(0, 500, 200, 500, 200, 900) else longArrayOf(0, 250, 150, 250)
            v.vibrate(VibrationEffect.createWaveform(pattern, -1))
        } catch (e: Exception) {
            // no vibrator
        }
    }

    private fun notify(ctx: Context, a: Alert) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        val n = Notification.Builder(ctx, CH_ALERT)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle((if (a.level == "crit") "🔴 " else "🟠 ") + a.title)
            .setContentText(a.detail)
            .setStyle(Notification.BigTextStyle().bigText(a.detail))
            .setColor(if (a.level == "crit") 0xFFFF3B4E.toInt() else 0xFFFFB020.toInt())
            .setCategory(Notification.CATEGORY_ALARM)
            .setContentIntent(openAppIntent(ctx))
            .setAutoCancel(true)
            .build()
        nm.notify(a.key.hashCode(), n)
    }
}

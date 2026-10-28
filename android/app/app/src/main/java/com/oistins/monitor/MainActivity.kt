package com.oistins.monitor

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient

class MainActivity : Activity() {
    private lateinit var web: WebView

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Alarm.channels(this)
        Monitor.start(this)
        window.statusBarColor = 0xFF070B12.toInt()
        window.navigationBarColor = 0xFF070B12.toInt()

        web = WebView(this)
        web.setBackgroundColor(0xFF070B12.toInt())
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.settings.allowContentAccess = false
        web.addJavascriptInterface(Bridge(), "Oistins")
        web.webViewClient = object : WebViewClient() {
            // The panel is a local page; any web link opens in the browser instead.
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val url = request.url
                if (url.scheme == "http" || url.scheme == "https") {
                    try { startActivity(Intent(Intent.ACTION_VIEW, url)) } catch (e: Exception) { }
                }
                return true
            }
        }
        setContentView(web)
        web.loadUrl("file:///android_asset/index.html")

        if (Monitor.store.bool("watch", false)) startWatch(true)
        askPermissions()
    }

    override fun onResume() {
        super.onResume()
        Monitor.uiVisible = true
    }

    override fun onPause() {
        super.onPause()
        Monitor.uiVisible = false
    }

    fun askPermissions() {
        val want = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.READ_PHONE_STATE,
        )
        if (Build.VERSION.SDK_INT >= 33) want.add(Manifest.permission.POST_NOTIFICATIONS)
        val missing = want.filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) requestPermissions(missing.toTypedArray(), 1)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        Monitor.runSlow()
    }

    private fun startWatch(on: Boolean) {
        val i = Intent(this, WatchService::class.java)
        Monitor.store.setBool("watch", on)
        try {
            if (on) startForegroundService(i) else stopService(i)
        } catch (e: Exception) {
            Monitor.store.setBool("watch", false)
        }
    }

    private fun openAppSettings() {
        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
    }

    /** Called from the panel's JavaScript. Only our own local page is ever loaded. */
    inner class Bridge {
        @JavascriptInterface
        fun state(): String = Monitor.snapshot()

        @JavascriptInterface
        fun action(name: String, arg: String) {
            runOnUiThread {
                when (name) {
                    "ack" -> Monitor.alerts.ack(arg.ifEmpty { null })
                    "speed" -> Monitor.runSpeed()
                    "trace" -> Monitor.runTrace()
                    "recheck" -> Monitor.runSlow()
                    "rebaseline" -> Monitor.rebaseline()
                    "sound" -> Monitor.store.setBool("sound", arg == "1")
                    "watch" -> startWatch(arg == "1")
                    "perms" -> {
                        askPermissions()
                        openAppSettings()
                    }
                    "usage" -> try {
                        startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
                    } catch (e: Exception) {
                        openAppSettings()
                    }
                    "devsettings" -> try {
                        startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
                    } catch (e: Exception) { }
                    "testalarm" -> Alarm.siren(this@MainActivity, 0)
                }
            }
        }
    }
}

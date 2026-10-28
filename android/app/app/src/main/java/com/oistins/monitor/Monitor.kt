package com.oistins.monitor

import android.content.Context
import android.net.TrafficStats
import android.os.SystemClock
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.util.Calendar
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/** Runs all checks on background threads and holds the dashboard state. */
object Monitor {
    val LAMPS = listOf("wifi", "tls", "dns", "injection", "cell", "routing", "ports", "apps", "privacy")
    private val TRACE_TARGETS = listOf("1.1.1.1", "8.8.8.8")

    lateinit var app: Context
    lateinit var store: Store
    lateinit var alerts: AlertBook
    val geo = Geo()

    @Volatile var uiVisible = false
    private var started = false
    private val exec: ScheduledExecutorService = Executors.newScheduledThreadPool(4)
    private val lock = Any()
    private val state = JSONObject()
    private val checks = JSONObject()
    private val history = ArrayDeque<DoubleArray>()
    private var lastRx = -1L
    private var lastTx = -1L
    private var lastT = 0L
    private var netId = "unknown"

    @Synchronized
    fun start(ctx: Context) {
        if (started) return
        started = true
        app = ctx.applicationContext
        store = Store(app)
        alerts = AlertBook { a -> Alarm.onAlert(app, a) }
        for (k in LAMPS) setCheck(k, "pending", "Waiting for first check…")
        put("speed", JSONObject().put("running", false))
        every(0, 2) { fast() }
        every(1, 3) { geo.resolvePending(); analyzeRoutes() }
        every(2, 60) { slow() }
        every(6, 600) { trace() }
        every(10, 1800) { speed() }
    }

    private fun every(delay: Long, period: Long, fn: () -> Unit) {
        exec.scheduleWithFixedDelay({ safe(fn) }, delay, period, TimeUnit.SECONDS)
    }

    private fun safe(fn: () -> Unit) {
        try {
            fn()
        } catch (t: Throwable) {
            Log.w("Oistins", "check failed", t)
        }
    }

    fun runNow(fn: () -> Unit) {
        exec.execute { safe(fn) }
    }

    fun runSlow() = runNow { slow() }
    fun runTrace() = runNow { trace() }
    fun runSpeed() = runNow { speed() }

    fun rebaseline() {
        store.resetBaselines()
        alerts.ack(null)
        runSlow()
        runTrace()
    }

    private fun put(k: String, v: Any?) = synchronized(lock) { state.put(k, v ?: JSONObject.NULL) }

    fun setCheck(name: String, status: String, detail: String) {
        synchronized(lock) {
            checks.put(name, JSONObject().put("status", status).put("detail", detail))
        }
    }

    fun quietHours(): Boolean {
        val h = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)
        return h < 6  // midnight to 6 am
    }

    // ------------------------------------------------------------------ every 2 s
    private fun fast() {
        val rx = TrafficStats.getTotalRxBytes()
        val tx = TrafficStats.getTotalTxBytes()
        val now = SystemClock.elapsedRealtime()
        if (lastRx >= 0 && rx >= 0 && tx >= 0) {
            val dt = (now - lastT).coerceAtLeast(1) / 1000.0
            val r = Checks.round2((rx - lastRx).coerceAtLeast(0) * 8 / dt / 1e6)
            val t = Checks.round2((tx - lastTx).coerceAtLeast(0) * 8 / dt / 1e6)
            synchronized(lock) {
                history.addLast(doubleArrayOf(r, t))
                while (history.size > 60) history.removeFirst()
                state.put("throughput", JSONObject().put("rx", r).put("tx", t))
            }
        }
        lastRx = rx; lastTx = tx; lastT = now

        val net = NetWatch.snapshot(app, store, alerts, ::setCheck)
        put("network", net)
        val wifi = net.optJSONObject("wifi")
        val newId = when {
            wifi != null && !wifi.isNull("ssid") -> "wifi:" + wifi.optString("ssid")
            else -> net.optString("kind", "offline")
        }
        if (newId != netId) {
            if (netId != "unknown") runTrace()
            netId = newId
        }
        put("cell", CellWatch.scan(app, store, alerts, ::setCheck))

        val vpn = net.optBoolean("vpn")
        val pdns = net.optBoolean("private_dns")
        setCheck(
            "privacy", if (vpn || pdns) "ok" else "off",
            when {
                vpn && pdns -> "VPN on and Private DNS active."
                vpn -> "VPN on: your provider can't see which sites you visit."
                pdns -> "Private DNS (${net.optString("private_dns_name").ifEmpty { "automatic" }}) encrypts your lookups. No VPN."
                else -> "No VPN or Private DNS: your network provider can see which sites you visit."
            }
        )

        if (uiVisible && alerts.alarm() == "crit" && store.bool("sound", true)) Alarm.siren(app, 6_000)
    }

    // ------------------------------------------------------------------ every 60 s
    private fun slow() {
        val nb = store.obj("net")
        val pip = Checks.publicIp()
        val old = nb.optString("public_ip", "")
        if (pip != null && old.isNotEmpty() && pip != old) {
            alerts.raise("pubip:$pip", "info", "Network", "Your public IP changed",
                "$old → $pip (normal when switching Wi-Fi/mobile data or VPN).")
        }
        if (pip != null) {
            nb.put("public_ip", pip); store.save("net")
            geo.get(pip)
        }
        put("public_ip", pip)

        checkTls()
        checkDns()
        checkInjection()

        val net = synchronized(lock) { state.optJSONObject("network") }
        val lan = net?.optString("local_ip", "")?.takeIf { it.isNotEmpty() && it != "null" }
        val ports = Checks.ports(app, lan)
        put("ports", ports)
        analyzePorts(ports)

        put("apps", AppTraffic.scan(app, alerts, quietHours(), ::setCheck))
        store.save("cells"); store.save("cellhist")
    }

    private fun checkTls() {
        val seen = store.obj("tls")
        val bad = ArrayList<String>()
        val inspect = ArrayList<String>()
        var reached = 0
        var changed = false
        for (h in Checks.TLS_HOSTS) {
            val r = Checks.tls(h)
            if (!r.has("verified")) continue
            reached++
            if (!r.optBoolean("verified")) {
                bad.add("$h: ${r.optString("error")}")
                continue
            }
            val issuer = r.optString("issuer")
            when (r.optString("kind")) {
                "interceptor" -> inspect.add("$h by $issuer")
                "unknown" -> inspect.add("$h by unknown issuer $issuer")
                "public" -> if (seen.optString(h) != issuer) { seen.put(h, issuer); changed = true }
            }
        }
        if (changed) store.save("tls")
        when {
            bad.isNotEmpty() -> {
                alerts.raise("tls:bad", "crit", "MITM", "Untrusted security certificates",
                    bad.joinToString("; ") + ". Something may be intercepting your encrypted traffic.")
                setCheck("tls", "crit", bad.joinToString("; "))
            }
            inspect.isNotEmpty() -> {
                alerts.raise("tls:inspect", "warn", "MITM", "Encrypted traffic is being inspected",
                    inspect.joinToString("; ") + ". Common on work networks; otherwise treat as man-in-the-middle.")
                setCheck("tls", "warn", inspect.joinToString("; "))
            }
            reached > 0 -> setCheck("tls", "ok", "$reached sites verified with genuine public certificates.")
            else -> setCheck("tls", "off", "Couldn't reach test sites (offline?).")
        }
    }

    private fun checkDns() {
        val r = Checks.dns()
        val wrong = r.getJSONObject("wrong")
        val nx = r.optString("nx")
        when {
            wrong.length() > 0 -> {
                val d = wrong.keys().asSequence().joinToString("; ") { "$it → ${wrong.optString(it)}" }
                alerts.raise("dns:wrong", "crit", "DNS", "DNS answers are being altered", d)
                setCheck("dns", "crit", d)
            }
            nx.isNotEmpty() -> {
                val d = "Made-up domains resolve to $nx (ISP ad redirect or hijack)."
                alerts.raise("dns:nx", "warn", "DNS", "DNS redirection detected", d)
                setCheck("dns", "warn", d)
            }
            r.optInt("failed") == Checks.DNS_EXPECT.size -> setCheck("dns", "off", "DNS lookups failing (offline?).")
            else -> setCheck("dns", "ok", "Known names resolve correctly; no redirection.")
        }
    }

    private fun checkInjection() {
        val r = Checks.injection()
        val t = r.getJSONArray("tampered")
        when {
            t.length() > 0 -> {
                val d = (0 until t.length()).joinToString("; ") { t.getString(it) }
                alerts.raise("inject", "warn", "Injection", "Web traffic is being modified or redirected",
                    "$d. Wi-Fi login page, provider injection, or an attacker.")
                setCheck("injection", "warn", d)
            }
            r.optInt("unreachable") == r.optInt("probes") -> setCheck("injection", "off", "Test pages unreachable.")
            else -> setCheck("injection", "ok", "Unencrypted test pages arrived unmodified.")
        }
    }

    private fun analyzePorts(p: JSONObject) {
        val open = p.getJSONArray("open")
        val notes = ArrayList<String>()
        var level = "ok"
        for (i in 0 until open.length()) {
            val o = open.getJSONObject(i)
            val port = o.getInt("port")
            val name = o.getString("name")
            if (o.getBoolean("exposed")) {
                val l = if (port == 5555 || port == 23 || port == 4444 || port == 31337) "crit" else "warn"
                alerts.raise("port:$port", l, "Ports", "Port $port ($name) is open to the network",
                    "Other devices on this network can connect to your phone on port $port." +
                        if (quietHours()) " Noticed during quiet hours." else "")
                if (AlertBook.rank(l) > AlertBook.rank(level)) level = l
                notes.add("$name :$port reachable")
            } else {
                notes.add("$name :$port (this phone only)")
            }
        }
        if (p.optBoolean("adb_wifi")) {
            alerts.raise("adbwifi", "crit", "Ports", "Wireless debugging is on",
                "Anyone who pairs with your phone over Wi-Fi can control it. Turn it off in Developer options.")
            level = "crit"; notes.add("wireless debugging ON")
        } else if (p.optBoolean("adb")) {
            alerts.raise("adb", "info", "Ports", "USB debugging is on",
                "A computer you plug into can control this phone. Turn it off when you don't need it.")
            notes.add("USB debugging on")
        }
        setCheck("ports", level, notes.joinToString("; ").ifEmpty { "No risky ports open; debugging off." })
    }

    // ------------------------------------------------------------------ routes
    private fun trace() {
        val routes = JSONObject()
        for (t in TRACE_TARGETS) {
            val hops = Checks.trace(t)
            if (hops == null) {
                setCheck("routing", "off", "This phone doesn't allow path tracing.")
                return
            }
            for (i in 0 until hops.length()) geo.get(hops.getJSONObject(i).optString("ip"))
            routes.put(t, JSONObject().put("hops", hops).put("at", System.currentTimeMillis() / 1000.0))
        }
        put("routes", routes)
        analyzeRoutes()
    }

    private fun analyzeRoutes() {
        val routes = synchronized(lock) { state.optJSONObject("routes")?.let { JSONObject(it.toString()) } } ?: return
        val base = store.obj("routes")
        val nbase = base.optJSONObject(netId) ?: JSONObject().also { base.put(netId, it) }
        val issues = ArrayList<String>()
        var level = "ok"
        var saved = false
        for (target in routes.keys()) {
            val hops = routes.getJSONObject(target).getJSONArray("hops")
            val ips = (0 until hops.length()).map { hops.getJSONObject(it) }
                .filter { !it.isNull("ip") }.map { it.getString("ip") }
            if (ips.isEmpty()) continue
            val ccs = ips.filter { Ip.isPublic(it) }.map { geo.get(it).optString("cc") }
            if (ccs.any { it.isEmpty() }) return  // wait for all countries
            val countries = ccs.toSortedSet()
            val b = nbase.optJSONObject(target)
            if (b == null) {
                nbase.put(target, JSONObject().put("first", ips[0]).put("countries", JSONArray(countries.toList()))
                    .put("len", hops.length()))
                saved = true
                continue
            }
            val bc = b.getJSONArray("countries").let { a -> (0 until a.length()).map { a.getString(it) } }
            if (ips[0] != b.optString("first")) {
                level = "crit"
                issues.add("$target: first hop ${b.optString("first")} → ${ips[0]}")
                alerts.raise("route1:$target:${ips[0]}", "crit", "Routing", "Traffic is leaving through a different first hop",
                    "Path to $target now starts at ${ips[0]} instead of ${b.optString("first")}. Possible rogue router or diversion.")
            }
            val new = countries.filter { it !in bc }
            if (new.isNotEmpty()) {
                if (level != "crit") level = "warn"
                issues.add("$target: new countries ${new.joinToString()}")
                alerts.raise("routecc:$target:${new.joinToString()}", "warn", "Routing",
                    "Traffic to $target now passes through ${new.joinToString()}",
                    "Usual path countries: ${bc.joinToString().ifEmpty { "none" }}.")
            }
        }
        if (saved) store.save("routes")
        setCheck("routing", level, issues.joinToString("; ").ifEmpty { "${routes.length()} paths match the learned routes." })
    }

    // ------------------------------------------------------------------ speed
    private fun speed() {
        synchronized(lock) { state.optJSONObject("speed")?.put("running", true) }
        val lat = Checks.latency()
        val down = Checks.downloadMbps()
        val up = Checks.uploadMbps()
        lat.put("download", down ?: JSONObject.NULL).put("upload", up ?: JSONObject.NULL)
            .put("at", System.currentTimeMillis() / 1000.0).put("running", false)
        put("speed", lat)
    }

    // ------------------------------------------------------------------ for the panel
    fun snapshot(): String {
        val s: JSONObject = synchronized(lock) {
            val copy = JSONObject(state.toString())
            copy.put("checks", JSONObject(checks.toString()))
            val h = JSONArray()
            for (p in history) h.put(JSONArray().put(p[0]).put(p[1]))
            copy.put("history", h)
        }
        s.optJSONObject("routes")?.let { routes ->
            for (t in routes.keys()) {
                val hops = routes.getJSONObject(t).getJSONArray("hops")
                for (i in 0 until hops.length()) {
                    val hop = hops.getJSONObject(i)
                    val g = geo.get(hop.optString("ip"))
                    hop.put("cc", g.optString("cc")).put("country", g.optString("country")).put("org", g.optString("org"))
                }
            }
        }
        val pip = s.optString("public_ip", "")
        if (pip.isNotEmpty() && pip != "null") s.put("public_geo", JSONObject(geo.get(pip).toString()))
        s.put("alerts", alerts.toJson())
        s.put("alarm", alerts.alarm() ?: JSONObject.NULL)
        s.put("quiet_hours", quietHours())
        s.put("settings", JSONObject().put("sound", store.bool("sound", true))
            .put("watch", store.bool("watch", false)))
        s.put("time", System.currentTimeMillis() / 1000.0)
        return s.toString()
    }
}

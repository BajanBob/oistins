package com.oistins.monitor

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

/** Learned baselines and settings, kept in SharedPreferences as JSON. */
class Store(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("oistins", Context.MODE_PRIVATE)
    private val cache = HashMap<String, JSONObject>()

    @Synchronized
    fun obj(key: String): JSONObject = cache.getOrPut(key) {
        try {
            JSONObject(prefs.getString(key, "{}") ?: "{}")
        } catch (e: Exception) {
            JSONObject()
        }
    }

    @Synchronized
    fun save(key: String) {
        val o = cache[key] ?: return
        prefs.edit().putString(key, o.toString()).apply()
    }

    fun bool(key: String, def: Boolean): Boolean = prefs.getBoolean("b_$key", def)
    fun setBool(key: String, v: Boolean) = prefs.edit().putBoolean("b_$key", v).apply()

    /** Forget everything learned (keeps settings). */
    @Synchronized
    fun resetBaselines() {
        val e = prefs.edit()
        for (k in listOf("wifi", "cells", "cellhist", "tls", "routes", "net")) e.remove(k)
        e.apply()
        cache.clear()
    }
}

class Alert(
    val key: String,
    var level: String,          // info | warn | crit
    val category: String,
    val title: String,
    var detail: String,
    val first: Long,
    var last: Long,
    var count: Int = 1,
    var acked: Boolean = false,
)

class AlertBook(private val onNew: (Alert) -> Unit) {
    private val map = LinkedHashMap<String, Alert>()

    fun raise(key: String, level: String, category: String, title: String, detail: String = "") {
        val now = System.currentTimeMillis()
        var fresh: Alert? = null
        synchronized(this) {
            val a = map[key]
            if (a != null && (!a.acked || now - a.last < 600_000)) {
                a.last = now
                a.count++
                if (detail.isNotEmpty()) a.detail = detail
                if (rank(level) > rank(a.level)) {
                    a.level = level
                    a.acked = false
                    fresh = a
                }
            } else {
                val n = Alert(key, level, category, title, detail, now, now)
                map[key] = n
                if (map.size > 300) {
                    map.values.minByOrNull { it.last }?.let { map.remove(it.key) }
                }
                fresh = n
            }
        }
        fresh?.let(onNew)
    }

    @Synchronized
    fun ack(key: String?) {
        for (a in map.values) if (key == null || a.key == key) a.acked = true
    }

    @Synchronized
    fun alarm(): String? {
        val levels = map.values.filter { !it.acked }.map { it.level }
        return when {
            "crit" in levels -> "crit"
            "warn" in levels -> "warn"
            else -> null
        }
    }

    @Synchronized
    fun toJson(): JSONArray {
        val arr = JSONArray()
        map.values.sortedWith(compareBy<Alert>({ it.acked }, { -rank(it.level) }, { -it.last }))
            .forEach {
                arr.put(
                    JSONObject().put("key", it.key).put("level", it.level).put("category", it.category)
                        .put("title", it.title).put("detail", it.detail).put("first", it.first / 1000.0)
                        .put("last", it.last / 1000.0).put("count", it.count).put("acked", it.acked)
                )
            }
        return arr
    }

    companion object {
        fun rank(l: String) = when (l) {
            "crit" -> 2
            "warn" -> 1
            else -> 0
        }
    }
}

object Ip {
    fun isPublic(ip: String?): Boolean {
        if (ip.isNullOrEmpty()) return false
        if (ip.contains(':')) {
            val l = ip.lowercase()
            return !(l == "::1" || l == "::" || l.startsWith("fe80") || l.startsWith("fc") || l.startsWith("fd"))
        }
        val p = ip.split('.').mapNotNull { it.toIntOrNull() }
        if (p.size != 4) return false
        val a = p[0]
        val b = p[1]
        return !(a == 10 || a == 127 || a == 0 || (a == 172 && b in 16..31) || (a == 192 && b == 168) ||
            (a == 169 && b == 254) || (a == 100 && b in 64..127) || a >= 224)
    }
}

object Http {
    private const val UA = "Oistins-Android/1.0"

    class Result(val code: Int, val body: ByteArray)

    fun get(url: String, timeoutMs: Int = 10_000, follow: Boolean = true, maxBytes: Int = 1_000_000): Result {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = timeoutMs
        c.readTimeout = timeoutMs
        c.instanceFollowRedirects = follow
        c.useCaches = false
        c.setRequestProperty("User-Agent", UA)
        try {
            val code = c.responseCode
            val stream: InputStream? = if (code >= 400) c.errorStream else c.inputStream
            val body = stream?.use { readUpTo(it, maxBytes) } ?: ByteArray(0)
            return Result(code, body)
        } finally {
            c.disconnect()
        }
    }

    fun post(url: String, body: ByteArray, timeoutMs: Int = 15_000): Result {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = timeoutMs
        c.readTimeout = timeoutMs
        c.requestMethod = "POST"
        c.doOutput = true
        c.setFixedLengthStreamingMode(body.size)
        c.setRequestProperty("User-Agent", UA)
        c.setRequestProperty("Content-Type", "application/octet-stream")
        try {
            c.outputStream.use { it.write(body) }
            val code = c.responseCode
            val stream: InputStream? = if (code >= 400) c.errorStream else c.inputStream
            return Result(code, stream?.use { readUpTo(it, 1_000_000) } ?: ByteArray(0))
        } finally {
            c.disconnect()
        }
    }

    fun readUpTo(input: InputStream, max: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(16_384)
        while (out.size() < max) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }
}

/** IP → country / owner via ip-api.com batch lookups, cached. */
class Geo {
    private val cache = HashMap<String, JSONObject>()
    private val pending = LinkedHashSet<String>()
    private var nextCall = 0L

    @Synchronized
    fun get(ip: String?): JSONObject {
        if (ip.isNullOrEmpty()) return JSONObject()
        if (!Ip.isPublic(ip)) return JSONObject().put("cc", "LAN").put("country", "Local network").put("org", "")
        cache[ip]?.let { return it }
        pending.add(ip)
        return JSONObject()
    }

    fun resolvePending() {
        val ips: List<String> = synchronized(this) {
            if (System.currentTimeMillis() < nextCall) return
            val batch = pending.filter { it !in cache }.take(100)
            pending.removeAll(batch.toSet())
            batch
        }
        if (ips.isEmpty()) return
        try {
            val r = Http.post(
                "http://ip-api.com/batch?fields=status,country,countryCode,city,isp,org,as,query",
                JSONArray(ips).toString().toByteArray()
            )
            val rows = JSONArray(String(r.body))
            synchronized(this) {
                for (i in 0 until rows.length()) {
                    val row = rows.getJSONObject(i)
                    val ip = row.optString("query")
                    if (row.optString("status") == "success") {
                        cache[ip] = JSONObject().put("cc", row.optString("countryCode"))
                            .put("country", row.optString("country")).put("city", row.optString("city"))
                            .put("org", row.optString("org").ifEmpty { row.optString("isp") })
                    } else {
                        cache[ip] = JSONObject().put("cc", "??").put("country", "Unknown").put("org", "")
                    }
                }
                nextCall = System.currentTimeMillis() + 4_500
            }
        } catch (e: Exception) {
            synchronized(this) {
                pending.addAll(ips)
                nextCall = System.currentTimeMillis() + 30_000
            }
        }
    }
}

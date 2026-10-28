package com.oistins.monitor

import android.content.Context
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.cert.X509Certificate
import java.util.Random
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

/** One-shot network checks. All of these block, so call them off the main thread. */
object Checks {

    // ---------------------------------------------------------- public IP
    fun publicIp(): String? = try {
        JSONObject(String(Http.get("https://api.ipify.org?format=json", 8_000).body)).optString("ip").ifEmpty { null }
    } catch (e: Exception) {
        null
    }

    // ---------------------------------------------------------- TLS / man-in-the-middle
    val TLS_HOSTS = listOf("www.google.com", "www.cloudflare.com", "github.com", "www.wikipedia.org")
    private val PUBLIC_CAS = listOf(
        "google trust services", "digicert", "let's encrypt", "sectigo", "globalsign", "amazon",
        "microsoft", "entrust", "godaddy", "comodo", "usertrust", "cloudflare", "certainly", "starfield",
        "identrust", "buypass", "ssl.com", "harica", "actalis", "quovadis", "certum", "zerossl", "telia",
        "geotrust", "thawte", "rapidssl", "apple"
    )
    private val INTERCEPTORS = listOf(
        "avast", "avg", "kaspersky", "eset", "bitdefender", "zscaler", "fortinet", "fortigate",
        "palo alto", "sophos", "netskope", "mitmproxy", "charles", "fiddler", "portswigger", "burp",
        "blue coat", "umbrella", "norton", "mcafee", "forcepoint", "barracuda", "watchguard", "sonicwall",
        "check point", "untangle", "cisco", "httptoolkit", "proxyman"
    )

    fun tls(host: String): JSONObject {
        val o = JSONObject().put("host", host)
        try {
            val c = URL("https://$host/").openConnection() as HttpsURLConnection
            c.connectTimeout = 8_000
            c.readTimeout = 8_000
            c.instanceFollowRedirects = false
            c.setRequestProperty("User-Agent", "Oistins-Android/1.0")
            try {
                c.connect()
                val cert = c.serverCertificates.firstOrNull() as? X509Certificate
                val dn = cert?.issuerX500Principal?.name ?: ""
                val org = Regex("(?:^|,)O=([^,]+)").find(dn)?.groupValues?.get(1)
                    ?: Regex("CN=([^,]+)").find(dn)?.groupValues?.get(1) ?: "?"
                val low = org.lowercase()
                val kind = when {
                    INTERCEPTORS.any { low.contains(it) } -> "interceptor"
                    PUBLIC_CAS.any { low.contains(it) } -> "public"
                    else -> "unknown"
                }
                o.put("verified", true).put("issuer", org).put("kind", kind)
            } finally {
                c.disconnect()
            }
        } catch (e: SSLException) {
            val msg = e.message ?: ""
            val trustFail = listOf("trust anchor", "certificate", "hostname", "not verified", "CertPath")
                .any { msg.contains(it, ignoreCase = true) }
            if (trustFail) o.put("verified", false).put("error", msg) else o.put("error", msg)
        } catch (e: Exception) {
            o.put("error", e.toString())
        }
        return o
    }

    // ---------------------------------------------------------- DNS
    val DNS_EXPECT = mapOf(
        "one.one.one.one" to setOf("1.1.1.1", "1.0.0.1"),
        "dns.google" to setOf("8.8.8.8", "8.8.4.4"),
    )

    private fun resolve(name: String): Set<String> = try {
        InetAddress.getAllByName(name).filterIsInstance<Inet4Address>().mapNotNull { it.hostAddress }.toSet()
    } catch (e: Exception) {
        emptySet()
    }

    fun dns(): JSONObject {
        val wrong = JSONObject()
        var failed = 0
        for ((name, expect) in DNS_EXPECT) {
            val got = resolve(name)
            if (got.isEmpty()) failed++
            else if (got.intersect(expect).isEmpty()) wrong.put(name, got.joinToString(", "))
        }
        val chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        val rnd = Random()
        val fake = (1..26).map { chars[rnd.nextInt(chars.length)] }.joinToString("") + ".com"
        return JSONObject().put("wrong", wrong).put("failed", failed)
            .put("nx", resolve(fake).joinToString(", "))
    }

    // ---------------------------------------------------------- HTTP injection / captive portal
    private val PROBES = listOf(
        Triple("http://connectivitycheck.gstatic.com/generate_204", 204, ""),
        Triple("http://detectportal.firefox.com/success.txt", 200, "success"),
    )

    fun injection(): JSONObject {
        val tampered = JSONArray()
        var unreachable = 0
        for ((url, code, body) in PROBES) {
            try {
                val r = Http.get(url, 8_000, follow = false, maxBytes = 4096)
                val text = String(r.body).trim()
                val bad = r.code != code || (body.isNotEmpty() && !text.startsWith(body)) ||
                    (body.isEmpty() && text.isNotEmpty())
                if (bad) tampered.put("$url → HTTP ${r.code}, ${r.body.size} bytes")
            } catch (e: Exception) {
                unreachable++
            }
        }
        return JSONObject().put("tampered", tampered).put("unreachable", unreachable)
            .put("probes", PROBES.size)
    }

    // ---------------------------------------------------------- speed
    fun latency(host: String = "1.1.1.1", port: Int = 443, n: Int = 6): JSONObject {
        val times = ArrayList<Double>()
        var lost = 0
        repeat(n) {
            val t = System.nanoTime()
            try {
                Socket().use { it.connect(InetSocketAddress(host, port), 3_000) }
                times.add((System.nanoTime() - t) / 1e6)
            } catch (e: Exception) {
                lost++
            }
            Thread.sleep(150)
        }
        val o = JSONObject().put("loss", lost * 100 / n)
        if (times.isEmpty()) return o
        val sorted = times.sorted()
        val jitter = if (times.size > 1) times.zipWithNext { a, b -> Math.abs(a - b) }.average() else 0.0
        return o.put("latency", round1(sorted[sorted.size / 2])).put("jitter", round1(jitter))
    }

    fun downloadMbps(maxBytes: Long = 50_000_000, maxSeconds: Double = 10.0): Double? = try {
        val c = URL("https://speed.cloudflare.com/__down?bytes=$maxBytes").openConnection() as HttpsURLConnection
        c.connectTimeout = 10_000
        c.readTimeout = 10_000
        c.setRequestProperty("User-Agent", "Oistins-Android/1.0")
        val start = System.nanoTime()
        var total = 0L
        try {
            c.inputStream.use { input ->
                val buf = ByteArray(65_536)
                while ((System.nanoTime() - start) / 1e9 < maxSeconds) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                }
            }
        } finally {
            c.disconnect()
        }
        round1(total * 8 / ((System.nanoTime() - start) / 1e9) / 1e6)
    } catch (e: Exception) {
        null
    }

    fun uploadMbps(size: Int = 8_000_000): Double? = try {
        val data = ByteArray(size).also { Random().nextBytes(it) }
        val start = System.nanoTime()
        Http.post("https://speed.cloudflare.com/__up", data, 30_000)
        round1(size * 8 / ((System.nanoTime() - start) / 1e9) / 1e6)
    } catch (e: Exception) {
        null
    }

    // ---------------------------------------------------------- traceroute without root (ping with rising TTL)
    fun trace(target: String, maxHops: Int = 20): JSONArray? {
        val hops = JSONArray()
        for (ttl in 1..maxHops) {
            val start = System.nanoTime()
            val out = run(listOf("/system/bin/ping", "-c", "1", "-W", "1", "-t", ttl.toString(), target), 4_000)
                ?: return if (ttl == 1) null else hops
            val ms = (System.nanoTime() - start) / 1e6
            val reply = Regex("bytes from ([0-9.]+).*time=([0-9.]+)").find(out)
            val from = Regex("From ([0-9.]+)").find(out)?.groupValues?.get(1)
            val ip = reply?.groupValues?.get(1) ?: from
            val rtt: Any = reply?.groupValues?.get(2)?.toDoubleOrNull() ?: if (ip != null) round1(ms) else JSONObject.NULL
            hops.put(JSONObject().put("ttl", ttl).put("ip", ip ?: JSONObject.NULL).put("rtt", rtt))
            if (reply != null) break
        }
        return hops
    }

    private fun run(cmd: List<String>, timeoutMs: Long): String? = try {
        val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
        if (!p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) p.destroy()
        p.inputStream.bufferedReader().readText()
    } catch (e: Exception) {
        null
    }

    // ---------------------------------------------------------- open ports on this phone + debugging
    val RISKY = linkedMapOf(
        5555 to "ADB remote control", 5037 to "ADB server", 21 to "FTP", 22 to "SSH", 23 to "Telnet",
        8022 to "SSH (Termux)", 80 to "Web server", 8080 to "Web server / proxy", 8000 to "Web server",
        445 to "SMB file sharing", 139 to "NetBIOS", 3389 to "Remote Desktop", 5900 to "VNC",
        1080 to "SOCKS proxy", 9050 to "Tor proxy", 2049 to "NFS", 4444 to "Known backdoor port",
        31337 to "Known backdoor port",
    )

    fun ports(ctx: Context, lanIp: String?): JSONObject {
        val open = JSONArray()
        val hosts = listOfNotNull("127.0.0.1", lanIp).distinct()
        for (host in hosts) for ((port, name) in RISKY) {
            try {
                Socket().use { it.connect(InetSocketAddress(host, port), 150) }
                open.put(JSONObject().put("host", host).put("port", port).put("name", name)
                    .put("exposed", host != "127.0.0.1"))
            } catch (e: Exception) {
                // closed
            }
        }
        val cr = ctx.contentResolver
        fun g(name: String) = try { Settings.Global.getInt(cr, name, 0) } catch (e: Exception) { 0 }
        return JSONObject().put("open", open)
            .put("adb", g(Settings.Global.ADB_ENABLED) == 1)
            .put("adb_wifi", g("adb_wifi_enabled") == 1)
            .put("dev", g(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED) == 1)
    }

    fun round1(v: Double) = Math.round(v * 10) / 10.0
    fun round2(v: Double) = Math.round(v * 100) / 100.0
}

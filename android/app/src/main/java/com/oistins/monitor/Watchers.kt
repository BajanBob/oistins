package com.oistins.monitor

import android.Manifest
import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Process
import android.telephony.CellIdentityNr
import android.telephony.CellInfo
import android.telephony.CellInfoCdma
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoTdscdma
import android.telephony.CellInfoWcdma
import android.telephony.TelephonyManager
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address

typealias SetCheck = (String, String, String) -> Unit

private fun granted(ctx: Context, perm: String) =
    ctx.checkSelfPermission(perm) == PackageManager.PERMISSION_GRANTED

/** Active network, Wi-Fi access point and router: evil-twin and rogue-router checks. */
object NetWatch {
    private val SECURITY = mapOf(
        0 to "Open (no password)", 1 to "WEP (broken)", 2 to "WPA2", 3 to "WPA2-Enterprise",
        4 to "WPA3", 5 to "WPA3-Enterprise", 6 to "Enhanced Open", 9 to "WPA3-Enterprise",
    )

    fun snapshot(ctx: Context, store: Store, alerts: AlertBook, setCheck: SetCheck): JSONObject {
        val o = JSONObject()
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        if (cm == null) {
            setCheck("wifi", "off", "Network information unavailable.")
            return o.put("kind", "offline")
        }
        val active = cm.activeNetwork
        val caps = active?.let { cm.getNetworkCapabilities(it) }
        val vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

        // Find the real (non-VPN) Wi-Fi or cellular network underneath any VPN.
        var wifiLp: LinkProperties? = null
        var physKind = "offline"
        @Suppress("DEPRECATION")
        val all = cm.allNetworks
        for (n in all) {
            val c = cm.getNetworkCapabilities(n) ?: continue
            if (c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            if (c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                wifiLp = cm.getLinkProperties(n); physKind = "wifi"
            } else if (physKind == "offline" && c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                physKind = "cellular"
            } else if (physKind == "offline" && c.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                physKind = "ethernet"
            }
        }
        val lp = wifiLp ?: active?.let { cm.getLinkProperties(it) }
        val gateway = lp?.routes?.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }
            ?.gateway?.hostAddress
        val localIp = lp?.linkAddresses?.firstOrNull { it.address is Inet4Address }?.address?.hostAddress
        val activeLp = active?.let { cm.getLinkProperties(it) }
        o.put("kind", physKind).put("vpn", vpn).put("gateway", gateway ?: JSONObject.NULL)
            .put("iface", lp?.interfaceName ?: "").put("local_ip", localIp ?: JSONObject.NULL)
            .put("dns", JSONArray(activeLp?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList<String>()))
            .put("private_dns", activeLp?.isPrivateDnsActive == true)
            .put("private_dns_name", activeLp?.privateDnsServerName ?: "")

        if (physKind != "wifi") {
            o.put("wifi", JSONObject.NULL)
            setCheck("wifi", "ok", if (physKind == "offline") "Offline." else "Not on Wi-Fi (using $physKind).")
            return o
        }
        val wm = ctx.applicationContext.getSystemService(WifiManager::class.java)
        @Suppress("DEPRECATION")
        val wiOrNull: WifiInfo? = wm?.connectionInfo
        val wi: WifiInfo = wiOrNull ?: run {
            o.put("wifi", JSONObject.NULL)
            setCheck("wifi", "off", "Wi-Fi details unavailable.")
            return o
        }
        val ssid: String? = wi.ssid?.removeSurrounding("\"")
        val bssid: String? = wi.bssid
        if (ssid.isNullOrEmpty() || ssid == "<unknown ssid>" || bssid.isNullOrEmpty() || bssid == "02:00:00:00:00:00") {
            o.put("wifi", JSONObject().put("ssid", JSONObject.NULL))
            setCheck("wifi", "off", "Allow location access so Oistins can identify the Wi-Fi access point.")
            return o
        }
        val secCode = if (Build.VERSION.SDK_INT >= 31) wi.currentSecurityType else -1
        val security = SECURITY[secCode] ?: if (secCode == -1) "Unknown" else "Type $secCode"
        val w = JSONObject().put("ssid", ssid).put("bssid", bssid).put("rssi", wi.rssi)
            .put("security", security).put("link_mbps", wi.linkSpeed)

        // ---- analysis against what we learned for this network name
        val db = store.obj("wifi")
        val rec = db.optJSONObject(ssid) ?: JSONObject().put("bssids", JSONArray())
        val list = rec.getJSONArray("bssids")
        val known = (0 until list.length()).map { list.getString(it) }
        var status = "ok"
        val notes = ArrayList<String>()
        var changed = false
        if (known.isEmpty()) {
            list.put(bssid); changed = true
        } else if (bssid !in known) {
            alerts.raise(
                "evil:$ssid:$bssid", "warn", "Wi-Fi", "New access point for \"$ssid\"",
                "Access point $bssid hasn't been seen on this network before. Normal for mesh systems " +
                    "and extenders; if you have a single router, this could be an evil-twin hotspot."
            )
            list.put(bssid); changed = true
            status = "warn"; notes.add("new access point $bssid")
        }
        val knownGw = rec.optString("gateway", "")
        if (gateway != null) {
            if (knownGw.isEmpty()) {
                rec.put("gateway", gateway); changed = true
            } else if (knownGw != gateway) {
                alerts.raise(
                    "gw:$ssid:$gateway", "crit", "MITM", "Router address changed on \"$ssid\"",
                    "The router was $knownGw and is now $gateway. A rogue router or DHCP server " +
                        "on the network can redirect all your traffic."
                )
                status = "crit"; notes.add("router $knownGw → $gateway")
            }
        }
        if (secCode == 0 || secCode == 1) {
            alerts.raise(
                "openwifi:$ssid", "warn", "Wi-Fi", "Insecure Wi-Fi: $security",
                "Anyone nearby can read unencrypted traffic on \"$ssid\". Use a VPN on this network."
            )
            if (status == "ok") status = "warn"
            notes.add(security)
        }
        if (changed) {
            db.put(ssid, rec); store.save("wifi")
        }
        w.put("known_aps", list.length())
        o.put("wifi", w)
        setCheck(
            "wifi", status, if (notes.isEmpty())
                "\"$ssid\" via known access point $bssid, router $gateway, $security."
            else notes.joinToString("; ")
        )
        return o
    }
}

/** Cell-tower watch: heuristics for fake base stations (IMSI catchers / "stingrays"). */
object CellWatch {
    private fun v(x: Int): Any = if (x == Int.MAX_VALUE || x == CellInfo.UNAVAILABLE) JSONObject.NULL else x
    private fun v(x: Long): Any = if (x == Long.MAX_VALUE || x == CellInfo.UNAVAILABLE_LONG) JSONObject.NULL else x

    private fun describe(ci: CellInfo): JSONObject? {
        val o = JSONObject().put("registered", ci.isRegistered)
        when (ci) {
            is CellInfoNr -> {
                val id = ci.cellIdentity as CellIdentityNr
                o.put("rat", "5G").put("cid", v(id.nci)).put("area", v(id.tac)).put("pci", v(id.pci))
                    .put("mcc", id.mccString ?: JSONObject.NULL).put("mnc", id.mncString ?: JSONObject.NULL)
                    .put("dbm", ci.cellSignalStrength.dbm)
            }
            is CellInfoLte -> {
                val id = ci.cellIdentity
                o.put("rat", "4G").put("cid", v(id.ci)).put("area", v(id.tac)).put("pci", v(id.pci))
                    .put("mcc", id.mccString ?: JSONObject.NULL).put("mnc", id.mncString ?: JSONObject.NULL)
                    .put("dbm", ci.cellSignalStrength.dbm)
            }
            is CellInfoWcdma -> {
                val id = ci.cellIdentity
                o.put("rat", "3G").put("cid", v(id.cid)).put("area", v(id.lac)).put("pci", v(id.psc))
                    .put("mcc", id.mccString ?: JSONObject.NULL).put("mnc", id.mncString ?: JSONObject.NULL)
                    .put("dbm", ci.cellSignalStrength.dbm)
            }
            is CellInfoTdscdma -> {
                val id = ci.cellIdentity
                o.put("rat", "3G").put("cid", v(id.cid)).put("area", v(id.lac))
                    .put("mcc", id.mccString ?: JSONObject.NULL).put("mnc", id.mncString ?: JSONObject.NULL)
                    .put("dbm", ci.cellSignalStrength.dbm)
            }
            is CellInfoGsm -> {
                val id = ci.cellIdentity
                o.put("rat", "2G").put("cid", v(id.cid)).put("area", v(id.lac))
                    .put("mcc", id.mccString ?: JSONObject.NULL).put("mnc", id.mncString ?: JSONObject.NULL)
                    .put("dbm", ci.cellSignalStrength.dbm)
            }
            is CellInfoCdma -> {
                val id = ci.cellIdentity
                o.put("rat", "CDMA").put("cid", v(id.basestationId)).put("area", v(id.networkId))
                    .put("mcc", JSONObject.NULL).put("mnc", v(id.systemId))
                    .put("dbm", ci.cellSignalStrength.dbm)
            }
            else -> return null
        }
        return o
    }

    fun scan(ctx: Context, store: Store, alerts: AlertBook, setCheck: SetCheck): JSONObject {
        val out = JSONObject()
        val tm = ctx.getSystemService(TelephonyManager::class.java)
        if (tm == null || tm.phoneType == TelephonyManager.PHONE_TYPE_NONE) {
            setCheck("cell", "off", "No cellular radio on this device.")
            return out
        }
        if (!granted(ctx, Manifest.permission.ACCESS_FINE_LOCATION)) {
            setCheck("cell", "off", "Allow precise location: Android only shares cell-tower details with it.")
            return out.put("need_permission", true)
        }
        val infos: List<CellInfo> = try {
            tm.allCellInfo ?: emptyList()
        } catch (e: SecurityException) {
            emptyList()
        }
        val cells = JSONArray()
        var reg: JSONObject? = null
        for (ci in infos) {
            val c = describe(ci) ?: continue
            cells.put(c)
            if (ci.isRegistered && reg == null) reg = c
        }
        val db = store.obj("cells")
        out.put("cells", cells).put("operator", tm.networkOperatorName ?: "")
            .put("learned", db.length()).put("registered", reg ?: JSONObject.NULL)
        val r = reg
        if (r == null) {
            setCheck("cell", "off", if (infos.isEmpty()) "No cell information (airplane mode or no SIM?)." else "Not registered to a tower.")
            return out
        }

        val rat = r.optString("rat")
        val mcc = r.optString("mcc", "")
        val mnc = r.optString("mnc", "")
        val area = r.opt("area")
        val cid = r.opt("cid")
        val dbm = r.optInt("dbm", -140)
        val key = "$mcc-$mnc-$area-$cid"
        val hist = store.obj("cellhist")
        val modern = hist.optInt("modern", 0)
        val known = db.has(key)
        var level = "ok"
        val notes = ArrayList<String>()
        fun bump(l: String) {
            if (AlertBook.rank(l) > AlertBook.rank(level)) level = l
        }

        // 1. Pushed down to 2G: weak encryption, the classic IMSI-catcher trick.
        if (rat == "2G") {
            val l = if (modern >= 3) "crit" else "warn"
            alerts.raise(
                "2g:$key", l, "Cell tower", "Phone pushed down to 2G",
                "Now on 2G tower $cid (area $area, $dbm dBm). 2G encryption is weak, and forcing phones onto it " +
                    "is a common fake-tower trick. It can also be normal in areas with poor coverage."
            )
            bump(l); notes.add("on 2G")
        } else if (rat == "4G" || rat == "5G") {
            hist.put("modern", modern + 1)
        }
        // 2. Tower with missing identity
        if (cid == JSONObject.NULL || area == JSONObject.NULL || r.optLong("cid", 1) == 0L || r.optInt("area", 1) == 0) {
            alerts.raise(
                "noid:$key", "warn", "Cell tower", "Tower is hiding its identity",
                "The tower you're connected to isn't broadcasting a complete cell ID / area code."
            )
            bump("warn"); notes.add("incomplete tower ID")
        }
        // 3. New, unusually strong tower whose area code doesn't match its neighbours
        val neighbourAreas = HashSet<String>()
        for (i in 0 until cells.length()) {
            val c = cells.getJSONObject(i)
            if (!c.optBoolean("registered") && c.optString("mnc") == mnc && !c.isNull("area")) neighbourAreas.add(c.optString("area"))
        }
        if (!known && db.length() >= 15 && dbm > -70 && neighbourAreas.isNotEmpty() && area.toString() !in neighbourAreas) {
            alerts.raise(
                "strong:$key", "warn", "Cell tower", "Unfamiliar, unusually strong tower",
                "New $rat tower $cid at $dbm dBm uses area code $area, unlike nearby towers (${neighbourAreas.joinToString()}). " +
                    "Fake towers transmit strongly to pull phones in."
            )
            bump("warn"); notes.add("unfamiliar strong tower")
        }
        // 4. Different network than the SIM, while not roaming (often national roaming; low weight)
        val simOp = tm.simOperator ?: ""
        if (mcc.isNotEmpty() && simOp.isNotEmpty() && "$mcc$mnc" != simOp && !tm.isNetworkRoaming) {
            alerts.raise(
                "op:$key", "info", "Cell tower", "Tower belongs to a different network than your SIM",
                "SIM network $simOp, tower $mcc$mnc. Usually a roaming partner."
            )
        }
        // 5. Strong 4G/5G cell that lists no neighbours
        if ((rat == "4G" || rat == "5G") && cells.length() <= 1 && dbm > -75) {
            alerts.raise("lonely:$key", "info", "Cell tower", "Tower reports no neighbouring cells",
                "Real networks usually advertise neighbours; some fake towers don't.")
        }

        val now = System.currentTimeMillis()
        val rec = db.optJSONObject(key)
        if (rec == null) {
            db.put(key, JSONObject().put("rat", rat).put("first", now).put("last", now).put("seen", 1).put("max", dbm))
            store.save("cells")
        } else {
            rec.put("last", now).put("seen", rec.optInt("seen") + 1).put("max", maxOf(rec.optInt("max", -140), dbm))
        }
        if (now / 1000 % 60 < 3) {
            store.save("cells"); store.save("cellhist")
        }
        val summary = "$rat · ${tm.networkOperatorName} · cell $cid · area $area · $dbm dBm · " +
            "${cells.length() - 1} neighbours · ${db.length()} towers learned"
        setCheck("cell", level, if (notes.isEmpty()) summary else notes.joinToString("; ") + " — " + summary)
        return out
    }
}

/** Data used per app in the last hour (needs "Usage access"). */
object AppTraffic {
    fun hasAccess(ctx: Context): Boolean = try {
        val aom = ctx.getSystemService(AppOpsManager::class.java)
        aom.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName) ==
            AppOpsManager.MODE_ALLOWED
    } catch (e: Exception) {
        false
    }

    private fun label(ctx: Context, uid: Int): String {
        when (uid) {
            NetworkStats.Bucket.UID_REMOVED -> return "Removed apps"
            NetworkStats.Bucket.UID_TETHERING -> return "Hotspot / tethering"
            Process.SYSTEM_UID -> return "Android system"
            0 -> return "Android core"
        }
        val pm = ctx.packageManager
        val pkg = pm.getPackagesForUid(uid)?.firstOrNull() ?: return "uid $uid"
        return try {
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
        } catch (e: Exception) {
            pkg
        }
    }

    fun scan(ctx: Context, alerts: AlertBook, quiet: Boolean, setCheck: SetCheck): JSONObject {
        if (!hasAccess(ctx)) {
            setCheck("apps", "off", "Grant \"Usage access\" to see which apps use the internet.")
            return JSONObject().put("access", false)
        }
        val nsm = ctx.getSystemService(NetworkStatsManager::class.java)
        val end = System.currentTimeMillis()
        val start = end - 3_600_000
        val totals = HashMap<Int, LongArray>()
        @Suppress("DEPRECATION")
        val types = listOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)
        for (type in types) {
            try {
                val stats = nsm.querySummary(type, null, start, end)
                val b = NetworkStats.Bucket()
                while (stats.hasNextBucket()) {
                    stats.getNextBucket(b)
                    val t = totals.getOrPut(b.uid) { LongArray(2) }
                    t[0] += b.rxBytes
                    t[1] += b.txBytes
                }
                stats.close()
            } catch (e: Exception) {
                // this network type unavailable
            }
        }
        val rows = JSONArray()
        var nightUploads = 0
        totals.entries.sortedByDescending { it.value[0] + it.value[1] }.take(25).forEach { (uid, t) ->
            val name = label(ctx, uid)
            rows.put(JSONObject().put("app", name).put("rx", t[0]).put("tx", t[1]))
            if (quiet && t[1] > 25_000_000) {
                nightUploads++
                alerts.raise(
                    "nightup:$uid", "warn", "App traffic", "$name uploaded ${t[1] / 1_000_000} MB during quiet hours",
                    "Large uploads at night can be backups, or data being taken without your knowledge."
                )
            }
        }
        setCheck(
            "apps", if (nightUploads > 0) "warn" else "ok",
            if (nightUploads > 0) "$nightUploads app(s) uploading heavily during quiet hours."
            else "${totals.size} apps used the internet in the last hour."
        )
        return JSONObject().put("access", true).put("rows", rows)
    }
}

package org.unphishable.sdk.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import org.unphishable.sdk.model.ScanResult
import org.unphishable.sdk.network.ScanApiClient
import org.unphishable.sdk.ui.WarningNotificationManager
import org.unphishable.sdk.utils.PacketParser
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.ConcurrentHashMap

class UnphishableVpnService : VpnService() {

    private val TAG = "Unphishable:VPN"
    private val FOREGROUND_ID = 9001
    private val CHANNEL_ID = "unphishable_vpn"

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val localCache = ConcurrentHashMap<String, CachedResult>()
    private data class CachedResult(val result: ScanResult, val expiresAt: Long)
    private val CACHE_TTL_MS = 60 * 60 * 1000L

    private val inFlightScans = ConcurrentHashMap<String, Boolean>()

    companion object {
        const val ACTION_STOP        = "org.unphishable.sdk.STOP_VPN"
        const val ACTION_SCAN_URL    = "org.unphishable.sdk.SCAN_URL"
        const val EXTRA_URL_TO_SCAN  = "url_to_scan"

        val BROWSER_PACKAGES = listOf(
            "com.android.chrome",
            "org.mozilla.firefox",
            "com.microsoft.emmx",
            "com.opera.browser",
            "com.brave.browser",
            "com.UCMobile.intl",
            "com.sec.android.app.sbrowser",
            "com.mi.globalbrowser",
            "com.kiwibrowser.browser",
            "com.vivaldi.browser",
            "com.opera.mini.native"
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_SCAN_URL) {
            val url = intent.getStringExtra(EXTRA_URL_TO_SCAN) ?: return START_NOT_STICKY
            val config = Unphishable.config ?: return START_NOT_STICKY
            val apiClient = ScanApiClient(config.apiKey, config.backendUrl, config.debug)
            serviceScope.launch { scanUrl(url, apiClient) }
            return START_NOT_STICKY
        }

        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        val config = Unphishable.config ?: run {
            Log.e(TAG, "SDK not initialized — stopping VPN")
            stopSelf()
            return START_NOT_STICKY
        }

        WarningNotificationManager.createChannels(this)
        startForeground(FOREGROUND_ID, buildForegroundNotification(config.brandName))
        startVpn()

        return START_STICKY
    }

    private fun startVpn() {
        if (isRunning) return

        val config = Unphishable.config ?: return
        val apiClient = ScanApiClient(config.apiKey, config.backendUrl, config.debug)

        try {
            val builder = Builder()
                .setSession("${config.brandName} Secure Mode")
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .setMtu(32767)
                .setBlocking(false)

            BROWSER_PACKAGES.forEach { pkg ->
                try { builder.addDisallowedApplication(pkg) } catch (e: Exception) { }
            }

            listOf(packageName, "com.google.android.gms", "com.android.vending").forEach { pkg ->
                try { builder.addDisallowedApplication(pkg) } catch (e: Exception) { }
            }

            config.trustedPackages.forEach { pkg ->
                try {
                    builder.addDisallowedApplication(pkg)
                    if (config.debug) Log.d(TAG, "Trusted (skipped): $pkg")
                } catch (e: Exception) {
                    Log.w(TAG, "Could not exclude package $pkg: ${e.message}")
                }
            }

            vpnInterface = builder.establish() ?: run {
                Log.e(TAG, "Failed to establish VPN interface")
                return
            }

            isRunning = true
            if (config.debug) Log.d(TAG, "VPN tunnel established ✅")

            serviceScope.launch { readPackets(apiClient) }

        } catch (e: Exception) {
            Log.e(TAG, "VPN start failed: ${e.message}")
            stopSelf()
        }
    }

    private suspend fun readPackets(apiClient: ScanApiClient) {
        val vpn    = vpnInterface ?: return
        val input  = FileInputStream(vpn.fileDescriptor)
        val output = FileOutputStream(vpn.fileDescriptor)
        val buffer = ByteArray(32767)

        if (Unphishable.config?.debug == true) Log.d(TAG, "Packet reader started")

        while (isRunning) {
            try {
                val length = input.read(buffer)
                if (length <= 0) { delay(10); continue }

                output.write(buffer, 0, length)
                output.flush()

                val packetCopy = buffer.copyOf(length)
                serviceScope.launch {
                    try {
                        val url = PacketParser.extractUrl(packetCopy, length) ?: return@launch
                        scanUrl(url, apiClient)
                    } catch (e: Exception) { }
                }

            } catch (e: Exception) {
                if (isRunning) { Log.e(TAG, "Packet read error: ${e.message}"); delay(50) }
            }
        }
    }

    private suspend fun scanUrl(url: String, apiClient: ScanApiClient) {
        if (url.contains("10.0.0.") || url.contains("127.0.0.1") ||
            url.contains("localhost") || url.length < 10) return

        val cached = localCache[url]
        if (cached != null && System.currentTimeMillis() < cached.expiresAt) {
            val result = cached.result
            if (!result.safe) {
                withContext(Dispatchers.Main) {
                    WarningNotificationManager.showWarning(
                        this@UnphishableVpnService, result, Unphishable.config!!
                    )
                }
            }
            return
        }

        if (inFlightScans.putIfAbsent(url, true) != null) return

        try {
            val result = apiClient.scan(url)

            localCache[url] = CachedResult(
                result = result,
                expiresAt = System.currentTimeMillis() + CACHE_TTL_MS
            )

            if (localCache.size > 1000) {
                localCache.entries
                    .filter { System.currentTimeMillis() > it.value.expiresAt }
                    .forEach { localCache.remove(it.key) }
            }

            if (!result.safe) {
                withContext(Dispatchers.Main) {
                    WarningNotificationManager.showWarning(
                        this@UnphishableVpnService, result, Unphishable.config!!
                    )
                }
            }

            if (Unphishable.config?.debug == true) {
                Log.d(TAG, "[${result.riskLevel}] $url — score: ${result.score}")
            }

        } catch (e: Exception) {
            Log.e(TAG, "Scan failed for $url: ${e.message}")
        } finally {
            inFlightScans.remove(url)
        }
    }

    private fun stopVpn() {
        isRunning = false
        serviceScope.cancel()
        try { vpnInterface?.close(); vpnInterface = null } catch (e: Exception) { }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        if (Unphishable.config?.debug == true) Log.d(TAG, "VPN stopped")
    }

    override fun onRevoke() { stopVpn() }
    override fun onDestroy() { stopVpn(); super.onDestroy() }

    private fun buildForegroundNotification(brandName: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Secure Mode",
                NotificationManager.IMPORTANCE_LOW).apply {
                description = "Secure Mode is active"
            }
        )
        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, UnphishableVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("🛡️ $brandName Secure Mode")
            .setContentText("Protecting you from phishing links")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .addAction(Notification.Action.Builder(null, "Turn Off", stopIntent).build())
            .setOngoing(true)
            .build()
    }
}

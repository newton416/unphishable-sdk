package org.unphishable.sdk.core

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import org.unphishable.sdk.model.ScanHistoryEntry
import org.unphishable.sdk.model.SmsScanResult
import org.unphishable.sdk.model.UnphishableConfig
import org.unphishable.sdk.network.ScanApiClient
import java.util.Collections

object Unphishable {

    private const val TAG = "Unphishable"
    private const val PREFS_NAME = "unphishable_prefs"
    private const val KEY_SECURE_MODE = "secure_mode_active"
    private const val KEY_TOTAL_SCANS = "total_scans"
    private const val KEY_THREATS_BLOCKED = "threats_blocked"

    internal var config: UnphishableConfig? = null

    // In-memory scan history (max 100 entries)
    private val _scanHistory = Collections.synchronizedList(mutableListOf<ScanHistoryEntry>())
    val scanHistory: List<ScanHistoryEntry> get() = _scanHistory.toList()

    /**
     * Initialize the SDK. Call in Application.onCreate() or MainActivity.onCreate().
     */
    @JvmStatic
    fun init(
        app: Application,
        apiKey: String,
        brandName: String,
        trustedPackages: List<String> = emptyList(),
        debug: Boolean = true
    ) {
        require(apiKey.isNotBlank()) { "Unphishable: apiKey must not be empty" }
        require(brandName.isNotBlank()) { "Unphishable: brandName must not be empty" }

        config = UnphishableConfig(
            apiKey = apiKey,
            brandName = brandName,
            trustedPackages = trustedPackages,
            debug = debug
        )

        // Auto-restart if secure mode was active before
        if (isSecureModeActive(app)) {
            if (debug) Log.d(TAG, "Restoring Secure Mode after restart")
            startVpnService(app)
        }

        if (debug) Log.d(TAG, "Unphishable SDK initialized — brand: $brandName, debug: $debug")
    }

    /**
     * Start Secure Mode (VPN-based phishing protection).
     * Android will prompt for VPN permission on first launch.
     *
     * @param activity The current activity
     * @param onPermissionNeeded Called with the Intent if the VPN dialog needs to be shown
     */
    @JvmStatic
    fun startSecureMode(
        activity: Activity,
        onPermissionNeeded: (Intent) -> Unit
    ) {
        val cfg = config ?: run {
            Log.e(TAG, "Call Unphishable.init() before startSecureMode()")
            return
        }

        val permIntent = VpnService.prepare(activity)
        if (permIntent != null) {
            if (cfg.debug) Log.d(TAG, "VPN permission required — showing dialog")
            onPermissionNeeded(permIntent)
            return
        }

        startVpnService(activity)
        saveSecureModeState(activity, true)
        if (cfg.debug) Log.d(TAG, "Secure Mode started ✅")
    }

    /**
     * Stop Secure Mode.
     */
    @JvmStatic
    fun stopSecureMode(context: Context) {
        context.startService(
            Intent(context, UnphishableVpnService::class.java).apply {
                action = UnphishableVpnService.ACTION_STOP
            }
        )
        saveSecureModeState(context, false)
        if (config?.debug == true) Log.d(TAG, "Secure Mode stopped")
    }

    /**
     * Scan an SMS or notification message for scam patterns.
     * Call this from your NotificationListenerService when a message arrives.
     *
     * @param sender The sender (phone number, short code or app name)
     * @param message The message text or notification preview
     * @param source Source of the message: "sms", "whatsapp", "facebook", "telegram"
     * @param userId Optional user identifier for analytics
     * @param onResult Callback with the scan result
     */
    @JvmStatic
    fun scanMessage(
        sender: String,
        message: String,
        source: String = "sms",
        userId: String = "anonymous",
        onResult: (SmsScanResult) -> Unit
    ) {
        val cfg = config ?: run {
            Log.e(TAG, "Call Unphishable.init() before scanMessage()")
            onResult(SmsScanResult.safe())
            return
        }

        Thread {
            try {
                val apiClient = ScanApiClient(
                    apiKey = cfg.apiKey,
                    backendUrl = "https://api.unphishable.org",
                    debug = cfg.debug
                )
                val result = apiClient.scanMessage(sender, message, source, userId)
                if (cfg.debug) Log.d(TAG, "Message scan: ${result.verdict} (${result.confidence}%) from $source")
                onResult(result)
            } catch (e: Exception) {
                if (cfg.debug) Log.e(TAG, "scanMessage error: ${e.message}")
                onResult(SmsScanResult.safe())
            }
        }.start()
    }

    @JvmStatic
    fun isSecureModeActive(context: Context): Boolean {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_SECURE_MODE, false)
    }

    @JvmStatic
    fun isInitialized(): Boolean = config != null

    fun getTotalScans(context: Context): Int {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getInt(KEY_TOTAL_SCANS, 0)
    }

    fun getThreatsBlocked(context: Context): Int {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getInt(KEY_THREATS_BLOCKED, 0)
    }

    // Clear in-memory history (called on VPN service start)
    internal fun clearHistory() {
        _scanHistory.clear()
    }

    internal fun recordScan(context: Context, entry: ScanHistoryEntry) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putInt(KEY_TOTAL_SCANS, prefs.getInt(KEY_TOTAL_SCANS, 0) + 1)
            .apply()

        if (entry.riskLevel != "SAFE") {
            prefs.edit()
                .putInt(KEY_THREATS_BLOCKED, prefs.getInt(KEY_THREATS_BLOCKED, 0) + 1)
                .apply()
        }

        _scanHistory.add(0, entry)
        if (_scanHistory.size > 100) _scanHistory.removeAt(_scanHistory.size - 1)
    }

    internal fun startVpnService(context: Context) {
        context.startForegroundService(
            Intent(context, UnphishableVpnService::class.java)
        )
    }

    private fun saveSecureModeState(context: Context, active: Boolean) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_SECURE_MODE, active).apply()
    }
}

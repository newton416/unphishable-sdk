package org.unphishable.sdk.core

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

/**
 * UnphishableAccessibilityService
 *
 * Reads the URL displayed in the address bar of Chrome and other browsers
 * without intercepting network traffic — internet is never blocked.
 *
 * When the URL changes, it is sent to the VPN service for analysis.
 */
class UnphishableAccessibilityService : AccessibilityService() {

    private val TAG = "Unphishable:A11y"
    private var lastScannedUrl = ""

    override fun onServiceConnected() {
        serviceInfo = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED or
                         AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            flags = AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                    AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
            notificationTimeout = 500
            // Monitor all known browsers
            packageNames = UnphishableVpnService.BROWSER_PACKAGES.toTypedArray()
        }
        Log.d(TAG, "Accessibility Service connected ✅")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return

        try {
            val url = extractUrlFromEvent(event) ?: return

            // Skip if same URL already scanned
            if (url == lastScannedUrl) return
            lastScannedUrl = url

            Log.d(TAG, "Browser URL detected: $url")

            // Send URL to VPN service for analysis
            val vpnServiceIntent = Intent(this, UnphishableVpnService::class.java).apply {
                action = UnphishableVpnService.ACTION_SCAN_URL
                putExtra(UnphishableVpnService.EXTRA_URL_TO_SCAN, url)
            }
            startService(vpnServiceIntent)

        } catch (e: Exception) {
            Log.e(TAG, "Accessibility event error: ${e.message}")
        }
    }

    private fun extractUrlFromEvent(event: AccessibilityEvent): String? {
        val rootNode = rootInActiveWindow ?: return null
        return try {
            findUrlInNode(rootNode)
        } finally {
            rootNode.recycle()
        }
    }

    private fun findUrlInNode(node: AccessibilityNodeInfo): String? {
        // Search for browser address bar by resource ID
        val urlBarIds = listOf(
            "com.android.chrome:id/url_bar",
            "org.mozilla.firefox:id/mozac_browser_toolbar_url_view",
            "com.microsoft.emmx:id/url_bar",
            "com.brave.browser:id/url_bar",
            "com.opera.browser:id/url_field",
            "com.sec.android.app.sbrowser:id/location_bar_edit_text"
        )

        for (id in urlBarIds) {
            val nodes = node.findAccessibilityNodeInfosByViewId(id)
            if (nodes != null && nodes.isNotEmpty()) {
                val text = nodes[0].text?.toString()
                nodes.forEach { it.recycle() }
                if (!text.isNullOrBlank() && (text.startsWith("http") || text.contains("."))) {
                    val url = if (text.startsWith("http")) text else "https://$text"
                    return url
                }
            }
        }
        return null
    }

    override fun onInterrupt() {
        Log.d(TAG, "Accessibility Service interrupted")
    }
}

package org.unphishable.sdk.core

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import org.unphishable.sdk.main.Unphishable
import org.unphishable.sdk.ui.WarningNotificationManager

class UnphishableNotificationListener : NotificationListenerService() {

    private val TAG = "Unphishable:Notif"

    // Apps we monitor for scam content
    private val MONITORED_PACKAGES = setOf(
        "com.whatsapp",
        "com.whatsapp.w4b",
        "com.google.android.apps.messaging", // Google Messages (SMS)
        "com.samsung.android.messaging",      // Samsung Messages (SMS)
        "com.android.mms",                    // Default SMS
        "org.telegram.messenger",
        "com.facebook.orca",                  // Facebook Messenger
        "com.facebook.mlite"
    )

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        sbn ?: return

        val packageName = sbn.packageName ?: return

        // Only process monitored apps
        if (packageName !in MONITORED_PACKAGES) return

        val config = Unphishable.config ?: return

        try {
            val extras = sbn.notification?.extras ?: return

            // Extract sender and message from notification
            val sender = extras.getString("android.title") ?: ""
            val message = extras.getCharSequence("android.text")?.toString() ?: ""
            val bigText = extras.getCharSequence("android.bigText")?.toString() ?: ""

            // Use bigText if available for more content
            val content = if (bigText.isNotBlank()) bigText else message

            // Skip empty or very short messages
            if (content.length < 10) return

            // Determine source from package name
            val source = when (packageName) {
                "com.whatsapp", "com.whatsapp.w4b" -> "whatsapp"
                "org.telegram.messenger"            -> "telegram"
                "com.facebook.orca",
                "com.facebook.mlite"                -> "facebook"
                else                                -> "sms"
            }

            if (config.debug) Log.d(TAG, "Scanning $source message from: $sender")

            // Scan the message
            Unphishable.scanMessage(
                sender = sender,
                message = content,
                source = source
            ) { result ->
                if (result.shouldAlert) {
                    if (config.debug) Log.d(TAG, "Threat detected in $source: ${result.verdict}")

                    // Show full screen alert
                    WarningNotificationManager.showSmsWarning(
                        context = this,
                        result = result,
                        config = config,
                        sender = sender,
                        source = source
                    )
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error processing notification: ${e.message}")
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        // Not needed
    }

    override fun onListenerConnected() {
        Log.d(TAG, "Notification Listener connected ✅")
    }

    override fun onListenerDisconnected() {
        Log.d(TAG, "Notification Listener disconnected")
    }
}

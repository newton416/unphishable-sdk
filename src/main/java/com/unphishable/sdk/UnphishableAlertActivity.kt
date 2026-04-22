package org.unphishable.sdk.ui

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import org.unphishable.sdk.main.Unphishable

class UnphishableAlertActivity : Activity() {

    private val TAG = "Unphishable:Alert"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Show over lock screen
        window.addFlags(
            WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
            WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
        )

        val url      = intent.getStringExtra(WarningNotificationManager.EXTRA_URL) ?: ""
        val risk     = intent.getStringExtra(WarningNotificationManager.EXTRA_RISK) ?: "HIGH"
        val score    = intent.getIntExtra(WarningNotificationManager.EXTRA_SCORE, 0)
        val notifId  = intent.getIntExtra(WarningNotificationManager.EXTRA_NOTIF_ID, 0)
        val patterns = intent.getStringExtra(WarningNotificationManager.EXTRA_PATTERNS) ?: ""
        val brand    = Unphishable.config?.brandName ?: "Unphishable"

        val isHigh = risk == "HIGH" || risk == "SCAM"
        val accentColor = if (isHigh) Color.parseColor("#C0392B") else Color.parseColor("#E67E22")
        val badgeText = if (isHigh) "DANGEROUS" else "SUSPICIOUS"
        val titleText = if (isHigh) "Phishing Link Detected" else "Suspicious Link Detected"
        val descText = if (isHigh)
            "This link is dangerous. Do not enter your personal or banking information."
        else
            "This link shows suspicious patterns. Proceed only if you fully trust the sender."

        // Root layout — dimmed overlay
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#99000000"))
            gravity = android.view.Gravity.BOTTOM
            setPadding(32, 0, 32, 64)
        }

        // White card
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.WHITE)
            elevation = 24f
        }
        card.background = android.graphics.drawable.GradientDrawable().apply {
            setColor(Color.WHITE)
            cornerRadius = 48f
        }

        // Top stripe
        val stripe = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 8
            )
            setBackgroundColor(accentColor)
        }

        // Card body
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 32)
        }

        // Brand name
        val brandLabel = TextView(this).apply {
            text = "$brand SECURITY"
            textSize = 11f
            setTextColor(Color.parseColor("#8E8E93"))
            letterSpacing = 0.1f
            setPadding(0, 0, 0, 32)
        }

        // Risk badge
        val badge = TextView(this).apply {
            text = "  $badgeText  "
            textSize = 11f
            setTextColor(accentColor)
            setBackgroundColor(
                if (isHigh) Color.parseColor("#FDF0EF") else Color.parseColor("#FEF6EE")
            )
            setPadding(16, 8, 16, 8)
            setPadding(0, 0, 0, 24)
        }

        // Title
        val title = TextView(this).apply {
            text = titleText
            textSize = 18f
            setTextColor(Color.parseColor("#1C1C1E"))
            setTypeface(null, android.graphics.Typeface.BOLD)
            setPadding(0, 0, 0, 16)
        }

        // URL
        val urlBox = TextView(this).apply {
            text = url.take(50) + if (url.length > 50) "..." else ""
            textSize = 12f
            setTextColor(Color.parseColor("#3A3A3C"))
            setBackgroundColor(Color.parseColor("#F2F2F7"))
            setPadding(24, 20, 24, 20)
            typeface = android.graphics.Typeface.MONOSPACE
            setPadding(0, 0, 0, 16)
        }

        // Description
        val desc = TextView(this).apply {
            text = descText
            textSize = 13f
            setTextColor(Color.parseColor("#3A3A3C"))
            lineHeight = (textSize * 1.55f).toInt()
            setPadding(0, 0, 0, 24)
        }

        // Signals
        if (patterns.isNotBlank()) {
            val signalsLabel = TextView(this).apply {
                text = patterns
                textSize = 11f
                setTextColor(Color.parseColor("#3A3A3C"))
                setBackgroundColor(Color.parseColor("#F2F2F7"))
                setPadding(16, 8, 16, 8)
            }
            body.addView(signalsLabel)
        }

        body.addView(brandLabel)
        body.addView(badge)
        body.addView(title)
        body.addView(urlBox)
        body.addView(desc)

        // Divider
        val divider = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 1
            )
            setBackgroundColor(Color.parseColor("#F2F2F7"))
        }

        // Block & Report button
        val btnBlock = TextView(this).apply {
            text = "Block & Report"
            textSize = 15f
            setTextColor(accentColor)
            setTypeface(null, android.graphics.Typeface.BOLD)
            gravity = android.view.Gravity.CENTER
            setPadding(0, 48, 0, 48)
            setOnClickListener {
                Log.d(TAG, "User blocked and reported: $url")
                WarningNotificationManager.dismiss(this@UnphishableAlertActivity, notifId)
                finish()
            }
        }

        // Continue button
        val btnContinue = TextView(this).apply {
            text = "Continue anyway"
            textSize = 13f
            setTextColor(Color.parseColor("#8E8E93"))
            gravity = android.view.Gravity.CENTER
            setPadding(0, 24, 0, 40)
            setOnClickListener {
                Log.d(TAG, "User continued to: $url")
                WarningNotificationManager.dismiss(this@UnphishableAlertActivity, notifId)
                try {
                    startActivity(
                        Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Could not open URL: ${e.message}")
                }
                finish()
            }
        }

        // Powered
        val powered = TextView(this).apply {
            text = "Protected by $brand · Unphishable SDK"
            textSize = 10f
            setTextColor(Color.parseColor("#C7C7CC"))
            gravity = android.view.Gravity.CENTER
            setPadding(0, 0, 0, 24)
        }

        card.addView(stripe)
        card.addView(body)
        card.addView(divider)
        card.addView(btnBlock)
        card.addView(btnContinue)
        card.addView(powered)

        root.addView(card)
        setContentView(root)

        if (Unphishable.config?.debug == true) {
            Log.d(TAG, "Alert shown — $risk: $url (score: $score)")
        }
    }

    override fun onBackPressed() {
        // Prevent dismiss on back press — user must choose
    }
}

package org.unphishable.sdk.model

data class ScanResult(
    val url: String,
    val verdict: String,
    val riskLevel: String,
    val score: Int,
    val patternsTriggered: List<String>,
    val warningMessage: String,
    val recommendation: String,
    val domain: String,
    val sslStatus: String,
    val sslIssuer: String,
    val ageMonths: Int?,
    val httpCode: Int?,
    val cached: Boolean,
    val scanId: String
) {
    val safe: Boolean get() = riskLevel == "SAFE"
    val isHigh: Boolean get() = riskLevel == "HIGH"
    val isMedium: Boolean get() = riskLevel == "MEDIUM"

    companion object {
        fun safe(url: String) = ScanResult(
            url = url,
            verdict = "SAFE",
            riskLevel = "SAFE",
            score = 0,
            patternsTriggered = emptyList(),
            warningMessage = "",
            recommendation = "",
            domain = "",
            sslStatus = "unknown",
            sslIssuer = "",
            ageMonths = null,
            httpCode = null,
            cached = false,
            scanId = ""
        )
    }
}

data class SmsScanResult(
    val verdict: String,
    val confidence: Int,
    val shouldAlert: Boolean,
    val signals: List<String>,
    val senderType: String,
    val source: String,
    val explanationEn: String,
    val explanationFr: String
) {
    val safe: Boolean get() = verdict == "SAFE"
    val isHigh: Boolean get() = verdict == "SCAM"
    val isSuspicious: Boolean get() = verdict == "SUSPICIOUS"

    companion object {
        fun safe() = SmsScanResult(
            verdict = "SAFE",
            confidence = 0,
            shouldAlert = false,
            signals = emptyList(),
            senderType = "unknown",
            source = "sms",
            explanationEn = "",
            explanationFr = ""
        )
    }
}

data class UnphishableConfig(
    val apiKey: String,
    val brandName: String,
    val trustedPackages: List<String> = emptyList(),
    val debug: Boolean = false,
    val backendUrl: String = "https://api.unphishable.org"
)

data class ScanHistoryEntry(
    val url: String,
    val riskLevel: String,
    val score: Int,
    val timestamp: Long,
    val domain: String
)

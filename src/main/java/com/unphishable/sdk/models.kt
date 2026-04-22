package org.unphishable.sdk.model

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

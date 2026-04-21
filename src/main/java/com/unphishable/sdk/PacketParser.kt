package org.unphishable.sdk.utils

import java.nio.ByteBuffer

/**
 * PacketParser — Extracts URLs from raw IP/TCP packets.
 *
 * ONLY inspects:
 * - HTTP (port 80)  → reads Host header + path → full URL
 * - HTTPS (port 443) → reads SNI from TLS ClientHello → domain only
 *
 * ALL other traffic (video, images, APIs, games etc.) is ignored instantly.
 * No payload content is ever read — only headers.
 */
internal object PacketParser {

    /**
     * Extract URL from raw packet bytes.
     * Returns null immediately for non-HTTP/HTTPS traffic.
     */
    fun extractUrl(buffer: ByteArray, length: Int): String? {
        // Minimum IP + TCP header = 40 bytes
        if (length < 40) return null

        // Only handle IPv4
        val ipVersion = (buffer[0].toInt() and 0xFF) shr 4
        if (ipVersion != 4) return null

        // Only handle TCP (protocol 6)
        val protocol = buffer[9].toInt() and 0xFF
        if (protocol != 6) return null

        val ipHeaderLen = (buffer[0].toInt() and 0x0F) * 4
        if (length < ipHeaderLen + 20) return null

        // Get destination port
        val destPort = ((buffer[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                (buffer[ipHeaderLen + 3].toInt() and 0xFF)

        // ONLY process HTTP (80) and HTTPS (443) — everything else ignored instantly
        if (destPort != 80 && destPort != 443) return null

        val tcpHeaderLen = ((buffer[ipHeaderLen + 12].toInt() and 0xFF) shr 4) * 4
        val payloadOffset = ipHeaderLen + tcpHeaderLen
        if (payloadOffset >= length) return null

        val payload = buffer.copyOfRange(payloadOffset, length)

        return when (destPort) {
            80   -> extractHttpUrl(payload)
            443  -> extractHttpsHost(payload)
            else -> null
        }
    }

    // Overload for ByteBuffer compatibility
    fun extractUrl(buffer: ByteBuffer, length: Int): String? {
        val bytes = ByteArray(length)
        val pos = buffer.position()
        buffer.get(bytes, 0, length)
        buffer.position(pos)
        return extractUrl(bytes, length)
    }

    /**
     * Extract full URL from HTTP packet.
     * Reads only the first line (request line) and Host header.
     * Never reads body content.
     */
    private fun extractHttpUrl(payload: ByteArray): String? {
        return try {
            val text = String(payload, Charsets.ISO_8859_1)

            // Only process HTTP requests
            if (!text.startsWith("GET ") && !text.startsWith("POST ") &&
                !text.startsWith("HEAD ") && !text.startsWith("PUT ") &&
                !text.startsWith("DELETE ") && !text.startsWith("PATCH ")) return null

            val lines = text.split("\r\n")
            val path = lines.firstOrNull()?.split(" ")?.getOrNull(1) ?: "/"
            val host = lines.firstOrNull { it.startsWith("Host:", ignoreCase = true) }
                ?.substringAfter(":")?.trim() ?: return null

            "http://$host$path"
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Extract domain from HTTPS packet via SNI field in TLS ClientHello.
     * SNI = Server Name Indication — the domain the client is connecting to.
     * This is sent in plaintext before encryption — no decryption needed.
     * Never reads encrypted payload.
     */
    private fun extractHttpsHost(payload: ByteArray): String? {
        return try {
            // TLS record: type=22 (handshake)
            if (payload.size < 5) return null
            if (payload[0].toInt() and 0xFF != 22) return null

            // Handshake type: 1 = ClientHello
            if (payload.size < 6) return null
            if (payload[5].toInt() and 0xFF != 1) return null

            extractSni(payload)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Parse SNI extension from TLS ClientHello.
     * SNI is always sent in plaintext — this is by design in TLS.
     */
    private fun extractSni(data: ByteArray): String? {
        return try {
            var i = 43
            if (i >= data.size) return null

            // Skip session ID
            val sessionIdLen = data[i].toInt() and 0xFF
            i += 1 + sessionIdLen
            if (i + 2 >= data.size) return null

            // Skip cipher suites
            val cipherLen = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2 + cipherLen
            if (i + 1 >= data.size) return null

            // Skip compression methods
            val compressionLen = data[i].toInt() and 0xFF
            i += 1 + compressionLen
            if (i + 2 >= data.size) return null

            // Parse extensions
            val extLen = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
            val extEnd = i + extLen

            while (i + 4 <= extEnd && i + 4 <= data.size) {
                val extType = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
                val extDataLen = ((data[i + 2].toInt() and 0xFF) shl 8) or (data[i + 3].toInt() and 0xFF)
                i += 4

                if (extType == 0 && i + 5 <= data.size) {
                    // SNI extension found
                    val nameLen = ((data[i + 3].toInt() and 0xFF) shl 8) or (data[i + 4].toInt() and 0xFF)
                    if (i + 5 + nameLen <= data.size) {
                        val sni = String(data, i + 5, nameLen, Charsets.US_ASCII)
                        return "https://$sni"
                    }
                }
                i += extDataLen
            }
            null
        } catch (e: Exception) {
            null
        }
    }
}

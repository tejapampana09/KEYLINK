package com.keylink.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket

class ConnectionManager {

    /**
     * Helper extensions to convert Hex <-> ByteArray
     */
    fun String.hexToByteArray(): ByteArray {
        val len = this.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(this[i], 16) shl 4) +
                    Character.digit(this[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }

    fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }

    /**
     * Interface to pass progress updates back to the UI log.
     */
    interface LogCallback {
        fun onLog(message: String)
    }

    /**
     * Performs pairing handshake over TCP.
     * 1. Connects to PC
     * 2. Sends public key
     * 3. Receives 32-byte challenge
     * 4. Invokes signCallback to request biometric prompt
     * 5. Sends back signed challenge
     * 6. Receives pairing result
     */
    suspend fun pairDevice(
        ip: String,
        port: Int,
        deviceName: String,
        publicKeyDerHex: String,
        log: LogCallback,
        signCallback: suspend (challenge: ByteArray) -> ByteArray?
    ): Boolean = withContext(Dispatchers.IO) {
        var socket: Socket? = null
        try {
            log.onLog("[TCP] Connecting to PC at $ip:$port...")
            socket = Socket()
            socket.connect(InetSocketAddress(ip, port), 5000) // 5 seconds connection timeout
            log.onLog("[TCP] Connected! Sending pairing request...")

            val writer = OutputStreamWriter(socket.getOutputStream(), "UTF-8")
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), "UTF-8"))

            // Send pairing request
            val pairingReq = JSONObject().apply {
                put("action", "pair")
                put("device_name", deviceName)
                put("public_key", publicKeyDerHex)
            }
            writer.write(pairingReq.toString() + "\n")
            writer.flush()

            // Receive challenge
            log.onLog("[TCP] Waiting for trial challenge from PC...")
            val challengeLine = reader.readLine() ?: throw Exception("PC disconnected during handshake.")
            val challengeJson = JSONObject(challengeLine)
            
            if (challengeJson.getString("action") != "challenge") {
                throw Exception("Unexpected action from PC: ${challengeJson.getString("action")}")
            }
            
            val challengeHex = challengeJson.getString("challenge")
            val challengeBytes = challengeHex.hexToByteArray()
            log.onLog("[TCP] Received challenge: $challengeHex")

            // Prompt user for biometrics & sign
            log.onLog("[Auth] Prompting user for biometric signature...")
            val signatureBytes = signCallback(challengeBytes)
            if (signatureBytes == null) {
                log.onLog("[Auth] Biometric signing cancelled or failed.")
                return@withContext false
            }

            // Send response back
            log.onLog("[TCP] Sending signature response to PC...")
            val responseJson = JSONObject().apply {
                put("action", "response")
                put("signature", signatureBytes.toHexString())
            }
            writer.write(responseJson.toString() + "\n")
            writer.flush()

            // Receive result
            val resultLine = reader.readLine() ?: throw Exception("PC disconnected before sending pairing result.")
            val resultJson = JSONObject(resultLine)
            val status = resultJson.getString("status")
            val message = resultJson.getString("message")

            if (status == "success") {
                log.onLog("[Success] Pairing confirmed: $message")
                return@withContext true
            } else {
                log.onLog("[Error] Pairing failed by PC: $message")
                return@withContext false
            }

        } catch (e: Exception) {
            log.onLog("[Error] Socket error during pairing: ${e.message}")
            return@withContext false
        } finally {
            try { socket?.close() } catch (ignored: Exception) {}
        }
    }

    /**
     * Performs authentication handshake over TCP.
     * 1. Connects to PC
     * 2. Sends auth request
     * 3. Receives 32-byte challenge
     * 4. Invokes signCallback to prompt biometric and sign
     * 5. Sends back signed challenge
     * 6. Receives unlock verification status
     */
    suspend fun authenticateDevice(
        ip: String,
        port: Int,
        log: LogCallback,
        signCallback: suspend (challenge: ByteArray) -> ByteArray?
    ): Boolean = withContext(Dispatchers.IO) {
        var socket: Socket? = null
        try {
            log.onLog("[TCP] Connecting to PC at $ip:$port...")
            socket = Socket()
            socket.connect(InetSocketAddress(ip, port), 5000)
            log.onLog("[TCP] Connected! Sending auth request...")

            val writer = OutputStreamWriter(socket.getOutputStream(), "UTF-8")
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), "UTF-8"))

            // Send auth request
            val authReq = JSONObject().apply {
                put("action", "auth")
            }
            writer.write(authReq.toString() + "\n")
            writer.flush()

            // Receive challenge
            log.onLog("[TCP] Waiting for challenge from PC...")
            val challengeLine = reader.readLine() ?: throw Exception("PC disconnected during handshake.")
            val challengeJson = JSONObject(challengeLine)
            
            if (challengeJson.getString("action") != "challenge") {
                throw Exception("Unexpected action from PC: ${challengeJson.getString("action")}")
            }
            
            val challengeHex = challengeJson.getString("challenge")
            val challengeBytes = challengeHex.hexToByteArray()
            log.onLog("[TCP] Received challenge: $challengeHex")

            // Prompt user for biometrics & sign
            log.onLog("[Auth] Prompting user for biometric signature...")
            val signatureBytes = signCallback(challengeBytes)
            if (signatureBytes == null) {
                log.onLog("[Auth] Biometric signing cancelled.")
                return@withContext false
            }

            // Send response back
            log.onLog("[TCP] Sending signature to PC...")
            val responseJson = JSONObject().apply {
                put("action", "response")
                put("signature", signatureBytes.toHexString())
            }
            writer.write(responseJson.toString() + "\n")
            writer.flush()

            // Receive result
            val resultLine = reader.readLine() ?: throw Exception("PC disconnected before verification result.")
            val resultJson = JSONObject(resultLine)
            val status = resultJson.getString("status")
            val message = resultJson.getString("message")

            if (status == "success") {
                log.onLog("[Success] Verification complete: $message")
                return@withContext true
            } else {
                log.onLog("[Error] Verification rejected: $message")
                return@withContext false
            }

        } catch (e: Exception) {
            log.onLog("[Error] Socket error during authentication: ${e.message}")
            return@withContext false
        } finally {
            try { socket?.close() } catch (ignored: Exception) {}
        }
    }
}

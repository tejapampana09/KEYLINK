package com.keylink.app

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.util.UUID

class BluetoothRfcommManager(
    private val context: Context,
    private val logCallback: LogCallback,
    private val stateCallback: StateCallback,
    private val biometricCallback: BiometricPromptCallback
) {
    interface LogCallback {
        fun onLog(message: String)
    }

    interface StateCallback {
        fun onStateChanged(state: String)
    }

    interface BiometricPromptCallback {
        suspend fun onSignChallengeWithBiometric(challengeBytes: ByteArray): ByteArray?
    }

    // Standard SPP UUID for Bluetooth RFCOMM sockets
    private val SPP_UUID: UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")
    private val bluetoothAdapter: BluetoothAdapter? = BluetoothAdapter.getDefaultAdapter()

    suspend fun connectAndUnlock(cryptoManager: CryptographyManager): Boolean = withContext(Dispatchers.IO) {
        if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled) {
            withContext(Dispatchers.Main) { logCallback.onLog("[Bluetooth Error] Bluetooth is turned off.") }
            return@withContext false
        }

        val bondedDevices = bluetoothAdapter.bondedDevices
        if (bondedDevices.isNullOrEmpty()) {
            withContext(Dispatchers.Main) { 
                logCallback.onLog("[Bluetooth Error] No paired Bluetooth devices found.")
                logCallback.onLog("[Bluetooth Hint] Please pair your phone with your PC in Windows Bluetooth Settings first.")
            }
            return@withContext false
        }

        // Find PC device (TEJA or matching computer name)
        var pcDevice: BluetoothDevice? = null
        for (device in bondedDevices) {
            val name = device.name ?: ""
            if (name.equals("TEJA", ignoreCase = true) || name.contains("KeyLink", ignoreCase = true) || name.contains("DESKTOP", ignoreCase = true) || name.contains("LAPTOP", ignoreCase = true)) {
                pcDevice = device
                break
            }
        }

        if (pcDevice == null) {
            // Pick first bonded device if name doesn't match
            pcDevice = bondedDevices.firstOrNull()
        }

        if (pcDevice == null) {
            withContext(Dispatchers.Main) { logCallback.onLog("[Bluetooth Error] PC device not found in paired list.") }
            return@withContext false
        }

        withContext(Dispatchers.Main) {
            logCallback.onLog("[Bluetooth] Target PC: ${pcDevice.name} [${pcDevice.address}]")
            stateCallback.onStateChanged("CONNECTING")
        }

        var socket: BluetoothSocket? = null
        val channelsToTry = arrayOf(4, 1, 5)
        var connected = false

        // Strategy 1: Insecure RFCOMM SDP
        try {
            socket = pcDevice.createInsecureRfcommSocketToServiceRecord(SPP_UUID)
            bluetoothAdapter.cancelDiscovery()
            socket.connect()
            connected = true
            withContext(Dispatchers.Main) { logCallback.onLog("[Bluetooth] Connected via Insecure SPP SDP!") }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) { logCallback.onLog("[Bluetooth Info] SDP lookup bypassed. Trying direct RFCOMM channels...") }
            try { socket?.close() } catch (ignored: Exception) {}
            socket = null
        }

        // Strategy 2: Direct RFCOMM Port Reflection (Bypasses Windows SDP requirement)
        if (!connected) {
            for (channel in channelsToTry) {
                try {
                    withContext(Dispatchers.Main) { logCallback.onLog("[Bluetooth] Trying direct RFCOMM channel $channel...") }
                    val method = pcDevice.javaClass.getMethod("createRfcommSocket", Int::class.javaPrimitiveType)
                    socket = method.invoke(pcDevice, channel) as BluetoothSocket
                    bluetoothAdapter.cancelDiscovery()
                    socket.connect()
                    connected = true
                    withContext(Dispatchers.Main) { logCallback.onLog("[Bluetooth] Connected directly on RFCOMM Channel $channel!") }
                    break
                } catch (e: Exception) {
                    try { socket?.close() } catch (ignored: Exception) {}
                    socket = null
                }
            }
        }

        val activeSocket = socket
        if (!connected || activeSocket == null || !activeSocket.isConnected) {
            withContext(Dispatchers.Main) { logCallback.onLog("[Bluetooth Error] Could not establish Bluetooth Socket on any channel.") }
            return@withContext false
        }

        try {
            withContext(Dispatchers.Main) {
                logCallback.onLog("[Bluetooth] CONNECTED to PC over RFCOMM Socket!")
                stateCallback.onStateChanged("CONNECTED")
            }

            val reader = BufferedReader(InputStreamReader(activeSocket.inputStream, Charsets.UTF_8))
            val writer = PrintWriter(activeSocket.outputStream, true)

            // Step 1: Send AUTH_REQUEST
            val req = JSONObject().apply {
                put("action", "auth")
                put("type", "AUTH_REQUEST")
            }
            writer.println(req.toString())

            // Step 2: Read challenge from PC
            val challengeLine = reader.readLine() ?: return@withContext false
            val challengeJson = JSONObject(challengeLine)
            val challengeHex = challengeJson.optString("challenge")
            if (challengeHex.isEmpty()) {
                withContext(Dispatchers.Main) { logCallback.onLog("[Bluetooth Error] Invalid challenge received from PC.") }
                return@withContext false
            }

            // Step 3 & 4: Trigger Biometric Prompt and sign challenge with authorized CryptoObject
            val challengeBytes = bytesFromHex(challengeHex)
            val signedBytes = biometricCallback.onSignChallengeWithBiometric(challengeBytes)

            if (signedBytes == null) {
                withContext(Dispatchers.Main) { logCallback.onLog("[Biometric Alert] Biometric signature rejected or cancelled.") }
                return@withContext false
            }

            val signatureHex = bytesToHex(signedBytes)

            // Step 5: Send AUTH_RESPONSE signature to PC
            val resp = JSONObject().apply {
                put("action", "auth_response")
                put("signature", signatureHex)
                put("response", android.util.Base64.encodeToString(challengeBytes, android.util.Base64.NO_WRAP))
            }
            writer.println(resp.toString())

            // Step 6: Read result from PC
            val resultLine = reader.readLine() ?: return@withContext false
            val resultJson = JSONObject(resultLine)
            val status = resultJson.optString("status")

            val success = status.equals("success", ignoreCase = true) || resultJson.optString("type").equals("AUTH_SUCCESS", ignoreCase = true)
            withContext(Dispatchers.Main) {
                if (success) {
                    stateCallback.onStateChanged("UNLOCKED ✓")
                    logCallback.onLog("[Success] PC unlocked over Bluetooth RFCOMM Socket!")
                } else {
                    stateCallback.onStateChanged("FAILED")
                    logCallback.onLog("[Error] PC authentication failed: ${resultJson.optString("message")}")
                }
            }

            return@withContext success

        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                stateCallback.onStateChanged("DISCONNECTED")
                logCallback.onLog("[Bluetooth Error] Socket connection failed: ${e.message}")
            }
            return@withContext false
        } finally {
            try { activeSocket.close() } catch (ignored: Exception) {}
        }
    }

    private fun bytesFromHex(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder()
        for (b in bytes) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }
}

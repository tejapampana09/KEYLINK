package com.keylink.app

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanRecord
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import android.util.Base64
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import kotlinx.coroutines.*

@SuppressLint("MissingPermission")
class BleConnectionManager(
    private val context: Context,
    private val logCallback: LogCallback,
    private val stateCallback: StateCallback
) {

    companion object {
        private const val TAG = "BleConnectionManager"
        
        // KeyLink BLE UUIDs
        val SERVICE_UUID: UUID = UUID.fromString("d1a53e0f-1f03-4d90-a03f-8c96c5b3e480")
        val RX_CHAR_UUID: UUID = UUID.fromString("d1a53e0f-1f03-4d90-a03f-8c96c5b3e481") // Phone -> PC (Write)
        val TX_CHAR_UUID: UUID = UUID.fromString("d1a53e0f-1f03-4d90-a03f-8c96c5b3e482") // PC -> Phone (Notify)
        
        // Client Characteristic Configuration Descriptor (CCCD) UUID
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }

    interface LogCallback {
        fun onLog(message: String)
    }

    interface StateCallback {
        fun onStateChanged(state: String)
    }

    interface BiometricPromptCallback {
        fun onRequestBiometricAuth(onSuccess: () -> Unit, onFailure: () -> Unit)
    }

    private var biometricCallback: BiometricPromptCallback? = null

    constructor(
        context: Context,
        logCallback: LogCallback,
        stateCallback: StateCallback,
        biometricCallback: BiometricPromptCallback? = null
    ) : this(context, logCallback, stateCallback) {
        this.biometricCallback = biometricCallback
    }

    private val bluetoothAdapter: BluetoothAdapter? by lazy {
        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothManager.adapter
    }

    private var bluetoothGatt: BluetoothGatt? = null
    private var isScanning = false
    private val handler = Handler(Looper.getMainLooper())
    
    // Message framing and write queue variables
    private var rxBuffer = StringBuilder()
    private val MAX_MESSAGE_SIZE = 4096
    private var writeDeferred: CompletableDeferred<Boolean>? = null

    init {
        // Register receiver for Bluetooth state changes to auto-reconnect when local radio turns ON
        val filter = android.content.IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        context.applicationContext.registerReceiver(object : android.content.BroadcastReceiver() {
            override fun onReceive(context: Context, intent: android.content.Intent) {
                val action = intent.action
                if (action == BluetoothAdapter.ACTION_STATE_CHANGED) {
                    val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
                    if (state == BluetoothAdapter.STATE_ON) {
                        logCallback.onLog("[BLE Status] Bluetooth turned ON. Reconnecting...")
                        // Delay slightly to let the BLE hardware warm up
                        handler.postDelayed({
                            startScan()
                        }, 1000)
                    }
                }
            }
        }, filter)
    }

    /**
     * Starts scanning for KeyLink BLE Peripheral devices.
     */
    fun startScan() {
        val adapter = bluetoothAdapter
        if (adapter == null || !adapter.isEnabled) {
            logCallback.onLog("[BLE Error] Bluetooth adapter is disabled or unavailable.")
            return
        }

        val scanner = adapter.bluetoothLeScanner
        if (scanner == null) {
            logCallback.onLog("[BLE Error] BLE scanner not initialized.")
            return
        }

        if (isScanning) {
            logCallback.onLog("[BLE Info] Scan already in progress.")
            return
        }

        // Clean up any existing connection first
        disconnect()

        logCallback.onLog("[BLE Status] SCANNING for KeyLink device...")
        stateCallback.onStateChanged("SCANNING")
        isScanning = true

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        // Scan timeout after 20 seconds to prevent battery drain
        handler.postDelayed({
            if (isScanning) {
                stopScan()
                logCallback.onLog("[BLE Info] Scan timeout reached.")
                if (bluetoothGatt == null) {
                    stateCallback.onStateChanged("DISCONNECTED")
                }
            }
        }, 20000)

        // Scan for WinRT GATT service advertisement
        logCallback.onLog("[BLE Status] SCANNING for KeyLink GATT peripheral...")
        scanner.startScan(null, settings, scanCallback)
    }

    /**
     * Stops BLE Scanning.
     */
    fun stopScan() {
        if (!isScanning) return
        bluetoothAdapter?.bluetoothLeScanner?.stopScan(scanCallback)
        isScanning = false
        logCallback.onLog("[BLE Info] Scanning stopped.")
    }

    /**
     * Disconnects the active BLE GATT session.
     */
    fun disconnect() {
        stopScan()
        bluetoothGatt?.let { gatt ->
            logCallback.onLog("[BLE Status] Disconnecting from PC...")
            gatt.disconnect()
            gatt.close()
            bluetoothGatt = null
        }
        stateCallback.onStateChanged("DISCONNECTED")
    }

    /**
     * Searches the raw BLE advertisement/scan-response bytes for our 128-bit Service UUID.
     * Android's ScanRecord.getServiceUuids() only reliably parses 16-bit UUIDs (AD types 0x02/0x03).
     * Windows WinRT GATT advertises 128-bit UUIDs using AD type 0x06/0x07, which many Android
     * versions silently skip. Searching raw bytes is the only reliable cross-platform approach.
     */
    private fun rawBytesContainServiceUuid(record: ScanRecord?): Boolean {
        val bytes: ByteArray = record?.bytes ?: return false
        // SERVICE_UUID in little-endian byte order (BLE wire format)
        val uuidBytes: ByteArray = uuidToLittleEndianBytes(SERVICE_UUID)
        // Slide a 16-byte window over the raw advertisement payload
        val limit = bytes.size - 16
        if (limit < 0) return false
        for (i in 0..limit) {
            var match = true
            for (j in 0..15) {
                if (bytes[i + j] != uuidBytes[j]) { match = false; break }
            }
            if (match) return true
        }
        return false
    }

    private fun uuidToLittleEndianBytes(uuid: UUID): ByteArray {
        val msb = uuid.mostSignificantBits
        val lsb = uuid.leastSignificantBits
        val out = ByteArray(16)
        // BLE 128-bit UUID is little-endian: LSB bytes first
        for (i in 0..7) out[i] = ((lsb ushr (i * 8)) and 0xFF).toByte()
        for (i in 0..7) out[8 + i] = ((msb ushr (i * 8)) and 0xFF).toByte()
        return out
    }

    private var currentTransport = BluetoothDevice.TRANSPORT_LE

    private fun connectGattToDevice(device: BluetoothDevice, transport: Int = BluetoothDevice.TRANSPORT_LE) {
        currentTransport = transport
        stopScan()
        bluetoothGatt?.disconnect()
        bluetoothGatt?.close()
        bluetoothGatt = null

        val transportName = if (transport == BluetoothDevice.TRANSPORT_AUTO) "AUTO (Bonded)" else "LE"
        logCallback.onLog("[BLE Status] CONNECTING to ${device.name ?: "PC"} [${device.address}] via $transportName transport...")
        stateCallback.onStateChanged("CONNECTING")

        handler.postDelayed({
            bluetoothGatt = device.connectGatt(
                context,
                false, // direct connection
                gattCallback,
                transport
            )
        }, 350)
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            super.onScanResult(callbackType, result)
            val device = result.device
            val scanRecord = result.scanRecord
            val serviceUuids = scanRecord?.serviceUuids
            val rawBytes: ByteArray? = scanRecord?.bytes
            val rawHex: String = rawBytes?.let { b ->
                b.take(16).joinToString("") { "%02x".format(it) }
            } ?: "null"

            // System logcat dump for diagnostic monitoring
            Log.d("BleConnectionManager", "ScanResult: Address=${device.address}, Name=${device.name}, Uuids=${serviceUuids?.joinToString(",") ?: "none"}, RawStart=$rawHex")

            // 1. Check parsed service UUIDs (works for 16-bit UUIDs)
            val hasServiceParsed = serviceUuids?.contains(ParcelUuid(SERVICE_UUID)) == true
            // 2. Search raw advertisement bytes for 128-bit UUID (Windows WinRT uses AD type 0x07)
            val hasServiceRaw = rawBytesContainServiceUuid(scanRecord)

            val hasService = hasServiceParsed || hasServiceRaw

            // Accept the device if it advertises the service UUID or matches the computer name
            val isTarget = hasService || (device.name != null && (device.name == "TEJA" || device.name.contains("KeyLink", ignoreCase = true)))
            
            if (isTarget) {
                logCallback.onLog("[BLE Status] DEVICE_FOUND: ${device.name ?: "Unknown"} [${device.address}]")
                stateCallback.onStateChanged("DEVICE_FOUND")
                connectGattToDevice(device, BluetoothDevice.TRANSPORT_LE)
            }
        }

        override fun onScanFailed(errorCode: Int) {
            super.onScanFailed(errorCode)
            logCallback.onLog("[BLE Error] Scanning failed (Code $errorCode)")
            isScanning = false
            stateCallback.onStateChanged("DISCONNECTED")
        }
    }

    private fun refreshGattCache(gatt: BluetoothGatt): Boolean {
        return try {
            val localMethod = gatt.javaClass.getMethod("refresh")
            (localMethod.invoke(gatt) as? Boolean) ?: false
        } catch (e: Exception) {
            false
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            super.onConnectionStateChange(gatt, status, newState)
            if (status != BluetoothGatt.GATT_SUCCESS) {
                logCallback.onLog("[BLE Error] GATT connection failed (Status: $status, Transport: $currentTransport)")
                refreshGattCache(gatt)
                gatt.disconnect()
                gatt.close()
                if (bluetoothGatt == gatt) {
                    bluetoothGatt = null
                }
                stateCallback.onStateChanged("DISCONNECTED")

                val device = gatt.device
                if (device != null) {
                    // Retry with alternative transport if first transport failed
                    if (currentTransport == BluetoothDevice.TRANSPORT_LE) {
                        logCallback.onLog("[BLE Retry] Retrying GATT connection with TRANSPORT_AUTO...")
                        handler.postDelayed({
                            connectGattToDevice(device, BluetoothDevice.TRANSPORT_AUTO)
                        }, 500)
                        return
                    }

                    if (device.bondState == BluetoothDevice.BOND_NONE) {
                        logCallback.onLog("[BLE Info] Windows requires Bluetooth pairing. Initiating pair request...")
                        try {
                            device.createBond()
                        } catch (e: Exception) {
                            logCallback.onLog("[BLE Error] Failed to start bonding: ${e.message}")
                        }
                    }
                }
                return
            }

            if (newState == BluetoothProfile.STATE_CONNECTED) {
                logCallback.onLog("[BLE Status] CONNECTED! Starting service discovery...")
                stateCallback.onStateChanged("CONNECTED")
                gatt.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                logCallback.onLog("[BLE Status] DISCONNECTED. Auto-reconnecting in background...")
                stateCallback.onStateChanged("DISCONNECTED")
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            super.onServicesDiscovered(gatt, status)
            if (status != BluetoothGatt.GATT_SUCCESS) {
                logCallback.onLog("[BLE Error] Service discovery failed.")
                return
            }

            var service = gatt.getService(SERVICE_UUID)
            if (service == null) {
                for (s in gatt.services) {
                    if (s.uuid.toString().equals(SERVICE_UUID.toString(), ignoreCase = true)) {
                        service = s
                        break
                    }
                }
            }

            if (service == null) {
                val availableUuids = gatt.services.joinToString(", ") { it.uuid.toString() }
                logCallback.onLog("[BLE Error] KeyLink service not found! Available services on PC: [$availableUuids]")
                return
            }
            logCallback.onLog("[BLE Status] Service discovered successfully.")

            var rxChar = service.getCharacteristic(RX_CHAR_UUID)
            if (rxChar == null) {
                for (c in service.characteristics) {
                    if (c.uuid.toString().equals(RX_CHAR_UUID.toString(), ignoreCase = true)) {
                        rxChar = c
                        break
                    }
                }
            }

            var txChar = service.getCharacteristic(TX_CHAR_UUID)
            if (txChar == null) {
                for (c in service.characteristics) {
                    if (c.uuid.toString().equals(TX_CHAR_UUID.toString(), ignoreCase = true)) {
                        txChar = c
                        break
                    }
                }
            }

            if (rxChar == null || txChar == null) {
                logCallback.onLog("[BLE Error] RX or TX Characteristic missing on PC!")
                return
            }
            logCallback.onLog("[BLE Status] RX/TX characteristics discovered.")

            // Enable notifications on the TX characteristic locally
            val success = gatt.setCharacteristicNotification(txChar, true)
            if (!success) {
                logCallback.onLog("[BLE Error] Failed to enable TX notification locally.")
                return
            }

            // Write to the Client Characteristic Configuration Descriptor (CCCD) to enable remote notifications
            val descriptor = txChar.getDescriptor(CCCD_UUID)
            if (descriptor == null) {
                logCallback.onLog("[BLE Error] CCCD descriptor missing on TX characteristic.")
                return
            }

            descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            val descriptorWriteSuccess = gatt.writeDescriptor(descriptor)
            if (descriptorWriteSuccess) {
                logCallback.onLog("[BLE Status] Subscribing to TX notifications...")
            } else {
                logCallback.onLog("[BLE Error] Failed to write CCCD descriptor.")
            }
        }

        override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            super.onDescriptorWrite(gatt, descriptor, status)
            if (status == BluetoothGatt.GATT_SUCCESS && descriptor.uuid == CCCD_UUID) {
                logCallback.onLog("[BLE Status] CONNECTED and notifications established.")
                stateCallback.onStateChanged("CONNECTED")
                
                // Explicitly send AUTH_REQUEST to request the authentication challenge
                try {
                    val requestJson = JSONObject().apply {
                        put("type", "AUTH_REQUEST")
                        put("version", 1)
                    }
                    writeBleMessage(requestJson.toString())
                } catch (e: Exception) {
                    logCallback.onLog("[BLE Error] Failed to send AUTH_REQUEST: ${e.message}")
                }
            } else {
                logCallback.onLog("[BLE Error] Descriptor write failed (Status: $status)")
            }
        }

        override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            super.onCharacteristicWrite(gatt, characteristic, status)
            val isSuccess = (status == BluetoothGatt.GATT_SUCCESS)
            writeDeferred?.complete(isSuccess)
        }

        // API 33+ callback - value is passed directly (preferred on Android 13+)
        @Suppress("OVERRIDE_DEPRECATION")
        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            if (characteristic.uuid == TX_CHAR_UUID) {
                handleNotificationPayload(value)
            }
        }

        // Deprecated pre-API-33 callback - kept for backwards compatibility on older devices
        @Suppress("DEPRECATION")
        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            super.onCharacteristicChanged(gatt, characteristic)
            if (characteristic.uuid == TX_CHAR_UUID) {
                @Suppress("DEPRECATION")
                handleNotificationPayload(characteristic.value ?: return)
            }
        }
    }

    private fun handleNotificationPayload(value: ByteArray) {
        val payload = value.toString(Charsets.UTF_8)
        Log.d(TAG, "[BLE Notify] Received ${value.size} bytes")
        
        // Buffer overflow protection
        if (rxBuffer.length + payload.length > MAX_MESSAGE_SIZE) {
            logCallback.onLog("[BLE Error] Receive buffer overflow. Resetting buffer.")
            rxBuffer.setLength(0)
            disconnect()
            return
        }
        
        rxBuffer.append(payload)
        var bufferStr = rxBuffer.toString()
        while (bufferStr.contains("\n")) {
            val index = bufferStr.indexOf("\n")
            val message = bufferStr.substring(0, index).trim()
            rxBuffer = StringBuilder(bufferStr.substring(index + 1))
            bufferStr = rxBuffer.toString()
            
            if (message.isNotEmpty()) {
                handleIncomingBleMessage(message)
            }
        }
    }

    private fun calculateHmacSha256(secret: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(secret, "HmacSHA256")
        mac.init(secretKey)
        return mac.doFinal(message)
    }

    private fun handleIncomingBleMessage(message: String) {
        try {
            val json = JSONObject(message)
            val type = json.optString("type")
            val version = json.optInt("version", 1)
            
            if (version != 1) {
                logCallback.onLog("[BLE Error] Unsupported version: $version")
                disconnect()
                return
            }
            
            when (type) {
                "AUTH_CHALLENGE" -> {
                    val challengeB64 = json.optString("challenge")
                    val challengeId = json.optString("challenge_id")
                    if (challengeB64.isEmpty() || challengeId.isEmpty()) {
                        logCallback.onLog("[BLE Error] Challenge message missing required fields.")
                        disconnect()
                        return
                    }
                    logCallback.onLog("[BLE AUTH] Challenge received: ID=$challengeId")
                    onChallengeReceived(challengeB64, challengeId)
                }
                "AUTH_SUCCESS" -> {
                    logCallback.onLog("[BLE AUTH] Authentication successful")
                    stateCallback.onStateChanged("AUTHENTICATED")
                }
                "AUTH_FAILURE" -> {
                    val reason = json.optString("reason", "UNKNOWN")
                    logCallback.onLog("[BLE AUTH] Authentication failed: $reason")
                    stateCallback.onStateChanged("AUTH_FAILED")
                    disconnect()
                }
                else -> {
                    logCallback.onLog("[BLE Error] Unexpected message type: $type")
                    disconnect()
                }
            }
        } catch (e: Exception) {
            logCallback.onLog("[BLE Error] Failed to parse message: ${e.message}")
            disconnect()
        }
    }

    private fun onChallengeReceived(challengeB64: String, challengeId: String) {
        val sendResponseAction = {
            logCallback.onLog("[BLE AUTH] Generating authentication response")
            try {
                val challengeBytes = Base64.decode(challengeB64, Base64.NO_WRAP)
                val sharedSecret = DefaultSecretProvider.getSharedSecret(context)
                val hmacBytes = calculateHmacSha256(sharedSecret, challengeBytes)
                val responseB64 = Base64.encodeToString(hmacBytes, Base64.NO_WRAP)
                
                val responseJson = JSONObject().apply {
                    put("type", "AUTH_RESPONSE")
                    put("version", 1)
                    put("challenge_id", challengeId)
                    put("response", responseB64)
                }
                
                logCallback.onLog("[BLE AUTH] Response sent")
                writeBleMessage(responseJson.toString())
            } catch (e: Exception) {
                logCallback.onLog("[BLE Error] Challenge response generation failed: ${e.message}")
                disconnect()
            }
        }

        val cb = biometricCallback
        if (cb != null) {
            logCallback.onLog("[BLE AUTH] Requesting fingerprint scan on phone...")
            cb.onRequestBiometricAuth(
                onSuccess = {
                    sendResponseAction()
                },
                onFailure = {
                    logCallback.onLog("[BLE AUTH] Fingerprint authentication canceled or failed.")
                    disconnect()
                }
            )
        } else {
            sendResponseAction()
        }
    }

    fun writeBleMessage(message: String) {
        val gatt = bluetoothGatt ?: return
        val service = gatt.getService(SERVICE_UUID) ?: return
        val rxChar = service.getCharacteristic(RX_CHAR_UUID) ?: return
        
        val fullMsg = "$message\n"
        val msgBytes = fullMsg.toByteArray(Charsets.UTF_8)
        val chunkSize = 20
        
        CoroutineScope(Dispatchers.Default).launch {
            for (i in 0 until msgBytes.size step chunkSize) {
                val end = minOf(i + chunkSize, msgBytes.size)
                val chunk = msgBytes.copyOfRange(i, end)
                
                writeDeferred = CompletableDeferred()
                
                @Suppress("DEPRECATION")
                rxChar.value = chunk
                rxChar.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
                
                var success = false
                withContext(Dispatchers.Main) {
                    success = gatt.writeCharacteristic(rxChar)
                }
                
                if (!success) {
                    // Fallback to WRITE_TYPE_DEFAULT if NO_RESPONSE is rejected by device stack
                    rxChar.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                    withContext(Dispatchers.Main) {
                        success = gatt.writeCharacteristic(rxChar)
                    }
                }

                if (!success) {
                    logCallback.onLog("[BLE Error] Failed to write characteristic chunk locally.")
                    withContext(Dispatchers.Main) {
                        disconnect()
                    }
                    break
                }
                
                // Wait briefly for write completion if default writeType was used
                if (rxChar.writeType == BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) {
                    val writeStatusSuccess = try {
                        withTimeout(2000) {
                            writeDeferred!!.await()
                        }
                    } catch (e: Exception) {
                        false
                    }
                    if (!writeStatusSuccess) {
                        logCallback.onLog("[BLE Warning] GATT write callback timed out — continuing transmission.")
                    }
                }
            }
        }
    }
}

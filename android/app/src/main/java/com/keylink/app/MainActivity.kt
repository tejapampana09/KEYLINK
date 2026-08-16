package com.keylink.app

import android.Manifest
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.security.Signature
import kotlin.coroutines.resume

class MainActivity : AppCompatActivity() {

    private lateinit var btnPair: Button
    private lateinit var btnResetKeys: Button
    private lateinit var tvLog: TextView
    
    // BLE UI components
    private lateinit var tvBleState: TextView
    private lateinit var btnBleScan: Button
    private lateinit var btnBleDisconnect: Button

    private lateinit var cryptoManager: CryptographyManager
    private lateinit var bleConnectionManager: BleConnectionManager
    private val mainScope = CoroutineScope(Dispatchers.Main)
    private lateinit var prefs: SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize managers
        cryptoManager = CryptographyManager()
        prefs = getSharedPreferences("KeyLinkPrefs", Context.MODE_PRIVATE)

        // Bind Views
        btnPair = findViewById(R.id.btnPair)
        btnResetKeys = findViewById(R.id.btnResetKeys)
        tvLog = findViewById(R.id.tvLog)
        
        // Bind BLE views
        tvBleState = findViewById(R.id.tvBleState)
        btnBleScan = findViewById(R.id.btnBleScan)
        btnBleDisconnect = findViewById(R.id.btnBleDisconnect)

        // Initialize BLE manager
        bleConnectionManager = BleConnectionManager(
            this,
            object : BleConnectionManager.LogCallback {
                override fun onLog(message: String) {
                    log(message)
                }
            },
            object : BleConnectionManager.StateCallback {
                override fun onStateChanged(state: String) {
                    runOnUiThread {
                        tvBleState.text = "State: $state"
                    }
                }
            },
            object : BleConnectionManager.BiometricPromptCallback {
                override fun onRequestBiometricAuth(onSuccess: () -> Unit, onFailure: () -> Unit) {
                    showFingerprintPromptForBle(onSuccess, onFailure)
                }
            }
        )

        val rfcommManager = BluetoothRfcommManager(
            this,
            object : BluetoothRfcommManager.LogCallback {
                override fun onLog(message: String) { log(message) }
            },
            object : BluetoothRfcommManager.StateCallback {
                override fun onStateChanged(state: String) {
                    runOnUiThread { tvBleState.text = "State: $state" }
                }
            },
            object : BluetoothRfcommManager.BiometricPromptCallback {
                override suspend fun onSignChallengeWithBiometric(challengeBytes: ByteArray): ByteArray? {
                    return showBiometricAndSign(challengeBytes)
                }
            }
        )

        // Add BLE / Bluetooth Listeners
        btnBleScan.setOnClickListener {
            checkBlePermissionsAndScan()
        }
        btnPair.setOnClickListener {
            checkBlePermissionsAndScan()
        }
        btnBleDisconnect.setOnClickListener { bleConnectionManager.disconnect() }
        btnResetKeys.setOnClickListener { onResetKeysClicked() }

        // Initial setup logs
        log("System Initialized.")
        if (cryptoManager.isKeyGenerated()) {
            log("[KeyInfo] Biometric P-256 key present in Android Keystore.")
        } else {
            log("[KeyInfo] Generating biometric key...")
            cryptoManager.generateBiometricKey()
        }

        checkBiometricSupport()
    }

    private fun log(message: String) {
        android.util.Log.d("KeyLink", message)
        runOnUiThread {
            tvLog.append("$message\n")
            // Auto scroll to bottom
            val scrollParent = tvLog.parent as? android.widget.ScrollView
            scrollParent?.post {
                scrollParent.fullScroll(android.widget.ScrollView.FOCUS_DOWN)
            }
        }
    }

    private fun checkBiometricSupport() {
        val biometricManager = BiometricManager.from(this)
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                log("[Biometrics] Device supports secure hardware biometrics.")
            }
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                log("[Warning] No biometric hardware detected on this device.")
            }
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                log("[Warning] Biometric hardware is currently unavailable.")
            }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                log("[Warning] No fingerprints or face profiles are enrolled on this device. Please enroll one in system settings.")
            }
        }
    }

    private fun onResetKeysClicked() {
        try {
            cryptoManager.deleteKey()
            log("[Keystore] Existing key deleted.")
            cryptoManager.generateBiometricKey()
            log("[Keystore] Fresh biometric-enforced P-256 key generated.")
        } catch (e: Exception) {
            log("[Error] Key generation failed: ${e.message}")
        }
    }

    /**
     * Shows the BiometricPrompt, unlocks the Keystore private key, signs the challenge,
     * and returns the signature byte array. Bridges the asynchronous callback API to
     * a clean synchronous suspend function.
     */
    private suspend fun showBiometricAndSign(challengeBytes: ByteArray): ByteArray? =
        withContext(Dispatchers.Main) {
            val signatureObj = cryptoManager.getInitializedSignatureObject()
            if (signatureObj == null) {
                log("[Error] Keystore private key not found. Regenerating key may be required.")
                return@withContext null
            }

            suspendCancellableCoroutine { continuation ->
                val executor = ContextCompat.getMainExecutor(this@MainActivity)
                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        log("[Biometric Error] ($errorCode): $errString")
                        if (continuation.isActive) {
                            continuation.resume(null)
                        }
                    }

                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        log("[Biometric Success] Signature authorized.")
                        try {
                            // Extract the authorized signature object from the crypto wrapper
                            val authorizedSignature = result.cryptoObject?.signature
                            if (authorizedSignature == null) {
                                throw Exception("CryptoObject signature is null.")
                            }
                            
                            // Perform signature calculation
                            val signedBytes = cryptoManager.signChallenge(authorizedSignature, challengeBytes)
                            if (continuation.isActive) {
                                continuation.resume(signedBytes)
                            }
                        } catch (e: Exception) {
                            log("[Error] Cryptographic signing failed: ${e.message}")
                            if (continuation.isActive) {
                                continuation.resume(null)
                            }
                        }
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        log("[Biometric Alert] Scan failed. Try again.")
                    }
                }

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("KeyLink PC Verify")
                    .setSubtitle("Confirm authentication challenge")
                    .setNegativeButtonText("Cancel")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build()

                val biometricPrompt = BiometricPrompt(this@MainActivity, executor, callback)
                
                // Pass the signature wrapped in CryptoObject to link it to the keystore authentication
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signatureObj))

                continuation.invokeOnCancellation {
                    biometricPrompt.cancelAuthentication()
                }
            }
        }

    private fun showFingerprintPromptForBle(onSuccess: () -> Unit, onFailure: () -> Unit) {
        runOnUiThread {
            val executor = ContextCompat.getMainExecutor(this)
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    log("[Biometric Error] ($errorCode): $errString")
                    onFailure()
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    log("[Biometric Success] Fingerprint verified!")
                    onSuccess()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    log("[Biometric Alert] Fingerprint scan failed. Try again.")
                }
            }

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("KeyLink PC Unlock")
                .setSubtitle("Scan fingerprint to unlock Windows PC")
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()

            val biometricPrompt = BiometricPrompt(this, executor, callback)
            biometricPrompt.authenticate(promptInfo)
        }
    }

    private fun checkBlePermissionsAndScan() {
        val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT
            )
        } else {
            arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        }

        val missingPermissions = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missingPermissions.isNotEmpty()) {
            log("[BLE Info] Requesting Bluetooth permissions...")
            ActivityCompat.requestPermissions(this, missingPermissions.toTypedArray(), 101)
        } else {
            bleConnectionManager.startScan()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 101) {
            val allGranted = grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            if (allGranted) {
                log("[BLE Info] Bluetooth permissions granted.")
                bleConnectionManager.startScan()
            } else {
                log("[BLE Error] Bluetooth permissions denied. Cannot perform BLE operations.")
            }
        }
    }
}

package com.keylink.app

import android.content.Context
import android.util.Base64

interface SecretProvider {
    fun getSharedSecret(context: Context): ByteArray
}

object DefaultSecretProvider : SecretProvider {
    private const val DEV_SECRET = "dev_shared_secret_key_12345"

    override fun getSharedSecret(context: Context): ByteArray {
        // Toggle or configuration for development vs production mode
        val isDevMode = true
        
        if (isDevMode) {
            // Clearly isolated development mode
            return DEV_SECRET.toByteArray(Charsets.UTF_8)
        }
        
        // Production secret loading architecture from secure preferences
        val prefs = context.getSharedPreferences("keylink_secure_prefs", Context.MODE_PRIVATE)
        val secretBase64 = prefs.getString("provisioned_secret", null)
        if (secretBase64 != null) {
            return Base64.decode(secretBase64, Base64.NO_WRAP)
        }
        
        throw IllegalStateException("KeyLink shared secret has not been provisioned.")
    }
}

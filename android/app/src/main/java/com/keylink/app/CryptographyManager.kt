package com.keylink.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class CryptographyManager {

    companion object {
        private const val KEY_ALIAS = "KeyLinkKey"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    /**
     * Checks if the KeyLink ECC keypair exists in AndroidKeyStore.
     */
    fun isKeyGenerated(): Boolean {
        return keyStore.containsAlias(KEY_ALIAS)
    }

    /**
     * Generates a biometric-protected ECDSA P-256 KeyPair in AndroidKeyStore.
     */
    fun generateBiometricKey() {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )

        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")) // P-256 Curve
            .setDigests(KeyProperties.DIGEST_SHA256)
            // Require user biometrics (fingerprint/face) to unlock the private key
            .setUserAuthenticationRequired(true)
            // Key is invalidated if new biometrics are enrolled (recommended for high security)
            .setInvalidatedByBiometricEnrollment(false)
            .build()

        keyPairGenerator.initialize(spec)
        keyPairGenerator.generateKeyPair()
    }

    /**
     * Retrieves the Public Key from the KeyStore.
     */
    fun getPublicKey(): PublicKey? {
        val certificate = keyStore.getCertificate(KEY_ALIAS)
        return certificate?.publicKey
    }

    /**
     * Returns the Public Key serialized as a hex string of its DER bytes.
     * This SubjectPublicKeyInfo format is directly readable by Python cryptography.
     */
    fun getPublicKeyDerHex(): String? {
        val pubKey = getPublicKey() ?: return null
        return pubKey.encoded.joinToString("") { "%02x".format(it) }
    }

    /**
     * Initializes and returns a Signature object ready for biometric verification.
     * This signature object must be wrapped in a BiometricPrompt.CryptoObject.
     */
    fun getInitializedSignatureObject(): Signature? {
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey ?: return null
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        return signature
    }

    /**
     * Signs the challenge bytes using the authenticated signature object.
     * Must be called in onAuthenticationSucceeded with the verified Signature.
     */
    fun signChallenge(signature: Signature, challengeBytes: ByteArray): ByteArray {
        signature.update(challengeBytes)
        return signature.sign()
    }

    /**
     * Deletes the KeyLink keypair from the Keystore.
     */
    fun deleteKey() {
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }
}

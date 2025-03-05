package com.adhikamera.biometricauthwrapper


import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Main class for handling biometric authentication
 */
class BiometricAuth private constructor(private val context: Context) {

    companion object {
        const val KEY_NAME = "biometric_auth_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        // Singleton instance
        @Volatile
        private var instance: BiometricAuth? = null

        fun getInstance(context: Context): BiometricAuth {
            return instance ?: synchronized(this) {
                instance ?: BiometricAuth(context.applicationContext).also { instance = it }
            }
        }
    }

    /**
     * Configuration class for BiometricAuth
     */
    data class BiometricConfig(
        val title: String = "Biometric Authentication",
        val subtitle: String = "Verify your identity",
        val description: String = "Place your finger on the sensor or look at the camera",
        val negativeButtonText: String = "Cancel",
        val confirmationRequired: Boolean = true,
        val strongAuthRequired: Boolean = true
    )

    /**
     * Check if device supports biometric authentication
     * @return BiometricStatus indicating the availability of biometric features
     */
    fun checkBiometricStatus(): BiometricStatus {
        val biometricManager = BiometricManager.from(context)

        return when (biometricManager.canAuthenticate(getBiometricAuthenticators())) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricStatus.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricStatus.NOT_AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricStatus.TEMPORARILY_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricStatus.NOT_ENROLLED
            else -> BiometricStatus.ERROR
        }
    }

    /**
     * Get appropriate biometric authenticators based on device capabilities and requirements
     */
    private fun getBiometricAuthenticators(strongAuthRequired: Boolean = true): Int {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (strongAuthRequired) {
                BiometricManager.Authenticators.BIOMETRIC_STRONG
            } else {
                BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.DEVICE_CREDENTIAL
            }
        } else {
            BiometricManager.Authenticators.BIOMETRIC_WEAK
        }
    }

    /**
     * Authenticate user with biometrics
     * @param activity The activity context
     * @param config Configuration for the biometric prompt
     * @param authCallback Callback for authentication results
     */
    fun authenticate(
        activity: FragmentActivity,
        config: BiometricConfig = BiometricConfig(),
        authCallback: BiometricCallback
    ) {
        // Check if biometric authentication is available
        when (checkBiometricStatus()) {
            BiometricStatus.AVAILABLE -> {
                // Proceed with authentication
                showBiometricPrompt(activity, config, authCallback)
            }
            BiometricStatus.NOT_ENROLLED -> {
                authCallback.onError(BiometricError.NOT_ENROLLED, "Biometric authentication not enrolled")
            }
            BiometricStatus.NOT_AVAILABLE -> {
                authCallback.onError(BiometricError.NOT_AVAILABLE, "Biometric authentication not available on this device")
            }
            BiometricStatus.TEMPORARILY_UNAVAILABLE -> {
                authCallback.onError(BiometricError.TEMPORARILY_UNAVAILABLE, "Biometric authentication temporarily unavailable")
            }
            BiometricStatus.ERROR -> {
                authCallback.onError(BiometricError.UNKNOWN_ERROR, "Unknown biometric error")
            }
        }
    }

    /**
     * Show the biometric prompt to the user
     */
    private fun showBiometricPrompt(
        activity: FragmentActivity,
        config: BiometricConfig,
        authCallback: BiometricCallback
    ) {
        val executor = ContextCompat.getMainExecutor(activity)

        val authenticationCallback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                authCallback.onSuccess()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                val error = when (errorCode) {
                    BiometricPrompt.ERROR_CANCELED -> BiometricError.CANCELED
                    BiometricPrompt.ERROR_HW_NOT_PRESENT -> BiometricError.NOT_AVAILABLE
                    BiometricPrompt.ERROR_HW_UNAVAILABLE -> BiometricError.TEMPORARILY_UNAVAILABLE
                    BiometricPrompt.ERROR_LOCKOUT -> BiometricError.LOCKOUT
                    BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> BiometricError.LOCKOUT_PERMANENT
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON -> BiometricError.CANCELED
                    BiometricPrompt.ERROR_NO_BIOMETRICS -> BiometricError.NOT_ENROLLED
                    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> BiometricError.NO_DEVICE_CREDENTIAL
                    BiometricPrompt.ERROR_TIMEOUT -> BiometricError.TIMEOUT
                    BiometricPrompt.ERROR_USER_CANCELED -> BiometricError.USER_CANCELED
                    else -> BiometricError.UNKNOWN_ERROR
                }
                authCallback.onError(error, errString.toString())
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                authCallback.onFailed()
            }
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(config.title)
            .setSubtitle(config.subtitle)
            .setDescription(config.description)
            .setNegativeButtonText(config.negativeButtonText)
            .setConfirmationRequired(config.confirmationRequired)
            .setAllowedAuthenticators(getBiometricAuthenticators(config.strongAuthRequired))
            .build()

        val biometricPrompt = BiometricPrompt(activity, executor, authenticationCallback)

        try {
            biometricPrompt.authenticate(promptInfo)
        } catch (e: Exception) {
            authCallback.onError(BiometricError.UNKNOWN_ERROR, e.message ?: "Unknown error occurred")
        }
    }

    /**
     * Authenticate with biometrics and perform cryptographic operation
     * @param activity The activity context
     * @param config Configuration for the biometric prompt
     * @param cryptoObject Cryptographic operation to perform
     * @param authCallback Callback for authentication results
     */
    fun authenticateWithCrypto(
        activity: FragmentActivity,
        config: BiometricConfig = BiometricConfig(),
        cryptoOperation: CryptoOperation,
        iv: ByteArray? = null, // Add IV parameter
        authCallback: BiometricCryptoCallback
    ) {
        try {
            val cipher = getCipher()

            when (cryptoOperation) {
                CryptoOperation.ENCRYPT -> {
                    val key = getOrCreateKey()
                    cipher.init(Cipher.ENCRYPT_MODE, key)
                }
                CryptoOperation.DECRYPT -> {
                    val key = getKey()
                    if (key == null) {
                        authCallback.onError(BiometricError.KEY_NOT_FOUND, "Encryption key not found")
                        return
                    }
                    if (iv == null) {
                        authCallback.onError(BiometricError.CRYPTO_ERROR, "IV required for decryption")
                        return
                    }
                    val ivSpec = javax.crypto.spec.IvParameterSpec(iv)
                    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
                }
            }

            val cryptoObject = BiometricPrompt.CryptoObject(cipher)

            // Create auth callback
            val executor = ContextCompat.getMainExecutor(activity)
            val authenticationCallback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    result.cryptoObject?.cipher?.let { successCipher ->
                        authCallback.onSuccess(successCipher)
                    } ?: authCallback.onError(BiometricError.CRYPTO_ERROR, "Cipher not available")
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    val error = when (errorCode) {
                        BiometricPrompt.ERROR_CANCELED -> BiometricError.CANCELED
                        BiometricPrompt.ERROR_HW_NOT_PRESENT -> BiometricError.NOT_AVAILABLE
                        BiometricPrompt.ERROR_HW_UNAVAILABLE -> BiometricError.TEMPORARILY_UNAVAILABLE
                        BiometricPrompt.ERROR_LOCKOUT -> BiometricError.LOCKOUT
                        BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> BiometricError.LOCKOUT_PERMANENT
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON -> BiometricError.CANCELED
                        BiometricPrompt.ERROR_NO_BIOMETRICS -> BiometricError.NOT_ENROLLED
                        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> BiometricError.NO_DEVICE_CREDENTIAL
                        BiometricPrompt.ERROR_TIMEOUT -> BiometricError.TIMEOUT
                        BiometricPrompt.ERROR_USER_CANCELED -> BiometricError.USER_CANCELED
                        else -> BiometricError.UNKNOWN_ERROR
                    }
                    authCallback.onError(error, errString.toString())
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    authCallback.onFailed()
                }
            }

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(config.title)
                .setSubtitle(config.subtitle)
                .setDescription(config.description)
                .setNegativeButtonText(config.negativeButtonText)
                .setConfirmationRequired(config.confirmationRequired)
                .setAllowedAuthenticators(getBiometricAuthenticators(config.strongAuthRequired))
                .build()

            val biometricPrompt = BiometricPrompt(activity, executor, authenticationCallback)

            biometricPrompt.authenticate(promptInfo, cryptoObject)

        } catch (e: Exception) {
            authCallback.onError(BiometricError.CRYPTO_ERROR, e.message ?: "Cryptographic error")
        }
    }

    /**
     * Get or create a cryptographic key for biometric operations
     */
    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        return if (keyStore.containsAlias(KEY_NAME)) {
            keyStore.getKey(KEY_NAME, null) as SecretKey
        } else {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )

            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(true)
                // Only set this to false for testing
                .setInvalidatedByBiometricEnrollment(true)
                .apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(
                            0, KeyProperties.AUTH_BIOMETRIC_STRONG
                        )
                    }
                }
                .build()

            keyGenerator.init(keyGenParameterSpec)
            keyGenerator.generateKey()
        }
    }

    /**
     * Get existing key from keystore
     */
    private fun getKey(): SecretKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        return if (keyStore.containsAlias(KEY_NAME)) {
            keyStore.getKey(KEY_NAME, null) as SecretKey
        } else {
            null
        }
    }

    /**
     * Get cipher instance for cryptographic operations
     */
    private fun getCipher(): Cipher {
        return Cipher.getInstance(
            KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7
        )
    }

    /**
     * Remove the biometric key
     * @return true if the key was successfully removed
     */
    fun removeKey(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            if (keyStore.containsAlias(KEY_NAME)) {
                keyStore.deleteEntry(KEY_NAME)
                true
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }
}
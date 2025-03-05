package com.adhikamera.biometricauth

import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.adhikamera.biometricauthwrapper.BiometricAuth
import com.adhikamera.biometricauthwrapper.BiometricCallback
import com.adhikamera.biometricauthwrapper.BiometricCrypto
import com.adhikamera.biometricauthwrapper.BiometricCryptoCallback
import com.adhikamera.biometricauthwrapper.BiometricError
import com.adhikamera.biometricauthwrapper.BiometricStatus
import com.adhikamera.biometricauthwrapper.CryptoOperation
import com.adhikamera.biometricauthwrapper.EncryptedData
import javax.crypto.Cipher


class MainActivity : AppCompatActivity() {

    private lateinit var biometricAuth: BiometricAuth
    private lateinit var statusTextView: TextView
    private lateinit var authenticateButton: Button
    private lateinit var authenticateWithCryptoButton: Button

    // Sample encrypted data
    private var encryptedData: EncryptedData? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize BiometricAuth
        biometricAuth = BiometricAuth.getInstance(this)

        // Initialize views
        statusTextView = findViewById(R.id.statusTextView)
        authenticateButton = findViewById(R.id.authenticateButton)
        authenticateWithCryptoButton = findViewById(R.id.authenticateWithCryptoButton)

        // Check biometric status
        updateBiometricStatus()

        // Set up authenticate button
        authenticateButton.setOnClickListener {
            authenticateUser()
        }

        // Set up authenticate with crypto button
        authenticateWithCryptoButton.setOnClickListener {
            if (encryptedData == null) {
                encryptData()
            } else {
                decryptData()
            }
        }
    }

    private fun updateBiometricStatus() {
        val status = biometricAuth.checkBiometricStatus()
        statusTextView.text = "Biometric Status: $status"

        // Enable/disable buttons based on status
        val isAvailable = status == BiometricStatus.AVAILABLE
        authenticateButton.isEnabled = isAvailable
        authenticateWithCryptoButton.isEnabled = isAvailable
    }

    private fun authenticateUser() {
        // Create custom configuration (optional)
        val config = BiometricAuth.BiometricConfig(
            title = "Verify Your Identity",
            subtitle = "Authentication required",
            description = "Use your biometric credential to verify your identity",
            negativeButtonText = "Cancel"
        )

        // Perform authentication
        biometricAuth.authenticate(
            activity = this,
            config = config,
            authCallback = object : BiometricCallback {
                override fun onSuccess() {
                    runOnUiThread {
                        Toast.makeText(
                            this@MainActivity,
                            "Authentication successful!",
                            Toast.LENGTH_SHORT
                        ).show()

                        statusTextView.text = "Authentication: SUCCESS"
                    }
                }

                override fun onFailed() {
                    runOnUiThread {
                        Toast.makeText(
                            this@MainActivity,
                            "Authentication failed. Try again.",
                            Toast.LENGTH_SHORT
                        ).show()

                        statusTextView.text = "Authentication: FAILED"
                    }
                }

                override fun onError(error: BiometricError, message: String) {
                    runOnUiThread {
                        Toast.makeText(
                            this@MainActivity,
                            "Error: $message",
                            Toast.LENGTH_SHORT
                        ).show()

                        Log.e("BiometricAuth Test LOG", "Error: $message")
                        statusTextView.text = "Authentication Error: $error"
                    }
                }
            }
        )
    }

    private fun encryptData() {
        val dataToEncrypt = "This is sensitive information that needs protection!"

        // Custom configuration
        val config = BiometricAuth.BiometricConfig(
            title = "Encrypt Sensitive Data",
            subtitle = "Authentication required",
            description = "Use your biometric credential to encrypt data"
        )

        biometricAuth.authenticateWithCrypto(
            activity = this,
            config = config,
            cryptoOperation = CryptoOperation.ENCRYPT,
            authCallback = object : BiometricCryptoCallback {
                override fun onSuccess(cipher: Cipher) {
                    try {
                        // Encrypt the data - now returns EncryptedData object
                        encryptedData = BiometricCrypto.encrypt(cipher, dataToEncrypt)

                        runOnUiThread {
                            Toast.makeText(
                                this@MainActivity,
                                "Data encrypted successfully!",
                                Toast.LENGTH_SHORT
                            ).show()

                            statusTextView.text = "Data encrypted. Tap again to decrypt."
                            authenticateWithCryptoButton.text = "Decrypt Data"
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            Toast.makeText(
                                this@MainActivity,
                                "Encryption failed: ${e.message}",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                }

                override fun onFailed() {
                    runOnUiThread {
                        Toast.makeText(
                            this@MainActivity,
                            "Authentication failed. Try again.",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }

                override fun onError(error: BiometricError, message: String) {
                    runOnUiThread {
                        Toast.makeText(
                            this@MainActivity,
                            "Error: $message",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        )
    }

    private fun decryptData() {
        // Ensure we have data to decrypt
        if (encryptedData == null) {
            Toast.makeText(
                this,
                "No encrypted data available.",
                Toast.LENGTH_SHORT
            ).show()
            return
        }

        // Custom configuration
        val config = BiometricAuth.BiometricConfig(
            title = "Decrypt Sensitive Data",
            subtitle = "Authentication required",
            description = "Use your biometric credential to decrypt data"
        )

        biometricAuth.authenticateWithCrypto(
            activity = this,
            config = config,
            cryptoOperation = CryptoOperation.DECRYPT,
            iv = encryptedData?.iv,
            authCallback = object : BiometricCryptoCallback {
                override fun onSuccess(cipher: Cipher) {
                    try {
                        // Decrypt the data using both encrypted data and IV
                        val decryptedString = BiometricCrypto.decryptToString(cipher, encryptedData!!)

                        runOnUiThread {
                            Toast.makeText(
                                this@MainActivity,
                                "Decrypted: $decryptedString",
                                Toast.LENGTH_LONG
                            ).show()

                            statusTextView.text = "Data decrypted successfully!"
                            authenticateWithCryptoButton.text = "Encrypt Data"
                            encryptedData = null
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            Toast.makeText(
                                this@MainActivity,
                                "Decryption failed: ${e.message}",
                                Toast.LENGTH_SHORT
                            ).show()

                            Log.e("BiometricAuth", "Decryption error", e)
                        }
                    }
                }

                override fun onFailed() {
                    runOnUiThread {
                        Toast.makeText(
                            this@MainActivity,
                            "Authentication failed. Try again.",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }

                override fun onError(error: BiometricError, message: String) {
                    runOnUiThread {
                        Toast.makeText(
                            this@MainActivity,
                            "Error: $message",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        )
    }
}
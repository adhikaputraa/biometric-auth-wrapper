package com.adhikamera.biometricauthwrapper

import javax.crypto.Cipher

class BiometricCrypto {
    companion object {
        /**
         * Encrypt data using a cipher from successful biometric authentication
         * @param cipher The cipher from successful authentication
         * @param data The data to encrypt
         * @return EncryptedData object containing both encrypted data and IV
         */
        fun encrypt(cipher: Cipher, data: ByteArray): EncryptedData {
            val encryptedData = cipher.doFinal(data)
            val iv = cipher.iv // Get the IV that was used
            return EncryptedData(encryptedData, iv)
        }

        /**
         * Encrypt string using a cipher from successful biometric authentication
         * @param cipher The cipher from successful authentication
         * @param data The string to encrypt
         * @return EncryptedData object containing both encrypted data and IV
         */
        fun encrypt(cipher: Cipher, data: String): EncryptedData {
            return encrypt(cipher, data.toByteArray())
        }

        /**
         * Decrypt data using a cipher from successful biometric authentication
         * @param cipher The cipher from successful authentication
         * @param encryptedData The EncryptedData object containing data and IV
         * @return Decrypted data as ByteArray
         */
        fun decrypt(cipher: Cipher, encryptedData: EncryptedData): ByteArray {
            return cipher.doFinal(encryptedData.encrypted)
        }

        /**
         * Decrypt data and convert to string using a cipher
         * @param cipher The cipher from successful authentication
         * @param encryptedData The EncryptedData object containing data and IV
         * @return Decrypted data as String
         */
        fun decryptToString(cipher: Cipher, encryptedData: EncryptedData): String {
            val decryptedData = decrypt(cipher, encryptedData)
            return String(decryptedData)
        }
    }
}

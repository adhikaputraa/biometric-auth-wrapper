package com.adhikamera.biometricauthwrapper

import javax.crypto.Cipher

interface BiometricCryptoCallback {
    fun onSuccess(cipher: Cipher)
    fun onFailed()
    fun onError(error: BiometricError, message: String)
}
package com.adhikamera.biometricauthwrapper

interface BiometricCallback {
    fun onSuccess()
    fun onFailed()
    fun onError(error: BiometricError, message: String)
}
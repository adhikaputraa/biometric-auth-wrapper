package com.adhikamera.biometricauthwrapper

enum class BiometricStatus {
    AVAILABLE,
    NOT_AVAILABLE,
    TEMPORARILY_UNAVAILABLE,
    NOT_ENROLLED,
    ERROR
}

enum class BiometricError {
    CANCELED,
    NOT_AVAILABLE,
    TEMPORARILY_UNAVAILABLE,
    NOT_ENROLLED,
    LOCKOUT,
    LOCKOUT_PERMANENT,
    NO_DEVICE_CREDENTIAL,
    TIMEOUT,
    USER_CANCELED,
    CRYPTO_ERROR,
    KEY_NOT_FOUND,
    UNKNOWN_ERROR
}

enum class CryptoOperation {
    ENCRYPT,
    DECRYPT
}

package com.adhikamera.biometricauthwrapper

data class EncryptedData(
    val encrypted: ByteArray,
    val iv: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as EncryptedData
        return encrypted.contentEquals(other.encrypted) && iv.contentEquals(other.iv)
    }

    override fun hashCode(): Int {
        var result = encrypted.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        return result
    }
}
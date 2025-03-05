BiometricAuth Library
Overview
BiometricAuth is a simple, powerful Android library for implementing biometric authentication.
Features

Easy biometric authentication
Cryptographic operations support
Cross-version compatibility
Comprehensive error handling

Installation
Gradle
Add JitPack to your project's root build.gradle:
gradleCopyallprojects {
    repositories {
        // Other repositories
        maven { url 'https://jitpack.io' }
    }
}
Add the dependency in your app's build.gradle:
gradleCopydependencies {
    implementation 'com.github.yourusername:biometricauth:v1.0.0'
}
Usage
Simple Authentication
kotlinCopyval biometricAuth = BiometricAuth.getInstance(context)

biometricAuth.authenticate(
    activity = this,
    authCallback = object : BiometricCallback {
        override fun onSuccess() {
            // Authentication successful
        }
        
        override fun onFailed() {
            // Authentication failed
        }
        
        override fun onError(error: BiometricError, message: String) {
            // Handle authentication error
        }
    }
)
Encryption with Biometric Auth
kotlinCopybiometricAuth.authenticateWithCrypto(
    activity = this,
    cryptoOperation = CryptoOperation.ENCRYPT,
    authCallback = object : BiometricCryptoCallback {
        override fun onSuccess(cipher: Cipher) {
            val encryptedData = BiometricCrypto.encrypt(cipher, sensitiveData)
        }
        // ... other callback methods
    }
)
Requirements

Android API 23+
AndroidX Biometric library
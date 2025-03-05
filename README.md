# BiometricAuth Android Library

## 🔐 Overview

BiometricAuth is a comprehensive Android library that simplifies biometric authentication, providing an easy-to-use wrapper for implementing secure fingerprint and face recognition features in your Android applications.

## ✨ Features

- 🚀 Simple and intuitive API for biometric authentication
- 💪 Support for both basic authentication and cryptographic operations
- 🔄 Cross-version compatibility (Android API 23+)
- 🛡️ Robust error handling
- 🔒 Secure key management for cryptographic interactions

## 📦 Installation

### Gradle

Add JitPack to your project's root `build.gradle`:

```gradle
allprojects {
    repositories {
        // Other repositories
        maven { url 'https://jitpack.io' }
    }
}
```

Add the dependency in your app's `build.gradle`:

```gradle
dependencies {
    implementation 'com.github.YourUsername:BiometricAuth:v1.0.0'
}
```

## 🚀 Quick Start

### Simple Authentication

```kotlin
val biometricAuth = BiometricAuth.getInstance(context)

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
```

### Encryption with Biometric Authentication

```kotlin
biometricAuth.authenticateWithCrypto(
    activity = this,
    cryptoOperation = CryptoOperation.ENCRYPT,
    authCallback = object : BiometricCryptoCallback {
        override fun onSuccess(cipher: Cipher) {
            val encryptedData = BiometricCrypto.encrypt(cipher, sensitiveData)
        }
        // Implement other callback methods
    }
)
```

## 📋 Requirements

- 📱 Minimum Android SDK: 23
- 🧩 AndroidX Biometric library
- 🔧 Kotlin 1.4+

## 🛠️ Customization

### Biometric Prompt Configuration

```kotlin
val config = BiometricAuth.BiometricConfig(
    title = "Verify Identity",
    subtitle = "Authentication Required",
    description = "Use your biometric credential",
    negativeButtonText = "Cancel"
)

biometricAuth.authenticate(
    activity = this,
    config = config,
    authCallback = // Your callback
)
```

## 🔍 Error Handling

The library provides comprehensive error handling through the `BiometricError` enum:

- `CANCELED`: User canceled the operation
- `NOT_AVAILABLE`: Biometric hardware not available
- `NOT_ENROLLED`: No biometric credentials enrolled
- `LOCKOUT`: Too many failed attempts
- `UNKNOWN_ERROR`: Other unexpected errors

## 📦 Sample Application

Check out the `app` module in the repository for a complete example of library usage.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🔒 License

Distributed under the MIT License. See `LICENSE` for more information.

## 📞 Contact

Your Name - [Your Email or Twitter]

Project Link: [https://github.com/YourUsername/BiometricAuth](https://github.com/YourUsername/BiometricAuth)

## 🙌 Acknowledgments

- [AndroidX Biometric Library](https://developer.android.com/jetpack/androidx/releases/biometric)
- [JitPack](https://jitpack.io)

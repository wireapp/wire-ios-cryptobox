//
// Wire
// Copyright (C) 2020 Wire Swiss GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.
//

import Foundation

/// See https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/aes-256-gcm

public enum AES256GCMEncryption {

    // MARK: - Public Functions

    /// Encrypts a message with a key.
    ///
    /// - Parameters:
    ///  - message: The message data to encrypt.
    ///  - context: Publicly known contextual data to be bound to the ciphertext.
    ///  - key: The key used to encrypt.
    ///
    /// - Returns: The ciphertext and public nonce used in the encryption.

    public static func encrypt(message: Data, context: Data, key: Data) throws -> (ciphertext: Data, nonce: Data) {
        try initializeSodium()

        let keyBytes = key.bytes
        try verifyKey(bytes: keyBytes)

        let messageBytes = message.bytes
        let messageLength = messageBytes.count

        let contextBytes = context.bytes
        let contextLength = contextBytes.count

        let nonceBytes = generateRandomNonceBytes()

        var ciphertextBytes = createByteArray(length: ciphertextLength(forMessageLength: messageLength))
        var actualCiphertextLength: UInt64 = 0

        crypto_aead_aes256gcm_encrypt(
            &ciphertextBytes,          // buffer in which enrypted data is written to
            &actualCiphertextLength,   // actual size of encrypted data
            messageBytes,              // message to encrypt
            UInt64(messageLength),     // length of message to encrypt
            contextBytes,              // additional (non encrypted) data
            UInt64(contextLength),     // additional data length
            nil,                       // nsec, not used by this function
            nonceBytes,                // unique nonce used as initizalization vector
            keyBytes                   // key used to encrypt the message
        )

        try verifyCiphertext(length: actualCiphertextLength)

        return (ciphertextBytes.data, nonceBytes.data)
    }

    /// Decrypts a ciphertext with a public nonce and a key.
    ///
    /// - Parameters:
    ///  - ciphertext: The data to decrypt.
    ///  - nonce: The public nonce used to encrypt the original message.
    ///  - context: The public contextual data bound to the ciphertext.
    ///  - key: The key used to encrypt the original message.
    ///
    /// - Returns: The plaintext message data.

    public static func decrypt(ciphertext: Data, nonce: Data, context: Data, key: Data) throws -> Data {
        try initializeSodium()

        let keyBytes = key.bytes
        try verifyKey(bytes: keyBytes)

        let nonceBytes = nonce.bytes
        try verifyNonce(bytes: nonceBytes)

        let ciphertextBytes = ciphertext.bytes
        let ciphertextLength = ciphertextBytes.count

        let contextBytes = context.bytes
        let contextLength = contextBytes.count

        var messageBytes = createByteArray(length: messageLength(forCiphertextLength: ciphertextLength))
        var actualMessageLength: UInt64 = 0

        let result = crypto_aead_aes256gcm_decrypt(
            &messageBytes,             // buffer in which decrypted data is written to
            &actualMessageLength,      // actual size of decrypted data
            nil,                       // nsec, not used by this function
            ciphertextBytes,           // ciphertext to decrypt
            UInt64(ciphertextLength),  // length of ciphertext
            contextBytes,              // additional (non encrypted) data
            UInt64(contextLength),     // additional data length
            nonceBytes,                // the unique nonce used to encrypt the original message
            keyBytes                   // the key used to encrypt the original message
        )

        guard result == 0 else { throw EncryptionError.failedToDecrypt }

        return Data(messageBytes)
    }

    enum EncryptionError: LocalizedError {

        case failedToInitializeSodium
        case implementationNotAvailable
        case malformedKey
        case malformedNonce
        case malformedCiphertext
        case failedToDecrypt

        var errorDescription: String? {
            switch self {
            case .failedToInitializeSodium:
                return "Failed to initialize sodium."
            case .implementationNotAvailable:
                return "AES256GCM implementation not available on this device."
            case .malformedKey:
                return "Encountered a malformed key."
            case .malformedNonce:
                return "Encountered a malformed nonce."
            case .malformedCiphertext:
                return "Encountered a malformed ciphertext."
            case .failedToDecrypt:
                return "Failed to decrypt."
            }
        }

    }

    // MARK: - Private Helpers

    private static func initializeSodium() throws {
        guard sodium_init() >= 0 else { throw EncryptionError.failedToInitializeSodium }
        guard isImplementationAvailable else { throw EncryptionError.implementationNotAvailable }
    }

    private static var isImplementationAvailable: Bool {
        return crypto_aead_aes256gcm_is_available() != 0
    }

    // MARK: - Verification

    private static func verifyKey(bytes: [Byte]) throws {
        guard bytes.count == keyLength else { throw EncryptionError.malformedKey }
    }

    private static func verifyNonce(bytes: [Byte]) throws {
        guard bytes.count == nonceLength else { throw EncryptionError.malformedNonce }
    }

    private static func verifyCiphertext(length: UInt64) throws {
        guard length >= UInt64(authenticationBytesLength) else { throw EncryptionError.malformedCiphertext }
    }

    // MARK: - Buffer Lengths

    private static let keyLength = Int(crypto_aead_aes256gcm_KEYBYTES)
    private static let nonceLength = Int(crypto_aead_aes256gcm_NPUBBYTES)
    private static let authenticationBytesLength = Int(crypto_aead_aes256gcm_ABYTES)

    private static func ciphertextLength(forMessageLength messageLength: Int) -> Int {
        return messageLength + authenticationBytesLength
    }

    private static func messageLength(forCiphertextLength ciphertextLength: Int) -> Int {
        return ciphertextLength - authenticationBytesLength
    }


    // MARK: - Buffer creation

    static func generateRandomNonceBytes() -> [Byte] {
        var nonce = createByteArray(length: nonceLength)
        randombytes_buf(&nonce, nonce.count)
        return nonce
    }

    private static func createByteArray(length: Int) -> [Byte] {
        return [Byte](repeating: 0, count: length)
    }

}

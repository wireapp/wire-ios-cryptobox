//
//  AES256GCMEncryptionTests.swift
//  WireCryptoboxTests
//
//  Created by John Nguyen on 06.08.20.
//  Copyright © 2020 Cryptobox. All rights reserved.
//

import XCTest
@testable import WireCryptobox

class AES256GCMEncryptionTests: XCTestCase {

    // MARK: - Helpers

    private typealias Sut = AES256CGMEncryption

    private func generateRandomCipher(length: UInt) -> Data {
        // Large enough to include authentication bytes in the cipher.
        return Data.secureRandomData(length: length + UInt(crypto_aead_aes256gcm_ABYTES))
    }

    // MARK: - Positive Tests

    func testThatItEncryptsAndDecryptsMessage() throws {
        // Given
        let message = "Hello, world".data(using: .utf8)!
        let key = Data.zmRandomSHA256Key()

        // When
        let (cipher, nonce) = try Sut.encrypt(message: message, key: key)

        // Then
        XCTAssertNotEqual(cipher, message)
        XCTAssertFalse(nonce.isEmpty)

        // When
        let decryptedMessage = try Sut.decrypt(cipher: cipher, nonce: nonce, key: key)

        // Then
        XCTAssertEqual(decryptedMessage, message)
    }

    // MARK: - Negative Tests

    func testThatItFailsToEncryptIfKeyIsMalformed() throws {
        // Given
        let keyOfWrongLength = Data.zmRandomSHA256Key().dropLast()

        do {
            // When
            _ = try Sut.encrypt(message: Data(), key: keyOfWrongLength)
        } catch let error as Sut.EncryptionError {
            // Then
            XCTAssertEqual(error, .malformedKey)
        } catch {
            XCTFail("Unexpected error: \(error.localizedDescription)")
        }
    }

    func testThatItFailsToDecryptIfKeyIsMalformed() throws {
        // Given
        let cipher = generateRandomCipher(length: 8)
        let nonce = Sut.generateRandomNonceBytes().data
        let keyOfWrongLength = Data.zmRandomSHA256Key().dropLast()

        do {
            // When
            _ = try Sut.decrypt(cipher: cipher, nonce: nonce, key: keyOfWrongLength)
        } catch let error as Sut.EncryptionError {
            // Then
            XCTAssertEqual(error, .malformedKey)
        } catch {
            XCTFail("Unexpected error: \(error.localizedDescription)")
        }
    }

    func testThatItFailsToDecryptIfNonceIsMalformed() throws {
        // Given
        let cipher = generateRandomCipher(length: 8)
        let nonceOfWrongLength = Sut.generateRandomNonceBytes().data.dropLast()
        let key = Data.zmRandomSHA256Key()

        do {
            // When
            _ = try Sut.decrypt(cipher: cipher, nonce: nonceOfWrongLength, key: key)
        } catch let error as Sut.EncryptionError {
            // Then
            XCTAssertEqual(error, .malformedNonce)
        } catch {
            XCTFail("Unexpected error: \(error.localizedDescription)")
        }
    }


    func testThatItFailsToDecryptWithDifferentKey() throws {
        // Given
        let message = "Hello, world".data(using: .utf8)!
        let key1 = Data.zmRandomSHA256Key()
        let key2 = Data.zmRandomSHA256Key()

        let (cipher, nonce) = try Sut.encrypt(message: message, key: key1)

        do {
            // When
            _ = try Sut.decrypt(cipher: cipher, nonce: nonce, key: key2)
        } catch let error as Sut.EncryptionError {
            // Then
            XCTAssertEqual(error, .failedToDecrypt)
        } catch {
            XCTFail("Unexpected error: \(error.localizedDescription)")
        }
    }

    func testThatItFailsToDecryptWithDifferentNonce() throws {
        // Given
        let message = "Hello, world".data(using: .utf8)!
        let key = Data.zmRandomSHA256Key()
        let randomNonce = Sut.generateRandomNonceBytes().data

        let (cipher, _) = try Sut.encrypt(message: message, key: key)

        do {
            // When
            _ = try Sut.decrypt(cipher: cipher, nonce: randomNonce, key: key)
        } catch let error as Sut.EncryptionError {
            // Then
            XCTAssertEqual(error, .failedToDecrypt)
        } catch {
            XCTFail("Unexpected error: \(error.localizedDescription)")
        }
    }

}

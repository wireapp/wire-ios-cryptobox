//
// Wire
// Copyright (C) 2018 Wire Swiss GmbH
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

public final class ChaCha20Encryption {
    
    private static let bufferSize = 1024 * 1024
    private static let keyGenerationIterations: UInt64 = 6
    private static let keyGenerationMemoryLimit: Int = 134217728
    
    public enum EncryptionError: Error {
        /// Couldn't read corrupt message header
        case malformedHeader
        /// Encryption failed
        case encryptionFailed
        /// Decryption failed to incorrect key, malformed message
        case decryptionFailed
        /// Failure reading input stream
        case readError(Error)
        /// Failure writing to output stream
        case writeError(Error)
        /// Stream end was reached while expecting more data
        case unexpectedStreamEnd
        /// Failure generating a key.
        case keyGenerationFailed
        /// Passphrase UUID is different from what was used during encryption
        case mismatchingUUID
        /// File was encrypted on a unsupported platform
        case unsupportedPlatform
        /// Failure initializing sodium
        case failureInitializingSodium
        /// Unknown error
        case unknown
    }
    
    internal enum Platform: String {
        case iOS = "WBUI"
        case Android = "WBUA"
        case Web = "WBUD"
        
        init?(buffer: Array<UInt8>) {
            guard buffer.count == 4, let platform = String(bytes: buffer, encoding: .ascii) else {
                return nil
            }
            
            self.init(rawValue: platform)
        }
        
        var bytes: Data {
            return rawValue.data(using: .ascii)!
        }
    }
    
    internal struct Header {
        
        public static var size: Int = 55
        
        static let platformRange = (0..<4)
        static let versionRange = (5..<7)
        static let saltRange = (7..<23)
        static let hashRange = (23..<55)
        
        let buffer: Array<UInt8>
        
        var salt: ArraySlice<UInt8> {
            return buffer[Header.saltRange]
        }
        var uuidHash: ArraySlice<UInt8> {
            return buffer[Header.hashRange]
        }
        var platform: Platform
        var version: UInt16
        
        init(buffer: Array<UInt8>) throws {
            
            guard buffer.count == Header.size else {
                throw EncryptionError.malformedHeader
            }
            
            guard let platform = Platform(buffer: Array(buffer[Header.platformRange])) else  {
                throw EncryptionError.malformedHeader
            }
            
            self.platform = platform
            self.version = UInt16(bigEndian: Data(bytes: Array(buffer[Header.versionRange])).withUnsafeBytes { $0.pointee })
            self.buffer = buffer
        }
        
        init(uuid: UUID, platform: Platform = .iOS) throws {
            var buffer = Array<UInt8>()
            
            buffer.append(contentsOf: [UInt8](platform.bytes))
            buffer.append(0)
            buffer.append(contentsOf: [0, 1])
            
            var salt = Array<UInt8>(repeating: 0, count: Int(crypto_pwhash_argon2i_SALTBYTES))
            randombytes(&salt, UInt64(crypto_pwhash_argon2i_SALTBYTES))
            buffer.append(contentsOf: salt)
            buffer.append(contentsOf: try Header.hash(uuid: uuid, salt: salt))
            
            self.version = 1
            self.platform = platform
            self.buffer = buffer
        }
        
        internal func deriveKey(from passphrase: Passphrase) throws -> Key {
            let salt = Array(self.salt)
            
            guard try Header.hash(uuid: passphrase.uuid, salt: salt) == Array(uuidHash) else {
                throw EncryptionError.mismatchingUUID
            }
            
            return try Key(password: passphrase.password, salt: salt)
        }
        
        fileprivate static func hash(uuid: UUID, salt: Array<UInt8>) throws -> Array<UInt8> {
            var uuidAsBytes = Array<UInt8>(repeating: 0, count: 128)
            (uuid as NSUUID).getBytes(&uuidAsBytes)
            
            let hashSize = 32
            var hash = Array<UInt8>(repeating: 0, count: hashSize)
            guard crypto_pwhash_argon2i(&hash,
                                        UInt64(hashSize),
                                        uuidAsBytes.map(Int8.init),
                                        UInt64(uuidAsBytes.count),
                                        salt,
                                        keyGenerationIterations,
                                        keyGenerationMemoryLimit,
                                        crypto_pwhash_argon2i_ALG_ARGON2I13) == 0 else {
                throw EncryptionError.keyGenerationFailed
            }
            
            return hash
        }
        
    }
    
    /// Passphrase for encrypting/decrypting using ChaCha20.
    public struct Passphrase {
        fileprivate let uuid: UUID
        fileprivate let password: String
        
        public init(password: String, uuid: UUID) {
            self.password = password
            self.uuid = uuid
        }
    }
    
    /// ChaCha20 Key
    internal struct Key {
        
        fileprivate let buffer: Array<UInt8>
        
        /// Generate a key from a passphrase.
        /// - passphrase: string which is used to derive the key
        ///
        /// NOTE: this can fail if the system runs out of memory.
        public init(password: String, salt: Array<UInt8>) throws {
            var buffer = Array<UInt8>(repeating: 0, count: Int(crypto_secretstream_xchacha20poly1305_KEYBYTES))
            
            guard crypto_pwhash_argon2i(&buffer,
                                        UInt64(crypto_secretstream_xchacha20poly1305_KEYBYTES),
                                        password, UInt64(password.lengthOfBytes(using: .utf8)),
                                        salt,
                                        keyGenerationIterations,
                                        keyGenerationMemoryLimit,
                                        crypto_pwhash_argon2i_ALG_ARGON2I13) == 0 else {
                throw EncryptionError.keyGenerationFailed
            }
            
            self.buffer = buffer
        }
        
    }
    
    fileprivate static func initializeSodium() throws {
        guard sodium_init() >= 0 else {
            throw EncryptionError.failureInitializingSodium
        }
    }
    
    /// Encrypts an input stream using xChaCha20
    /// - input: plaintext input stream
    /// - output: decrypted output stream
    /// - passphrase: passphrase
    ///
    /// - Throws: Stream errors.
    /// - Returns: number of encrypted bytes written to the output stream
    @discardableResult
    public static func encrypt(input: InputStream, output: OutputStream, passphrase: Passphrase) throws -> Int {
        
        try initializeSodium()
        
        input.open()
        output.open()
        
        defer {
            input.close()
            output.close()
        }
        
        var totalBytesWritten = 0
        var bytesWritten = -1
        var bytesRead = -1
        var bytesReadReadAhead = -1
        
        let fileHeader = try Header(uuid: passphrase.uuid)
        let key = try fileHeader.deriveKey(from: passphrase)
    
        bytesWritten = output.write(fileHeader.buffer, maxLength: fileHeader.buffer.count)
        totalBytesWritten += bytesWritten
        
        guard bytesWritten > 0 else {
            throw EncryptionError.writeError(output.streamError ?? EncryptionError.unexpectedStreamEnd)
        }

        var chachaHeader = Array<UInt8>(repeating: 0, count: Int(crypto_secretstream_xchacha20poly1305_HEADERBYTES))
        var state = crypto_secretstream_xchacha20poly1305_state()
        
        guard crypto_secretstream_xchacha20poly1305_init_push(&state, &chachaHeader, key.buffer) == 0 else {
            throw EncryptionError.encryptionFailed
        }
        
        var messageBuffer = Array<UInt8>(repeating: 0, count: bufferSize)
        var messageBufferReadAhead = Array<UInt8>(repeating: 0, count: bufferSize)
        
        let cipherBufferSize = bufferSize + Int(crypto_secretstream_xchacha20poly1305_ABYTES)
        var cipherBuffer = Array<UInt8>(repeating: 0, count: cipherBufferSize)
        
        bytesWritten = output.write(chachaHeader, maxLength: Int(crypto_secretstream_xchacha20poly1305_HEADERBYTES))
        totalBytesWritten += bytesWritten
        
        guard bytesWritten > 0 else {
            throw EncryptionError.writeError(output.streamError ?? EncryptionError.unexpectedStreamEnd)
        }
        
        repeat {
            if bytesRead < 0 {
                bytesRead = input.read(&messageBuffer, maxLength: bufferSize)
                if let error = input.streamError {
                    throw EncryptionError.readError(error)
                }
            } else {
                (bytesRead, messageBuffer) = (bytesReadReadAhead, messageBufferReadAhead)
            }
            
            bytesReadReadAhead = input.read(&messageBufferReadAhead, maxLength: bufferSize)
            
            guard bytesRead > 0 else { break }
            
            let messageLength: UInt64 = UInt64(bytesRead)
            var cipherLength: UInt64 = 0
            let tag: UInt8 = input.hasBytesAvailable ? 0 : UInt8(crypto_secretstream_xchacha20poly1305_TAG_FINAL)

            guard crypto_secretstream_xchacha20poly1305_push(&state, &cipherBuffer, &cipherLength, messageBuffer, messageLength, nil, 0, tag) == 0 else {
                throw EncryptionError.encryptionFailed
            }
            
            bytesWritten = output.write(cipherBuffer, maxLength: Int(cipherLength))
            if let error = output.streamError {
                throw EncryptionError.writeError(error)
            }
            
            totalBytesWritten += bytesWritten
        } while bytesRead > 0 && bytesWritten > 0
        
        if bytesRead < 0 {
            throw EncryptionError.readError(input.streamError ?? EncryptionError.unknown)
        }
        
        if bytesWritten < 0 {
            throw EncryptionError.writeError(output.streamError ?? EncryptionError.unknown)
        }
        
        return totalBytesWritten
    }
    
    /// Decrypts an input stream using xChaCha20
    /// - input: encrypted input stream
    /// - output: plaintext output stream
    /// - passphrase: passphrase
    ///
    /// - Throws: Stream errors and `malformedHeader` or `decryptionFailed` if decryption fails.
    /// - Returns: number of decrypted bytes written to the output stream.
    @discardableResult
    public static func decrypt(input: InputStream, output: OutputStream, passphrase: Passphrase) throws -> Int {
        
        try initializeSodium()
        
        input.open()
        output.open()
        
        defer {
            input.close()
            output.close()
        }
        
        var totalBytesWritten = 0
        var bytesWritten = -1
        var bytesRead = -1
        
        var fileHeaderBuffer = Array<UInt8>(repeating: 0, count: Int(Header.size))
        
        guard input.read(&fileHeaderBuffer, maxLength: Header.size) > 0  else {
            throw EncryptionError.readError(input.streamError ?? EncryptionError.unexpectedStreamEnd)
        }
        
        let fileHeader = try Header(buffer: fileHeaderBuffer)
        
        guard fileHeader.platform == .iOS, fileHeader.version == 1 else {
            throw EncryptionError.unsupportedPlatform
        }
        
        let key = try fileHeader.deriveKey(from: passphrase)
        var state = crypto_secretstream_xchacha20poly1305_state()
        var chachaHeader = Array<UInt8>(repeating: 0, count: Int(crypto_secretstream_xchacha20poly1305_HEADERBYTES))
        
        guard input.read(&chachaHeader, maxLength: Int(crypto_secretstream_xchacha20poly1305_HEADERBYTES)) > 0  else {
            throw EncryptionError.readError(input.streamError ?? EncryptionError.unexpectedStreamEnd)
        }

        guard crypto_secretstream_xchacha20poly1305_init_pull(&state, chachaHeader, key.buffer) == 0 else {
            throw EncryptionError.malformedHeader
        }
        
        var messageBuffer = Array<UInt8>(repeating: 0, count: bufferSize)
        let cipherBufferSize = bufferSize + Int(crypto_secretstream_xchacha20poly1305_ABYTES)
        var cipherBuffer = Array<UInt8>(repeating: 0, count: cipherBufferSize)
        var tag: UInt8 = 0
        
        repeat {
            bytesRead = input.read(&cipherBuffer, maxLength: cipherBufferSize)
            
            guard bytesRead > 0 else { continue }
            
            var messageLength: UInt64 = 0
            let cipherLength: UInt64 = UInt64(bytesRead)
            
            guard crypto_secretstream_xchacha20poly1305_pull(&state, &messageBuffer, &messageLength, &tag, cipherBuffer, cipherLength, nil, 0) == 0 else {
                throw EncryptionError.decryptionFailed
            }
            
            bytesWritten = output.write(messageBuffer, maxLength: Int(messageLength))
            if let error = output.streamError {
                throw EncryptionError.writeError(error)
            }

            totalBytesWritten += bytesWritten
            
            if tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL {
                break // avoid reading data after final message is decrypted
            }
        } while bytesRead > 0 && bytesWritten > 0
        
        guard tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL else {
            throw EncryptionError.decryptionFailed
        }
        
        if bytesRead < 0 {
            throw EncryptionError.readError(input.streamError ?? EncryptionError.unknown)
        }
        
        if bytesWritten < 0 {
            throw EncryptionError.writeError(output.streamError ?? EncryptionError.unknown)
        }
        
        return totalBytesWritten
    }
    
}

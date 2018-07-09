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

// Caching proxy for @c backingEncryptor
class CachingEncryptor: Encryptor {
    private weak var backingEncryptor: Encryptor?
    private let cache = NSCache<NSString, NSData>()
    
    public init(encryptor: Encryptor) {
        backingEncryptor = encryptor
        
        cache.countLimit = 100
        cache.name = "Encrypted payloads cache"
        cache.totalCostLimit = 100_000 // Max 100 KB of data
    }
    
    public func encrypt(_ plainText: Data, for recipientIdentifier: WireCryptobox.EncryptionSessionIdentifier) throws -> Data {
        guard let backingEncryptor = self.backingEncryptor else {
            fatalError("Backing enryptor missing")
        }
        
        let cacheID: NSString = ("\(plainText.hashValue)" + recipientIdentifier.rawValue) as NSString
        
        if let cachedObject = cache.object(forKey: cacheID) {
            return cachedObject as Data
        }
        else {
            let data = try backingEncryptor.encrypt(plainText, for: recipientIdentifier)
            cache.setObject(data as NSData, forKey: cacheID, cost: data.count)
            return data
        }
    }
}

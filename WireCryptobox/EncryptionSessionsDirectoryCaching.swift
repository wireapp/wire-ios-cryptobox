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
    
    class Cache<Key: Hashable, Value> {
        private var cache: [Key: EntryMetadata<Value>] = [:]
        private let maxCost: Int
        private let maxElements: Int
        
        private struct EntryMetadata<Value> {
            let value: Value
            let cost: Int
            let insertedAt: TimeInterval
            
            init(value: Value, cost: Int) {
                self.value = value
                self.cost = cost
                self.insertedAt = Date().timeIntervalSinceReferenceDate
            }
        }
        
        init(maxCost: Int, maxElements: Int) {
            assert(maxCost > 0, "maxCost must be greather than 0")
            assert(maxElements > 0, "maxElements must be greather than 0")
            self.maxCost = maxCost
            self.maxElements = maxElements
        }
        
        func set(value: Value, for key: Key, cost: Int) {
            assert(cost > 0, "Cost must be greather than 0")
            cache[key] = EntryMetadata(value: value, cost: cost)
            purgeCacheIfNeeded()
        }
        
        func value(for key: Key) -> Value? {
            return cache[key]?.value
        }
        
        private func purgeCacheIfNeeded() {
            purgeBasedOnElementsCount()
            purgeBasedOnCost()
        }
        
        private func sorted() -> [(Key, EntryMetadata<Value>)] {
            return cache.map { key, metadata in (key, metadata) }.sorted { left, right in
                left.1.insertedAt < right.1.insertedAt
            }
        }
        
        private func currentCost() -> Int {
            return cache.reduce(0) { result, element in
                return result + element.value.cost
            }
        }
        
        private func purgeBasedOnElementsCount() {
            guard cache.count > maxElements else {
                return
            }
            
            let sorted = self.sorted()
            
            sorted.prefix(upTo: cache.count - maxElements).forEach { (key, _) in
                cache[key] = nil
            }
        }
        
        private func purgeBasedOnCost() {
            let currentCost = self.currentCost()
            
            guard currentCost > maxCost else {
                return
            }
            
            let costToClear = currentCost - maxCost
            
            let sorted = self.sorted()
            
            var accumulatedCost: Int = 0
            var index: Int = 0
            
            for (_, metadata) in sorted {
                index = index + 1
                accumulatedCost = accumulatedCost + metadata.cost
                
                if accumulatedCost >= costToClear {
                    break
                }
            }
        
            sorted.prefix(upTo: index).forEach { (key, _) in
                cache[key] = nil
            }
        }
    }
    
    private unowned let backingEncryptor: Encryptor
    // The maximum size of the end-to-end encrypted payload is defined by ZMClientMessageByteSizeExternalThreshold
    // It's currently 128KB of data. We will allow up to 8 messages of maximum size to persist in the cache.
    private let cache = Cache<GenericHash, Data>(maxCost: 1_000_000, maxElements: 100)
    
    deinit {
        zmLog.debug("Cache flushed / deallocated")
    }
    
    init(encryptor: Encryptor) {
        backingEncryptor = encryptor
    }
    
    private func hash(for data: Data, recepient: EncryptionSessionIdentifier) -> GenericHash {
        let builder = GenericHashBuilder()
        builder.append(data)
        builder.append(recepient.rawValue.data(using: .utf8)!)
        return builder.build()
    }
    
    func encrypt(_ plainText: Data, for recipientIdentifier: EncryptionSessionIdentifier) throws -> Data {
        let key = hash(for: plainText, recepient: recipientIdentifier)

        if let cachedObject = cache.value(for: key) {
            zmLog.debug("Cache hit: \(key)")
            return cachedObject
        }
        else {
            zmLog.debug("Cache miss: \(key)")
            let data = try backingEncryptor.encrypt(plainText, for: recipientIdentifier)
            cache.set(value: data, for: key, cost: data.count)
            return data
        }
    }
}

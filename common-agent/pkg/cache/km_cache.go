/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package cache

import (
	"regexp"
	"strings"
	"sync"

	eventhubTypes "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"
	logger "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/loggers"
)

// KeyManagerCache singleton instance for managing Key Manager details in-memory
type KeyManagerCache struct {
	mu          sync.RWMutex
	keyManagers map[string]*eventhubTypes.ResolvedKeyManager // map[kmName]*ResolvedKeyManager
}

var (
	kmCacheInstance *KeyManagerCache
	once            sync.Once
)

// GetKeyManagerCacheInstance returns the singleton instance of KeyManagerCache
func GetKeyManagerCacheInstance() *KeyManagerCache {
	once.Do(func() {
		kmCacheInstance = &KeyManagerCache{
			keyManagers: make(map[string]*eventhubTypes.ResolvedKeyManager),
		}
		logger.LoggerCache.Info("KeyManager cache singleton instance created")
	})
	return kmCacheInstance
}

// AddOrUpdateKeyManager adds or updates a Key Manager in the cache
func (kmc *KeyManagerCache) AddOrUpdateKeyManager(km *eventhubTypes.ResolvedKeyManager) {
	if km == nil {
		logger.LoggerCache.Warn("Attempted to add nil KeyManager to cache")
		return
	}

	kmc.mu.Lock()
	defer kmc.mu.Unlock()
	km.Name = sanitizeKeyManagerName(km.Name)
	kmc.keyManagers[km.Name] = km
	logger.LoggerCache.Infof("KeyManager '%s' added/updated in cache", km.Name)
}

// GetKeyManager retrieves a Key Manager by name from the cache
func (kmc *KeyManagerCache) GetKeyManager(kmName string) (*eventhubTypes.ResolvedKeyManager, bool) {
	kmc.mu.RLock()
	defer kmc.mu.RUnlock()

	km, exists := kmc.keyManagers[kmName]
	if exists {
		logger.LoggerCache.Debugf("KeyManager '%s' found in cache", kmName)
	} else {
		logger.LoggerCache.Debugf("KeyManager '%s' not found in cache", kmName)
	}
	return km, exists
}

// GetAllKeyManagers returns a copy of all Key Managers in the cache
func (kmc *KeyManagerCache) GetAllKeyManagers() map[string]*eventhubTypes.ResolvedKeyManager {
	kmc.mu.RLock()
	defer kmc.mu.RUnlock()

	// Create a copy to avoid external modifications
	result := make(map[string]*eventhubTypes.ResolvedKeyManager)
	for name, km := range kmc.keyManagers {
		result[name] = km
	}

	logger.LoggerCache.Debugf("Retrieved %d KeyManagers from cache", len(result))
	return result
}

// DeleteKeyManager removes a Key Manager from the cache
func (kmc *KeyManagerCache) DeleteKeyManager(kmName string) bool {
	kmc.mu.Lock()
	defer kmc.mu.Unlock()

	if _, exists := kmc.keyManagers[kmName]; exists {
		delete(kmc.keyManagers, kmName)
		logger.LoggerCache.Infof("KeyManager '%s' deleted from cache", kmName)
		return true
	}

	logger.LoggerCache.Warnf("Attempted to delete non-existent KeyManager '%s' from cache", kmName)
	return false
}

// GetKeyManagerCount returns the number of Key Managers in the cache
func (kmc *KeyManagerCache) GetKeyManagerCount() int {
	kmc.mu.RLock()
	defer kmc.mu.RUnlock()
	return len(kmc.keyManagers)
}

// ClearCache removes all Key Managers from the cache
func (kmc *KeyManagerCache) ClearCache() {
	kmc.mu.Lock()
	defer kmc.mu.Unlock()

	count := len(kmc.keyManagers)
	kmc.keyManagers = make(map[string]*eventhubTypes.ResolvedKeyManager)
	logger.LoggerCache.Infof("KeyManager cache cleared. Removed %d entries", count)
}

// GetKeyManagerNames returns a list of all Key Manager names in the cache
func (kmc *KeyManagerCache) GetKeyManagerNames() []string {
	kmc.mu.RLock()
	defer kmc.mu.RUnlock()

	names := make([]string, 0, len(kmc.keyManagers))
	for name := range kmc.keyManagers {
		names = append(names, name)
	}
	return names
}

// IsKeyManagerEnabled checks if a specific Key Manager is enabled
func (kmc *KeyManagerCache) IsKeyManagerEnabled(kmName string) bool {
	kmc.mu.RLock()
	defer kmc.mu.RUnlock()

	if km, exists := kmc.keyManagers[kmName]; exists {
		return km.Enabled
	}
	return false
}

func sanitizeKeyManagerName(input string) string {
	lower := strings.ToLower(input)
	reg := regexp.MustCompile(`[^a-z0-9]+`)
	sanitized := reg.ReplaceAllString(lower, "")
	return sanitized
}
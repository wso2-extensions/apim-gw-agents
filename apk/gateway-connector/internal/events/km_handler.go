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

// Package messaging holds the implementation for event listeners functions
package events

import (
	"strings"

	k8sclient "github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/cache"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub/types"
	msg "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/messaging"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// HandleKMConfiguration to handle Key Manager configurations
func HandleKMConfiguration(keyManager *types.KeyManager, notification msg.EventKeyManagerNotification, c client.Client) {
	// Get singleton cache instance for runtime updates
	kmCache := cache.GetKeyManagerCacheInstance()
	if strings.EqualFold(msg.KeyManagerConfigEvent, notification.Event.PayloadData.EventType) {
		if strings.EqualFold(msg.ActionDelete, notification.Event.PayloadData.Action) {
			// Delete from cache
			deleted := kmCache.DeleteKeyManager(notification.Event.PayloadData.Name)
			if deleted {
				logger.LoggerMessaging.Infof("KeyManager '%s' deleted from cache during runtime event", notification.Event.PayloadData.Name)
			}
			// !!!TODO: Need to change this to DeleteSecurityPolicyCRs
			// k8sclient.DeleteTokenIssuersCR(c, notification.Event.PayloadData.Name, notification.Event.PayloadData.TenantDomain)
			// Delete SecurityPolicy CRs(Not sure whether this is needed because now SPs are created per API so when the API is deleted the SPs should be deleted)
			k8sclient.DeleteKMSecurityPolicyCRs(notification.Event.PayloadData.Name, notification.Event.PayloadData.TenantDomain, c)
			logger.LoggerMessaging.Debugf("Deleting TokenIssuer CR: %v", notification.Event.PayloadData.Name)
		} else if keyManager != nil {
			if strings.EqualFold(msg.ActionAdd, notification.Event.PayloadData.Action) ||
				strings.EqualFold(msg.ActionUpdate, notification.Event.PayloadData.Action) {
				resolvedKeyManager := eventhub.MarshalKeyManager(keyManager)
				// Add/Update in cache during runtime
				kmCache.AddOrUpdateKeyManager(&resolvedKeyManager)
				logger.LoggerMessaging.Infof("KeyManager '%s' updated in cache during runtime event", resolvedKeyManager.Name)
				if strings.EqualFold(msg.ActionAdd, notification.Event.PayloadData.Action) {
					// Now the config-ds is responsible for creating the security policy CRs for KMs
					// No need to create the security policy CRs here
					logger.LoggerMessaging.Debugf("New KeyManager is added from the CP: %+v", resolvedKeyManager)
				} else {
					//Update SecurityPolicy CR
					err := k8sclient.UpdateSecurityPolicyCR(resolvedKeyManager, c)
					if err != nil {
						logger.LoggerMessaging.Errorf("Error updating SecurityPolicy CR: %v", err)
					}
					logger.LoggerMessaging.Debugf("Updating SecurityPolicy CR: %v", resolvedKeyManager)
				}
				logger.LoggerMessaging.Infof("KeyManager cache Content: %+v", kmCache.GetAllKeyManagers())
			}
		}
	}
}

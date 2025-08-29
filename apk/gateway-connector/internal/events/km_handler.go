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
	"github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/internal/synchronizer"
	"github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/internal/utils"
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
			// Delete the backend,backendTLS and secret and remove it from cache
			kmToDelete, _ := kmCache.GetKeyManager(notification.Event.PayloadData.Name)
			k8sclient.DeleteBackendCRByName(kmToDelete.K8sBackendName, kmToDelete.K8sBackendNamespace, c)
			// !!!TODO: Need to change this to DeleteSecurityPolicyCRs
			k8sclient.UpdateSecurityPolicyCRs(notification.Event.PayloadData.Name, notification.Event.PayloadData.TenantDomain, c, true)
			deleted := kmCache.DeleteKeyManager(notification.Event.PayloadData.Name)
			if deleted {
				logger.LoggerMessaging.Infof("KeyManager '%s' deleted from cache during runtime event", notification.Event.PayloadData.Name)
			}
			logger.LoggerMessaging.Infof("KM and related resources deleted from the dataplane...")
		} else if keyManager != nil {
			if strings.EqualFold(msg.ActionAdd, notification.Event.PayloadData.Action) ||
				strings.EqualFold(msg.ActionUpdate, notification.Event.PayloadData.Action) {
				resolvedKeyManager := eventhub.MarshalKeyManager(keyManager)
				// Add/Update in cache during runtime
				logger.LoggerMessaging.Infof("Key Manager details(from runtime event): %+v", resolvedKeyManager)
				backendName, hostname , backendPort, namespace := utils.GetBackendConfigForKM(resolvedKeyManager)

				kmCache.AddOrUpdateKeyManager(&cache.KMCacheObject{
					ResolvedKM: &resolvedKeyManager, 
					K8sBackendName: backendName, 
					K8sBackendPort: backendPort,
					K8sBackendNamespace: namespace,
				})
				logger.LoggerMessaging.Infof("KeyManager '%s' updated in cache during runtime event", resolvedKeyManager.Name)
				if strings.EqualFold(msg.ActionAdd, notification.Event.PayloadData.Action) {
					// Now the config-ds is responsible for creating the security policy CRs for KMs
					// No need to create the security policy CRs here
					logger.LoggerMessaging.Debugf("New KeyManager is added from the CP: %+v", resolvedKeyManager)
					err := synchronizer.CreateOrUpdateBackendAndBackendTLSForKMs(resolvedKeyManager, backendPort, backendName, namespace, hostname, c)
					if err != nil {
						logger.LoggerSynchronizer.Errorf("Error creating backend and backend TLS for KM: %+v", err)
					}
				} else {
					//Update SecurityPolicy CR
					err := synchronizer.CreateOrUpdateBackendAndBackendTLSForKMs(resolvedKeyManager, backendPort, backendName, namespace, hostname, c)
					if err != nil {
						logger.LoggerSynchronizer.Errorf("Error creating backend and backend TLS for KM: %+v", err)
					}
					k8sclient.UpdateSecurityPolicyCRs(notification.Event.PayloadData.Name, notification.Event.PayloadData.TenantDomain, c, false)
					logger.LoggerMessaging.Debugf("Updating SecurityPolicy CR: %v", resolvedKeyManager)
				}
				logger.LoggerMessaging.Infof("KeyManager cache Content: %+v", kmCache.GetAllKeyManagers())
			}
		}
	}
}

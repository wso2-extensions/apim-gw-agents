/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

	k8sclient "github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/internal/k8sClient"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"
	msg "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/messaging"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// HandleKMConfiguration to handle Key Manager configurations
func HandleKMConfiguration(keyManager *types.KeyManager, notification msg.EventKeyManagerNotification, c client.Client) {
	if strings.EqualFold(msg.KeyManagerConfigEvent, notification.Event.PayloadData.EventType) {
		if strings.EqualFold(msg.ActionDelete, notification.Event.PayloadData.Action) {
			k8sclient.DeleteTokenIssuersCR(c, notification.Event.PayloadData.Name, notification.Event.PayloadData.TenantDomain)
		} else if keyManager != nil {
			if strings.EqualFold(msg.ActionAdd, notification.Event.PayloadData.Action) ||
				strings.EqualFold(msg.ActionUpdate, notification.Event.PayloadData.Action) {
				resolvedKeyManager := eventhub.MarshalKeyManager(keyManager)
				if strings.EqualFold(msg.ActionAdd, notification.Event.PayloadData.Action) {
					k8sclient.CreateAndUpdateTokenIssuersCR(resolvedKeyManager, c)
				} else {
					err := k8sclient.UpdateTokenIssuersCR(resolvedKeyManager, c)
					if err != nil {
						k8sclient.CreateAndUpdateTokenIssuersCR(resolvedKeyManager, c)
					}
				}
			}
		}
	}
}

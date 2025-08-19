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

package events

import (
	"strings"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"
	msg "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/messaging"
	k8sclient "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/pkg/synchronizer"
	"github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/pkg/transformer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// HandleKMConfiguration to handle Key Manager configurations
func HandleKMConfiguration(keyManager *types.KeyManager, notification msg.EventKeyManagerNotification, c client.Client) {
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		logger.LoggerSynchronizer.Errorf("Error reading configs: %v", errReadConfig)
	}

	if strings.EqualFold(msg.KeyManagerConfigEvent, notification.Event.PayloadData.EventType) {
		if strings.EqualFold(msg.ActionDelete, notification.Event.PayloadData.Action) {
			k8sclient.UnDeploySecretCR(notification.Event.PayloadData.Name, c, conf)
		} else if keyManager != nil {
			if strings.EqualFold(msg.ActionAdd, notification.Event.PayloadData.Action) ||
				strings.EqualFold(msg.ActionUpdate, notification.Event.PayloadData.Action) {
				resolvedKeyManager := eventhub.MarshalKeyManager(keyManager)

				if resolvedKeyManager.KeyManagerConfig.CertificateType == "PEM" {
					publicKey, err := synchronizer.ExtractPublicKey(resolvedKeyManager.KeyManagerConfig.CertificateValue)
					if err == nil && publicKey != "" {
						config := map[string]string{
							"issuer":     resolvedKeyManager.KeyManagerConfig.Issuer,
							"public_key": publicKey,
						}
						secretLabels := map[string]string{
							"type": "issuer",
						}
						keyManagerSecret := transformer.GenerateK8sSecret(notification.Event.PayloadData.Name, secretLabels, config)
						keyManagerSecret.Namespace = conf.DataPlane.Namespace

						k8sclient.DeploySecretCR(keyManagerSecret, c)
					}
				} else {
					logger.LoggerMessaging.Infoln("Only PEM certificate type is supported")
					k8sclient.UnDeploySecretCR(notification.Event.PayloadData.Name, c, conf)
				}
			}
		}
	}
}

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

package events

import (
	"strings"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub/types"
	msg "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/messaging"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	k8sclient "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/synchronizer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// HandleKMConfiguration to handle Key Manager configurations
func HandleKMConfiguration(keyManager *types.KeyManager, notification msg.EventKeyManagerNotification, c client.Client) {
	logger.LoggerEvents.Infof("Processing KM event with EventType: %s", notification.Event.PayloadData.EventType)
	if !strings.EqualFold(msg.KeyManagerConfigEvent, notification.Event.PayloadData.EventType) {
		return
	}

	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		logger.LoggerEvents.Errorf("Error reading configs: %v", errReadConfig)
		return
	}

	action := notification.Event.PayloadData.Action
	name := notification.Event.PayloadData.Name

	if strings.EqualFold(msg.ActionDelete, action) {
		k8sclient.UnDeploySecretCR(name, c, conf)
		return
	}

	if keyManager == nil {
		return
	}

	if !strings.EqualFold(msg.ActionAdd, action) && !strings.EqualFold(msg.ActionUpdate, action) {
		return
	}

	resolvedKeyManager := eventhub.MarshalKeyManager(keyManager)

	if !strings.EqualFold(constants.PEMCertificateType, resolvedKeyManager.KeyManagerConfig.CertificateType) {
		logger.LoggerEvents.Infoln("Only PEM certificate type is supported")
		k8sclient.UnDeploySecretCR(name, c, conf)
		return
	}

	err := synchronizer.CreateAndDeployKeyManagerSecret(resolvedKeyManager, conf, c)
	if err != nil {
		logger.LoggerEvents.Errorf("Failed to create and deploy key manager secret for %s: %v", resolvedKeyManager.Name, err)
		return
	}
}

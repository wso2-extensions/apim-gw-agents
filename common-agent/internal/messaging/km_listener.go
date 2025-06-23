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
package messaging

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	logger "github.com/wso2-extensions/apim-gw-agents/common-agent/internal/loggers"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/agent"
	eventhubTypes "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/logging"
	msg "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/messaging"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// handleKMConfiguration
func handleKMConfiguration(c client.Client, agent agent.Agent) {
	for d := range msg.KeyManagerChannel {
		var notification msg.EventKeyManagerNotification
		var keyManager eventhubTypes.KeyManager
		unmarshalErr := json.Unmarshal([]byte(string(d.Body)), &notification)
		if unmarshalErr != nil {
			logger.LoggerMessaging.ErrorC(logging.ErrorDetails{
				Message:   fmt.Sprintf("Error occurred while unmarshalling key manager event data %v", unmarshalErr.Error()),
				Severity:  logging.CRITICAL,
				ErrorCode: 2000,
			})
			return
		}
		logger.LoggerMessaging.Infof("Event %s is received", notification.Event.PayloadData.EventType)

		var decodedByte, err = base64.StdEncoding.DecodeString(notification.Event.PayloadData.Value)

		if err != nil {
			if _, ok := err.(base64.CorruptInputError); ok {
				logger.LoggerMessaging.ErrorC(logging.ErrorDetails{
					Message:   "\nbase64 input is corrupt, check the provided key",
					Severity:  logging.MINOR,
					ErrorCode: 2001,
				})
			}
			logger.LoggerMessaging.ErrorC(logging.ErrorDetails{
				Message:   fmt.Sprintf("Error occurred while decoding the notification event %v", err.Error()),
				Severity:  logging.CRITICAL,
				ErrorCode: 2002,
			})
			return
		}

		if decodedByte != nil {
			kmConfigMapErr := json.Unmarshal([]byte(string(decodedByte)), &keyManager)
			if kmConfigMapErr != nil {
				logger.LoggerMessaging.ErrorC(logging.ErrorDetails{
					Message:   fmt.Sprintf("Error occurred while unmarshalling key manager config map %v", kmConfigMapErr),
					Severity:  logging.CRITICAL,
					ErrorCode: 2003,
				})
				return
			}
		}
		agent.HandleKMConfiguration(&keyManager, notification, c)

		logger.LoggerMessaging.Info("handle: deliveries channel closed")
		d.Ack(false)
	}
}

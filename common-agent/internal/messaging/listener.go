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
	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/agent"
	msg "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/messaging"
	"sigs.k8s.io/controller-runtime/pkg/client"

	logger "github.com/wso2-extensions/apim-gw-agents/common-agent/internal/loggers"
)

// ProcessEvents to pass event consumption
func ProcessEvents(config *config.Config, c client.Client, agent agent.Agent) {
	msg.InitiateJMSConnection(config.ControlPlane.BrokerConnectionParameters.EventListeningEndpoints)
	go handleNotification(c, agent)
	go handleKMConfiguration(c, agent)

	// run agent specific event handlers
	logger.LoggerAgent.Info("Running gateway event handler...")
	agent.ProcessEvents(config, c)
}

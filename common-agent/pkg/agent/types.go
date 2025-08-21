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

package agent

import (
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub/types"
	msg "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/messaging"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Agent defines the functions of a pluggable agent
type Agent interface {
	// PreRun handles any prerequisites before agent Run
	PreRun(conf *config.Config, scheme *runtime.Scheme)
	// Run initiates the gateway specific agent
	Run(conf *config.Config, manager manager.Manager)
	// ProcessEvents handles gateway specific functions need to be triggered on event processing
	ProcessEvents(conf *config.Config, client client.Client)
	// HandleLifeCycleEvents handles the events of an api through out the life cycle
	HandleLifeCycleEvents(data []byte)
	// HandleAPIEvents to process api related data
	HandleAPIEvents(data []byte, eventType string, conf *config.Config, client client.Client)
	// HandleApplicationEvents to process application related events
	HandleApplicationEvents(data []byte, eventType string, client client.Client)
	// HandleSubscriptionEvents to process subscription related events
	HandleSubscriptionEvents(data []byte, eventType string, client client.Client)
	// HandlePolicyEvents to process policy related events
	HandlePolicyEvents(data []byte, eventType string, client client.Client)
	// HandleAIProviderEvents to process AI Provider related events
	HandleAIProviderEvents(data []byte, eventType string, client client.Client)
	// HandleScopeEvents to process Scope related events
	HandleScopeEvents(data []byte, eventType string, client client.Client)
	// HandleKMConfiguration to handle Key Manager configurations
	HandleKMConfiguration(keyManager *types.KeyManager, notification msg.EventKeyManagerNotification, client client.Client)
}

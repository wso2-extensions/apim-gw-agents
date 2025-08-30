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
	"encoding/json"
	"strings"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	eventConstants "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub/constants"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub/types"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/managementserver"
	msg "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/messaging"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	internalk8sClient "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/synchronizer"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/transformer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// var variables
var (
	ScopeList = make([]types.Scope, 0)
	// timestamps needs to be maintained as it is not guranteed to receive them in order,
	// hence older events should be discarded
	apiListTimeStampMap          = make(map[string]int64, 0)
	subsriptionsListTimeStampMap = make(map[string]int64, 0)
	applicationListTimeStampMap  = make(map[string]int64, 0)
)

// HandleLifeCycleEvents handles the events of an api through out the life cycle
func HandleLifeCycleEvents(data []byte) {
	logger.LoggerEvents.Infof("Processing API lifecycle event with data length: %d bytes", len(data))

	var apiEvent msg.APIEvent
	if err := json.Unmarshal(data, &apiEvent); err != nil {
		logger.LoggerEvents.Errorf("%s: %v", constants.UnmarshalErrorLifecycle, err)
		return
	}

	logger.LoggerEvents.Debugf("%s: %+v", "API lifecycle event received", apiEvent)
}

// HandleAPIEvents to process api related data
func HandleAPIEvents(data []byte, eventType string, conf *config.Config, c client.Client) {
	logger.LoggerEvents.Infof("Processing API event with EventType: %s, data length: %d bytes", eventType, len(data))

	var apiEvent msg.APIEvent
	if err := json.Unmarshal(data, &apiEvent); err != nil {
		logger.LoggerEvents.Errorf("%s: %v", constants.UnmarshalErrorAPI, err)
		return
	}

	if !belongsToTenant(apiEvent.TenantDomain) {
		logger.LoggerEvents.Debugf("API event for the API %s:%s is dropped due to having non related tenantDomain : %s",
			apiEvent.APIName, apiEvent.Version, apiEvent.TenantDomain)
		return
	}

	currentTimeStamp := apiEvent.Event.TimeStamp

	if strings.EqualFold(eventConstants.DeployAPIToGateway, apiEvent.Event.Type) {
		internalk8sClient.UndeployAPICRs(apiEvent.UUID, c)
		go synchronizer.FetchAPIsOnEvent(conf, &apiEvent.UUID, c)
	}

	for _, env := range apiEvent.GatewayLabels {
		mapKey := apiEvent.UUID + ":" + env
		if isLaterEvent(apiListTimeStampMap, mapKey, currentTimeStamp) {
			logger.LoggerEvents.Debugf("Skipping older event for API %s, environment %s", apiEvent.UUID, env)
			break
		}
		if strings.EqualFold(eventConstants.RemoveAPIFromGateway, apiEvent.Event.Type) {
			internalk8sClient.UndeployAPICRs(apiEvent.UUID, c)
			break
		}
	}
}

// HandlePolicyEvents to process policy related events
func HandlePolicyEvents(data []byte, eventType string, c client.Client) {
	logger.LoggerEvents.Infof("Processing Policy event with EventType: %s, data length: %d bytes", eventType, len(data))

	conf, _ := config.ReadConfigs()

	var policyEvent msg.PolicyInfo
	if err := json.Unmarshal(data, &policyEvent); err != nil {
		logger.LoggerEvents.Errorf("%s: %v", constants.UnmarshalErrorPolicy, err)
		return
	}

	processPolicyEvent(policyEvent, eventType, c, conf)
}

// processPolicyEvent handles common policy event processing logic
func processPolicyEvent(policyEvent msg.PolicyInfo, eventType string, c client.Client, conf *config.Config) {
	switch {
	case strings.EqualFold(policyEvent.PolicyType, constants.APIPolicyType):
		handleAPIPolicyEvent(policyEvent, eventType, c, conf)
	case strings.EqualFold(policyEvent.PolicyType, constants.SubscriptionPolicyType):
		handleSubscriptionPolicyEvent(policyEvent, eventType, c, conf)
	default:
		logger.LoggerEvents.Warnf("Unknown policy type: %s", policyEvent.PolicyType)
	}
}

// handleAPIPolicyEvent processes API policy events
func handleAPIPolicyEvent(policyEvent msg.PolicyInfo, eventType string, c client.Client, conf *config.Config) {
	logger.LoggerEvents.Infof("Policy: %s for policy type: %s for tenant: %s",
		policyEvent.PolicyName, policyEvent.PolicyType, policyEvent.TenantDomain)

	switch eventType {
	case eventConstants.PolicyCreate, eventConstants.PolicyUpdate:
		synchronizer.FetchRateLimitPoliciesOnEvent(policyEvent.PolicyName, policyEvent.TenantDomain, c)
		logger.LoggerEvents.Debugf("Successfully processed %s event for API policy: %s", eventType, policyEvent.PolicyName)
	case eventConstants.PolicyDelete:
		managementserver.DeleteRateLimitPolicy(policyEvent.PolicyName, policyEvent.TenantDomain)
		crName := transformer.GeneratePolicyCRName(policyEvent.PolicyName, policyEvent.TenantDomain, constants.RateLimitingPlugin, constants.PolicyTypeKey)
		internalk8sClient.UnDeployKongPluginCR(crName, c, conf)
		logger.LoggerEvents.Debugf("Successfully deleted API policy: %s and undeployed CR: %s", policyEvent.PolicyName, crName)
	}

	ratelimitPolicies := managementserver.GetAllRateLimitPolicies()
	logger.LoggerEvents.Debugf("%s: %v", "Rate Limit Policies Internal Map", ratelimitPolicies)
}

// handleSubscriptionPolicyEvent processes subscription policy events
func handleSubscriptionPolicyEvent(policyEvent msg.PolicyInfo, eventType string, c client.Client, conf *config.Config) {
	logger.LoggerEvents.Infof("Policy: %s for policy type: %s for tenant: %s",
		policyEvent.PolicyName, policyEvent.PolicyType, policyEvent.TenantDomain)

	switch eventType {
	case eventConstants.PolicyCreate, eventConstants.PolicyUpdate:
		synchronizer.FetchSubscriptionRateLimitPoliciesOnEvent(policyEvent.PolicyName, policyEvent.TenantDomain, c, false)
		logger.LoggerEvents.Debugf("Successfully processed %s event for subscription policy: %s", eventType, policyEvent.PolicyName)
	case eventConstants.PolicyDelete:
		managementserver.DeleteSubscriptionPolicy(policyEvent.PolicyName, policyEvent.TenantDomain)
		crName := transformer.GeneratePolicyCRName(policyEvent.PolicyName, policyEvent.TenantDomain,
			constants.RateLimitingTypeKey, constants.SubscriptionTypeKey)
		internalk8sClient.UnDeployKongPluginCR(crName, c, conf)
		logger.LoggerEvents.Debugf("Successfully deleted subscription policy: %s and undeployed CR: %s", policyEvent.PolicyName, crName)
	}

	ratelimitPolicies := managementserver.GetAllRateLimitPolicies()
	logger.LoggerEvents.Debugf("%s: %v", "Rate Limit Policies Internal Map", ratelimitPolicies)
}

// HandleAIProviderEvents to process AI Provider related events
func HandleAIProviderEvents(data []byte, eventType string, client client.Client) {
	logger.LoggerEvents.Infof("Processing AI Provider event with EventType: %s, data length: %d bytes", eventType, len(data))

	var aiProviderEvent msg.AIProviderEvent
	if err := json.Unmarshal(data, &aiProviderEvent); err != nil {
		logger.LoggerEvents.Errorf("%s: %v", constants.UnmarshalErrorAIProvider, err)
		return
	}

	logger.LoggerEvents.Debugf("%s: %+v", "AI provider event received", aiProviderEvent)
}

// HandleScopeEvents to process scope related events
func HandleScopeEvents(data []byte, eventType string, client client.Client) {
	logger.LoggerEvents.Infof("Processing Scope event with EventType: %s, data length: %d bytes", eventType, len(data))

	var scopeEvent msg.ScopeEvent
	if err := json.Unmarshal(data, &scopeEvent); err != nil {
		logger.LoggerEvents.Errorf("%s: %v", constants.UnmarshalErrorScope, err)
		return
	}

	logger.LoggerEvents.Debugf("%s: %+v", "Scope event received", scopeEvent)
}

// belongsToTenant checks if the tenant domain belongs to the connected tenant
func belongsToTenant(tenantDomain string) bool {
	// TODO : enable this once the events are fixed in apim
	// return config.GetControlPlaneConnectedTenantDomain() == tenantDomain
	return true
}

// isLaterEvent checks if the current event is later than the stored timestamp
// and updates the timestamp map accordingly
func isLaterEvent(timeStampMap map[string]int64, mapKey string, currentTimeStamp int64) bool {
	if timeStamp, exists := timeStampMap[mapKey]; exists && timeStamp > currentTimeStamp {
		return true
	}
	timeStampMap[mapKey] = currentTimeStamp
	return false
}

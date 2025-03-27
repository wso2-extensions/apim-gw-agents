package events

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	eventConstants "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/constants"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/logging"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/managementserver"
	msg "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/messaging"
	internalk8sClient "github.com/wso2-extensions/apim-gw-agents/kong/agent/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-agents/kong/agent/internal/loggers"
	internalutils "github.com/wso2-extensions/apim-gw-agents/kong/agent/internal/utils"
	"github.com/wso2-extensions/apim-gw-agents/kong/agent/pkg/synchronizer"
	"github.com/wso2-extensions/apim-gw-agents/kong/agent/pkg/transformer"
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
	var apiEvent msg.APIEvent
	apiLCEventErr := json.Unmarshal([]byte(string(data)), &apiEvent)
	if apiLCEventErr != nil {
		logger.LoggerMessaging.Errorf("Error occurred while unmarshalling Lifecycle event data %v", apiLCEventErr)
		return
	}
	if !belongsToTenant(apiEvent.TenantDomain) {
		logger.LoggerMessaging.Debugf("API Lifecycle event for the API %s:%s is dropped due to having non related tenantDomain : %s",
			apiEvent.APIName, apiEvent.APIVersion, apiEvent.TenantDomain)
		return
	}

	apiEventObj := types.API{UUID: apiEvent.UUID, APIID: apiEvent.APIID, Name: apiEvent.APIName,
		Context: apiEvent.APIContext, Version: apiEvent.APIVersion, Provider: apiEvent.APIProvider}

	logger.LoggerMessaging.Infof("API event data %v", apiEventObj)
	logger.LoggerMessaging.Debugf("%s : %s API life cycle state change event triggered", apiEvent.APIName, apiEvent.APIVersion)
}

// HandleAPIEvents to process api related data
func HandleAPIEvents(data []byte, eventType string, conf *config.Config, c client.Client) {
	var (
		apiEvent         msg.APIEvent
		currentTimeStamp int64 = apiEvent.Event.TimeStamp
	)

	apiEventErr := json.Unmarshal([]byte(string(data)), &apiEvent)
	if apiEventErr != nil {
		logger.LoggerMessaging.ErrorC(logging.ErrorDetails{
			Message:   fmt.Sprintf("Error occurred while unmarshalling API event data %v", apiEventErr),
			Severity:  logging.MAJOR,
			ErrorCode: 2004,
		})
		return
	}
	logger.LoggerMessaging.Infof("API event received %+v", apiEvent)

	if !belongsToTenant(apiEvent.TenantDomain) {
		apiName := apiEvent.APIName
		if apiEvent.APIName == "" {
			apiName = apiEvent.Name
		}
		apiVersion := apiEvent.Version
		if apiEvent.Version == "" {
			apiVersion = apiEvent.Version
		}
		logger.LoggerMessaging.Debugf("API event for the API %s:%s is dropped due to having non related tenantDomain : %s",
			apiName, apiVersion, apiEvent.TenantDomain)
		return
	}

	apiEventObj := types.API{UUID: apiEvent.UUID, APIID: apiEvent.APIID, Name: apiEvent.APIName,
		Context: apiEvent.APIContext, Version: apiEvent.APIVersion, Provider: apiEvent.APIProvider}

	logger.LoggerMessaging.Infof("API event data %+v", apiEventObj)

	//Per each revision, synchronization should happen.
	if strings.EqualFold(eventConstants.DeployAPIToGateway, apiEvent.Event.Type) {
		// undeploy current API if exists
		internalk8sClient.UndeployAPICRs(apiEvent.UUID, c)
		// deploy new API
		go internalutils.FetchAPIsOnEvent(conf, &apiEvent.UUID, c)
	}

	for _, env := range apiEvent.GatewayLabels {
		if isLaterEvent(apiListTimeStampMap, apiEvent.UUID+":"+env, currentTimeStamp) {
			break
		}
	}

	for _, env := range apiEvent.GatewayLabels {
		if isLaterEvent(apiListTimeStampMap, apiEvent.UUID+":"+env, currentTimeStamp) {
			break
		}
		// removeFromGateway event with multiple labels could only appear when the API is subjected
		// to delete. Hence we could simply delete after checking against just one iteration.
		if strings.EqualFold(eventConstants.RemoveAPIFromGateway, apiEvent.Event.Type) {
			internalk8sClient.UndeployAPICRs(apiEvent.UUID, c)
			break
		}
	}
}

// HandlePolicyEvents to process policy related events
func HandlePolicyEvents(data []byte, eventType string, c client.Client) {
	conf, _ := config.ReadConfigs()

	var policyEvent msg.PolicyInfo
	policyEventErr := json.Unmarshal([]byte(string(data)), &policyEvent)
	if policyEventErr != nil {
		logger.LoggerMessaging.Errorf("Error occurred while unmarshalling Throttling Policy event data %v", policyEventErr)
		return
	}

	logger.LoggerMessaging.Infof("Policy event received: %+v", policyEvent)
	if strings.EqualFold(eventType, eventConstants.PolicyCreate) {
		if strings.EqualFold(policyEvent.PolicyType, "API") {
			logger.LoggerMessaging.Infof("Policy: %s for policy type: %s for tenant: %s", policyEvent.PolicyName, policyEvent.PolicyType, policyEvent.TenantDomain)
			synchronizer.FetchRateLimitPoliciesOnEvent(policyEvent.PolicyName, policyEvent.TenantDomain, c)
			ratelimitPolicies := managementserver.GetAllRateLimitPolicies()
			logger.LoggerMessaging.Infof("Rate Limit Policies Internal Map: %v", ratelimitPolicies)
		} else if strings.EqualFold(policyEvent.PolicyType, "SUBSCRIPTION") {
			logger.LoggerMessaging.Infof("Policy: %s for policy type: %s", policyEvent.PolicyName, policyEvent.PolicyType)
			synchronizer.FetchSubscriptionRateLimitPoliciesOnEvent(policyEvent.PolicyName, policyEvent.TenantDomain, c, false)
			ratelimitPolicies := managementserver.GetAllRateLimitPolicies()
			logger.LoggerMessaging.Infof("Rate Limit Policies Internal Map: %v", ratelimitPolicies)
		}
	} else if strings.EqualFold(eventType, eventConstants.PolicyUpdate) {
		if strings.EqualFold(policyEvent.PolicyType, "API") {
			logger.LoggerMessaging.Infof("Policy: %s for policy type: %s for tenant: %s", policyEvent.PolicyName, policyEvent.PolicyType, policyEvent.TenantDomain)
			synchronizer.FetchRateLimitPoliciesOnEvent(policyEvent.PolicyName, policyEvent.TenantDomain, c)
			ratelimitPolicies := managementserver.GetAllRateLimitPolicies()
			logger.LoggerMessaging.Infof("Rate Limit Policies Internal Map: %v", ratelimitPolicies)
		} else if strings.EqualFold(policyEvent.PolicyType, "SUBSCRIPTION") {
			logger.LoggerMessaging.Infof("Policy: %s for policy type: %s", policyEvent.PolicyName, policyEvent.PolicyType)
			synchronizer.FetchSubscriptionRateLimitPoliciesOnEvent(policyEvent.PolicyName, policyEvent.TenantDomain, c, false)
			ratelimitPolicies := managementserver.GetAllRateLimitPolicies()
			logger.LoggerMessaging.Infof("Rate Limit Policies Internal Map: %v", ratelimitPolicies)
		}
	} else if strings.EqualFold(eventType, eventConstants.PolicyDelete) {
		if strings.EqualFold(policyEvent.PolicyType, "API") {
			logger.LoggerMessaging.Infof("Policy: %s for policy type: %s", policyEvent.PolicyName, policyEvent.PolicyType)
			managementserver.DeleteRateLimitPolicy(policyEvent.PolicyName, policyEvent.TenantDomain)
			ratelimitPolicies := managementserver.GetAllRateLimitPolicies()
			logger.LoggerMessaging.Infof("Rate Limit Policies Internal Map: %v", ratelimitPolicies)
		} else if strings.EqualFold(policyEvent.PolicyType, "SUBSCRIPTION") {
			logger.LoggerMessaging.Infof("Policy: %s for policy type: %s", policyEvent.PolicyName, policyEvent.PolicyType)
			managementserver.DeleteSubscriptionPolicy(policyEvent.PolicyName, policyEvent.TenantDomain)
			crName := transformer.GeneratePolicyCRName(policyEvent.PolicyName, policyEvent.TenantDomain, "rate-limiting", "subscription")
			internalk8sClient.UnDeployKongPluginCR(crName, c, conf)
			// TODO: undeploy AI ratelimit plugin
			ratelimitPolicies := managementserver.GetAllRateLimitPolicies()
			logger.LoggerMessaging.Infof("Rate Limit Policies Internal Map: %v", ratelimitPolicies)
		}
	}
}

// HandleAIProviderEvents to process AI Provider related events
func HandleAIProviderEvents(data []byte, eventType string, client client.Client) {
	var aiProviderEvent msg.AIProviderEvent
	aiProviderEventErr := json.Unmarshal([]byte(string(data)), &aiProviderEvent)
	if aiProviderEventErr != nil {
		logger.LoggerMessaging.Errorf("Error occurred while unmarshalling AI Provider event data %v", aiProviderEventErr)
		return
	}

	logger.LoggerMessaging.Infof("AI provider event received: %+v", aiProviderEvent)
}

// HandleScopeEvents to process scope related events
func HandleScopeEvents(data []byte, eventType string, client client.Client) {
	var scopeEvent msg.ScopeEvent
	scopeEventErr := json.Unmarshal([]byte(string(data)), &scopeEvent)
	if scopeEventErr != nil {
		logger.LoggerMessaging.Errorf("Error occurred while unmarshalling scope event data %v", scopeEventErr)
		return
	}

	logger.LoggerMessaging.Infof("Scope event received: %+v", scopeEvent)
}

func belongsToTenant(tenantDomain string) bool {
	// TODO : enable this once the events are fixed in apim
	// return config.GetControlPlaneConnectedTenantDomain() == tenantDomain
	return true
}

func isLaterEvent(timeStampMap map[string]int64, mapKey string, currentTimeStamp int64) bool {
	if timeStamp, ok := timeStampMap[mapKey]; ok {
		if timeStamp > currentTimeStamp {
			return true
		}
	}
	timeStampMap[mapKey] = currentTimeStamp
	return false
}

func marshalAppAttributes(attributes interface{}) map[string]string {
	attributesMap := make(map[string]string)
	if attributes != nil {
		for key, value := range attributes.(map[string]interface{}) {
			attributesMap[key] = value.(string)
		}
	}
	return attributesMap
}

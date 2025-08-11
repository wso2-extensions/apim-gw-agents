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

/*
 * Package "synchronizer" contains artifacts relate to fetching APIs and
 * API related updates from the control plane event-hub.
 * This file contains functions to retrieve APIs and API updates.
 */

package synchronizer

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	pkgAuth "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/auth"
	eventhub "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"
	logger "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/loggers"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/managementserver"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/tlsutils"
)

const (
	policiesEndpoint                    string = "internal/data/v1/api-policies"
	policiesByNameEndpoint              string = "internal/data/v1/api-policies?policyName="
	subscriptionsPoliciesEndpoint       string = "internal/data/v1/subscription-policies"
	subscriptionsPoliciesByNameEndpoint string = "internal/data/v1/subscription-policies?policyName="
)

// FetchRateLimitPoliciesOnEvent fetches the policies from the control plane on the start up and notification event updates
func FetchRateLimitPoliciesOnEvent(ratelimitName string, organization string) ([]eventhub.RateLimitPolicy, string) {
	logger.LoggerSync.Info("Fetching RateLimit Policies from Control Plane.")

	// Read configurations and derive the eventHub details
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		// This has to be error. For debugging purpose info
		logger.LoggerSync.Errorf("Error reading configs: %v", errReadConfig)
	}
	// Populate data from the config
	ehConfigs := conf.ControlPlane
	ehURL := ehConfigs.ServiceURL
	// If the eventHub URL is configured with trailing slash
	if strings.HasSuffix(ehURL, "/") {
		if ratelimitName != "" {
			ehURL += policiesByNameEndpoint + ratelimitName
		} else {
			ehURL += policiesEndpoint
		}
	} else {
		if ratelimitName != "" {
			ehURL += "/" + policiesByNameEndpoint + ratelimitName
		} else {
			ehURL += "/" + policiesEndpoint
		}
	}

	logger.LoggerSync.Debugf("Fetching RateLimit Policies from the URL %v: ", ehURL)

	ehUname := ehConfigs.Username
	ehPass := ehConfigs.Password
	basicAuth := "Basic " + pkgAuth.GetBasicAuth(ehUname, ehPass)

	// Check if TLS is enabled
	skipSSL := ehConfigs.SkipSSLVerification

	// Create a HTTP request
	req, err := http.NewRequest("GET", ehURL, nil)
	if err != nil {
		logger.LoggerSync.Errorf("Error while creating http request for RateLimit Policies Endpoint : %v", err)
	}

	var queryParamMap map[string]string

	if queryParamMap != nil && len(queryParamMap) > 0 {
		q := req.URL.Query()
		// Making necessary query parameters for the request
		for queryParamKey, queryParamValue := range queryParamMap {
			q.Add(queryParamKey, queryParamValue)
		}
		req.URL.RawQuery = q.Encode()
	}
	// Setting authorization header
	req.Header.Set(Authorization, basicAuth)

	if organization != "" {
		logger.LoggerSync.Debugf("Setting the organization header for the request: %v", organization)
		req.Header.Set("xWSO2Tenant", organization)
	} else {
		logger.LoggerSync.Debugf("Setting the organization header for the request: %v", "ALL")
		req.Header.Set("xWSO2Tenant", "ALL")
	}

	// Make the request
	logger.LoggerSync.Debug("Sending the control plane request")
	resp, err := tlsutils.InvokeControlPlane(req, skipSSL)
	var errorMsg string
	if err != nil {
		errorMsg = "Error occurred while calling the REST API: " + policiesEndpoint
		return make([]eventhub.RateLimitPolicy, 0), errorMsg
	}
	responseBytes, err := ioutil.ReadAll(resp.Body)
	logger.LoggerSync.Debugf("Response String received for Policies: %v", string(responseBytes))

	if err != nil {
		errorMsg = "Error occurred while reading the response received for: " + policiesEndpoint
		return make([]eventhub.RateLimitPolicy, 0), errorMsg
	}

	if resp.StatusCode == http.StatusOK {
		var rateLimitPolicyList eventhub.RateLimitPolicyList
		err := json.Unmarshal(responseBytes, &rateLimitPolicyList)
		if err != nil {
			logger.LoggerSync.Errorf("Error occurred while unmarshelling RateLimit Policies event data %v", err)
			return nil, ""
		}
		logger.LoggerSync.Debugf("Policies received: %+v", rateLimitPolicyList.List)
		var rateLimitPolicies []eventhub.RateLimitPolicy = rateLimitPolicyList.List
		for _, policy := range rateLimitPolicies {
			if policy.DefaultLimit.RequestCount.TimeUnit == "min" {
				policy.DefaultLimit.RequestCount.TimeUnit = "Minute"
			} else if policy.DefaultLimit.RequestCount.TimeUnit == "hours" {
				policy.DefaultLimit.RequestCount.TimeUnit = "Hour"
			} else if policy.DefaultLimit.RequestCount.TimeUnit == "days" {
				policy.DefaultLimit.RequestCount.TimeUnit = "Day"
			}
			managementserver.AddRateLimitPolicy(policy)
		}
		return rateLimitPolicies, ""
	}

	errorMsg = "Failed to fetch data! " + policiesEndpoint + " responded with " + strconv.Itoa(resp.StatusCode)
	return make([]eventhub.RateLimitPolicy, 0), errorMsg
}

// FetchSubscriptionRateLimitPoliciesOnEvent fetches the policies from the control plane on the start up and notification event updates
func FetchSubscriptionRateLimitPoliciesOnEvent(ratelimitName string, organization string) ([]eventhub.SubscriptionPolicy, string) {
	logger.LoggerSync.Info("Fetching Subscription RateLimit Policies from Control Plane.")

	// Read configurations and derive the eventHub details
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		// This has to be error. For debugging purpose info
		logger.LoggerSync.Errorf("Error reading configs: %v", errReadConfig)
	}
	// Populate data from the config
	ehConfigs := conf.ControlPlane
	ehURL := ehConfigs.ServiceURL
	// If the eventHub URL is configured with trailing slash
	if strings.HasSuffix(ehURL, "/") {
		if ratelimitName != "" {
			ehURL += subscriptionsPoliciesByNameEndpoint + ratelimitName
		} else {
			ehURL += subscriptionsPoliciesEndpoint
		}
	} else {
		if ratelimitName != "" {
			ehURL += "/" + subscriptionsPoliciesByNameEndpoint + ratelimitName
		} else {
			ehURL += "/" + subscriptionsPoliciesEndpoint
		}
	}

	logger.LoggerSync.Infof("Fetching Subscription RateLimit Policies from the URL %v: ", ehURL)

	ehUname := ehConfigs.Username
	ehPass := ehConfigs.Password
	basicAuth := "Basic " + pkgAuth.GetBasicAuth(ehUname, ehPass)

	// Check if TLS is enabled
	skipSSL := ehConfigs.SkipSSLVerification

	// Create a HTTP request
	req, err := http.NewRequest("GET", ehURL, nil)
	if err != nil {
		logger.LoggerSync.Errorf("Error while creating http request for Subscription RateLimit Policies Endpoint : %v", err)
	}

	// Setting authorization header
	req.Header.Set(Authorization, basicAuth)

	if organization != "" {
		logger.LoggerSync.Debugf("Setting the organization header for the request: %v", organization)
		req.Header.Set("xWSO2Tenant", organization)
	} else {
		logger.LoggerSync.Debugf("Setting the organization header for the request: %v", "ALL")
		req.Header.Set("xWSO2Tenant", "ALL")
	}

	// Make the request
	logger.LoggerSync.Debug("Sending the control plane request")
	resp, err := tlsutils.InvokeControlPlane(req, skipSSL)
	var errorMsg string
	if err != nil {
		errorMsg = "Error occurred while calling the REST API: " + policiesEndpoint
		return make([]eventhub.SubscriptionPolicy, 0), errorMsg
	}
	responseBytes, err := ioutil.ReadAll(resp.Body)
	logger.LoggerSync.Debugf("Response String received for Policies: %v", string(responseBytes))

	if err != nil {
		errorMsg = "Error occurred while reading the response received for: " + policiesEndpoint
		return make([]eventhub.SubscriptionPolicy, 0), errorMsg
	}

	if resp.StatusCode == http.StatusOK {
		var rateLimitPolicyList eventhub.SubscriptionPolicyList
		err := json.Unmarshal(responseBytes, &rateLimitPolicyList)
		if err != nil {
			logger.LoggerSync.Errorf("Error occurred while unmarshelling Subscription RateLimit Policies event data %v", err)
			return nil, ""
		}
		logger.LoggerSync.Infof("Policies received: %+v", rateLimitPolicyList.List)
		var rateLimitPolicies []eventhub.SubscriptionPolicy = rateLimitPolicyList.List
		for _, policy := range rateLimitPolicies {
			if policy.QuotaType == "aiApiQuota" {
				if policy.DefaultLimit.AiAPIQuota != nil {
					switch policy.DefaultLimit.AiAPIQuota.TimeUnit {
					case "min":
						policy.DefaultLimit.AiAPIQuota.TimeUnit = "Minute"
					case "hours":
						policy.DefaultLimit.AiAPIQuota.TimeUnit = "Hour"
					case "days":
						policy.DefaultLimit.AiAPIQuota.TimeUnit = "Day"
					default:
						continue
					}
					if policy.DefaultLimit.AiAPIQuota.PromptTokenCount == nil && policy.DefaultLimit.AiAPIQuota.TotalTokenCount != nil {
						policy.DefaultLimit.AiAPIQuota.PromptTokenCount = policy.DefaultLimit.AiAPIQuota.TotalTokenCount
					}
					if policy.DefaultLimit.AiAPIQuota.CompletionTokenCount == nil && policy.DefaultLimit.AiAPIQuota.TotalTokenCount != nil {
						policy.DefaultLimit.AiAPIQuota.CompletionTokenCount = policy.DefaultLimit.AiAPIQuota.TotalTokenCount
					}
					if policy.DefaultLimit.AiAPIQuota.TotalTokenCount == nil && policy.DefaultLimit.AiAPIQuota.PromptTokenCount != nil && policy.DefaultLimit.AiAPIQuota.CompletionTokenCount != nil {
						total := *policy.DefaultLimit.AiAPIQuota.PromptTokenCount + *policy.DefaultLimit.AiAPIQuota.CompletionTokenCount
						policy.DefaultLimit.AiAPIQuota.TotalTokenCount = &total
					}
					managementserver.AddSubscriptionPolicy(policy)
				}
			} else {
				if policy.DefaultLimit.RequestCount.TimeUnit == "min" {
					policy.DefaultLimit.RequestCount.TimeUnit = "Minute"
				} else if policy.DefaultLimit.RequestCount.TimeUnit == "hours" {
					policy.DefaultLimit.RequestCount.TimeUnit = "Hour"
				} else if policy.DefaultLimit.RequestCount.TimeUnit == "days" {
					policy.DefaultLimit.RequestCount.TimeUnit = "Day"
				}
				managementserver.AddSubscriptionPolicy(policy)
			}
		}
		return rateLimitPolicies, ""
	}

	errorMsg = "Failed to fetch data! " + policiesEndpoint + " responded with " +
		strconv.Itoa(resp.StatusCode)
	return make([]eventhub.SubscriptionPolicy, 0), errorMsg
}

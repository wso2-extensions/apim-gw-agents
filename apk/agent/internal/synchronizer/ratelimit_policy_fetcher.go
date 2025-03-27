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
	"time"

	k8sclient "github.com/wso2-extensions/apim-gw-agents/apk/agent/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-agents/apk/agent/internal/loggers"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	sync "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/synchronizer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FetchRateLimitPoliciesOnEvent fetches the policies from the control plane on the start up and notification event updates
func FetchRateLimitPoliciesOnEvent(ratelimitName string, organization string, c client.Client) {
	// Read configurations and derive the eventHub details
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		// This has to be error. For debugging purpose info
		logger.LoggerSynchronizer.Errorf("Error reading configs: %v", errReadConfig)
	}

	rateLimitPolicies, errorMsg := sync.FetchRateLimitPoliciesOnEvent(ratelimitName, organization)
	if rateLimitPolicies != nil {
		if len(rateLimitPolicies) == 0 && errorMsg != "" {
			go retryRLPFetchData(conf, errorMsg, c)
		} else {
			for _, policy := range rateLimitPolicies {
				if policy.DefaultLimit.RequestCount.TimeUnit == "min" {
					policy.DefaultLimit.RequestCount.TimeUnit = "Minute"
				} else if policy.DefaultLimit.RequestCount.TimeUnit == "hour" {
					policy.DefaultLimit.RequestCount.TimeUnit = "Hour"
				} else if policy.DefaultLimit.RequestCount.TimeUnit == "day" {
					policy.DefaultLimit.RequestCount.TimeUnit = "Day"
				}
				// Update the exisitng rate limit policies with current policy
				k8sclient.UpdateRateLimitPolicyCR(policy, c)
			}
		}
	}
}

// FetchSubscriptionRateLimitPoliciesOnEvent fetches the policies from the control plane on the start up and notification event updates
func FetchSubscriptionRateLimitPoliciesOnEvent(ratelimitName string, organization string, c client.Client, cleanupDeletedPolicies bool) {
	// Read configurations and derive the eventHub details
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		// This has to be error. For debugging purpose info
		logger.LoggerSynchronizer.Errorf("Error reading configs: %v", errReadConfig)
	}

	rateLimitPolicies, errorMsg := sync.FetchSubscriptionRateLimitPoliciesOnEvent(ratelimitName, organization)
	if rateLimitPolicies != nil {
		if len(rateLimitPolicies) == 0 && errorMsg != "" {
			go retrySubscriptionRLPFetchData(conf, errorMsg, c)
		} else {
			if cleanupDeletedPolicies {
				// This logic is executed once at the startup time so no need to worry about the nested for loops for performance.
				// Fetch all AiRatelimitPolicies
				airls, _, retrieveAllAIRLErr := k8sclient.RetrieveAllAIRatelimitPoliciesSFromK8s(c, "")
				rls, _, retrieveAllRLErr := k8sclient.RetrieveAllRatelimitPoliciesSFromK8s(c, "")
				if retrieveAllAIRLErr == nil {
					for _, airl := range airls {
						if cpName, exists := airl.ObjectMeta.Labels["CPName"]; exists {
							found := false
							for _, policy := range rateLimitPolicies {
								if policy.Name == cpName {
									found = true
									break
								}
							}
							if !found {
								// Delete the airatelimitpolicy
								k8sclient.UndeploySubscriptionAIRateLimitPolicyCR(airl.Name, c)
							}
						}
					}
				} else {
					logger.LoggerSynchronizer.Errorf("Error while fetching airatelimitpolicies for cleaning up outdataed crs. Error: %+v", retrieveAllAIRLErr)
				}
				if retrieveAllRLErr == nil {
					for _, rl := range rls {
						if cpName, exists := rl.ObjectMeta.Labels["CPName"]; exists {
							found := false
							for _, policy := range rateLimitPolicies {
								if policy.Name == cpName {
									found = true
									break
								}
							}
							if !found {
								// Delete the airatelimitpolicy
								k8sclient.UnDeploySubscriptionRateLimitPolicyCR(rl.Name, c)
							}
						}
					}
				} else {
					logger.LoggerSynchronizer.Errorf("Error while fetching ratelimitpolicies for cleaning up outdataed crs. Error: %+v", retrieveAllRLErr)
				}
			}

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
							logger.LoggerSynchronizer.Errorf("Unsupported timeunit %s", policy.DefaultLimit.AiAPIQuota.TimeUnit)
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
						// managementserver.AddSubscriptionPolicy(policy)
						k8sclient.DeployAIRateLimitPolicyFromCPPolicy(policy, c)
					} else {
						logger.LoggerSynchronizer.Errorf("AIQuota type response recieved but no data found. %+v", policy.DefaultLimit)
					}
				} else {
					if policy.DefaultLimit.RequestCount.TimeUnit == "min" {
						policy.DefaultLimit.RequestCount.TimeUnit = "Minute"
					} else if policy.DefaultLimit.RequestCount.TimeUnit == "hours" {
						policy.DefaultLimit.RequestCount.TimeUnit = "Hour"
					} else if policy.DefaultLimit.RequestCount.TimeUnit == "days" {
						policy.DefaultLimit.RequestCount.TimeUnit = "Day"
					}
					// managementserver.AddSubscriptionPolicy(policy)
					logger.LoggerSynchronizer.Infof("RateLimit Policy added to internal map: %v", policy)
					// Update the exisitng rate limit policies with current policy
					k8sclient.DeploySubscriptionRateLimitPolicyCR(policy, c)
				}
			}
		}
	}
}

func retryRLPFetchData(conf *config.Config, errorMessage string, c client.Client) {
	logger.LoggerSynchronizer.Debugf("Time Duration for retrying: %v",
		conf.ControlPlane.RetryInterval*time.Second)
	time.Sleep(conf.ControlPlane.RetryInterval * time.Second)
	FetchRateLimitPoliciesOnEvent("", "", c)
	retryAttempt++
	if retryAttempt >= retryCount {
		logger.LoggerSynchronizer.Error(errorMessage)
		return
	}
}

func retrySubscriptionRLPFetchData(conf *config.Config, errorMessage string, c client.Client) {
	logger.LoggerSynchronizer.Debugf("Time Duration for retrying: %v",
		conf.ControlPlane.RetryInterval*time.Second)
	time.Sleep(conf.ControlPlane.RetryInterval * time.Second)
	FetchSubscriptionRateLimitPoliciesOnEvent("", "", c, false)
	retryAttempt++
	if retryAttempt >= retryCount {
		logger.LoggerSynchronizer.Error(errorMessage)
		return
	}
}

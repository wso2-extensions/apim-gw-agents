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

	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	sync "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/synchronizer"
	internalk8sClient "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/pkg/transformer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FetchRateLimitPoliciesOnEvent fetches the policies from the control plane on the start up and notification event updates
func FetchRateLimitPoliciesOnEvent(ratelimitName string, organization string, c client.Client) {
	logger.LoggerSynchronizer.Debugf("Starting rate limit policy fetch|ratelimitName:%s organization:%s\n", ratelimitName, organization)

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
				if policy.QuotaType == "aiApiQuota" {
					// TODO: implement ai rate limits
					logger.LoggerSynchronizer.Printf("AI API Quota ratelimit policy %v", policy)
				} else {
					if policy.DefaultLimit.RequestCount.TimeUnit != "" {
						rateLimitConfig := transformer.KongPluginConfig{
							"limit_by": "service",
						}
						// Add corresponding rate limit configuration
						transformer.PrepareRateLimit(&rateLimitConfig, policy.DefaultLimit.RequestCount.TimeUnit, policy.DefaultLimit.RequestCount.UnitTime)
						// Create and deploy rate-limit plugins
						ratelimitPlugin := transformer.GenerateKongPlugin(nil, "rate-limiting", "consumer", rateLimitConfig, true)
						ratelimitPlugin.ObjectMeta.Name = transformer.GeneratePolicyCRName(policy.Name, policy.TenantDomain, "rate-limiting", "policy")
						ratelimitPlugin.Namespace = conf.DataPlane.Namespace
						internalk8sClient.DeployKongPluginCR(ratelimitPlugin, c)
					}
				}
			}
		}
	}
}

// FetchSubscriptionRateLimitPoliciesOnEvent fetches the policies from the control plane on the start up and notification event updates
func FetchSubscriptionRateLimitPoliciesOnEvent(ratelimitName string, organization string, c client.Client, cleanupDeletedPolicies bool) {
	logger.LoggerSynchronizer.Debugf("Starting subscription rate limit policy fetch|ratelimitName:%s organization:%s cleanupDeletedPolicies:%v\n", ratelimitName, organization, cleanupDeletedPolicies)

	// read configurations and derive the eventHub details
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		// this has to be error. For debugging purpose info
		logger.LoggerSynchronizer.Errorf("Error reading configs: %v", errReadConfig)
	}

	rateLimitPolicies, errorMsg := sync.FetchSubscriptionRateLimitPoliciesOnEvent(ratelimitName, organization)
	if rateLimitPolicies != nil {
		if len(rateLimitPolicies) == 0 && errorMsg != "" {
			go retrySubscriptionRLPFetchData(conf, errorMsg, c)
		} else {
			for _, policy := range rateLimitPolicies {
				if policy.QuotaType == "aiApiQuota" {
					// TODO: implement ai rate limits
					logger.LoggerSynchronizer.Printf("AI API Quota ratelimit policy %v", policy)
				} else {
					rateLimitConfig := transformer.KongPluginConfig{
						"limit_by": "consumer",
					}
					// add corresponding rate limit configuration
					transformer.PrepareRateLimit(&rateLimitConfig, policy.DefaultLimit.RequestCount.TimeUnit, policy.DefaultLimit.RequestCount.UnitTime)
					// create and deploy subscription rate-limit plugins
					ratelimitPlugin := transformer.GenerateKongPlugin(nil, "rate-limiting", "subscriber", rateLimitConfig, true)
					ratelimitPlugin.ObjectMeta.Name = transformer.GeneratePolicyCRName(policy.Name, policy.TenantDomain, "rate-limiting", "subscription")
					ratelimitPlugin.Namespace = conf.DataPlane.Namespace
					internalk8sClient.DeployKongPluginCR(ratelimitPlugin, c)
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

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

/*
 * Package "synchronizer" contains artifacts relate to fetching APIs and
 * API related updates from the control plane event-hub.
 * This file contains functions to retrieve APIs and API updates.
 */

package synchronizer

import (
	"time"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	sync "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/synchronizer"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	internalk8sClient "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/loggers"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/transformer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FetchRateLimitPoliciesOnEvent fetches the policies from the control plane on the start up and notification event updates
func FetchRateLimitPoliciesOnEvent(ratelimitName string, organization string, c client.Client) {
	logger.LoggerSynchronizer.Debugf("Starting rate limit policy fetch|ratelimitName:%s organization:%s\n", ratelimitName, organization)

	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		logger.LoggerSynchronizer.Errorf("Error reading configs: %v", errReadConfig)
	}

	rateLimitPolicies, errorMsg := sync.FetchRateLimitPoliciesOnEvent(ratelimitName, organization)
	if rateLimitPolicies != nil {
		if len(rateLimitPolicies) == 0 && errorMsg != constants.EmptyString {
			logger.LoggerSynchronizer.Warnf("Error fetching rate limit policies in retry attempt %d : %s", retryAttempt, errorMsg)
			go retryRLPFetchData(ratelimitName, organization, conf, errorMsg, c)
		} else {
			for _, policy := range rateLimitPolicies {
				switch policy.QuotaType {
				case constants.AIAPIQuotaType:
					logger.LoggerSynchronizer.Infof("AI rate limits are not yet implemented for policy: %s", policy.Name)
				case constants.RequestCountType:
					deployRateLimitPlugin(conf, policy.Name, policy.TenantDomain, constants.ServiceLimitBy, constants.ConsumerLimitBy, constants.PolicyTypeKey,
						policy.DefaultLimit.RequestCount.TimeUnit, policy.DefaultLimit.RequestCount.UnitTime, policy.DefaultLimit.RequestCount.RequestCount, c)
				case constants.EventCountType:
					deployRateLimitPlugin(conf, policy.Name, policy.TenantDomain, constants.ServiceLimitBy, constants.ConsumerLimitBy, constants.PolicyTypeKey,
						policy.DefaultLimit.EventCount.TimeUnit, policy.DefaultLimit.EventCount.UnitTime, policy.DefaultLimit.EventCount.EventCount, c)
				}
			}
		}
	}
}

// FetchSubscriptionRateLimitPoliciesOnEvent fetches the policies from the control plane on the start up and notification event updates
func FetchSubscriptionRateLimitPoliciesOnEvent(ratelimitName string, organization string, c client.Client, cleanupDeletedPolicies bool) {
	logger.LoggerSynchronizer.Debugf("Starting subscription rate limit policy fetch|ratelimitName:%s organization:%s cleanupDeletedPolicies:%v\n",
		ratelimitName, organization, cleanupDeletedPolicies)

	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		logger.LoggerSynchronizer.Errorf("Error reading configs: %v", errReadConfig)
	}

	rateLimitPolicies, errorMsg := sync.FetchSubscriptionRateLimitPoliciesOnEvent(ratelimitName, organization)
	if rateLimitPolicies != nil {
		if len(rateLimitPolicies) == 0 && errorMsg != constants.EmptyString {
			go retrySubscriptionRLPFetchData(ratelimitName, organization, conf, errorMsg, c)
		} else {
			for _, policy := range rateLimitPolicies {
				switch policy.QuotaType {
				case constants.AIAPIQuotaType:
					logger.LoggerSynchronizer.Infof("AI rate limits are not yet implemented for subscription policy: %s", policy.Name)
				case constants.RequestCountType:
					deployRateLimitPlugin(conf, policy.Name, policy.TenantDomain, constants.ConsumerLimitBy, constants.SubscriberTypeKey, constants.SubscriptionTypeKey,
						policy.DefaultLimit.RequestCount.TimeUnit, policy.DefaultLimit.RequestCount.UnitTime, policy.DefaultLimit.RequestCount.RequestCount, c)
				case constants.EventCountType:
					deployRateLimitPlugin(conf, policy.Name, policy.TenantDomain, constants.ConsumerLimitBy, constants.SubscriberTypeKey, constants.SubscriptionTypeKey,
						policy.DefaultLimit.EventCount.TimeUnit, policy.DefaultLimit.EventCount.UnitTime, policy.DefaultLimit.EventCount.EventCount, c)
				}
			}
		}
	}
}

func retryRLPFetchData(ratelimitName string, organization string, conf *config.Config, errorMessage string, c client.Client) {
	logger.LoggerSynchronizer.Debugf("Time Duration for retrying: %v",
		conf.ControlPlane.RetryInterval*time.Second)
	time.Sleep(conf.ControlPlane.RetryInterval * time.Second)
	FetchRateLimitPoliciesOnEvent(ratelimitName, organization, c)
	retryAttempt++
	if retryAttempt > constants.MaxRetries {
		logger.LoggerSynchronizer.Error(errorMessage)
		return
	}
}

func retrySubscriptionRLPFetchData(ratelimitName string, organization string, conf *config.Config, errorMessage string, c client.Client) {
	logger.LoggerSynchronizer.Debugf("Time Duration for retrying: %v",
		conf.ControlPlane.RetryInterval*time.Second)
	time.Sleep(conf.ControlPlane.RetryInterval * time.Second)
	FetchSubscriptionRateLimitPoliciesOnEvent(ratelimitName, organization, c, false)
	retryAttempt++
	if retryAttempt > constants.MaxRetries {
		logger.LoggerSynchronizer.Error(errorMessage)
		return
	}
}

// deployRateLimitPlugin creates and deploys a rate limit plugin with the given configuration
func deployRateLimitPlugin(conf *config.Config, policyName, tenantDomain, limitBy, pluginType, policyType, timeUnit string, unitTime, count int, c client.Client) {
	logger.LoggerSynchronizer.Infof("Request to deploy rate limit plugin for policy: %s, tenant: %s, type: %s", policyName, tenantDomain, policyType)

	if timeUnit == constants.EmptyString {
		return
	}

	rateLimitConfig := transformer.KongPluginConfig{
		constants.PluginLimitByField: limitBy,
	}

	transformer.PrepareRateLimit(&rateLimitConfig, timeUnit, unitTime, count)

	ratelimitPlugin := transformer.GenerateKongPlugin(nil, constants.RateLimitingPlugin, pluginType, rateLimitConfig, true)
	ratelimitPlugin.ObjectMeta.Name = transformer.GeneratePolicyCRName(policyName, tenantDomain, constants.RateLimitingPlugin, policyType)
	ratelimitPlugin.Namespace = conf.DataPlane.Namespace
	internalk8sClient.DeployKongPluginCR(ratelimitPlugin, c)
	logger.LoggerSynchronizer.Infof("Successfully deployed rate limit plugin for policy: %s, tenant: %s, type: %s", policyName, tenantDomain, policyType)
}

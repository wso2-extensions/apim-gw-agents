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
package managementserver

import (
	eventHub "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub/types"
)

var (
	rateLimitPolicyMap    map[string]eventHub.RateLimitPolicy
	aiProviderMap         map[string]eventHub.AIProvider
	subscriptionMap       map[string]Subscription
	subscriptionPolicyMap map[string]eventHub.SubscriptionPolicy
)

func init() {
	rateLimitPolicyMap = make(map[string]eventHub.RateLimitPolicy)
	aiProviderMap = make(map[string]eventHub.AIProvider)
	subscriptionMap = make(map[string]Subscription)
	subscriptionPolicyMap = make(map[string]eventHub.SubscriptionPolicy)
}

// AddAIProvider adds an AI provider to the aiProviderMap
func AddAIProvider(aiProvider eventHub.AIProvider) {
	aiProviderMap[aiProvider.ID] = aiProvider
}

// GetAIProvider returns an AI provider from the aiProviderMap
func GetAIProvider(id string) eventHub.AIProvider {
	return aiProviderMap[id]
}

// DeleteAIProvider deletes an AI provider from the aiProviderMap
func DeleteAIProvider(id string) {
	delete(aiProviderMap, id)
}

// GetAllAIProviders returns all the AI providers in the aiProviderMap
func GetAllAIProviders() []eventHub.AIProvider {
	var aiProviders []eventHub.AIProvider
	for _, aiProvider := range aiProviderMap {
		aiProviders = append(aiProviders, aiProvider)
	}
	return aiProviders
}

// AddRateLimitPolicy adds a rate limit policy to the rateLimitPolicyMap
func AddRateLimitPolicy(rateLimitPolicy eventHub.RateLimitPolicy) {
	rateLimitPolicyMap[rateLimitPolicy.Name+rateLimitPolicy.TenantDomain] = rateLimitPolicy
}

// AddSubscriptionPolicy adds a rate limit policy to the subscriptionPolicyMap
func AddSubscriptionPolicy(rateLimitPolicy eventHub.SubscriptionPolicy) {
	subscriptionPolicyMap[rateLimitPolicy.Name+rateLimitPolicy.TenantDomain] = rateLimitPolicy
}

// GetSubscriptionPolicy returns a subscription policy from the subscriptionPolicyMap
func GetSubscriptionPolicy(name string, tenantDomain string) eventHub.SubscriptionPolicy {
	return subscriptionPolicyMap[name+tenantDomain]
}

// GetSubscriptionPolicies return the subscription policy map
func GetSubscriptionPolicies() map[string]eventHub.SubscriptionPolicy {
	return subscriptionPolicyMap
}

// GetRateLimitPolicy returns a rate limit policy from the rateLimitPolicyMap
func GetRateLimitPolicy(name string, tenantDomain string) eventHub.RateLimitPolicy {
	return rateLimitPolicyMap[name+tenantDomain]
}

// GetAllRateLimitPolicies returns all the rate limit policies in the rateLimitPolicyMap
func GetAllRateLimitPolicies() []eventHub.RateLimitPolicy {
	var rateLimitPolicies []eventHub.RateLimitPolicy
	for _, rateLimitPolicy := range rateLimitPolicyMap {
		rateLimitPolicies = append(rateLimitPolicies, rateLimitPolicy)
	}
	return rateLimitPolicies
}

// DeleteRateLimitPolicy deletes a rate limit policy from the rateLimitPolicyMap
func DeleteRateLimitPolicy(name string, tenantDomain string) {
	delete(rateLimitPolicyMap, name+tenantDomain)
}

// DeleteSubscriptionPolicy deletes a subscription policy from the subscriptionPolicyMap
func DeleteSubscriptionPolicy(name string, tenantDomain string) {
	delete(subscriptionPolicyMap, name+tenantDomain)
}

// UpdateRateLimitPolicy updates a rate limit policy in the rateLimitPolicyMap
func UpdateRateLimitPolicy(name string, tenantDomain string, rateLimitPolicy eventHub.RateLimitPolicy) {
	rateLimitPolicyMap[name+tenantDomain] = rateLimitPolicy
}

// AddSubscription adds a subscription to the subscriptionMap
func AddSubscription(subscription Subscription) {
	subscriptionMap[subscription.UUID] = subscription
}

// GetAllSubscriptions returns all the subscriptions in the subscriptionMap
func GetAllSubscriptions() []Subscription {
	var subscriptions []Subscription
	for _, subscription := range subscriptionMap {
		subscriptions = append(subscriptions, subscription)
	}
	return subscriptions
}

// GetSubscription returns a subscription from the subscriptionMap
func GetSubscription(uuid string) Subscription {
	return subscriptionMap[uuid]
}

// DeleteSubscription deletes a subscription from the subscriptionMap
func DeleteSubscription(uuid string) {
	delete(subscriptionMap, uuid)
}

// UpdateSubscription updates a subscription in the subscriptionMap
func UpdateSubscription(uuid string, subscription Subscription) {
	subscriptionMap[uuid] = subscription
}

// DeleteAllSubscriptions deletes all the subscriptions in the subscriptionMap
func DeleteAllSubscriptions() {
	subscriptionMap = make(map[string]Subscription)
}

// AddAllSubscriptions adds all the subscriptions in the subscriptionMap
func AddAllSubscriptions(subscriptionMapTemp map[string]Subscription) {
	subscriptionMap = subscriptionMapTemp
}

// DeleteAllSubscriptionsByApplicationsUUID deletes all the subscriptions in the subscriptionMap
func DeleteAllSubscriptionsByApplicationsUUID(uuid string) {
	for _, subscription := range subscriptionMap {
		if subscription.Organization == uuid {
			delete(subscriptionMap, subscription.UUID)
		}
	}
}

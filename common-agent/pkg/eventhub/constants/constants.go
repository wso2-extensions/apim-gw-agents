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

package constants

// constant variables
const (
	APIEventType                = "API"
	ApplicationEventType        = "APPLICATION"
	SubscriptionEventType       = "SUBSCRIPTION"
	ScopeEventType              = "SCOPE"
	PolicyEventType             = "POLICY"
	RemoveAPIFromGateway        = "REMOVE_API_FROM_GATEWAY"
	DeployAPIToGateway          = "DEPLOY_API_IN_GATEWAY"
	ApplicationRegistration     = "APPLICATION_REGISTRATION_CREATE"
	RemoveApplicationKeyMapping = "REMOVE_APPLICATION_KEYMAPPING"
	APILifeCycleChange          = "LIFECYCLE_CHANGE"
	ApplicationCreate           = "APPLICATION_CREATE"
	ApplicationUpdate           = "APPLICATION_UPDATE"
	ApplicationDelete           = "APPLICATION_DELETE"
	SubscriptionCreate          = "SUBSCRIPTIONS_CREATE"
	SubscriptionUpdate          = "SUBSCRIPTIONS_UPDATE"
	SubscriptionDelete          = "SUBSCRIPTIONS_DELETE"
	PolicyCreate                = "POLICY_CREATE"
	PolicyUpdate                = "POLICY_UPDATE"
	PolicyDelete                = "POLICY_DELETE"
	BlockedStatus               = "BLOCKED"
	APIUpdate                   = "API_UPDATE"
	AIProviderEventType         = "LLM_PROVIDER"
	AIProviderCreate            = "LLM_PROVIDER_CREATE"
	AIProviderUpdate            = "LLM_PROVIDER_UPDATE"
	AIProviderDelete            = "LLM_PROVIDER_DELETE"
)

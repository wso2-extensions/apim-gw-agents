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
	"fmt"
	"slices"
	"strings"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	eventConstants "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/constants"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/constants"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/managementserver"
	msg "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/messaging"
	internalk8sClient "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/pkg/transformer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// HandleSubscriptionEvents to process subscription related events
func HandleSubscriptionEvents(data []byte, eventType string, c client.Client) {
	logger.LoggerMessaging.Debugf("Starting subscription event processing|EventType:%s\n", eventType)

	conf, _ := config.ReadConfigs()

	var subscriptionEvent msg.SubscriptionEvent
	subEventErr := json.Unmarshal([]byte(string(data)), &subscriptionEvent)
	if subEventErr != nil {
		logger.LoggerMessaging.Errorf("Error occurred while unmarshalling Subscription event data %v", subEventErr)
		return
	}
	if !belongsToTenant(subscriptionEvent.TenantDomain) {
		logger.LoggerMessaging.Debugf("Subscription event for the Application : %s and API %s is dropped due to having non related tenantDomain : %s",
			subscriptionEvent.ApplicationUUID, subscriptionEvent.APIUUID, subscriptionEvent.TenantDomain)
		return
	}

	if isLaterEvent(subsriptionsListTimeStampMap, fmt.Sprint(subscriptionEvent.SubscriptionID), subscriptionEvent.TimeStamp) {
		return
	}

	logger.LoggerMessaging.Infof("Received Subscription Event: %+v", subscriptionEvent)
	switch subscriptionEvent.Event.Type {
	case eventConstants.SubscriptionCreate:
		// create production consumer and acl credential
		createSubscription(subscriptionEvent, c, conf, constants.ProductionType)
		// create sandbox consumer and acl credential
		createSubscription(subscriptionEvent, c, conf, constants.SandboxType)
	case eventConstants.SubscriptionUpdate:
		// update production consumer and configurations
		updateSubscription(subscriptionEvent, c, conf, constants.ProductionType)
		// update sandbox consumer and configurations
		updateSubscription(subscriptionEvent, c, conf, constants.SandboxType)
	case eventConstants.SubscriptionDelete:
		// remove production ACL credentials and consumer
		removeSubscription(subscriptionEvent, c, conf, constants.ProductionType)
		// remove sandbox ACL credentials and consumer
		removeSubscription(subscriptionEvent, c, conf, constants.SandboxType)
	}
}

func createSubscription(subscriptionEvent msg.SubscriptionEvent, c client.Client, conf *config.Config, environment string) {
	logger.LoggerMessaging.Debugf("Creating subscription|ApplicationUUID:%s Environment:%s\n", subscriptionEvent.ApplicationUUID, environment)

	addCredentials := []string{}
	addAnnotations := []string{}

	// create and deploy kong acl secret CR
	aclCredentialSecretConfig := map[string]string{
		"group": transformer.GenerateACLGroupName(subscriptionEvent.APIName, environment),
	}
	subscriptionIdentifier := subscriptionEvent.APIUUID + environment
	aclCredentialSecret := transformer.GenerateK8sCredentialSecret(subscriptionEvent.ApplicationUUID, subscriptionIdentifier, "acl", aclCredentialSecretConfig)
	aclCredentialSecret.Namespace = conf.DataPlane.Namespace
	addCredentials = append(addCredentials, aclCredentialSecret.ObjectMeta.Name)
	internalk8sClient.DeploySecretCR(aclCredentialSecret, c)

	// update consumer subscription limit plugin annotation
	subscriptionPolicy := managementserver.GetSubscriptionPolicy(subscriptionEvent.PolicyID, subscriptionEvent.TenantDomain)
	logger.LoggerMessaging.Infof("Subscription Policy: %+v", subscriptionPolicy)
	if subscriptionPolicy.Name != "" && subscriptionPolicy.Name != "Unlimited" {
		rateLimitCRName := transformer.GeneratePolicyCRName(subscriptionPolicy.Name, subscriptionPolicy.TenantDomain, "rate-limiting", "subscription")
		addAnnotations = append(addAnnotations, rateLimitCRName)
	}

	// get available jwt credentials for the application
	jwtSecretCredentials := internalk8sClient.GetK8sSecrets(map[string]string{
		"applicationUUID":       subscriptionEvent.ApplicationUUID,
		"environment":           environment,
		"konghq.com/credential": "jwt",
	}, c, conf)
	for _, jwtSecretCredential := range jwtSecretCredentials {
		addCredentials = append(addCredentials, jwtSecretCredential.Name)
	}

	// update consumers credentials
	internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, environment, c, conf, addCredentials, nil)
	// update consumers annotations
	internalk8sClient.UpdateKongConsumerPluginAnnotation(subscriptionEvent.ApplicationUUID, environment, c, conf, addAnnotations, nil)

}

func updateSubscription(subscriptionEvent msg.SubscriptionEvent, c client.Client, conf *config.Config, environment string) {
	logger.LoggerMessaging.Debugf("Updating subscription|ApplicationUUID:%s Environment:%s\n", subscriptionEvent.ApplicationUUID, environment)

	var removeAnnotations []string
	var addAnnotations []string
	// retrieving current production subscription policy
	consumerName := transformer.GenerateConsumerName(subscriptionEvent.ApplicationUUID, environment)
	consumer := internalk8sClient.GetKongConsumerCR(consumerName, c, conf)

	if consumer == nil {
		logger.LoggerMessaging.Infof("Kong consumer credential not found for %v", environment)
	} else {
		subscriptionPolicy := managementserver.GetSubscriptionPolicy(subscriptionEvent.PolicyID, subscriptionEvent.TenantDomain)
		rateLimitCRName := transformer.GeneratePolicyCRName(subscriptionPolicy.Name, subscriptionPolicy.TenantDomain, "rate-limiting", "subscription")
		// handle subscription rate limiting
		if annotations, ok := consumer.Annotations["konghq.com/plugins"]; ok {
			annotationsArr := strings.Split(annotations, ",")
			if !slices.Contains(annotationsArr, rateLimitCRName) {
				// remove old subscription policy name
				for _, name := range annotationsArr {
					if strings.Contains(name, "subscription") && strings.Contains(name, "rate-limiting") {
						removeAnnotations = append(removeAnnotations, name)
						break
					}
				}

				// updating new subscription policy name
				if subscriptionPolicy.Name != "" && subscriptionPolicy.Name != "Unlimited" {
					addAnnotations = append(addAnnotations, rateLimitCRName)
				}

				internalk8sClient.UpdateKongConsumerPluginAnnotation(subscriptionEvent.ApplicationUUID, environment, c, conf, addAnnotations, removeAnnotations)
			}
		}

		// handle subscription state
		subscriptionIdentifier := subscriptionEvent.APIUUID + environment
		aclCredentialSecretName := transformer.GenerateSecretName(subscriptionEvent.ApplicationUUID, subscriptionIdentifier, "acl")
		credentials := []string{aclCredentialSecretName}
		switch subscriptionEvent.SubscriptionState {
		case "BLOCKED":
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.SandboxType, c, conf, nil, credentials)
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.ProductionType, c, conf, nil, credentials)
		case "PROD_ONLY_BLOCKED":
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.SandboxType, c, conf, credentials, nil)
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.ProductionType, c, conf, nil, credentials)
		case "UNBLOCKED":
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.SandboxType, c, conf, credentials, nil)
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.ProductionType, c, conf, credentials, nil)
		}
	}

}

func removeSubscription(subscriptionEvent msg.SubscriptionEvent, c client.Client, conf *config.Config, environment string) {
	logger.LoggerMessaging.Debugf("Removing subscription|ApplicationUUID:%s Environment:%s\n", subscriptionEvent.ApplicationUUID, environment)

	subscriptionIdentifier := subscriptionEvent.APIUUID + environment
	aclSecretCredentialName := transformer.GenerateSecretName(subscriptionEvent.ApplicationUUID, subscriptionIdentifier, "acl")

	// remove secret from kong consumer CR
	removeCredentials := []string{aclSecretCredentialName}
	internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, environment, c, conf, nil, removeCredentials)

	// remove acl secret credential
	internalk8sClient.UnDeploySecretCR(aclSecretCredentialName, c, conf)
}

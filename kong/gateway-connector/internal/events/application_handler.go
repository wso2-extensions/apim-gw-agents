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
	"strings"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	eventConstants "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub/constants"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib/constants"
	msg "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/messaging"
	internalk8sClient "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/loggers"
	pkgConstants "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/constants"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/transformer"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// HandleApplicationEvents to process application related events
func HandleApplicationEvents(data []byte, eventType string, c client.Client) {
	logger.LoggerMessaging.Debugf("Processing application event|EventType:%s\n", eventType)

	conf, _ := config.ReadConfigs()

	if strings.EqualFold(eventConstants.ApplicationRegistration, eventType) ||
		strings.EqualFold(eventConstants.RemoveApplicationKeyMapping, eventType) {
		var applicationRegistrationEvent msg.ApplicationRegistrationEvent
		appRegEventErr := json.Unmarshal([]byte(string(data)), &applicationRegistrationEvent)
		if appRegEventErr != nil {
			logger.LoggerMessaging.Errorf("Error occurred while unmarshalling Application Registration event data %v", appRegEventErr)
			return
		}

		if !belongsToTenant(applicationRegistrationEvent.TenantDomain) {
			logger.LoggerMessaging.Debugf("Application Registration event for the Consumer Key : %s is dropped due to having non related tenantDomain : %s",
				applicationRegistrationEvent.ConsumerKey, applicationRegistrationEvent.TenantDomain)
			return
		}

		logger.LoggerMessaging.Infof("Application registration event received: %+v", applicationRegistrationEvent)
		if strings.EqualFold(eventConstants.ApplicationRegistration, eventType) {
			issuerSecrets := internalk8sClient.GetK8sSecrets(map[string]string{"type": "issuer"}, c, conf)
			if len(issuerSecrets) == 0 {
				logger.LoggerMessaging.Errorf("No issuers are found")
			} else {
				// create secret CR for each issuer and add as a jwt authenticating credential to consumer
				addCredentials := []string{}
				for _, issuerSecret := range issuerSecrets {
					jwtCredentialSecret := createIssuerKongSecretCredential(issuerSecret, c, conf, applicationRegistrationEvent.ApplicationUUID, applicationRegistrationEvent.ConsumerKey, applicationRegistrationEvent.KeyType)
					addCredentials = append(addCredentials, jwtCredentialSecret.ObjectMeta.Name)
				}
				// update consumer with issuer credentials
				internalk8sClient.UpdateKongConsumerCredential(applicationRegistrationEvent.ApplicationUUID, strings.ToLower(applicationRegistrationEvent.KeyType), c, conf, addCredentials, nil)
			}
		} else if strings.EqualFold(eventConstants.RemoveApplicationKeyMapping, eventType) {
			logger.LoggerMessaging.Info("Application registration remove")
			jwtCredentialSecretName := transformer.GenerateSecretName(applicationRegistrationEvent.ApplicationUUID, applicationRegistrationEvent.ConsumerKey, pkgConstants.KongJwtSecretName)
			removeCredentials := []string{jwtCredentialSecretName}

			internalk8sClient.UpdateKongConsumerCredential(applicationRegistrationEvent.ApplicationUUID, "", c, conf, nil, removeCredentials)
			internalk8sClient.UnDeploySecretCR(jwtCredentialSecretName, c, conf)
		}
	} else {
		var applicationEvent msg.ApplicationEvent
		appEventErr := json.Unmarshal([]byte(string(data)), &applicationEvent)
		if appEventErr != nil {
			logger.LoggerMessaging.Errorf("Error occurred while unmarshalling Application event data %v", appEventErr)
			return
		}

		if !belongsToTenant(applicationEvent.TenantDomain) {
			logger.LoggerMessaging.Debugf("Application event for the Application : %s (with uuid %s) is dropped due to having non related tenantDomain : %s",
				applicationEvent.ApplicationName, applicationEvent.UUID, applicationEvent.TenantDomain)
			return
		}

		if isLaterEvent(applicationListTimeStampMap, fmt.Sprint(applicationEvent.ApplicationID), applicationEvent.TimeStamp) {
			return
		}

		logger.LoggerMessaging.Infof("Application event received: %+v", applicationEvent)
		if applicationEvent.Event.Type == eventConstants.ApplicationCreate {
			/* create an application level consumer CR (this can be used when subscription is not supported but jwt authentication is required) */
			// production
			createApplicationConsumer(applicationEvent.UUID, c, conf, constants.ProductionType)
			// sandbox
			createApplicationConsumer(applicationEvent.UUID, c, conf, constants.SandboxType)
		} else if applicationEvent.Event.Type == eventConstants.ApplicationUpdate {
			logger.LoggerMessaging.Info("Application update")
		} else if applicationEvent.Event.Type == eventConstants.ApplicationDelete {
			internalk8sClient.UndeployAPPCRs(applicationEvent.UUID, c)
		} else {
			logger.LoggerMessaging.Warnf("Application Event Type is not recognized for the Event under "+
				"Application UUID %s", applicationEvent.UUID)
			return
		}
	}
}

func createIssuerKongSecretCredential(issuerSecret v1.Secret, c client.Client, conf *config.Config, applicationUUID string, consumerKey string, environment string) *v1.Secret {
	logger.LoggerMessaging.Debugf("Creating issuer Kong secret credential|ApplicationUUID:%s Environment:%s\n", applicationUUID, environment)

	rsaPublicKey := issuerSecret.Data["public_key"]
	jwtCredentialSecretConfig := map[string]string{
		"algorithm":      "RS256",
		"key":            consumerKey,
		"rsa_public_key": string(rsaPublicKey),
	}
	jwtCredentialSecret := transformer.GenerateK8sCredentialSecret(applicationUUID, consumerKey, pkgConstants.KongJwtSecretName, jwtCredentialSecretConfig)
	jwtCredentialSecret.Labels["environment"] = strings.ToLower(environment)
	jwtCredentialSecret.Namespace = conf.DataPlane.Namespace

	// deploy secret CR
	internalk8sClient.DeploySecretCR(jwtCredentialSecret, c)

	return jwtCredentialSecret
}

func createApplicationConsumer(applicationUUID string, c client.Client, conf *config.Config, environment string) {
	logger.LoggerMessaging.Debugf("Creating application consumer|ApplicationUUID:%s Environment:%s\n", applicationUUID, environment)

	consumer := transformer.CreateConsumer(applicationUUID, environment)
	consumer.Namespace = conf.DataPlane.Namespace

	internalk8sClient.DeployKongConsumerCR(consumer, c)
}

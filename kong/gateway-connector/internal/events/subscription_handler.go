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
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	eventConstants "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub/constants"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib/constants"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/managementserver"
	msg "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/messaging"
	kongConstants "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/discovery"
	internalk8sClient "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/utils"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/transformer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// HandleSubscriptionEvents to process subscription related events
func HandleSubscriptionEvents(data []byte, eventType string, c client.Client) {
	logger.LoggerEvents.Infof("Processing subscription event processing with EventType: %s, data length: %d bytes", eventType, len(data))

	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		logger.LoggerEvents.Errorf("Error reading configs: %v", errReadConfig)
		return
	}

	var subscriptionEvent msg.SubscriptionEvent
	if subEventErr := json.Unmarshal(data, &subscriptionEvent); subEventErr != nil {
		logger.LoggerEvents.Errorf("%s: %v", kongConstants.UnmarshalErrorSubscription, subEventErr)
		return
	}

	if !belongsToTenant(subscriptionEvent.TenantDomain) {
		logger.LoggerEvents.Debugf("Subscription event for the Application: %s and API %s is dropped due to having non related tenantDomain: %s",
			subscriptionEvent.ApplicationUUID, subscriptionEvent.APIUUID, subscriptionEvent.TenantDomain)
		return
	}

	if isLaterEvent(subsriptionsListTimeStampMap, fmt.Sprint(subscriptionEvent.SubscriptionID), subscriptionEvent.TimeStamp) {
		return
	}

	logger.LoggerEvents.Infof("Received Subscription Event: %+v", subscriptionEvent)
	switch subscriptionEvent.Event.Type {
	case eventConstants.SubscriptionCreate:
		createSubscription(subscriptionEvent, c, conf, constants.ProductionType)
		createSubscription(subscriptionEvent, c, conf, constants.SandboxType)
	case eventConstants.SubscriptionUpdate:
		updateSubscription(subscriptionEvent, c, conf, constants.ProductionType)
		updateSubscription(subscriptionEvent, c, conf, constants.SandboxType)
	case eventConstants.SubscriptionDelete:
		removeSubscription(subscriptionEvent, c, conf, constants.ProductionType)
		removeSubscription(subscriptionEvent, c, conf, constants.SandboxType)
	}
}

func createSubscription(subscriptionEvent msg.SubscriptionEvent, c client.Client, conf *config.Config, environment string) {
	logger.LoggerEvents.Debugf("Creating subscription|ApplicationUUID:%s Environment:%s\n", subscriptionEvent.ApplicationUUID, environment)

	addCredentials := []string{}
	addAnnotations := []string{}

	// create and deploy kong acl secret CR
	aclGroupNames, err := generateACLGroupNameFromK8s(subscriptionEvent.APIName, environment, c, conf)
	if err != nil {
		logger.LoggerEvents.Debugf("Failed to generate ACL group names from K8s resources: %v", err)
		logger.LoggerEvents.Infof("Generating the ACL group name using general method")
		aclGroupNames = []string{transformer.GenerateACLGroupName(subscriptionEvent.APIName, environment)}
	}

	aclCredentialSecretConfig := map[string]string{
		kongConstants.GroupField: aclGroupNames[0],
	}
	subscriptionIdentifier := subscriptionEvent.APIUUID + environment
	aclCredentialSecret := transformer.GenerateK8sCredentialSecret(subscriptionEvent.ApplicationUUID, subscriptionIdentifier, kongConstants.ACLCredentialType, aclCredentialSecretConfig)
	aclCredentialSecret.Namespace = conf.DataPlane.Namespace
	addCredentials = append(addCredentials, aclCredentialSecret.ObjectMeta.Name)
	internalk8sClient.DeploySecretCR(aclCredentialSecret, c)

	// update consumer subscription limit plugin annotation
	subscriptionPolicy := managementserver.GetSubscriptionPolicy(subscriptionEvent.PolicyID, subscriptionEvent.TenantDomain)
	logger.LoggerEvents.Infof("Subscription Policy: %+v", subscriptionPolicy)
	if subscriptionPolicy.Name != kongConstants.EmptyString && subscriptionPolicy.Name != kongConstants.UnlimitedPolicyName {
		rateLimitCRName := transformer.GeneratePolicyCRName(subscriptionPolicy.Name, subscriptionPolicy.TenantDomain, kongConstants.RateLimitingPlugin, kongConstants.SubscriptionTypeKey)
		addAnnotations = append(addAnnotations, rateLimitCRName)
	}

	// get available jwt credentials for the application
	jwtSecretCredentials := internalk8sClient.GetK8sSecrets(map[string]string{
		kongConstants.ApplicationUUIDLabel: subscriptionEvent.ApplicationUUID,
		kongConstants.EnvironmentLabel:     environment,
		kongConstants.KongCredentialLabel:  kongConstants.JWTCredentialType,
	}, c, conf)
	for _, jwtSecretCredential := range jwtSecretCredentials {
		addCredentials = append(addCredentials, jwtSecretCredential.Name)
	}

	if len(addCredentials) > 0 {
		updateErr := utils.RetryKongCRUpdate(func() error {
			return internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, environment, c, conf, addCredentials, nil)
		}, kongConstants.UpdateConsumerCredentialTask, kongConstants.MaxRetries)
		if updateErr != nil {
			logger.LoggerEvents.Errorf("Failed to update Kong consumer credentials: %v", updateErr)
			return
		}
	}

	if len(addAnnotations) > 0 {
		updateErr := utils.RetryKongCRUpdate(func() error {
			return internalk8sClient.UpdateKongConsumerPluginAnnotation(subscriptionEvent.ApplicationUUID, environment, c, conf, addAnnotations, nil)
		}, kongConstants.UpdateConsumerPluginAnnotationTask, kongConstants.MaxRetries)
		if updateErr != nil {
			logger.LoggerEvents.Errorf("Failed to update Kong consumer plugin annotations: %v", updateErr)
			return
		}
	}
}

func updateSubscription(subscriptionEvent msg.SubscriptionEvent, c client.Client, conf *config.Config, environment string) {
	logger.LoggerEvents.Debugf("Updating subscription|ApplicationUUID:%s Environment:%s\n", subscriptionEvent.ApplicationUUID, environment)

	var removeAnnotations []string
	var addAnnotations []string
	// retrieving current production subscription policy
	consumerName := transformer.GenerateConsumerName(subscriptionEvent.ApplicationUUID, environment)
	consumer := internalk8sClient.GetKongConsumerCR(consumerName, c, conf)

	if consumer == nil {
		logger.LoggerEvents.Infof("Kong consumer credential not found for %v", environment)
	} else {
		subscriptionPolicy := managementserver.GetSubscriptionPolicy(subscriptionEvent.PolicyID, subscriptionEvent.TenantDomain)
		rateLimitCRName := transformer.GeneratePolicyCRName(subscriptionPolicy.Name, subscriptionPolicy.TenantDomain, kongConstants.RateLimitingPlugin, kongConstants.SubscriptionTypeKey)
		// handle subscription rate limiting
		if annotations, ok := consumer.Annotations[kongConstants.KongPluginsAnnotation]; ok {
			annotationsArr := strings.Split(annotations, ",")
			if !slices.Contains(annotationsArr, rateLimitCRName) {
				// remove old subscription policy name
				for _, name := range annotationsArr {
					if strings.Contains(name, kongConstants.SubscriptionTypeKey) && strings.Contains(name, kongConstants.RateLimitingPlugin) {
						removeAnnotations = append(removeAnnotations, name)
						break
					}
				}

				// updating new subscription policy name
				if subscriptionPolicy.Name != kongConstants.EmptyString && subscriptionPolicy.Name != kongConstants.UnlimitedPolicyName {
					addAnnotations = append(addAnnotations, rateLimitCRName)
				}

				err := utils.RetryKongCRUpdate(func() error {
					return internalk8sClient.UpdateKongConsumerPluginAnnotation(subscriptionEvent.ApplicationUUID, environment, c, conf, addAnnotations, removeAnnotations)
				}, kongConstants.UpdateConsumerPluginAnnotationTask, kongConstants.MaxRetries)
				if err != nil {
					logger.LoggerEvents.Errorf("Failed to update consumer plugin annotations: %v", err)
					return
				}
			}
		}

		// handle subscription state
		subscriptionIdentifier := subscriptionEvent.APIUUID + environment
		aclCredentialSecretName := transformer.GenerateSecretName(subscriptionEvent.ApplicationUUID, subscriptionIdentifier, kongConstants.ACLCredentialType)
		credentials := []string{aclCredentialSecretName}

		switch subscriptionEvent.SubscriptionState {
		case kongConstants.SubscriptionStateBlocked:
			if err := utils.RetryKongCRUpdate(func() error {
				return internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, environment, c, conf, nil, credentials)
			}, kongConstants.UpdateConsumerCredentialBlockedTask+environment, kongConstants.MaxRetries); err != nil {
				logger.LoggerEvents.Errorf("Failed to block %s credentials: %v", environment, err)
				return
			}
		case kongConstants.SubscriptionStateProdOnlyBlocked:
			if err := utils.RetryKongCRUpdate(func() error {
				return internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, environment, c, conf, credentials, nil)
			}, kongConstants.UpdateConsumerCredentialProdBlockedTask+environment, kongConstants.MaxRetries); err != nil {
				logger.LoggerEvents.Errorf("Failed to enable %s credentials for prod-only-blocked: %v", environment, err)
				return
			}
		case kongConstants.SubscriptionStateUnblocked:
			if err := utils.RetryKongCRUpdate(func() error {
				return internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, environment, c, conf, credentials, nil)
			}, kongConstants.UpdateConsumerCredentialUnblockedTask+environment, kongConstants.MaxRetries); err != nil {
				logger.LoggerEvents.Errorf("Failed to unblock %s credentials: %v", environment, err)
				return
			}
		}
	}

}

func removeSubscription(subscriptionEvent msg.SubscriptionEvent, c client.Client, conf *config.Config, environment string) {
	logger.LoggerEvents.Debugf("Removing subscription|ApplicationUUID:%s Environment:%s\n", subscriptionEvent.ApplicationUUID, environment)

	subscriptionIdentifier := subscriptionEvent.APIUUID + environment
	aclSecretCredentialName := transformer.GenerateSecretName(subscriptionEvent.ApplicationUUID, subscriptionIdentifier, kongConstants.ACLCredentialType)

	// remove secret from kong consumer CR
	removeCredentials := []string{aclSecretCredentialName}
	err := utils.RetryKongCRUpdate(func() error {
		return internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, environment, c, conf, nil, removeCredentials)
	}, kongConstants.UpdateConsumerCredentialRemoveTask, kongConstants.MaxRetries)
	if err != nil {
		logger.LoggerEvents.Errorf("Failed to remove Kong consumer credentials: %v", err)
		return
	}

	// remove acl secret credential
	internalk8sClient.UnDeploySecretCR(aclSecretCredentialName, c, conf)
}

// generateACLGroupNameFromK8s generates ACL group names by discovering services and their ACL plugins
func generateACLGroupNameFromK8s(apiName, environment string, c client.Client, conf *config.Config) ([]string, error) {
	service, err := findServiceByAPIName(apiName, c, conf)
	if err != nil || service == nil {
		return nil, fmt.Errorf("failed to find service for API %s: %v", apiName, err)
	}

	httpRoutes, err := getHTTPRoutesForService(service.Name, service.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get HTTPRoutes for service %s: %v", service.Name, err)
	}

	allPluginNames := findAllPluginsFromHTTPRoutes(httpRoutes)

	allowValues, err := extractACLAllowValues(allPluginNames, service.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ACL allow values: %v", err)
	}

	if len(allowValues) > 0 {
		return allowValues, nil
	}

	fallbackGroup := transformer.GenerateACLGroupName(apiName, environment)
	return []string{fallbackGroup}, nil
}

// findServiceByAPIName finds a service by API name in all namespaces
func findServiceByAPIName(apiName string, c client.Client, conf *config.Config) (*corev1.Service, error) {
	if apiName == kongConstants.EmptyString {
		return nil, fmt.Errorf("API name cannot be empty")
	}

	namespace := conf.DataPlane.Namespace
	serviceList := &corev1.ServiceList{}
	ctx := context.Background()

	err := c.List(ctx, serviceList, client.InNamespace(namespace))
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	for _, service := range serviceList.Items {
		if service.Name == apiName {
			return &service, nil
		}
	}

	return nil, fmt.Errorf("service not found for API name: %s", apiName)
}

// getHTTPRoutesForService finds HTTPRoutes that reference the given service
func getHTTPRoutesForService(serviceName, namespace string) ([]unstructured.Unstructured, error) {
	httpRoutes := discovery.FetchAllHTTPRoutesWithServiceName(namespace, serviceName)

	if len(httpRoutes) == 0 {
		return nil, nil
	}

	result := make([]unstructured.Unstructured, 0, len(httpRoutes))
	for _, route := range httpRoutes {
		if route != nil {
			result = append(result, *route)
		}
	}

	return result, nil
}

// findAllPluginsFromHTTPRoutes extracts all plugin names from HTTPRoute annotations
func findAllPluginsFromHTTPRoutes(httpRoutes []unstructured.Unstructured) []string {
	if len(httpRoutes) == 0 {
		return nil
	}

	var allPluginNames []string
	pluginNameSet := make(map[string]bool)

	for _, route := range httpRoutes {
		annotations, found, err := unstructured.NestedStringMap(route.Object, kongConstants.MetadataField, kongConstants.AnnotationsField)
		if !found || err != nil {
			continue
		}
		for key, value := range annotations {
			if strings.Contains(key, kongConstants.KongPluginsAnnotation) {
				pluginNames := strings.Split(value, ",")
				for _, pluginName := range pluginNames {
					pluginName = strings.TrimSpace(pluginName)
					if pluginName != kongConstants.EmptyString && !pluginNameSet[pluginName] {
						pluginNameSet[pluginName] = true
						allPluginNames = append(allPluginNames, pluginName)
					}
				}
			}
		}
	}

	return allPluginNames
}

// extractACLAllowValues gets ACL plugin resources and extracts config.allow values
func extractACLAllowValues(allPluginNames []string, namespace string) ([]string, error) {
	if len(allPluginNames) == 0 {
		return nil, nil
	}

	var allowValues []string
	allowValueSet := make(map[string]bool)

	for _, pluginName := range allPluginNames {
		plugin := discovery.FetchKongPlugin(namespace, pluginName)
		if plugin == nil {
			logger.LoggerEvents.Warnf("Failed to get KongPlugin %s", pluginName)
			continue
		}

		pluginType, found, err := unstructured.NestedString(plugin.Object, kongConstants.PluginField)
		if !found || err != nil || pluginType != kongConstants.ACLPlugin {
			continue
		}

		config, found, err := unstructured.NestedMap(plugin.Object, kongConstants.ConfigField)
		if !found || err != nil {
			continue
		}

		allow, found, err := unstructured.NestedSlice(config, kongConstants.AllowField)
		if found && err == nil {
			for _, val := range allow {
				if strVal, ok := val.(string); ok && strVal != kongConstants.EmptyString {
					if !allowValueSet[strVal] {
						allowValueSet[strVal] = true
						allowValues = append(allowValues, strVal)
					}
				}
			}
		}
	}

	return allowValues, nil
}

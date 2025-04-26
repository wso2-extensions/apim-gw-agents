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
	if subscriptionEvent.Event.Type == eventConstants.SubscriptionCreate {
		// create production consumer and acl credential
		createSubscription(subscriptionEvent, c, conf, constants.ProductionType)
		// create sandbox consumer and acl credential
		createSubscription(subscriptionEvent, c, conf, constants.SanboxType)
	} else if subscriptionEvent.Event.Type == eventConstants.SubscriptionUpdate {
		// update production consumer and configurations
		updateSubscription(subscriptionEvent, c, conf, constants.ProductionType)
		// update sandbox consumer and configurations
		updateSubscription(subscriptionEvent, c, conf, constants.SanboxType)
	} else if subscriptionEvent.Event.Type == eventConstants.SubscriptionDelete {
		// remove production ACL credentials and consumer
		removeSubscription(subscriptionEvent, c, conf, constants.ProductionType)
		// remove sandbox ACL credentials and consumer
		removeSubscription(subscriptionEvent, c, conf, constants.SanboxType)
	}
}

func createSubscription(subscriptionEvent msg.SubscriptionEvent, c client.Client, conf *config.Config, environment string) {
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
		if subscriptionEvent.SubscriptionState == "BLOCKED" {
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.SanboxType, c, conf, nil, credentials)
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.ProductionType, c, conf, nil, credentials)
		} else if subscriptionEvent.SubscriptionState == "PROD_ONLY_BLOCKED" {
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.SanboxType, c, conf, credentials, nil)
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.ProductionType, c, conf, nil, credentials)
		} else if subscriptionEvent.SubscriptionState == "UNBLOCKED" {
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.SanboxType, c, conf, credentials, nil)
			internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, constants.ProductionType, c, conf, credentials, nil)
		}
	}

}

func removeSubscription(subscriptionEvent msg.SubscriptionEvent, c client.Client, conf *config.Config, environment string) {
	subscriptionIdentifier := subscriptionEvent.APIUUID + environment
	aclSecretCredentialName := transformer.GenerateSecretName(subscriptionEvent.ApplicationUUID, subscriptionIdentifier, "acl")

	// remove secret from kong consumer CR
	removeCredentials := []string{aclSecretCredentialName}
	internalk8sClient.UpdateKongConsumerCredential(subscriptionEvent.ApplicationUUID, environment, c, conf, nil, removeCredentials)

	// remove acl secret credential
	internalk8sClient.UnDeploySecretCR(aclSecretCredentialName, c, conf)
}

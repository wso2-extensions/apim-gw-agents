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

package eventhub

import (
	"github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/pkg/managementserver"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"
	mgtServer "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/managementserver"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/utils"
)

// MarshalMultipleApplications is used to update the applicationList during the startup where
func MarshalMultipleApplications(appList *ApplicationList) {
	applicationMap := make(map[string]managementserver.Application)
	for _, application := range appList.List {
		applicationSub := MarshalApplication(&application)
		applicationMap[applicationSub.UUID] = applicationSub
	}
	managementserver.AddAllApplications(applicationMap)
}

// MarshalMultipleApplicationKeyMappings is used to update the application key mappings during the startup where
// multiple key mappings are pulled at once. And then it returns the ApplicationKeyMappingList.
func MarshalMultipleApplicationKeyMappings(keymappingList *ApplicationKeyMappingList) {
	resourceMap := make(map[string]managementserver.ApplicationKeyMapping)
	for _, keyMapping := range keymappingList.List {
		applicationKeyMappingReference := GetApplicationKeyMappingReference(&keyMapping)
		keyMappingSub := marshalKeyMapping(&keyMapping)
		resourceMap[applicationKeyMappingReference] = keyMappingSub
	}
	managementserver.AddAllApplicationKeyMappings(resourceMap)
}

// MarshalMultipleSubscriptions is used to update the subscriptions during the startup where
// multiple subscriptions are pulled at once. And then it returns the SubscriptionList.
func MarshalMultipleSubscriptions(subscriptionsList *types.SubscriptionList) {
	subscriptionMap := make(map[string]mgtServer.Subscription)
	applicationMappingMap := make(map[string]managementserver.ApplicationMapping)
	for _, subscription := range subscriptionsList.List {
		subscriptionSub := MarshalSubscription(&subscription)
		subscriptionMap[subscriptionSub.UUID] = subscriptionSub
		applicationMappingMap[subscriptionSub.UUID] = managementserver.ApplicationMapping{
			UUID:            utils.GetUniqueIDOfApplicationMapping(subscription.ApplicationUUID, subscription.SubscriptionUUID),
			ApplicationRef:  subscription.ApplicationUUID,
			SubscriptionRef: subscription.SubscriptionUUID,
			Organization:    subscriptionSub.Organization,
		}
	}
	managementserver.AddAllApplicationMappings(applicationMappingMap)
	mgtServer.AddAllSubscriptions(subscriptionMap)

}

// MarshalSubscription is used to map to internal Subscription struct
func MarshalSubscription(subscriptionInternal *types.Subscription) mgtServer.Subscription {
	sub := mgtServer.Subscription{
		SubStatus:     subscriptionInternal.SubscriptionState,
		UUID:          subscriptionInternal.SubscriptionUUID,
		Organization:  subscriptionInternal.ApplicationOrganization,
		SubscribedAPI: &mgtServer.SubscribedAPI{Name: subscriptionInternal.APIName, Version: subscriptionInternal.APIVersion},
		RateLimit:     subscriptionInternal.PolicyID,
		TimeStamp:     subscriptionInternal.TimeStamp,
	}
	return sub
}

// MarshalApplication is used to map to internal Application struct
func MarshalApplication(appInternal *Application) managementserver.Application {
	app := managementserver.Application{
		UUID:         appInternal.UUID,
		Name:         appInternal.Name,
		Owner:        appInternal.SubName,
		Organization: appInternal.Organization,
		Attributes:   appInternal.Attributes,
		TimeStamp:    appInternal.TimeStamp,
	}
	return app
}

func marshalKeyMapping(keyMappingInternal *ApplicationKeyMapping) managementserver.ApplicationKeyMapping {
	return managementserver.ApplicationKeyMapping{
		ApplicationUUID:       keyMappingInternal.ApplicationUUID,
		ApplicationIdentifier: keyMappingInternal.ConsumerKey,
		KeyType:               keyMappingInternal.KeyType,
		SecurityScheme:        "OAuth2",
		EnvID:                 "Default",
		Timestamp:             keyMappingInternal.TimeStamp,
	}
}

// GetApplicationKeyMappingReference returns unique reference for each key Mapping event.
// It is the combination of consumerKey:keyManager
func GetApplicationKeyMappingReference(keyMapping *ApplicationKeyMapping) string {
	return keyMapping.ConsumerKey + ":" + keyMapping.KeyManager
}

// CheckIfAPIMetadataIsAlreadyAvailable returns true only if the API Metadata for the given API UUID
// is already available
// func CheckIfAPIMetadataIsAlreadyAvailable(apiUUID, label string) bool {
// 	if _, labelAvailable := APIListMap[label]; labelAvailable {
// 		if _, apiAvailale := APIListMap[label][apiUUID]; apiAvailale {
// 			return true
// 		}
// 	}
// 	return false
// }

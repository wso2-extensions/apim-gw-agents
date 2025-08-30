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
package discovery

import (
	"context"

	discoverPkg "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/discovery"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/loggers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KongAPIImportCallback implements the APIImportCallback interface for Kong gateway connector
type KongAPIImportCallback struct{}

// OnAPIImportSuccess is called when an API has been successfully imported to the control plane.
// It updates the Service and HTTPRoute CRs with the apiID label for Kong discovery mode.
func (k *KongAPIImportCallback) OnAPIImportSuccess(apiUUID, apiID, revisionID, crName, crNamespace, agentName string) {
	loggers.LoggerWatcher.Infof("%s API import callback triggered - apiUUID: %s, apiID: %s, revisionID: %s, CR: %s/%s",
		agentName, apiUUID, apiID, revisionID, crNamespace, crName)

	// Find and update the Service CR with the API ID label
	if err := k.updateServiceCR(apiUUID, apiID, revisionID, crNamespace); err != nil {
		loggers.LoggerWatcher.Errorf("Failed to update Service with apiID for API %s: %v", apiUUID, err)
	}

	// Find and update all related HTTPRoute CRs with the API ID label
	if err := k.updateHTTPRouteCR(apiUUID, apiID, revisionID, crNamespace); err != nil {
		loggers.LoggerWatcher.Errorf("Failed to update HTTPRoutes with apiID for API %s: %v", apiUUID, err)
	}

	api, ok := discoverPkg.APIMap[apiUUID]
	if !ok {
		loggers.LoggerWatcher.Errorf("API not found in APIMap: %s", apiUUID)
		return
	}

	api.APIUUID = apiID
	api.RevisionID = revisionID
	discoverPkg.APIMap[apiUUID] = api

	loggers.LoggerWatcher.Infof("Successfully updated API in APIMap - originalKey: %s, newAPIUUID: %s", apiUUID, apiID)
}

// updateServiceCR finds the Service CR by kongAPIUUID label and updates it with the apiID label
func (k *KongAPIImportCallback) updateServiceCR(kongAPIUUID, apiID, revisionID, namespace string) error {
	if CRWatcher == nil || CRWatcher.DynamicClient == nil {
		loggers.LoggerWatcher.Error("CRWatcher or DynamicClient is not initialized")
		return nil
	}

	serviceList, err := CRWatcher.DynamicClient.Resource(constants.ServiceGVR).Namespace(namespace).List(
		context.Background(),
		metav1.ListOptions{
			LabelSelector: constants.KongAPIUUIDLabel + constants.EqualString + kongAPIUUID,
		},
	)
	if err != nil {
		return err
	}

	for i := range serviceList.Items {
		service := &serviceList.Items[i]
		loggers.LoggerWatcher.Infof("Updating Service %s/%s with apiID: %s", service.GetNamespace(), service.GetName(), apiID)
		serviceLabels := map[string]string{
			constants.RevisionIDLabel: revisionID,
			constants.APIUUIDLabel:    apiID,
		}
		updateServiceLabels(service, serviceLabels)
	}

	return nil
}

// updateHTTPRouteCR finds HTTPRoute CRs by kongAPIUUID label and updates them with the apiID label
func (k *KongAPIImportCallback) updateHTTPRouteCR(kongAPIUUID, apiID, revisionID, namespace string) error {
	if CRWatcher == nil || CRWatcher.DynamicClient == nil {
		loggers.LoggerWatcher.Error("CRWatcher or DynamicClient is not initialized")
		return nil
	}

	httpRouteList, err := CRWatcher.DynamicClient.Resource(constants.HTTPRouteGVR).Namespace(namespace).List(
		context.Background(),
		metav1.ListOptions{
			LabelSelector: constants.KongAPIUUIDLabel + constants.EqualString + kongAPIUUID,
		},
	)
	if err != nil {
		return err
	}

	for i := range httpRouteList.Items {
		httpRoute := &httpRouteList.Items[i]
		loggers.LoggerWatcher.Infof("Updating HTTPRoute %s/%s with apiID: %s", httpRoute.GetNamespace(), httpRoute.GetName(), apiID)
		routeLabels := map[string]string{
			constants.RevisionIDLabel: revisionID,
			constants.APIUUIDLabel:    apiID,
		}
		updateHTTPRouteLabels(httpRoute, routeLabels)
	}

	return nil
}

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
	"sync"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	discoveryPkg "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/discovery"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/loggers"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Define the resources to watch
var (
	configOnce sync.Once
	apiMutex   sync.RWMutex
)

// IsControlPlaneInitiated checks if the resource was initiated from control plane
func IsControlPlaneInitiated(u *unstructured.Unstructured) bool {
	if origin, exists := u.GetLabels()[constants.K8sInitiatedFromField]; exists {
		return origin == constants.ControlPlaneOrigin
	}
	return false
}

// addResource handles the addition of a resource
func addResource(u *unstructured.Unstructured) {
	loggers.LoggerWatcher.Debugf("Resource Added: %s/%s (Kind: %s), APIVersion: %s, Labels: %v",
		u.GetNamespace(), u.GetName(), u.GetKind(), u.GetAPIVersion(), u.GetLabels())
	if u.GetKind() == constants.ServiceKind && !IsControlPlaneInitiated(u) {
		handleAddServiceResource(u)
	}
	if u.GetKind() == constants.HTTPRouteKind && !IsControlPlaneInitiated(u) {
		handleAddHttpRouteResource(u)
	}
}

// updateResource handles the update of a resource
func updateResource(oldU, newU *unstructured.Unstructured) {
	if oldU.GetResourceVersion() == newU.GetResourceVersion() {
		loggers.LoggerWatcher.Debugf("Skipping resync event for %s/%s", newU.GetNamespace(), newU.GetName())
		return
	}
	loggers.LoggerWatcher.Debugf("Resource Updated: %s/%s (Kind: %s), APIVersion: %s, Generation: %d -> %d",
		newU.GetNamespace(), newU.GetName(), newU.GetKind(), newU.GetAPIVersion(), oldU.GetGeneration(), newU.GetGeneration())
	if newU.GetKind() == constants.ServiceKind && !IsControlPlaneInitiated(newU) {
		handleUpdateServiceResource(oldU, newU)
	}
	if newU.GetKind() == constants.HTTPRouteKind && !IsControlPlaneInitiated(newU) {
		handleUpdateHttpRouteResource(oldU, newU)
	}
}

// deleteResource handles the deletion of a resource
func deleteResource(u *unstructured.Unstructured) {
	loggers.LoggerWatcher.Debugf("Resource Deleted: %s/%s (Kind: %s), APIVersion: %s, UID: %s",
		u.GetNamespace(), u.GetName(), u.GetKind(), u.GetAPIVersion(), u.GetUID())
	if u.GetKind() == constants.ServiceKind && !IsControlPlaneInitiated(u) {
		handleDeleteServiceResource(u)
	}
	if u.GetKind() == constants.HTTPRouteKind && !IsControlPlaneInitiated(u) {
		handleDeleteHttpRouteResource(u)
	}
}

// CRWatcher with separate handler functions
var CRWatcher *discoveryPkg.CRWatcher

func init() {
	configOnce.Do(func() {
		conf, _ := config.ReadConfigs()

		CRWatcher = &discoveryPkg.CRWatcher{
			Namespace:     conf.DataPlane.Namespace,
			GroupVersions: constants.GVRs,
			AddFunc:       addResource,
			UpdateFunc:    updateResource,
			DeleteFunc:    deleteResource,
		}
	})
}

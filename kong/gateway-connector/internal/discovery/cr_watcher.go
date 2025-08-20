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

	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	discoveryPkg "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/discovery"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/loggers"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Define the resources to watch
var (
	configOnce sync.Once
	apiMutex   sync.RWMutex
	gvrs       = []schema.GroupVersionResource{
		{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"},
	}
	allowedTimeUnits = map[string]string{
		"minute": "min",
		"hour":   "hours",
		"day":    "days",
	}
)

// addResource handles the addition of a resource
func addResource(u *unstructured.Unstructured) {
	loggers.LoggerWatcher.Infof("Resource Added: %s/%s (Kind: %s)\n", u.GetNamespace(), u.GetName(), u.GetKind())
	if u.GetKind() == "HTTPRoute" {
		handleAddHttpRouteResource(u)
	}
}

// updateResource handles the update of a resource
func updateResource(oldU, newU *unstructured.Unstructured) {
	loggers.LoggerWatcher.Infof("Resource Updated: %s/%s (Kind: %s)\n", newU.GetNamespace(), newU.GetName(), newU.GetKind())
	if newU.GetKind() == "HTTPRoute" {
		handleUpdateHTTPRouteResource(oldU, newU)
	}
}

// deleteResource handles the deletion of a resource
func deleteResource(u *unstructured.Unstructured) {
	loggers.LoggerWatcher.Infof("Resource Deleted: %s/%s (Kind: %s)\n", u.GetNamespace(), u.GetName(), u.GetKind())
	if u.GetKind() == "HTTPRoute" {
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
			GroupVersions: gvrs,
			AddFunc:       addResource,
			UpdateFunc:    updateResource,
			DeleteFunc:    deleteResource,
		}
	})
}

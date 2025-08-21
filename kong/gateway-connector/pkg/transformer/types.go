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

package transformer

import (
	v1 "github.com/kong/kubernetes-configuration/api/configuration/v1"
	corev1 "k8s.io/api/core/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// K8sArtifacts k8s artifact representation of API
type K8sArtifacts struct {
	APIName     string
	APIUUID     string
	Namespace   string
	KongPlugins map[string]*v1.KongPlugin
	Services    map[string]*corev1.Service
	HTTPRoutes  map[string]*gwapiv1.HTTPRoute
}

// KongPluginConfig defines the type for config of a kong plugin
type KongPluginConfig = map[string]interface{}

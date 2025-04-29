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

/*
 * Package "mapper" contains artifacts relate to fetching APIs and
 * API related updates from the control plane event-hub.
 * This file contains functions to retrieve APIs and API updates.
 */

package mapper

import (
	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	internalk8sClient "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/pkg/transformer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// MapAndCreateCR will read the CRD Yaml and based on the Kind of the CR, unmarshal and maps the
// data and sends to the K8-Client for creating the respective CR inside the cluster
func MapAndCreateCR(k8sArtifact transformer.K8sArtifacts, k8sClient client.Client) *error {
	namespace, err := getDeploymentNamespace(k8sArtifact)
	if err != nil {
		return &err
	}
	k8sArtifact.Namespace = namespace
	// deploy httproute CRs
	for _, httpRoutes := range k8sArtifact.HTTPRoutes {
		httpRoutes.Namespace = namespace
		internalk8sClient.DeployHTTPRouteCR(httpRoutes, k8sClient)
	}
	// deploy service CRs
	for _, service := range k8sArtifact.Services {
		service.Namespace = namespace
		internalk8sClient.DeployServiceCR(service, k8sClient)
	}
	// deploy kong plugin CRs
	for _, kongPlugin := range k8sArtifact.KongPlugins {
		kongPlugin.Namespace = namespace
		internalk8sClient.DeployKongPluginCR(kongPlugin, k8sClient)
	}
	return nil
}

func getDeploymentNamespace(k8sArtifact transformer.K8sArtifacts) (string, error) {
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		logger.LoggerMapper.Errorf("Error reading configs: %v", errReadConfig)
		return "", errReadConfig
	}
	return conf.DataPlane.Namespace, nil
}

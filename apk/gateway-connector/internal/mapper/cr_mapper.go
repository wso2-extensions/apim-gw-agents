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
	internalk8sClient "github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/pkg/transformer"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// MapAndCreateCR will read the CRD Yaml and based on the Kind of the CR, unmarshal and maps the
// data and sends to the K8-Client for creating the respective CR inside the cluster
func MapAndCreateCR(k8sArtifact transformer.K8sArtifacts, k8sClient client.Client) *error {
	namespace, err := getDeploymentNamespace(k8sArtifact)
	logger.LoggerMapper.Debugf("Namespace: %s", namespace)
	if err != nil {
		return &err
	}
	routeMeta := k8sArtifact.RouteMetadata
	routeMeta.Namespace = namespace
	uid, _ := internalk8sClient.DeployRouteMetadataCR(routeMeta, k8sClient)
	ownerRef := &metav1.OwnerReference{
		APIVersion: "dp.wso2.com/v2alpha1",
		Kind:       "RouteMetadata",
		Name:       routeMeta.ObjectMeta.Name,
		UID:        uid,
	}
	logger.LoggerMapper.Debugf("OwnerRef: %+v", ownerRef)

	for _, configMaps := range k8sArtifact.ConfigMaps {
		configMaps.Namespace = namespace
		internalk8sClient.DeployConfigMapCR(configMaps, ownerRef, k8sClient)
	}
	for _, secrets := range k8sArtifact.Secrets {
		secrets.Namespace = namespace
		internalk8sClient.DeploySecretCR(secrets, ownerRef, k8sClient)
	}
	for _, httpRoutes := range k8sArtifact.HTTPRoutes {
		httpRoutes.Namespace = namespace
		internalk8sClient.DeployHTTPRouteCR(httpRoutes, ownerRef, k8sClient)
	}
	for _, httpRouteFilters := range k8sArtifact.HTTPRouteFilters {
		httpRouteFilters.Namespace = namespace
		internalk8sClient.DeployHTTPRouteFilterCR(httpRouteFilters, ownerRef, k8sClient)
	}
	for _, backends := range k8sArtifact.Backends {
		backends.Namespace = namespace
		internalk8sClient.DeployBackendCR(backends, ownerRef, k8sClient)
	}
	for _, securityPolicy := range k8sArtifact.SecurityPolicies {
		securityPolicy.Namespace = namespace
		internalk8sClient.DeploySecurityPolicyCR(securityPolicy, ownerRef, k8sClient)
	}
	for _, backendTLSPolicies := range k8sArtifact.BackendTLSPolicies {
		backendTLSPolicies.Namespace = namespace
		internalk8sClient.DeployBackendTLSPolicyCR(backendTLSPolicies, ownerRef, k8sClient)
	}
	for _, routePolicies := range k8sArtifact.RoutePolicies {
		routePolicies.Namespace = namespace
		internalk8sClient.DeployRoutePolicyCR(routePolicies, ownerRef, k8sClient)
	}
	for _, envoyExtensionPolicies := range k8sArtifact.EnvoyExtensionPolicies {
		envoyExtensionPolicies.Namespace = namespace
		internalk8sClient.DeployEnvoyExtensionPolicyCR(envoyExtensionPolicies, ownerRef, k8sClient)
	}
	for _, backendTrafficPolicy := range k8sArtifact.BackendTrafficPolicies {
		backendTrafficPolicy.Namespace = namespace
		internalk8sClient.DeployBakcendTrafficPolicyCR(backendTrafficPolicy, ownerRef, k8sClient)
	}
	for _, grpcRoute := range k8sArtifact.GRPCRoutes {
		grpcRoute.Namespace = namespace
		internalk8sClient.DeployGRPCRouteCR(grpcRoute, ownerRef, k8sClient)
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

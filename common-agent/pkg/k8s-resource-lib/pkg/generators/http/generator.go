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

package httpgenerator

import (
	"strconv"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib/pkg/utils"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib/types"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// HTTPRouteGenerator is the interface for the HTTP route generator.
type HTTPRouteGenerator struct {
	GenerateHTTPRouteRules        func(k8sArtifacts *K8sArtifacts, apkConf types.APKConf, operations []types.Operation, endpoint *[]types.EndpointDetails, endpointType string) ([]gwapiv1.HTTPRouteRule, error)
	GenerateHTTPRouteRule         func(k8sArtifacts *K8sArtifacts, apkConf types.APKConf, operation types.Operation, endpoint *[]types.EndpointDetails, endpointType string) (*gwapiv1.HTTPRouteRule, error)
	GenerateAndRetrieveParentRefs func(gatewayConfig types.GatewayConfigurations, uniqueID string) []gwapiv1.ParentReference
	GenerateHTTPRouteFilters      func(k8sArtifacts *K8sArtifacts, apkConf types.APKConf, endpointToUse []types.EndpointDetails, operation types.Operation, endpointType string) ([]gwapiv1.HTTPRouteFilter, bool)
	ExtractHTTPRouteFilter        func(k8sArtifacts *K8sArtifacts, apkConf *types.APKConf, endpoint []types.EndpointDetails, operation types.Operation, operationPolicies []types.OperationPolicy, isRequest bool) ([]gwapiv1.HTTPRouteFilter, bool)
	GetHostNames                  func(apkConf types.APKConf, endpointType string, organization types.Organization) []gwapiv1.Hostname
	RetrieveHTTPMatches           func(apkConf types.APKConf, operation types.Operation) ([]gwapiv1.HTTPRouteMatch, error)
	RetrieveHTTPMatch             func(apkConf types.APKConf, operation types.Operation) (gwapiv1.HTTPRouteMatch, error)
	GenerateHTTPBackEndRef        func(k8sArtifacts *K8sArtifacts, endpoint []types.EndpointDetails, operation types.Operation, endpointType string) []gwapiv1.HTTPBackendRef
	GenerateService               func(k8sArtifacts *K8sArtifacts, endpoint types.EndpointDetails, operation types.Operation, endpointType string) corev1.Service
}

// Generator creates a new HTTP route generator.
func Generator() *HTTPRouteGenerator {
	gen := &HTTPRouteGenerator{}
	gen.GenerateHTTPRouteRules = gen.generateHTTPRouteRules
	gen.GenerateHTTPRouteRule = gen.generateHTTPRouteRule
	gen.GenerateAndRetrieveParentRefs = gen.generateAndRetrieveParentRefs
	gen.GenerateHTTPRouteFilters = gen.generateHTTPRouteFilters
	gen.ExtractHTTPRouteFilter = gen.extractHTTPRouteFilter
	gen.GetHostNames = utils.GetHostNames
	gen.RetrieveHTTPMatches = gen.retrieveHTTPMatches
	gen.RetrieveHTTPMatch = gen.retrieveHTTPMatch
	gen.GenerateHTTPBackEndRef = gen.generateHTTPBackEndRef
	gen.GenerateService = gen.generateService
	return gen
}

// GenerateHTTPRoute generates a HTTPRoute based on the provided configurations.
func (g *HTTPRouteGenerator) GenerateHTTPRoute(apkConf types.APKConf, organization types.Organization, gatewayConfiguration types.GatewayConfigurations, operations []types.Operation, endpoint *[]types.EndpointDetails, endpointType string, uniqueID string, count int) (*K8sArtifacts, error) {
	k8sArtifacts := K8sArtifacts{Name: apkConf.Name, Context: apkConf.BasePath, Version: apkConf.Version, OrganizationID: organization.Name, Services: make(map[string]*corev1.Service, 0)}
	httpRouteRules, err := g.GenerateHTTPRouteRules(&k8sArtifacts, apkConf, operations, endpoint, endpointType)
	if err != nil {
		return nil, err
	}
	k8sArtifacts.HTTPRoute = &gwapiv1.HTTPRoute{
		TypeMeta: v1.TypeMeta{
			Kind:       "HTTPRoute",
			APIVersion: "gateway.sigs.k8s.io/v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: uniqueID + "-" + endpointType + "-httproute-" + strconv.Itoa(count),
		},
		Spec: gwapiv1.HTTPRouteSpec{
			CommonRouteSpec: gwapiv1.CommonRouteSpec{
				ParentRefs: g.GenerateAndRetrieveParentRefs(gatewayConfiguration, uniqueID),
			},
			Rules:     httpRouteRules,
			Hostnames: g.GetHostNames(apkConf, endpointType, organization),
		},
	}
	return &k8sArtifacts, nil
}

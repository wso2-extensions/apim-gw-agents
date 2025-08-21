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
	"testing"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib/constants"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib/pkg/utils"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib/types"
	v1 "k8s.io/api/core/v1"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestGenerateHTTPRoute(t *testing.T) {
	g := Generator()
	apkConf := types.APKConf{
		Name:                   "EmployeeServiceAPI",
		Version:                "3.14",
		BasePath:               "/employees-info",
		Type:                   "REST",
		DefaultVersion:         false,
		SubscriptionValidation: false,
		EndpointConfigurations: &types.EndpointConfigurations{
			Production: &[]types.EndpointConfiguration{
				types.EndpointConfiguration{
					Endpoint: types.EndpointURL("http://employee-service:8080"),
				},
			},
		},
		RateLimit: &types.RateLimit{
			Unit:            "Minute",
			RequestsPerUnit: 5,
		},
		Authentication: &[]types.AuthConfiguration{
			{
				AuthType: "APIKey",
				Enabled:  true,
			},
		},
		Operations: &[]types.Operation{
			{Target: "/employees", Verb: "GET", Secured: true, Scopes: []string{}},
			{Target: "/employee", Verb: "POST", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "PUT", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "DELETE", Secured: true, Scopes: []string{}},
		},
	}

	organization := types.Organization{
		Name: "wso2",
	}
	gatewayConfiguration := types.GatewayConfigurations{
		Name:         "wso2-apim",
		ListenerName: "wso2-apim-gateway",
		Hostname:     "wso2-apim",
	}
	operations := *apkConf.Operations
	endpoints := utils.GetEndpoints(apkConf)
	endpoint := endpoints[constants.ProductionType]
	endpointType := constants.ProductionType
	uniqueID := "test-id"
	count := 1

	k8sArtifacts, err := g.GenerateHTTPRoute(apkConf, organization, gatewayConfiguration, operations, &endpoint, endpointType, uniqueID, count)
	httpRoute := k8sArtifacts.HTTPRoute
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if httpRoute == nil {
		t.Fatalf("Expected HTTPRoute, got nil")
	}

	expectedName := uniqueID + "-" + endpointType + "-httproute-" + strconv.Itoa(count)
	if httpRoute.ObjectMeta.Name != expectedName {
		t.Errorf("Expected name %s, got %s", expectedName, httpRoute.ObjectMeta.Name)
	}
}

func TestGenerateHTTPRouteRules(t *testing.T) {
	g := Generator()
	apkConf := types.APKConf{
		Name:                   "EmployeeServiceAPI",
		Version:                "3.14",
		BasePath:               "/employees-info",
		Type:                   "REST",
		DefaultVersion:         false,
		SubscriptionValidation: false,
		EndpointConfigurations: &types.EndpointConfigurations{
			Production: &[]types.EndpointConfiguration{
				types.EndpointConfiguration{
					Endpoint: types.EndpointURL("http://employee-service:8080"),
				},
			},
		},
		RateLimit: &types.RateLimit{
			Unit:            "Minute",
			RequestsPerUnit: 5,
		},
		Authentication: &[]types.AuthConfiguration{
			{
				AuthType: "APIKey",
				Enabled:  true,
			},
		},
		Operations: &[]types.Operation{
			{Target: "/employees", Verb: "GET", Secured: true, Scopes: []string{}},
			{Target: "/employee", Verb: "POST", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "PUT", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "DELETE", Secured: true, Scopes: []string{}},
		},
	}
	operations := *apkConf.Operations
	endpoints := utils.GetEndpoints(apkConf)
	endpoint := endpoints[constants.ProductionType]
	endpointType := constants.ProductionType
	k8sArtifacts := K8sArtifacts{Name: apkConf.Name, Version: apkConf.Version, OrganizationID: "", Services: make(map[string]*v1.Service)}

	httpRouteRules, err := g.GenerateHTTPRouteRules(&k8sArtifacts, apkConf, operations, &endpoint, endpointType)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if httpRouteRules == nil {
		t.Fatalf("Expected HTTPRouteRules, got nil")
	}
}

func TestGenerateHTTPRouteRule(t *testing.T) {
	g := Generator()
	apkConf := types.APKConf{
		Name:                   "EmployeeServiceAPI",
		Version:                "3.14",
		BasePath:               "/employees-info",
		Type:                   "REST",
		DefaultVersion:         false,
		SubscriptionValidation: false,
		EndpointConfigurations: &types.EndpointConfigurations{
			Production: &[]types.EndpointConfiguration{
				types.EndpointConfiguration{
					Endpoint: types.EndpointURL("http://employee-service:8080"),
				},
			},
		},
		RateLimit: &types.RateLimit{
			Unit:            "Minute",
			RequestsPerUnit: 5,
		},
		Authentication: &[]types.AuthConfiguration{
			{
				AuthType: "APIKey",
				Enabled:  true,
			},
		},
		Operations: &[]types.Operation{
			{Target: "/employees", Verb: "GET", Secured: true, Scopes: []string{}},
			{Target: "/employee", Verb: "POST", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "PUT", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "DELETE", Secured: true, Scopes: []string{}},
		},
	}
	operation := (*apkConf.Operations)[0]
	endpoints := utils.GetEndpoints(apkConf)
	endpoint := endpoints[constants.ProductionType]
	endpointType := constants.ProductionType
	k8sArtifacts := K8sArtifacts{Name: apkConf.Name, Version: apkConf.Version, OrganizationID: "", Services: make(map[string]*v1.Service)}

	httpRouteRule, err := g.GenerateHTTPRouteRule(&k8sArtifacts, apkConf, operation, &endpoint, endpointType)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if httpRouteRule == nil {
		t.Fatalf("Expected HTTPRouteRule, got nil")
	}
}

func TestGenerateAndRetrieveParentRefs(t *testing.T) {
	g := Generator()
	gatewayConfig := types.GatewayConfigurations{
		Name:         "test-gateway",
		ListenerName: "test-listener",
	}
	uniqueID := "test-id"

	parentRefs := g.GenerateAndRetrieveParentRefs(gatewayConfig, uniqueID)
	if len(parentRefs) == 0 {
		t.Fatalf("Expected ParentReferences, got none")
	}

	expectedName := gwapiv1.ObjectName(gatewayConfig.Name)
	if parentRefs[0].Name != expectedName {
		t.Errorf("Expected name %s, got %s", expectedName, parentRefs[0].Name)
	}
}

func TestGenerateHTTPBackEndRef(t *testing.T) {
	g := Generator()
	endpoint := []types.EndpointDetails{types.EndpointDetails{Name: "test-endpoint"}}
	operation := types.Operation{}
	k8sArtifacts := K8sArtifacts{Name: "api-name", Version: "v1", OrganizationID: "", Services: make(map[string]*v1.Service)}
	endpointType := constants.SanboxType

	httpBackEndRefs := g.GenerateHTTPBackEndRef(&k8sArtifacts, endpoint, operation, endpointType)
	if len(httpBackEndRefs) == 0 {
		t.Fatalf("Expected HTTPBackendRefs, got none")
	}

	expectedName := utils.GenerateServiceName(k8sArtifacts.Name, k8sArtifacts.Version, k8sArtifacts.OrganizationID, endpointType)
	if httpBackEndRefs[0].BackendRef.Name != gwapiv1.ObjectName(expectedName) {
		t.Errorf("Expected name %s, got %s", expectedName, httpBackEndRefs[0].BackendRef.Name)
	}
}

func TestGenerateHTTPRouteFilters(t *testing.T) {
	g := Generator()
	apkConf := types.APKConf{
		Name:                   "EmployeeServiceAPI",
		Version:                "3.14",
		BasePath:               "/employees-info",
		Type:                   "REST",
		DefaultVersion:         false,
		SubscriptionValidation: false,
		EndpointConfigurations: &types.EndpointConfigurations{
			Production: &[]types.EndpointConfiguration{
				types.EndpointConfiguration{
					Endpoint: types.EndpointURL("http://employee-service:8080/api/v3"),
				},
			},
		},
		RateLimit: &types.RateLimit{
			Unit:            "Minute",
			RequestsPerUnit: 5,
		},
		Authentication: &[]types.AuthConfiguration{
			{
				AuthType: "APIKey",
				Enabled:  true,
			},
		},
		Operations: &[]types.Operation{
			{Target: "/employees", Verb: "GET", Secured: true, Scopes: []string{}},
			{Target: "/employee", Verb: "POST", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "PUT", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "DELETE", Secured: true, Scopes: []string{}},
		},
	}
	endpointToUse := []types.EndpointDetails{{}}
	operation := (*apkConf.Operations)[0]
	endpointType := constants.ProductionType
	k8sArtifacts := K8sArtifacts{Name: apkConf.Name, Version: apkConf.Version, OrganizationID: "", Services: make(map[string]*v1.Service)}

	filters, hasRedirectPolicy := g.GenerateHTTPRouteFilters(&k8sArtifacts, apkConf, endpointToUse, operation, endpointType)
	if filters == nil {
		t.Fatalf("Expected HTTPRouteFilters, got nil")
	}

	if hasRedirectPolicy {
		t.Errorf("Expected no redirect policy, got one")
	}
}

func TestRetrieveHTTPMatches(t *testing.T) {
	g := Generator()
	apkConf := types.APKConf{
		Name:                   "EmployeeServiceAPI",
		Version:                "3.14",
		BasePath:               "/employees-info",
		Type:                   "REST",
		DefaultVersion:         false,
		SubscriptionValidation: false,
		EndpointConfigurations: &types.EndpointConfigurations{
			Production: &[]types.EndpointConfiguration{
				types.EndpointConfiguration{
					Endpoint: types.EndpointURL("http://employee-service:8080"),
				},
			},
		},
		RateLimit: &types.RateLimit{
			Unit:            "Minute",
			RequestsPerUnit: 5,
		},
		Authentication: &[]types.AuthConfiguration{
			{
				AuthType: "APIKey",
				Enabled:  true,
			},
		},
		Operations: &[]types.Operation{
			{Target: "/employees", Verb: "GET", Secured: true, Scopes: []string{}},
			{Target: "/employee", Verb: "POST", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "PUT", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "DELETE", Secured: true, Scopes: []string{}},
		},
	}
	operation := (*apkConf.Operations)[0]

	httpRouteMatches, err := g.RetrieveHTTPMatches(apkConf, operation)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if httpRouteMatches == nil {
		t.Fatalf("Expected HTTPRouteMatches, got nil")
	}
}

func TestGenerateService(t *testing.T) {
	g := Generator()
	apkConf := types.APKConf{
		Name:                   "EmployeeServiceAPI",
		Version:                "3.14",
		BasePath:               "/employees-info",
		Type:                   "REST",
		DefaultVersion:         false,
		SubscriptionValidation: false,
		EndpointConfigurations: &types.EndpointConfigurations{
			Production: &[]types.EndpointConfiguration{
				types.EndpointConfiguration{
					Endpoint: types.EndpointURL("http://employee-service:8080"),
				},
			},
		},
		RateLimit: &types.RateLimit{
			Unit:            "Minute",
			RequestsPerUnit: 5,
		},
		Authentication: &[]types.AuthConfiguration{
			{
				AuthType: "APIKey",
				Enabled:  true,
			},
		},
		Operations: &[]types.Operation{
			{Target: "/employees", Verb: "GET", Secured: true, Scopes: []string{}},
			{Target: "/employee", Verb: "POST", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "PUT", Secured: true, Scopes: []string{}},
			{Target: "/employee/{employeeId}", Verb: "DELETE", Secured: true, Scopes: []string{}},
		},
	}
	endpoints := utils.GetEndpoints(apkConf)
	endpoint := endpoints[constants.ProductionType]
	endpointType := constants.ProductionType
	operation := types.Operation{}
	k8sArtifacts := K8sArtifacts{Name: apkConf.Name, Version: apkConf.Version, OrganizationID: "", Services: make(map[string]*v1.Service)}

	k8sService := g.GenerateService(&k8sArtifacts, endpoint[0], operation, endpointType)
	_, ok := k8sArtifacts.Services[k8sService.ObjectMeta.Name]
	if !ok {
		t.Fatalf("Expected K8sService, got nil")
	}
}

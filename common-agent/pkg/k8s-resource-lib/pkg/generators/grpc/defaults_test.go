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

package grpcgenerator

import (
	"strconv"
	"testing"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib/types"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestGenerateGRPCRoute(t *testing.T) {
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
	endpoint := &[]types.EndpointDetails{types.EndpointDetails{Name: "employee-service"}}
	endpointType := "test-endpoint"
	uniqueID := "test-id"
	count := 1

	grpcRoute, err := g.GenerateGRPCRoute(apkConf, organization, gatewayConfiguration, operations, endpoint, endpointType, uniqueID, 1)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if grpcRoute.ObjectMeta.Name != uniqueID+"-"+endpointType+"-grpcroute-"+strconv.Itoa(count) {
		t.Errorf("Expected name %s, got %s", uniqueID+"-"+endpointType+"-grpcroute-"+strconv.Itoa(count), grpcRoute.ObjectMeta.Name)
	}
}

func TestGenerateGRPCRouteRules(t *testing.T) {
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
	endpoint := &[]types.EndpointDetails{types.EndpointDetails{Name: "employee-service"}}
	endpointType := "test-endpoint"

	grpcRouteRules, err := g.generateGRPCRouteRules(apkConf, operations, endpoint, endpointType)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if grpcRouteRules == nil {
		t.Fatalf("Expected GRPCRouteRules, got nil")
	}
}

func TestGenerateGRPCRouteRule(t *testing.T) {
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
	endpoint := &[]types.EndpointDetails{types.EndpointDetails{Name: "employee-service"}}
	endpointType := "test-endpoint"

	grpcRouteRule, err := g.generateGRPCRouteRule(apkConf, operation, endpoint, endpointType)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if grpcRouteRule == nil {
		t.Fatalf("Expected GRPCRouteRule, got nil")
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

func TestGenerateGRPCBackEndRef(t *testing.T) {
	g := Generator()
	endpoint := []types.EndpointDetails{{Name: "test-endpoint"}}
	operation := types.Operation{}

	grpcBackEndRefs := g.generateGRPCBackEndRef(endpoint, operation)
	if len(grpcBackEndRefs) == 0 {
		t.Fatalf("Expected GRPCBackendRefs, got none")
	}

	expectedName := gwapiv1.ObjectName(endpoint[0].Name)
	if grpcBackEndRefs[0].BackendRef.Name != expectedName {
		t.Errorf("Expected name %s, got %s", expectedName, grpcBackEndRefs[0].BackendRef.Name)
	}
}

func TestRetrieveGRPCMatches(t *testing.T) {
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

	grpcRouteMatches := g.RetrieveGRPCMatch(operation)
	if grpcRouteMatches.Method == nil {
		t.Fatalf("Expected GRPCRouteMatches, got nil")
	}
}

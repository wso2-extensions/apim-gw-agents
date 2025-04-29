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

package grpcgenerator

import (
	"errors"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/pkg/utils"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/types"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// generateGRPCRouteRules generates a list of GRPCRouteRules based on the provided configurations.
func (g *GRPCRouteGenerator) generateGRPCRouteRules(apkConf types.APKConf, operations []types.Operation, endpoint *[]types.EndpointDetails, endpointType string) ([]gwapiv1.GRPCRouteRule, error) {
	var grpcRouteRules []gwapiv1.GRPCRouteRule
	for _, operation := range operations {
		grpcRouteRule, err := g.GenerateGRPCRouteRule(apkConf, operation, endpoint, endpointType)
		if err != nil {
			return nil, err
		}

		grpcRouteRules = append(grpcRouteRules, *grpcRouteRule)
	}
	return grpcRouteRules, nil
}

// generateRouteRule generates a route rule based on the operation and endpoint details.
func (g *GRPCRouteGenerator) generateGRPCRouteRule(apkConf types.APKConf, operation types.Operation, endpoint *[]types.EndpointDetails, endpointType string) (*gwapiv1.GRPCRouteRule, error) {
	var endpointToUse *[]types.EndpointDetails = utils.GetEndpointToUse(operation.EndpointConfigurations, endpointType)
	if endpointToUse == nil && endpoint != nil {
		endpointToUse = endpoint
	}
	if endpointToUse != nil {
		grpcRouteRule := gwapiv1.GRPCRouteRule{
			Matches:     g.RetrieveGRPCMatches(operation),
			BackendRefs: g.GenerateGRPCBackEndRef(*endpointToUse, operation),
		}
		return &grpcRouteRule, nil
	}

	return nil, errors.New("invalid endpoint specified")
}

// generateAndRetrieveParentRefs generates and retrieves the parent references for the GRPCRoute.
func (g *GRPCRouteGenerator) generateAndRetrieveParentRefs(gatewayConfig types.GatewayConfigurations, uniqueID string) []gwapiv1.ParentReference {
	var parentRefs = make([]gwapiv1.ParentReference, 0)
	gatewayName := gatewayConfig.Name
	listenerName := gwapiv1.SectionName(gatewayConfig.ListenerName)
	parentGroup := gwapiv1.Group("gateway.networking.k8s.io")
	parentKind := gwapiv1.Kind("Gateway")

	parentRef := gwapiv1.ParentReference{
		Group:       &parentGroup,
		Kind:        &parentKind,
		Name:        gwapiv1.ObjectName(gatewayName),
		SectionName: &listenerName,
	}
	parentRefs = append(parentRefs, parentRef)
	return parentRefs
}

// generateGRPCBackEndRef generates a list of GRPCBackendRefs based on the provided configurations.
func (g *GRPCRouteGenerator) generateGRPCBackEndRef(endpoints []types.EndpointDetails, operation types.Operation) []gwapiv1.GRPCBackendRef {
	kind := gwapiv1.Kind("Service")
	grpcBackEndRefs := []gwapiv1.GRPCBackendRef{}

	for _, endpoint := range endpoints {
		grpcBackEndRef := gwapiv1.GRPCBackendRef{
			BackendRef: gwapiv1.BackendRef{
				BackendObjectReference: gwapiv1.BackendObjectReference{
					Kind: &kind,
					Name: gwapiv1.ObjectName(endpoint.Name),
				},
			},
		}
		grpcBackEndRefs = append(grpcBackEndRefs, grpcBackEndRef)
	}
	return grpcBackEndRefs
}

// retrieveGRPCMatches retrieves the GRPCRouteMatches based on the provided configurations.
func (g *GRPCRouteGenerator) retrieveGRPCMatches(operation types.Operation) []gwapiv1.GRPCRouteMatch {
	var grpcRouteMatches []gwapiv1.GRPCRouteMatch
	grpcRouteMatch := g.RetrieveGRPCMatch(operation)
	grpcRouteMatches = append(grpcRouteMatches, grpcRouteMatch)
	return grpcRouteMatches
}

// retrieveGRPCMatch retrieves the GRPCRouteMatch based on the provided configurations.
func (g *GRPCRouteGenerator) retrieveGRPCMatch(operation types.Operation) gwapiv1.GRPCRouteMatch {
	matchType := gwapiv1.GRPCMethodMatchType("Exact")
	return gwapiv1.GRPCRouteMatch{
		Method: &gwapiv1.GRPCMethodMatch{
			Type:    &matchType,
			Service: &operation.Target,
			Method:  &operation.Verb,
		},
	}
}

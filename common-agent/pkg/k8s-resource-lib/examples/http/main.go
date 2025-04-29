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

package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/constants"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/pkg/utils"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/types"

	http_generator "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/pkg/generators/http"
)

func main() {
	gen := http_generator.Generator()

	// Read the configuration from the file
	apkConf := utils.ReadAPKConf("./examples/assets/example.apk-conf")
	organization := types.Organization{
		Name: "wso2",
	}
	gatewayConfig := types.GatewayConfigurations{
		Name:         "wso2-apim",
		ListenerName: "wso2-apim-gateway",
		Hostname:     "wso2-apim",
	}

	// Get the endpoint to use
	endpoints := utils.GetEndpoints(*apkConf)
	// If endpoints has production type
	if endpoint, ok := endpoints[constants.ProductionType]; ok {
		k8sArtifacts, err := gen.GenerateHTTPRoute(*apkConf, organization, gatewayConfig, *apkConf.Operations, &endpoint, constants.ProductionType, "unique-route-id", 1)
		if err != nil {
			log.Fatalf("Failed to generate http route: %v", err)
		}
		httpRoute := k8sArtifacts.HTTPRoute
		services := k8sArtifacts.Services

		httpRouteJSONBytes, _ := json.MarshalIndent(httpRoute, " ", " ")
		serviceJSONBytes, _ := json.MarshalIndent(services, " ", " ")
		fmt.Println("HTTPRoute: ")
		fmt.Println(string(httpRouteJSONBytes))
		fmt.Println("Service: ")
		fmt.Println(string(serviceJSONBytes))
	}
}

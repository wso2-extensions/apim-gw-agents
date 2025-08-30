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
package utils

import (
	logger "github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/internal/loggers"
	types "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/managementserver"
)

// APKAPIYamlCreator implements the APIYamlCreator interface for APK
type APKAPIYamlCreator struct{}

// CreateAPIYaml creates APK-specific API YAML configuration
func (a *APKAPIYamlCreator) CreateAPIYaml(event *types.APICPEvent) (string, string, string) {
	logger.LoggerUtils.Infof("Creating APK API YAML for API: %s, Version: %s, UUID: %s",
		event.API.APIName, event.API.APIVersion, event.API.APIUUID)

	// Use the common agent's default CreateAPIYaml function which sets gatewayType to "wso2/apk"
	apiYaml, definition, endpointsYaml := types.CreateAPIYaml(event)

	return apiYaml, definition, endpointsYaml
}

// NewAPKAPIYamlCreator creates a new instance of APKAPIYamlCreator
func NewAPKAPIYamlCreator() *APKAPIYamlCreator {
	logger.LoggerUtils.Info("Creating new APK API YAML creator instance")
	return &APKAPIYamlCreator{}
}

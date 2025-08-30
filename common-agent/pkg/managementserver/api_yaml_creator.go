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
package managementserver

// APIYamlCreator interface defines the contract for creating API YAML configurations
type APIYamlCreator interface {
	CreateAPIYaml(event *APICPEvent) (apiYaml string, definition string, endpointsYaml string)
}

// Global variable to hold the API YAML creator implementation
var apiYamlCreator APIYamlCreator

// SetAPIYamlCreator sets the implementation for API YAML creation
func SetAPIYamlCreator(creator APIYamlCreator) {
	apiYamlCreator = creator
}

// GetAPIYamlCreator returns the current API YAML creator implementation
func GetAPIYamlCreator() APIYamlCreator {
	return apiYamlCreator
}

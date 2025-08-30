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

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	logger "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/loggers"
	utils "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/utils"
)

// HandleDeleteEvent processes a delete event and returns an error if it fails
func HandleDeleteEvent(event APICPEvent) error {
	cpConfig, err := config.ReadConfigs()
	envLabel := []string{"Default"}
	if err == nil {
		envLabel = cpConfig.ControlPlane.EnvironmentLabels
	}

	logger.LoggerMgtServer.Infof("Delete event received with APIUUID: %s", event.API.APIUUID)
	payload := []map[string]interface{}{
		{
			"revisionUuid":       event.API.RevisionID,
			"name":               envLabel[0],
			"vhost":              event.API.Vhost,
			"displayOnDevportal": true,
		},
	}
	jsonPayload, err := json.Marshal(payload)
	logger.LoggerMgtServer.Debugf("Sending payload for revision undeploy: %+v", string(jsonPayload))
	if err != nil {
		logger.LoggerMgtServer.Errorf("Error while preparing payload to delete revision. Processed object: %+v", payload)
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Delete the API revision
	if err := utils.DeleteAPIRevision(event.API.APIUUID, event.API.RevisionID, string(jsonPayload)); err != nil {
		logger.LoggerMgtServer.Errorf("Error while undeploying api revision. RevisionId: %s, API ID: %s", event.API.RevisionID, event.API.APIUUID)
		return fmt.Errorf("failed to undeploy revision: %v", err)
	}
	return nil
}

// HandleCreateOrUpdateEvent processes create or update events and returns id, revisionID, and error
func HandleCreateOrUpdateEvent(event APICPEvent) (string, string, error) {
	// Set default OpenAPI definition for REST APIs if missing
	if strings.EqualFold(event.API.APIType, "rest") && event.API.Definition == "" {
		event.API.Definition = utils.OpenAPIDefaultYaml
	}
	// Convert JSON to YAML for REST APIs
	if strings.EqualFold(event.API.APIType, "rest") {
		if yaml, err := JSONToYAML(event.API.Definition); err == nil {
			event.API.Definition = yaml
		}
	}

	// Generate API and deployment YAMLs using the injected API YAML creator
	if apiYamlCreator == nil {
		logger.LoggerMgtServer.Errorf("API YAML creator not set.")
		return "", "", fmt.Errorf("API YAML creator not configured")
	}
	apiYaml, definition, endpointsYaml := apiYamlCreator.CreateAPIYaml(&event)
	deploymentContent := CreateDeploymentYaml(event.API.Vhost)
	logger.LoggerMgtServer.Debugf("Created apiYaml: %s, \n\n\n created definition file: %s", apiYaml, definition)

	// Determine definition file path
	definitionPath := fmt.Sprintf("%s-%s/Definitions/swagger.yaml", event.API.APIName, event.API.APIVersion)
	if strings.ToUpper(event.API.APIType) == "GRAPHQL" {
		definitionPath = fmt.Sprintf("%s-%s/Definitions/schema.graphql", event.API.APIName, event.API.APIVersion)
	}

	// Prepare zip files
	var zipFiles []utils.ZipFile
	logger.LoggerMgtServer.Debugf("endpoints yaml: %s", endpointsYaml)
	if endpointsYaml != "{}\n" {
		logger.LoggerMgtServer.Debugf("Creating zip file with endpoints")
		zipFiles = []utils.ZipFile{{
			Path:    fmt.Sprintf("%s-%s/api.yaml", event.API.APIName, event.API.APIVersion),
			Content: apiYaml,
		}, {
			Path:    fmt.Sprintf("%s-%s/endpoints.yaml", event.API.APIName, event.API.APIVersion),
			Content: endpointsYaml,
		}, {
			Path:    fmt.Sprintf("%s-%s/deployment_environments.yaml", event.API.APIName, event.API.APIVersion),
			Content: deploymentContent,
		}, {
			Path:    definitionPath,
			Content: definition,
		}}
	} else {
		logger.LoggerMgtServer.Debugf("Creating zip file without endpoints")
		zipFiles = []utils.ZipFile{{
			Path:    fmt.Sprintf("%s-%s/api.yaml", event.API.APIName, event.API.APIVersion),
			Content: apiYaml,
		}, {
			Path:    fmt.Sprintf("%s-%s/deployment_environments.yaml", event.API.APIName, event.API.APIVersion),
			Content: deploymentContent,
		}, {
			Path:    definitionPath,
			Content: definition,
		}}
	}

	var buf bytes.Buffer
	if err := utils.CreateZipFile(&buf, zipFiles); err != nil {
		logger.LoggerMgtServer.Errorf("Error while creating apim zip file for api uuid: %s. Error: %+v", event.API.APIUUID, err)
		return "", "", fmt.Errorf("failed to create zip file: %v", err)
	}

	// Import API
	id, revisionID, err := utils.ImportAPI(fmt.Sprintf("admin-%s-%s.zip", event.API.APIName, event.API.APIVersion), &buf)
	if err != nil {
		logger.LoggerMgtServer.Errorf("Error while importing API.")
		return "", "", fmt.Errorf("failed to import API: %v", err)
	}
	return id, revisionID, nil
}

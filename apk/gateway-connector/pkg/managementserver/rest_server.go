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
package managementserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	logger "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/loggers"
	mgtServer "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/managementserver"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/utils"
)

// StartInternalServer starts the internal server
func StartInternalServer(port uint) {
	cpConfig, err := config.ReadConfigs()
	envLabel := []string{"Default"}
	if err == nil {
		envLabel = cpConfig.ControlPlane.EnvironmentLabels
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.GET("/applications", func(c *gin.Context) {
		applicationList := GetAllApplications()
		c.JSON(http.StatusOK, ResolvedApplicationList{List: applicationList})
	})
	r.GET("/subscriptions", func(c *gin.Context) {
		subscriptionList := mgtServer.GetAllSubscriptions()
		c.JSON(http.StatusOK, mgtServer.SubscriptionList{List: subscriptionList})
	})
	r.GET("/applicationmappings", func(c *gin.Context) {
		applicationMappingList := GetAllApplicationMappings()
		c.JSON(http.StatusOK, ApplicationMappingList{List: applicationMappingList})
	})
	r.POST("/apis", func(c *gin.Context) {
		var event mgtServer.APICPEvent
		if err := c.ShouldBindJSON(&event); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		logger.LoggerMgtServer.Debugf("Recieved payload for endpoint /apis: %+v", event)
		if event.Event == mgtServer.DeleteEvent {
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
				c.JSON(http.StatusInternalServerError, err.Error())
				return
			}
			// Delete the api
			errorUndeployRevision := utils.DeleteAPIRevision(event.API.APIUUID, event.API.RevisionID, string(jsonPayload))
			if errorUndeployRevision != nil {
				logger.LoggerMgtServer.Errorf("Error while undeploying api revision. RevisionId: %s, API ID: %s . Sending error response to Adapter.", event.API.RevisionID, event.API.APIUUID)
				c.JSON(http.StatusServiceUnavailable, errorUndeployRevision.Error())
				return
			}
			c.JSON(http.StatusOK, map[string]string{"message": "Success"})
		} else {
			if strings.EqualFold(event.API.APIType, "rest") && event.API.Definition == "" {
				event.API.Definition = utils.OpenAPIDefaultYaml
			}
			if strings.EqualFold(event.API.APIType, "rest") {
				yaml, errJSONToYaml := mgtServer.JSONToYAML(event.API.Definition)
				if errJSONToYaml == nil {
					event.API.Definition = yaml
				}
			}
			apiYaml, definition, endpointsYaml := mgtServer.CreateAPIYaml(&event)
			deploymentContent := mgtServer.CreateDeploymentYaml(event.API.Vhost)
			logger.LoggerMgtServer.Debugf("Created apiYaml : %s, \n\n\n created definition file: %s, \n\n\n created endpointYaml : %s", apiYaml, definition, endpointsYaml)
			definitionPath := fmt.Sprintf("%s-%s/Definitions/swagger.yaml", event.API.APIName, event.API.APIVersion)
			if strings.ToUpper(event.API.APIType) == "GRAPHQL" {
				definitionPath = fmt.Sprintf("%s-%s/Definitions/schema.graphql", event.API.APIName, event.API.APIVersion)
			}
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
			}

			id, revisionID, err := utils.ImportAPI(fmt.Sprintf("admin-%s-%s.zip", event.API.APIName, event.API.APIVersion), &buf)
			if err != nil {
				logger.LoggerMgtServer.Errorf("Error while importing API. Sending error response to Adapter.")
				c.JSON(http.StatusServiceUnavailable, err.Error())
				return
			}
			c.JSON(http.StatusOK, map[string]string{"id": id, "revisionID": revisionID})
		}
	})
	publicKeyLocation, privateKeyLocation, _ := config.GetKeyLocations()
	r.RunTLS(fmt.Sprintf(":%d", port), publicKeyLocation, privateKeyLocation)
}

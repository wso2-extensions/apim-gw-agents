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

/*
 * Package "synchronizer" contains artifacts relate to fetching APIs and
 * API related updates from the control plane event-hub.
 * This file contains functions to retrieve APIs and API updates.
 */

package synchronizer

import (
	"fmt"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	sync "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/synchronizer"
	transformer "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/transformer"
	logger "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/loggers"
	mapperUtil "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/mapper"
	kongTransformer "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/pkg/transformer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func init() {
	conf, _ := config.ReadConfigs()
	sync.InitializeWorkerPool(conf.ControlPlane.RequestWorkerPool.PoolSize, conf.ControlPlane.RequestWorkerPool.QueueSizePerPool,
		conf.ControlPlane.RequestWorkerPool.PauseTimeAfterFailure, conf.Agent.TrustStore.Location,
		conf.ControlPlane.SkipSSLVerification, conf.ControlPlane.HTTPClient.RequestTimeOut, conf.ControlPlane.RetryInterval,
		conf.ControlPlane.ServiceURL, conf.ControlPlane.Username, conf.ControlPlane.Password)
}

// FetchAPIsOnEvent  will fetch API from control plane during the API Notification Event
func FetchAPIsOnEvent(conf *config.Config, apiUUID *string, k8sClient client.Client) (*[]string, error) {
	apis := make([]string, 0)
	apiResult, err := sync.FetchAPIsOnEvent(conf, apiUUID, k8sClient)
	if err != nil {
		return nil, err
	}

	if apiResult != nil {
		apis = *apiResult.APIs
		if apiResult.APIDeployments != nil {
			for _, apiDeployment := range *apiResult.APIDeployments {
				apiZip, exists := apiResult.APIFiles[apiDeployment.APIFile]
				if exists {
					artifact, decodingError := transformer.DecodeAPIArtifact(apiZip)
					if decodingError != nil {
						logger.LoggerUtils.Errorf("Error while decoding the API Project Artifact: %v", decodingError)
						return nil, err
					}

					logger.LoggerUtils.Infof("Environments: %+v", apiDeployment.Environments)
					envLabel := "Default"
					if apiDeployment.Environments != nil && len(*apiDeployment.Environments) > 0 {
						envLabel = (*apiDeployment.Environments)[0].Name
					}
					logger.LoggerUtils.Infof("Selected Environment Label: %s", envLabel)

					api, apiUUID, revisionID, configuredRateLimitPoliciesMap, _, _, _, _, apkErr := transformer.GenerateConf(artifact.APIJson, artifact.CertArtifact, artifact.Endpoints, apiDeployment.OrganizationID, envLabel)
					if apkErr != nil {
						logger.LoggerUtils.Errorf("Error while generating APK-Conf: %v", apkErr)
						return nil, err
					}
					logger.LoggerUtils.Infof("APK Conf: %v", api)

					crResources := kongTransformer.GenerateCR(api, apiDeployment.OrganizationID, apiUUID)
					kongTransformer.UpdateCRS(crResources, apiDeployment.Environments, apiDeployment.OrganizationID, apiUUID, fmt.Sprint(revisionID), "namespace", configuredRateLimitPoliciesMap)
					mapperUtil.MapAndCreateCR(*crResources, k8sClient)
					apis = append(apis, apiUUID)
					logger.LoggerUtils.Info("API applied successfully.\n")
				}
			}
		}
		return &apis, nil
	}
	return nil, nil
}

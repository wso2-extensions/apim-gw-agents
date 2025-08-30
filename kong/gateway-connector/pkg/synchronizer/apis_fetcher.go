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
 * Package "synchronizer" contains utilities for fetching APIs and
 * API related updates from the control plane event-hub.
 * This file contains functions to retrieve APIs and API updates.
 */

package synchronizer

import (
	"fmt"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	sync "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/synchronizer"
	transformer "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/transformer"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	mapperUtil "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/mapper"
	logger "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/loggers"
	kongTransformer "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/transformer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func init() {
	conf, err := config.ReadConfigs()
	if err != nil {
		logger.LoggerSynchronizer.Errorf("Failed to read configuration during initialization: %v", err)
		return
	}

	poolConfig := conf.ControlPlane.RequestWorkerPool
	sync.InitializeWorkerPool(poolConfig.PoolSize, poolConfig.QueueSizePerPool,
		poolConfig.PauseTimeAfterFailure, conf.Agent.TrustStore.Location,
		conf.ControlPlane.SkipSSLVerification, conf.ControlPlane.HTTPClient.RequestTimeOut,
		conf.ControlPlane.RetryInterval, conf.ControlPlane.ServiceURL,
		conf.ControlPlane.Username, conf.ControlPlane.Password)
}

// FetchAPIsOnEvent will fetch API from control plane during the API Notification Event
func FetchAPIsOnEvent(conf *config.Config, apiUUID *string, k8sClient client.Client) (*[]string, error) {
	apis := make([]string, 0)
	apiResult, err := sync.FetchAPIsOnEvent(conf, apiUUID, k8sClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch APIs from control plane: %w", err)
	}

	if apiResult == nil {
		logger.LoggerSynchronizer.Debug("No API result received from control plane")
		return &apis, nil
	}

	if apiResult.APIs != nil {
		apis = append(apis, *apiResult.APIs...)
	}

	if apiResult.APIDeployments != nil {
		deployments := *apiResult.APIDeployments
		logger.LoggerSynchronizer.Debugf("Processing %d API deployments", len(deployments))

		for i, apiDeployment := range deployments {
			apiZip, exists := apiResult.APIFiles[apiDeployment.APIFile]
			if !exists {
				logger.LoggerSynchronizer.Warnf("API file %s not found for deployment %d", apiDeployment.APIFile, i+1)
				continue
			}

			artifact, decodingError := transformer.DecodeAPIArtifact(apiZip)
			if decodingError != nil {
				logger.LoggerSynchronizer.Errorf("Error while decoding the API Project Artifact: %v", decodingError)
				continue
			}

			envLabel := constants.DefaultEnvironmentLabel
			if apiDeployment.Environments != nil && len(*apiDeployment.Environments) > 0 {
				firstEnv := (*apiDeployment.Environments)[0]
				if firstEnv.Name != "" {
					envLabel = firstEnv.Name
				}
			}
			logger.LoggerSynchronizer.Infof("Selected Environment Label: %s", envLabel)

			api, apiName, generatedAPIUUID, revisionID, configuredRateLimitPoliciesMap, _, _, _, _, kongErr := transformer.GenerateConf(
				artifact.APIJson, artifact.CertArtifact, artifact.Endpoints, apiDeployment.OrganizationID, envLabel)
			if kongErr != nil {
				logger.LoggerSynchronizer.Errorf("Error while generating Kong-Conf: %v", kongErr)
				continue
			}

			logger.LoggerSynchronizer.Debugf("Generated API Value : %+v\n", api)

			crResources := kongTransformer.GenerateCR(api, apiDeployment.OrganizationID, generatedAPIUUID, conf)
			if crResources != nil {
				kongTransformer.UpdateCRS(crResources, apiDeployment.Environments,
					apiDeployment.OrganizationID, generatedAPIUUID, apiName,
					fmt.Sprint(revisionID), constants.DefaultKongNamespace,
					configuredRateLimitPoliciesMap)

				mapperUtil.MapAndCreateCR(*crResources, k8sClient)
				apis = append(apis, generatedAPIUUID)
				logger.LoggerSynchronizer.Infof("API Applied Successfully: %s", generatedAPIUUID)
			}
		}
	}

	logger.LoggerSynchronizer.Infof("Total APIs processed: %d", len(apis))
	return &apis, nil
}

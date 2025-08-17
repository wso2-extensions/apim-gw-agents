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

/*
 * Package "synchronizer" contains artifacts relate to fetching APIs and
 * API related updates from the control plane event-hub.
 * This file contains functions to retrieve APIs and API updates.
 */

package synchronizer

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"

	logger "github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/internal/loggers"
	apkTransformer "github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/pkg/transformer"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	sync "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/synchronizer"
	transformer "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/transformer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mapperUtil "github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/internal/mapper"
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
	// Populate data from config.
	apis := make([]string, 0)
	// Common agent logic for control plane communication and artifact fetching
	// including Handles HTTP requests, ZIP processing, and retry logic
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

					apkConf, apiUUID, revisionID, configuredRateLimitPoliciesMap, endpointSecurityData, api, prodAIRL, sandAIRL, apkErr := transformer.GenerateConf(artifact.APIJson, artifact.CertArtifact, artifact.Endpoints, apiDeployment.OrganizationID)
					if prodAIRL == nil {
						// Try to delete production AI ratelimit for this api
						// !!!TODO: Might hava to change the implementation becuase now we use BackendTrafficPolicy + RoutePolicy
						// k8sclientUtil.DeleteAIRatelimitPolicy(generateSHA1HexHash(api.Name, api.Version, "production"), k8sClient)
						logger.LoggerUtils.Debugf("Trying to delete production AI ratelimit for API: %v", api.Name)
					}
					if sandAIRL == nil {
						// Try to delete sandbox AI ratelimit for this api
						// !!!TODO: Might hava to change the implementation becuase now we use BackendTrafficPolicy + RoutePolicy
						// k8sclientUtil.DeleteAIRatelimitPolicy(generateSHA1HexHash(api.Name, api.Version, "sandbox"), k8sClient)
						logger.LoggerUtils.Debugf("Trying to delete sandbox AI ratelimit for API: %v", api.Name)
					}
					if apkErr != nil {
						logger.LoggerUtils.Errorf("Unable to generate APK-Conf: %+v", apkErr)
						return nil, err
					}
					certContainer := transformer.CertContainer{
						ClientCertObj:   artifact.CertMeta,
						EndpointCertObj: artifact.EndpointCertMeta,
						SecretData:      endpointSecurityData,
					}
					k8ResourceEndpoint := conf.DataPlane.K8ResourceEndpoint
					crResponse, err := apkTransformer.GenerateCRs(apkConf, artifact.Schema, certContainer, k8ResourceEndpoint, apiDeployment.OrganizationID)
					if err != nil {
						logger.LoggerUtils.Errorf("Error occured in receiving the updated CRDs: %+v", err)
						return nil, err
					}
					apkTransformer.UpdateCRS(crResponse, apiDeployment.Environments, apiDeployment.OrganizationID, apiUUID, fmt.Sprint(revisionID), "namespace", configuredRateLimitPoliciesMap)
					mapperUtil.MapAndCreateCR(*crResponse, k8sClient)
					apis = append(apis, apiUUID)
					logger.LoggerUtils.Info("API applied successfully.\n")
				}
			}
		}
		return &apis, nil
	}
	return nil, nil
}

// generateSHA1HexHash hashes the concatenated strings and returns the SHA-1 hash in base16 (hex) encoding.
func generateSHA1HexHash(name, version, env string) string {
	data := name + version + env
	hasher := sha1.New()
	hasher.Write([]byte(data))
	hashBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

// GetAPI function calls the FetchAPIs() with relevant environment labels defined in the config.
func GetAPI(c chan sync.SyncAPIResponse, id *string, envs []string, endpoint string, sendType bool) {
	if len(envs) > 0 {
		// If the envrionment labels are present, call the controle plane with labels.
		logger.LoggerUtils.Debugf("Environment labels present: %v", envs)
		go sync.FetchAPIs(id, envs, c, endpoint, sendType)
	}
}

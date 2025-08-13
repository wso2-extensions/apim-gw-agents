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
 * Package "transformer" contains functions related to converting
 * API project to apk-conf and generating and modifying CRDs belonging to
 * a particular API.
 */

package transformer

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/internal/constants"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/cache"
	eventHub "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"
	logger "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/loggers"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/managementserver"

	"gopkg.in/yaml.v2"
)

// GenerateConf will Generate the mapped .apk-conf file for a given API Project zip
func GenerateConf(APIJson string, certArtifact CertificateArtifact, endpoints string, organizationID string) (string, string, uint32, map[string]eventHub.RateLimitPolicy, []EndpointSecurityConfig, *API, *AIRatelimit, *AIRatelimit, error) {

	apk := &API{}

	var apiYaml APIYaml
	var endpointsYaml EndpointsYaml

	var configuredRateLimitPoliciesMap = make(map[string]eventHub.RateLimitPolicy)

	logger.LoggerTransformer.Debugf("APIJson: %v", APIJson)
	logger.LoggerTransformer.Debugf("Endpoints: %v", endpoints)

	apiYamlError := json.Unmarshal([]byte(APIJson), &apiYaml)
	if apiYamlError != nil {
		apiYamlError = yaml.Unmarshal([]byte(APIJson), &apiYaml)
	}

	endpointsYamlError := json.Unmarshal([]byte(endpoints), &endpointsYaml)
	if endpointsYamlError != nil {
		endpointsYamlError = yaml.Unmarshal([]byte(endpoints), &endpointsYaml)
	}

	if apiYamlError != nil {
		logger.LoggerTransformer.Error("Error while unmarshalling api.json/api.yaml content", apiYamlError)
		return "", "null", 0, nil, []EndpointSecurityConfig{}, nil, nil, nil, apiYamlError
	}

	if endpointsYamlError != nil {
		logger.LoggerTransformer.Error("Error while unmarshalling endpoints.json/endpoints.yaml content", endpointsYamlError)
		return "", "null", 0, nil, []EndpointSecurityConfig{}, nil, nil, nil, endpointsYamlError
	}

	endpointList := endpointsYaml.Data
	logger.LoggerTransformer.Debugf("EndpointList: %v", endpointList)

	apiYamlData := apiYaml.Data
	logger.LoggerTransformer.Debugf("apiYamlData: %v", apiYamlData)

	apk.Name = apiYamlData.Name
	apk.Context = apiYamlData.Context
	apk.Version = apiYamlData.Version
	apk.Type = getAPIType(apiYamlData.Type)
	apk.DefaultVersion = apiYamlData.DefaultVersion
	apk.DefinitionPath = "/definition"
	apk.SubscriptionValidation = true

	sandboxURL := apiYamlData.EndpointConfig.SandboxEndpoints.URL
	prodURL := apiYamlData.EndpointConfig.ProductionEndpoints.URL
	primaryProdEndpointID := apiYamlData.PrimaryProductionEndpointID
	primarySandboxEndpointID := apiYamlData.PrimarySandboxEndpointID

	primaryProdEndpoint := Endpoint{
		ID:   primaryProdEndpointID,
		Name: "Primary Production Endpoint",
		EndpointConfig: EndpointConfig{
			ProductionEndpoints: EndpointDetails{
				URL: prodURL,
			},
			EndpointType:     apiYamlData.EndpointConfig.EndpointType,
			EndpointSecurity: apiYamlData.EndpointConfig.EndpointSecurity,
		},
		DeploymentStage: "PRODUCTION",
	}

	primarySandboxEndpoint := Endpoint{
		ID:   primarySandboxEndpointID,
		Name: "Primary Sandbox Endpoint",
		EndpointConfig: EndpointConfig{
			SandboxEndpoints: EndpointDetails{
				URL: sandboxURL,
			},
			EndpointType:     apiYamlData.EndpointConfig.EndpointType,
			EndpointSecurity: apiYamlData.EndpointConfig.EndpointSecurity,
		},
		DeploymentStage: "SANDBOX",
	}

	var defaultEndpointList []Endpoint
	defaultEndpointList = append(defaultEndpointList, primaryProdEndpoint)
	defaultEndpointList = append(defaultEndpointList, primarySandboxEndpoint)

	if apiYamlData.SubtypeConfiguration.Subtype == "AIAPI" && apiYamlData.SubtypeConfiguration.Configuration != "" {
		// Unmarshal the _configuration field into the Configuration struct
		var config Configuration
		err := json.Unmarshal([]byte(apiYamlData.SubtypeConfiguration.Configuration), &config)
		if err != nil {
			fmt.Println("Error unmarshalling _configuration:", err)
			return "", "null", 0, nil, []EndpointSecurityConfig{}, nil, nil, nil, err
		}
		sha1ValueforCRName := config.LLMProviderID
		apk.AIProvider = &AIProvider{
			Name:       sha1ValueforCRName,
			APIVersion: "1",
		}
	}

	if apiYamlData.APIThrottlingPolicy != "" {
		rateLimitPolicy := managementserver.GetRateLimitPolicy(apiYamlData.APIThrottlingPolicy, organizationID)
		logger.LoggerTransformer.Debugf("Rate Limit Policy: %v", rateLimitPolicy)
		if rateLimitPolicy.Name != "" && rateLimitPolicy.Name != "Unlimited" {
			var rateLimitPolicyConfigured = RateLimit{
				RequestsPerUnit: rateLimitPolicy.DefaultLimit.RequestCount.RequestCount,
				Unit:            rateLimitPolicy.DefaultLimit.RequestCount.TimeUnit,
			}
			apk.RateLimit = &rateLimitPolicyConfigured
			configuredRateLimitPoliciesMap["API"] = rateLimitPolicy
		}
	}
	apkOperations := make([]Operation, len(apiYamlData.Operations))

	for i, operation := range apiYamlData.Operations {

		reqPolicyCount := len(operation.OperationPolicies.Request)
		resPolicyCount := len(operation.OperationPolicies.Response)
		reqInterceptor, resInterceptor := getReqAndResInterceptors(reqPolicyCount, resPolicyCount,
			operation.OperationPolicies.Request, operation.OperationPolicies.Response, endpointList, defaultEndpointList)

		var opRateLimit *RateLimit
		if apiYamlData.APIThrottlingPolicy == "" && operation.ThrottlingPolicy != "" {
			rateLimitPolicy := managementserver.GetRateLimitPolicy(operation.ThrottlingPolicy, organizationID)
			logger.LoggerTransformer.Debugf("Op Rate Limit Policy Name: %v", rateLimitPolicy.Name)
			if rateLimitPolicy.Name != "" && rateLimitPolicy.Name != "Unlimited" {
				var rateLimitPolicyConfigured = RateLimit{
					RequestsPerUnit: rateLimitPolicy.DefaultLimit.RequestCount.RequestCount,
					Unit:            rateLimitPolicy.DefaultLimit.RequestCount.TimeUnit,
				}
				opRateLimit = &rateLimitPolicyConfigured
				configuredRateLimitPoliciesMap["Resource"] = rateLimitPolicy
			}
		}
		logger.LoggerTransformer.Debugf("Operation Auth Type: %v", operation.AuthType)
		AuthSecured := true
		if operation.AuthType == "None" {
			logger.LoggerTransformer.Debugf("Setting AuthSecured to false")
			AuthSecured = false
		}
		op := &Operation{
			Target:  operation.Target,
			Verb:    operation.Verb,
			Scopes:  operation.Scopes,
			Secured: AuthSecured,
			OperationPolicies: &OperationPolicies{
				Request:  *reqInterceptor,
				Response: *resInterceptor,
			},
			RateLimit: opRateLimit,
		}
		apkOperations[i] = *op
	}

	apk.Operations = &apkOperations

	//Adding API Level Operation Policies to the conf
	reqPolicyCount := len(apiYaml.Data.APIPolicies.Request)
	resPolicyCount := len(apiYaml.Data.APIPolicies.Response)
	reqInterceptor, resInterceptor := getReqAndResInterceptors(reqPolicyCount, resPolicyCount,
		apiYaml.Data.APIPolicies.Request, apiYaml.Data.APIPolicies.Response, endpointList, defaultEndpointList)

	apk.APIPolicies = &OperationPolicies{
		Request:  *reqInterceptor,
		Response: *resInterceptor,
	}

	//Adding Endpoint-certificate configurations to the conf
	var endpointCertList EndpointCertDescriptor
	endCertAvailable := false

	if certArtifact.EndpointCerts != "" {
		certErr := json.Unmarshal([]byte(certArtifact.EndpointCerts), &endpointCertList)
		if certErr != nil {
			logger.LoggerTransformer.Errorf("Error while unmarshalling endpoint_cert.json content: %v", apiYamlError)
			return "", "null", 0, nil, []EndpointSecurityConfig{}, nil, nil, nil, certErr
		}
		endCertAvailable = true
	}

	endpointSecurityDataList := []EndpointSecurityConfig{}

	apiUniqueID := GetUniqueIDForAPI(apiYamlData.Name, apiYamlData.Version, apiYamlData.OrganizationID)
	logger.LoggerTransformer.Debugf("Maxtps: %+v", apiYamlData)
	prodAIRatelimit, sandAIRatelimit := prepareAIRatelimit(apiYamlData.MaxTps)
	endpointRes := EndpointConfigurations{}
	logger.LoggerTransformer.Debugf("EndpointList len: %d", len(endpointList))
	if len(endpointList) == 0 {
		endpointSecurityData := apiYamlData.EndpointConfig.EndpointSecurity
		endpointRes, endpointSecurityData = getEndpointConfigs(sandboxURL, prodURL, endCertAvailable, endpointCertList, endpointSecurityData, apiUniqueID, prodAIRatelimit, sandAIRatelimit)
		apk.EndpointConfigurations = &endpointRes
		endpointSecurityDataList = append(endpointSecurityDataList, endpointSecurityData)
	} else {
		mergedEndpointList := append(endpointList, defaultEndpointList...)
		endpointRes, endpointSecurityDataList = getMultiEndpointConfigs(mergedEndpointList, primaryProdEndpointID, primarySandboxEndpointID, endCertAvailable, endpointCertList, apiUniqueID, prodAIRatelimit, sandAIRatelimit)
		apk.EndpointConfigurations = &endpointRes
	}

	//Adding client-certificate configurations to the conf
	var certList CertDescriptor
	certAvailable := false

	if certArtifact.ClientCerts != "" {
		certErr := json.Unmarshal([]byte(certArtifact.ClientCerts), &certList)
		if certErr != nil {
			logger.LoggerTransformer.Errorf("Error while unmarshalling client_cert.json content: %v", apiYamlError)
			return "", "null", 0, nil, []EndpointSecurityConfig{}, nil, nil, nil, certErr
		}
		certAvailable = true
	}

	authConfigList := mapAuthConfigs(apiYamlData.ID, apiYamlData.AuthorizationHeader, apiYamlData.APIKeyHeader,
		apiYamlData.SecuritySchemes, certAvailable, certList, apiUniqueID)

	apk.Authentication = &authConfigList

	corsEnabled := apiYamlData.CORSConfiguration.CORSConfigurationEnabled

	if corsEnabled {
		apk.CorsConfig = &apiYamlData.CORSConfiguration
	}

	aditionalProperties := make([]AdditionalProperty, len(apiYamlData.AdditionalProperties))

	for i, property := range apiYamlData.AdditionalProperties {
		prop := &AdditionalProperty{
			Name:  property.Name,
			Value: property.Value,
		}
		aditionalProperties[i] = *prop
	}

	apk.AdditionalProperties = &aditionalProperties

	//!!!TODO: Add KeyManagers to the conf
	// Since we only get the KM name, need to get the rest of the details from the internal map we keep
	// after fetching the key managers from the control plane.
	logger.LoggerTransformer.Infof("KeyManager data from yaml: %+v", apiYamlData.KeyManagers)
	kmData := mapKeyManagers(apiYamlData.KeyManagers)
	logger.LoggerTransformer.Debugf("KeyManager data after mapping: %+v", kmData)
	apk.KeyManagers = &kmData

	c, marshalError := yaml.Marshal(apk)

	if marshalError != nil {
		logger.LoggerTransformer.Error("Error while marshalling apk yaml", marshalError)
		return "", "null", 0, nil, []EndpointSecurityConfig{}, nil, prodAIRatelimit, sandAIRatelimit, marshalError
	}
	return string(c), apiYamlData.RevisionedAPIID, apiYamlData.RevisionID, configuredRateLimitPoliciesMap, endpointSecurityDataList, apk, prodAIRatelimit, sandAIRatelimit, nil
}

// Generate the interceptor policy if request or response policy exists
func getReqAndResInterceptors(reqPolicyCount, resPolicyCount int, reqPolicies []APIMOperationPolicy, resPolicies []APIMOperationPolicy, endpointList []Endpoint, defaultEndpointList []Endpoint) (*[]OperationPolicy, *[]OperationPolicy) {
	var requestPolicyList, responsePolicyList []OperationPolicy
	var interceptorParams *InterceptorService
	var requestInterceptorPolicy, responseInterceptorPolicy, requestBackendJWTPolicy OperationPolicy
	var mirrorRequestPolicy OperationPolicy
	var mirrorUrls []string

	if reqPolicyCount > 0 {
		for _, reqPolicy := range reqPolicies {
			logger.LoggerTransformer.Debugf("Request Policy: %v", reqPolicy)
			if strings.HasSuffix(reqPolicy.PolicyName, constants.InterceptorService) {
				logger.LoggerTransformer.Debugf("Interceptor Type Request Policy: %v", reqPolicy)
				logger.LoggerTransformer.Debugf("Interceptor Service URL: %v", reqPolicy.Parameters[interceptorServiceURL])
				logger.LoggerTransformer.Debugf("Interceptor Includes: %v", reqPolicy.Parameters[includes])
				interceptorServiceURL := reqPolicy.Parameters[interceptorServiceURL].(string)
				includes := reqPolicy.Parameters[includes].(string)
				substrings := strings.Split(includes, ",")
				bodyEnabled := false
				headerEnabled := false
				trailersEnabled := false
				contextEnabled := false
				sslEnabled := false
				tlsSecretName := ""
				tlsSecretKey := ""
				for _, substring := range substrings {
					if strings.Contains(substring, requestHeader) {
						headerEnabled = true
					} else if strings.Contains(substring, requestBody) {
						bodyEnabled = true
					} else if strings.Contains(substring, requestTrailers) {
						trailersEnabled = true
					} else if strings.Contains(substring, requestContext) {
						contextEnabled = true
					}
				}

				if strings.Contains(interceptorServiceURL, https) {
					sslEnabled = true
				}

				if sslEnabled {
					tlsSecretName = reqPolicy.PolicyID + requestInterceptorSecretName
					tlsSecretKey = tlsKey
				}

				interceptorParams = &InterceptorService{
					BackendURL:      interceptorServiceURL,
					HeadersEnabled:  headerEnabled,
					BodyEnabled:     bodyEnabled,
					TrailersEnabled: trailersEnabled,
					ContextEnabled:  contextEnabled,
					TLSSecretName:   tlsSecretName,
					TLSSecretKey:    tlsSecretKey,
				}

				// Create an instance of OperationPolicy
				requestInterceptorPolicy = OperationPolicy{
					PolicyName:    interceptorPolicy,
					PolicyVersion: v1,
					Parameters:    interceptorParams,
				}
			} else if reqPolicy.PolicyName == constants.BackendJWT {
				encoding := reqPolicy.Parameters[encoding].(string)
				header := reqPolicy.Parameters[header].(string)
				signingAlgorithm := reqPolicy.Parameters[signingAlgorithm].(string)
				tokenTTL := reqPolicy.Parameters[tokenTTL].(string)
				tokenTTLConverted, err := strconv.Atoi(tokenTTL)
				if err != nil {
					logger.LoggerTransformer.Errorf("Error while converting tokenTTL to integer: %v", err)
				}

				if encoding == base64Url {
					encoding = base64url
				}

				backendJWTParams := &BackendJWT{
					Encoding:         encoding,
					Header:           header,
					SigningAlgorithm: signingAlgorithm,
					TokenTTL:         tokenTTLConverted,
				}

				// Create an instance of OperationPolicy
				requestBackendJWTPolicy = OperationPolicy{
					PolicyName:    backendJWTPolicy,
					PolicyVersion: v1,
					Parameters:    backendJWTParams,
				}
			} else if reqPolicy.PolicyName == constants.AddHeader {
				logger.LoggerTransformer.Debugf("AddHeader Type Request Policy: %v", reqPolicy)
				requestAddHeader := OperationPolicy{
					PolicyName:    addHeaderPolicy,
					PolicyVersion: v1,
					Parameters: Header{
						HeaderName:  reqPolicy.Parameters[headerName].(string),
						HeaderValue: reqPolicy.Parameters[headerValue].(string),
					},
				}
				requestPolicyList = append(requestPolicyList, requestAddHeader)
			} else if reqPolicy.PolicyName == constants.RemoveHeader {
				logger.LoggerTransformer.Debugf("RemoveHeader Type Request Policy: %v", reqPolicy)
				requestRemoveHeader := OperationPolicy{
					PolicyName:    removeHeaderPolicy,
					PolicyVersion: v1,
					Parameters: Header{
						HeaderName: reqPolicy.Parameters[headerName].(string),
					},
				}
				requestPolicyList = append(requestPolicyList, requestRemoveHeader)
			} else if reqPolicy.PolicyName == constants.RedirectRequest {
				logger.LoggerTransformer.Debugf("RedirectRequest Type Request Policy: %v", reqPolicy)
				redirectRequestPolicy := OperationPolicy{
					PolicyName:    requestRedirectPolicy,
					PolicyVersion: v1,
				}
				parameters := RedirectPolicy{
					URL: reqPolicy.Parameters[url].(string),
				}
				switch v := reqPolicy.Parameters[statusCode].(type) {
				case int:
					parameters.StatusCode = v
				case string:
					if intValue, err := strconv.Atoi(v); err == nil {
						parameters.StatusCode = intValue
					} else {
						logger.LoggerTransformer.Error("Invalid status code provided.")
					}
				default:
					parameters.StatusCode = 302
				}
				redirectRequestPolicy.Parameters = parameters
				requestPolicyList = append(requestPolicyList, redirectRequestPolicy)
			} else if reqPolicy.PolicyName == constants.MirrorRequest {
				logger.LoggerTransformer.Debugf("MirrorRequest Type Request Policy: %v", reqPolicy)
				if mirrorRequestPolicy.PolicyName == "" {
					mirrorRequestPolicy = OperationPolicy{
						PolicyName:    requestMirrorPolicy,
						PolicyVersion: v1,
					}
					mirrorUrls = []string{}
				}
				if reqPolicyParameters, ok := reqPolicy.Parameters[url]; ok {
					url := reqPolicyParameters.(string)
					mirrorUrls = append(mirrorUrls, url)
				}
			} else if reqPolicy.PolicyName == constants.ModelRoundRobin || reqPolicy.PolicyName == constants.ModelWeightedRoundRobin {
				logger.LoggerTransformer.Debugf("ModelRoundRobin Type Request Policy: %v", reqPolicy)
				modelRoundRobinPolicy := OperationPolicy{
					PolicyName:    modelBasedRoundRobin,
					PolicyVersion: v1,
				}
				var configs interface{}
				if reqPolicy.PolicyName == constants.ModelRoundRobin {
					configs = reqPolicy.Parameters["roundRobinConfigs"]
				} else if reqPolicy.PolicyName == constants.ModelWeightedRoundRobin {
					configs = reqPolicy.Parameters["weightedRoundRobinConfigs"]
				}

				logger.LoggerTransformer.Debugf("Configs: %v", configs)
				// Convert interface{} to string, then to []byte
				configStr, ok := configs.(string)
				if !ok {
					fmt.Println("Error: expected a JSON string, but got a different type")
				}
				// Replace single quotes with double quotes to make valid JSON
				configStr = strings.ReplaceAll(configStr, "'", "\"")
				jsonBytes := []byte(configStr)
				var config Config
				if err := json.Unmarshal(jsonBytes, &config); err != nil {
					fmt.Println("Error unmarshalling JSON:", err)
				}
				logger.LoggerTransformer.Debugf("Parsed Config: %+v\n", config)
				parameters := ModelBasedRoundRobin{
					OnQuotaExceedSuspendDuration: func() int {
						duration, err := strconv.Atoi(config.SuspendDuration)
						if err != nil {
							logger.LoggerTransformer.Errorf("Error while converting SuspendDuration to integer: %v", err)
							return 0
						}
						return duration
					}(),
				}
				var productionModels []ModelEndpoints
				var sandboxModels []ModelEndpoints
				var endpointIdtoURL = make(map[string]string)
				for _, endpoint := range endpointList {
					if endpoint.EndpointConfig.ProductionEndpoints.URL != "" {
						endpointIdtoURL[endpoint.ID] = endpoint.EndpointConfig.ProductionEndpoints.URL
					}
					if endpoint.EndpointConfig.SandboxEndpoints.URL != "" {
						endpointIdtoURL[endpoint.ID] = endpoint.EndpointConfig.SandboxEndpoints.URL
					}
				}
				for _, endpoint := range defaultEndpointList {
					if endpoint.EndpointConfig.ProductionEndpoints.URL != "" {
						endpointIdtoURL[endpoint.ID] = endpoint.EndpointConfig.ProductionEndpoints.URL
					}
					if endpoint.EndpointConfig.SandboxEndpoints.URL != "" {
						endpointIdtoURL[endpoint.ID] = endpoint.EndpointConfig.SandboxEndpoints.URL
					}
				}
				for _, model := range config.Production {
					endpointURL := endpointIdtoURL[model.EndpointID]
					if model.Weight == 0 {
						model.Weight = 1
					}
					modelEndpoints := ModelEndpoints{
						Model:    model.Model,
						Weight:   model.Weight,
						Endpoint: endpointURL,
					}
					productionModels = append(productionModels, modelEndpoints)
				}
				for _, model := range config.Sandbox {
					if model.Weight == 0 {
						model.Weight = 1
					}
					endpointURL := endpointIdtoURL[model.EndpointID]
					modelEndpoints := ModelEndpoints{
						Model:    model.Model,
						Weight:   model.Weight,
						Endpoint: endpointURL,
					}
					sandboxModels = append(sandboxModels, modelEndpoints)
				}
				parameters.ProductionModels = productionModels
				parameters.SandboxModels = sandboxModels
				modelRoundRobinPolicy.Parameters = parameters
				requestPolicyList = append(requestPolicyList, modelRoundRobinPolicy)
			}
		}
	}

	if resPolicyCount > 0 {
		for _, resPolicy := range resPolicies {
			if resPolicy.PolicyName == constants.InterceptorService {
				interceptorServiceURL := resPolicy.Parameters[interceptorServiceURL].(string)
				includes := resPolicy.Parameters[includes].(string)
				substrings := strings.Split(includes, ",")
				bodyEnabled := false
				headerEnabled := false
				trailersEnabled := false
				contextEnabled := false
				sslEnabled := false
				tlsSecretName := ""
				tlsSecretKey := ""
				for _, substring := range substrings {
					if strings.Contains(substring, requestHeader) {
						headerEnabled = true
					} else if strings.Contains(substring, requestBody) {
						bodyEnabled = true
					} else if strings.Contains(substring, requestTrailers) {
						trailersEnabled = true
					} else if strings.Contains(substring, requestContext) {
						contextEnabled = true
					}
				}

				if strings.Contains(interceptorServiceURL, https) {
					sslEnabled = true
				}

				if sslEnabled {
					tlsSecretName = resPolicies[0].PolicyID + responseInterceptorSecretName
					tlsSecretKey = tlsKey
				}

				interceptorParams = &InterceptorService{
					BackendURL:      interceptorServiceURL,
					HeadersEnabled:  headerEnabled,
					BodyEnabled:     bodyEnabled,
					TrailersEnabled: trailersEnabled,
					ContextEnabled:  contextEnabled,
					TLSSecretName:   tlsSecretName,
					TLSSecretKey:    tlsSecretKey,
				}

				// Create an instance of OperationPolicy
				responseInterceptorPolicy = OperationPolicy{
					PolicyName:    interceptorPolicy,
					PolicyVersion: v1,
					Parameters:    interceptorParams,
				}
			} else if resPolicy.PolicyName == constants.AddHeader {
				logger.LoggerTransformer.Debugf("AddHeader Type Response Policy: %v", resPolicy)

				responseAddHeader := OperationPolicy{
					PolicyName:    addHeaderPolicy,
					PolicyVersion: v2,
					Parameters: Header{
						HeaderName:  resPolicy.Parameters[headerName].(string),
						HeaderValue: resPolicy.Parameters[headerValue].(string),
					},
				}
				responsePolicyList = append(responsePolicyList, responseAddHeader)
			} else if resPolicy.PolicyName == constants.RemoveHeader {
				logger.LoggerTransformer.Debugf("RemoveHeader Type Response Policy: %v", resPolicy)
				responseRemoveHeader := OperationPolicy{
					PolicyName:    removeHeaderPolicy,
					PolicyVersion: v1,
					Parameters: Header{
						HeaderName: resPolicy.Parameters[headerName].(string),
					},
				}
				responsePolicyList = append(responsePolicyList, responseRemoveHeader)
			}
		}
	}

	if reqPolicyCount > 0 {
		if requestInterceptorPolicy.PolicyName != "" {
			requestPolicyList = append(requestPolicyList, requestInterceptorPolicy)
		}
		if requestBackendJWTPolicy.PolicyName != "" {
			requestPolicyList = append(requestPolicyList, requestBackendJWTPolicy)
		}
		if mirrorRequestPolicy.PolicyName != "" {
			mirrorRequestPolicy.Parameters = URLList{
				URLs: mirrorUrls,
			}
			requestPolicyList = append(requestPolicyList, mirrorRequestPolicy)
		}
	}

	if resPolicyCount > 0 {
		if responseInterceptorPolicy.PolicyName != "" {
			responsePolicyList = append(responsePolicyList, responseInterceptorPolicy)
		}
	}
	return &requestPolicyList, &responsePolicyList
}

// prepareAIRatelimit Function that accepts apiYamlData and returns AIRatelimit
func prepareAIRatelimit(maxTps *MaxTps) (*AIRatelimit, *AIRatelimit) {
	if maxTps == nil {
		return nil, nil
	}
	prodAIRL := &AIRatelimit{}
	if maxTps.TokenBasedThrottlingConfiguration == nil ||
		maxTps.TokenBasedThrottlingConfiguration.IsTokenBasedThrottlingEnabled == nil ||
		maxTps.TokenBasedThrottlingConfiguration.ProductionMaxPromptTokenCount == nil ||
		maxTps.TokenBasedThrottlingConfiguration.ProductionMaxCompletionTokenCount == nil ||
		maxTps.TokenBasedThrottlingConfiguration.ProductionMaxTotalTokenCount == nil ||
		maxTps.ProductionTimeUnit == nil {
		prodAIRL = nil
	} else {
		prodAIRL = &AIRatelimit{
			Enabled: *maxTps.TokenBasedThrottlingConfiguration.IsTokenBasedThrottlingEnabled,
			Token: TokenAIRL{
				PromptLimit:     *maxTps.TokenBasedThrottlingConfiguration.ProductionMaxPromptTokenCount,
				CompletionLimit: *maxTps.TokenBasedThrottlingConfiguration.ProductionMaxCompletionTokenCount,
				TotalLimit:      *maxTps.TokenBasedThrottlingConfiguration.ProductionMaxTotalTokenCount,
				Unit:            CapitalizeFirstLetter(*maxTps.ProductionTimeUnit),
			},
			Request: RequestAIRL{
				RequestLimit: *maxTps.Production,
				Unit:         CapitalizeFirstLetter(*maxTps.ProductionTimeUnit),
			},
		}
	}
	sandAIRL := &AIRatelimit{}
	if maxTps.TokenBasedThrottlingConfiguration == nil ||
		maxTps.TokenBasedThrottlingConfiguration.IsTokenBasedThrottlingEnabled == nil ||
		maxTps.TokenBasedThrottlingConfiguration.SandboxMaxPromptTokenCount == nil ||
		maxTps.TokenBasedThrottlingConfiguration.SandboxMaxCompletionTokenCount == nil ||
		maxTps.TokenBasedThrottlingConfiguration.SandboxMaxTotalTokenCount == nil ||
		maxTps.SandboxTimeUnit == nil {
		sandAIRL = nil
	} else {
		sandAIRL = &AIRatelimit{
			Enabled: *maxTps.TokenBasedThrottlingConfiguration.IsTokenBasedThrottlingEnabled,
			Token: TokenAIRL{
				PromptLimit:     *maxTps.TokenBasedThrottlingConfiguration.SandboxMaxPromptTokenCount,
				CompletionLimit: *maxTps.TokenBasedThrottlingConfiguration.SandboxMaxCompletionTokenCount,
				TotalLimit:      *maxTps.TokenBasedThrottlingConfiguration.SandboxMaxTotalTokenCount,
				Unit:            CapitalizeFirstLetter(*maxTps.SandboxTimeUnit),
			},
			Request: RequestAIRL{
				RequestLimit: *maxTps.Sandbox,
				Unit:         CapitalizeFirstLetter(*maxTps.SandboxTimeUnit),
			},
		}
	}

	return prodAIRL, sandAIRL
}

// getEndpointConfigs will map the endpoints and there security configurations and returns them
// TODO: Currently the APK-Conf does not support giving multiple certs for a particular endpoint.
// After fixing this, the following logic should be changed to map multiple cert configs
func getEndpointConfigs(sandboxURL string, prodURL string, endCertAvailable bool, endpointCertList EndpointCertDescriptor, endpointSecurityData EndpointSecurityConfig, apiUniqueID string, prodAIRatelimit *AIRatelimit, sandAIRatelimit *AIRatelimit) (EndpointConfigurations, EndpointSecurityConfig) {
	var sandboxEndpointConf, prodEndpointConf EndpointConfiguration
	var sandBoxEndpointEnabled = false
	var prodEndpointEnabled = false
	if sandboxURL != "" {
		sandBoxEndpointEnabled = true
	}
	if prodURL != "" {
		prodEndpointEnabled = true
	}
	if prodAIRatelimit != nil {
		prodEndpointConf.AIRatelimit = *prodAIRatelimit
	}
	if sandAIRatelimit != nil {
		sandboxEndpointConf.AIRatelimit = *sandAIRatelimit
	}
	sandboxEndpointConf.Endpoint = sandboxURL
	prodEndpointConf.Endpoint = prodURL
	if endCertAvailable {
		for _, endCert := range endpointCertList.EndpointCertData {
			if endCert.Endpoint == sandboxURL {
				sandboxEndpointConf.EndCertificate = EndpointCertificate{
					Name: endCert.Alias,
					Key:  endCert.Certificate,
				}
			}
			if endCert.Endpoint == prodURL {
				prodEndpointConf.EndCertificate = EndpointCertificate{
					Name: endCert.Alias,
					Key:  endCert.Certificate,
				}
			}
		}
	}

	if endpointSecurityData.Sandbox.Enabled {
		endpointSecurityData.Sandbox.EndpointUUID = "primary"
		sandboxEndpointConf.EndSecurity.Enabled = true
		if endpointSecurityData.Sandbox.Type == "apikey" {
			sandboxEndpointConf.EndSecurity.SecurityType = SecretInfo{
				SecretName:     strings.Join([]string{apiUniqueID, generateSHA1Hash(endpointSecurityData.Sandbox.EndpointUUID), "sandbox", "secret"}, "-"),
				In:             "Header",
				APIKeyNameKey:  endpointSecurityData.Sandbox.APIKeyIdentifier,
				APIKeyValueKey: "apiKey",
			}
		} else {
			sandboxEndpointConf.EndSecurity.SecurityType = SecretInfo{
				SecretName:  strings.Join([]string{apiUniqueID, generateSHA1Hash(endpointSecurityData.Sandbox.EndpointUUID), "sandbox", "secret"}, "-"),
				UsernameKey: "username",
				PasswordKey: "password",
			}
		}
	}

	if endpointSecurityData.Production.Enabled {
		endpointSecurityData.Production.EndpointUUID = "primary"
		prodEndpointConf.EndSecurity.Enabled = true
		if endpointSecurityData.Production.Type == "apikey" {
			prodEndpointConf.EndSecurity.SecurityType = SecretInfo{
				SecretName:     strings.Join([]string{apiUniqueID, generateSHA1Hash(endpointSecurityData.Production.EndpointUUID), "production", "secret"}, "-"),
				In:             "Header",
				APIKeyNameKey:  endpointSecurityData.Production.APIKeyIdentifier,
				APIKeyValueKey: "apiKey",
			}
		} else {
			prodEndpointConf.EndSecurity.SecurityType = SecretInfo{
				SecretName:  strings.Join([]string{apiUniqueID, generateSHA1Hash(endpointSecurityData.Production.EndpointUUID), "production", "secret"}, "-"),
				UsernameKey: "username",
				PasswordKey: "password",
			}
		}
	}

	epconfigs := EndpointConfigurations{}
	sandboxEndpoints := []EndpointConfiguration{}
	productionEndpoints := []EndpointConfiguration{}
	if sandBoxEndpointEnabled && prodEndpointEnabled {
		sandboxEndpoints = append(sandboxEndpoints, sandboxEndpointConf)
		productionEndpoints = append(productionEndpoints, prodEndpointConf)
		epconfigs = EndpointConfigurations{
			Sandbox:    &sandboxEndpoints,
			Production: &productionEndpoints,
		}
	} else if sandBoxEndpointEnabled {
		sandboxEndpoints = append(sandboxEndpoints, sandboxEndpointConf)
		epconfigs = EndpointConfigurations{
			Sandbox: &sandboxEndpoints,
		}
	} else if prodEndpointEnabled {
		productionEndpoints = append(productionEndpoints, prodEndpointConf)
		epconfigs = EndpointConfigurations{
			Production: &productionEndpoints,
		}
	}
	return epconfigs, endpointSecurityData
}

// getMultiEndpointConfigs will map the endpoints and there security configurations and returns them
func getMultiEndpointConfigs(endpointList []Endpoint, primaryProdEndpointID string, primarySandboxEndpointID string, endCertAvailable bool, endpointCertList EndpointCertDescriptor, apiUniqueID string, prodAIRatelimit *AIRatelimit, sandAIRatelimit *AIRatelimit) (EndpointConfigurations, []EndpointSecurityConfig) {
	sandboxEndpoints := []EndpointConfiguration{}
	productionEndpoints := []EndpointConfiguration{}
	endpointSecurityConfigs := []EndpointSecurityConfig{}
	if primaryProdEndpointID == "" && primarySandboxEndpointID == "" {
		logger.LoggerTransformer.Error("Primary Production and Sandbox Endpoint ID's are empty. Unable to map the endpoints.")
	}
	for _, endpoint := range endpointList {
		prodURL := endpoint.EndpointConfig.ProductionEndpoints.URL
		sandboxURL := endpoint.EndpointConfig.SandboxEndpoints.URL
		endpointSecurityData := endpoint.EndpointConfig.EndpointSecurity
		endpointSecurityData.Production.EndpointUUID = endpoint.ID
		endpointSecurityData.Sandbox.EndpointUUID = endpoint.ID
		endpointSecurityConfigs = append(endpointSecurityConfigs, endpointSecurityData)
		var sandboxEndpointConf, prodEndpointConf EndpointConfiguration
		var sandBoxEndpointEnabled = false
		var prodEndpointEnabled = false
		if sandboxURL != "" {
			sandBoxEndpointEnabled = true
		}
		if prodURL != "" {
			prodEndpointEnabled = true
		}
		if prodAIRatelimit != nil {
			prodEndpointConf.AIRatelimit = *prodAIRatelimit
		}
		if sandAIRatelimit != nil {
			sandboxEndpointConf.AIRatelimit = *sandAIRatelimit
		}
		sandboxEndpointConf.Endpoint = sandboxURL
		prodEndpointConf.Endpoint = prodURL
		if endCertAvailable {
			for _, endCert := range endpointCertList.EndpointCertData {
				if endCert.Endpoint == sandboxURL {
					sandboxEndpointConf.EndCertificate = EndpointCertificate{
						Name: endCert.Alias,
						Key:  endCert.Certificate,
					}
				}
				if endCert.Endpoint == prodURL {
					prodEndpointConf.EndCertificate = EndpointCertificate{
						Name: endCert.Alias,
						Key:  endCert.Certificate,
					}
				}
			}
		}

		if endpointSecurityData.Sandbox.Enabled {
			sandboxEndpointConf.EndSecurity.Enabled = true

			if endpointSecurityData.Sandbox.Type == "apikey" {
				sandboxEndpointConf.EndSecurity.SecurityType = SecretInfo{
					SecretName:     strings.Join([]string{apiUniqueID, generateSHA1Hash(endpoint.ID), "sandbox", "secret"}, "-"),
					In:             "Header",
					APIKeyNameKey:  endpointSecurityData.Sandbox.APIKeyIdentifier,
					APIKeyValueKey: "apiKey",
				}
			} else {
				sandboxEndpointConf.EndSecurity.SecurityType = SecretInfo{
					SecretName:  strings.Join([]string{apiUniqueID, generateSHA1Hash(endpoint.ID), "sandbox", "secret"}, "-"),
					UsernameKey: "username",
					PasswordKey: "password",
				}
			}
		}

		if endpointSecurityData.Production.Enabled {
			prodEndpointConf.EndSecurity.Enabled = true
			if endpointSecurityData.Production.Type == "apikey" {
				prodEndpointConf.EndSecurity.SecurityType = SecretInfo{
					SecretName:     strings.Join([]string{apiUniqueID, generateSHA1Hash(endpoint.ID), "production", "secret"}, "-"),
					In:             "Header",
					APIKeyNameKey:  endpointSecurityData.Production.APIKeyIdentifier,
					APIKeyValueKey: "apiKey",
				}
			} else {
				prodEndpointConf.EndSecurity.SecurityType = SecretInfo{
					SecretName:  strings.Join([]string{apiUniqueID, generateSHA1Hash(endpoint.ID), "production", "secret"}, "-"),
					UsernameKey: "username",
					PasswordKey: "password",
				}
			}
		}

		if sandBoxEndpointEnabled && prodEndpointEnabled {
			logger.LoggerTransformer.Debugf("Sandbox/Prod both Endpoints Enabled: %v", sandBoxEndpointEnabled)
			sandboxEndpoints = append(sandboxEndpoints, sandboxEndpointConf)
			productionEndpoints = append(productionEndpoints, prodEndpointConf)
		} else if sandBoxEndpointEnabled {
			logger.LoggerTransformer.Debugf("Sandbox Endpoint Enabled: %v", sandBoxEndpointEnabled)
			sandboxEndpoints = append(sandboxEndpoints, sandboxEndpointConf)
		} else if prodEndpointEnabled {
			logger.LoggerTransformer.Debugf("Production Endpoint Enabled: %v", prodEndpointEnabled)
			productionEndpoints = append(productionEndpoints, prodEndpointConf)
		}
	}
	logger.LoggerTransformer.Debugf("Sandbox Endpoints: %v", sandboxEndpoints)
	logger.LoggerTransformer.Debugf("Production Endpoints: %v", productionEndpoints)
	epconfigs := EndpointConfigurations{
		Sandbox:    &sandboxEndpoints,
		Production: &productionEndpoints,
	}
	logger.LoggerTransformer.Debugf("Endpoint Configurations: %v", epconfigs)
	return epconfigs, endpointSecurityConfigs
}

// generateSHA1Hash returns the SHA1 hash for the given string
func generateSHA1Hash(input string) string {
	h := sha1.New() /* #nosec */
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

// mapAuthConfigs will take the security schemes as the parameter and will return the mapped auth configs to be
// added into the apk-conf
func mapAuthConfigs(apiUUID string, authHeader string, configuredAPIKeyHeader string, securitySchemes []string, certAvailable bool, certList CertDescriptor, apiUniqueID string) []AuthConfiguration {
	var authConfigs []AuthConfiguration
	if StringExists(oAuth2SecScheme, securitySchemes) {
		var oauth2Config AuthConfiguration
		oauth2Config.AuthType = oAuth2
		oauth2Config.Enabled = true
		oauth2Config.HeaderName = authHeader
		if StringExists(applicationSecurityMandatory, securitySchemes) {
			oauth2Config.Required = mandatory
		} else {
			oauth2Config.Required = optional
		}

		authConfigs = append(authConfigs, oauth2Config)
	}
	if !StringExists("oauth2", securitySchemes) {
		oAuth2DisabledConfig := AuthConfiguration{
			AuthType: oAuth2,
			Enabled:  false,
		}
		authConfigs = append(authConfigs, oAuth2DisabledConfig)
	}
	if StringExists(mutualSSL, securitySchemes) && certAvailable {
		var mtlsConfig AuthConfiguration
		mtlsConfig.AuthType = mTLS
		mtlsConfig.Enabled = true
		if StringExists(mutualSSLMandatory, securitySchemes) {
			mtlsConfig.Required = mandatory
		} else {
			mtlsConfig.Required = optional
		}

		clientCerts := make([]Certificate, len(certList.CertData))

		for i, cert := range certList.CertData {
			prop := &Certificate{
				Name: apiUniqueID + "-" + cert.Alias,
				Key:  cert.Certificate,
			}
			clientCerts[i] = *prop
		}
		mtlsConfig.Certificates = clientCerts
		authConfigs = append(authConfigs, mtlsConfig)
	}

	internalKeyAuthConfig := AuthConfiguration{
		AuthType:   jwt,
		Enabled:    true,
		Audience:   []string{apiUUID},
		HeaderName: internalKeyHeader,
	}
	authConfigs = append(authConfigs, internalKeyAuthConfig)

	if StringExists(apiKeySecScheme, securitySchemes) {
		apiKeyAuthConfig := AuthConfiguration{
			AuthType:       apiKey,
			Enabled:        true,
			HeaderName:     configuredAPIKeyHeader,
			HeaderEnabled:  true,
			QueryParamName: apiKeyHeader,
		}
		if StringExists(applicationSecurityMandatory, securitySchemes) {
			apiKeyAuthConfig.Required = mandatory
		} else if StringExists(applicationSecurityOptional, securitySchemes) {
			apiKeyAuthConfig.Required = optional
		}
		authConfigs = append(authConfigs, apiKeyAuthConfig)
	}
	return authConfigs
}

func mapKeyManagers(keyManagers []string) []KeyManager {
	// Get the key manager cache instance and fetch all configured key managers
	kmCache := cache.GetKeyManagerCacheInstance()
	kmList := kmCache.GetAllKeyManagers()
	kmListForAPI := []KeyManager{}
	for _, keyManager := range keyManagers {
		if keyManager == "all" {
			// Add all the key manager settings to the km details
			for _, km := range kmList {
				newkmConfig := KeyManager{
					Name: km.Name,
					Issuer: km.KeyManagerConfig.Issuer,
					JWKSEndpoint: km.KeyManagerConfig.CertificateValue,
					ClaimMapping: km.KeyManagerConfig.ClaimMappings,
				}
				kmListForAPI = append(kmListForAPI, newkmConfig)
			}
			break
		} 
		// Otherwise add only the specific key manager settings to the km details
		for _, km := range kmList {
			if keyManager == km.Name {
				newkmConfig := KeyManager{
					Name: km.Name,
					Issuer: km.KeyManagerConfig.Issuer,
					JWKSEndpoint: km.KeyManagerConfig.CertificateValue,
				}
				kmListForAPI = append(kmListForAPI, newkmConfig)
			}
		}
		
	}
	return kmListForAPI
}

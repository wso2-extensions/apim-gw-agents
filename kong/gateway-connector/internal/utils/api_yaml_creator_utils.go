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
	"fmt"
	"regexp"
	"strings"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	types "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/managementserver"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	logger "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/loggers"
	"gopkg.in/yaml.v2"
)

// KongAPIYamlCreator implements the APIYamlCreator interface for Kong Gateway
type KongAPIYamlCreator struct{}

// NewKongAPIYamlCreator creates a new instance of KongAPIYamlCreator
func NewKongAPIYamlCreator() *KongAPIYamlCreator {
	return &KongAPIYamlCreator{}
}

// CreateAPIYaml implements the APIYamlCreator interface
func (k *KongAPIYamlCreator) CreateAPIYaml(event *types.APICPEvent) (string, string, string) {
	return CreateKongAPIYaml(event)
}

// CreateKongAPIYaml creates the API yaml content
func CreateKongAPIYaml(apiCPEvent *types.APICPEvent) (string, string, string) {
	logger.LoggerUtils.Infof("Creating Kong API YAML for API: %s, Version: %s, Organization: %s",
		apiCPEvent.API.APIName, apiCPEvent.API.APIVersion, apiCPEvent.API.Organization)

	config, err := config.ReadConfigs()
	provider := constants.DefaultProvider
	if err == nil {
		provider = config.ControlPlane.Provider
	}

	context := removeVersionSuffix(apiCPEvent.API.BasePath, apiCPEvent.API.APIVersion)

	apimEndpoints := make([]types.APIMEndpoint, 0)
	prodCount := 0
	sandCount := 0

	operations, scopes, operationsErr := extractOperations(*apiCPEvent, apimEndpoints)
	if operationsErr != nil {
		logger.LoggerUtils.Errorf("Error occured while extracting operations from open API: %s, \nError: %+v", apiCPEvent.API.Definition, operationsErr)
		operations = make([]types.APIOperation, 0)
	}

	sandEndpoint := constants.EmptyString
	if apiCPEvent.API.SandEndpoint != constants.EmptyString {
		sandEndpoint = apiCPEvent.API.SandEndpoint
	}
	prodEndpoint := constants.EmptyString
	if apiCPEvent.API.ProdEndpoint != constants.EmptyString {
		prodEndpoint = apiCPEvent.API.ProdEndpoint
	}
	logger.LoggerUtils.Debugf("Sandbox Endpoint: %s, Production Endpoint: %s", sandEndpoint, prodEndpoint)
	authHeader := apiCPEvent.API.AuthHeader
	if authHeader == constants.EmptyString {
		authHeader = constants.DefaultAuthHeader
	}
	apiKeyHeader := apiCPEvent.API.APIKeyHeader
	if apiKeyHeader == constants.EmptyString {
		apiKeyHeader = constants.DefaultAPIKeyHeader
	}
	apiType := constants.APITypeHTTP
	if apiCPEvent.API.APIType == constants.APITypeGraphQLInput {
		apiType = constants.APITypeGraphQL
	}

	subTypeConfiguration := make(map[string]interface{})
	if apiCPEvent.API.APISubType != constants.EmptyString && apiCPEvent.API.AIConfiguration.LLMProviderID != constants.EmptyString &&
		apiCPEvent.API.AIConfiguration.LLMProviderName != constants.EmptyString &&
		apiCPEvent.API.AIConfiguration.LLMProviderAPIVersion != constants.EmptyString {
		logger.LoggerUtils.Debugf("AI Configuration: %+v", apiCPEvent.API.AIConfiguration)
		subTypeConfiguration[constants.ConfigKeySubtype] = apiCPEvent.API.APISubType
		subTypeConfiguration[constants.ConfigKeyConfiguration] = "{\"llmProviderId\":\"" +
			apiCPEvent.API.AIConfiguration.LLMProviderID + "\"}"
	}
	logger.LoggerUtils.Debugf("Subtype Configuration: %+v", subTypeConfiguration)

	data := map[string]interface{}{
		"type":    constants.YAMLTypeAPI,
		"version": constants.DefaultYAMLAPIVersion,
		"data": map[string]interface{}{
			"name":                         apiCPEvent.API.APIName,
			"context":                      context,
			"version":                      apiCPEvent.API.APIVersion,
			"organizationId":               apiCPEvent.API.Organization,
			"provider":                     provider,
			"lifeCycleStatus":              constants.DefaultLifeCycleStatus,
			"responseCachingEnabled":       false,
			"cacheTimeout":                 constants.DefaultCacheTimeout,
			"hasThumbnail":                 false,
			"isDefaultVersion":             apiCPEvent.API.IsDefaultVersion,
			"isRevision":                   false,
			"enableSchemaValidation":       false,
			"enableSubscriberVerification": false,
			"type":                         apiType,
			"transport":                    []string{constants.TransportHTTP, constants.TransportHTTPS},
			"endpointConfig": map[string]interface{}{
				"endpoint_type": apiCPEvent.API.EndpointProtocol,
				constants.EndpointTypeSandbox: map[string]interface{}{
					"url": sandEndpoint,
				},
				constants.EndpointTypeProduction: map[string]interface{}{
					"url": prodEndpoint,
				},
			},
			"policies":             []string{constants.DefaultThrottlingPolicy},
			"gatewayType":          constants.GatewayTypeKong,
			"gatewayVendor":        constants.GatewayVendorExt,
			"operations":           operations,
			"additionalProperties": createAdditionalProperties(apiCPEvent.API.APIProperties),
			"securityScheme":       apiCPEvent.API.SecurityScheme,
			"authorizationHeader":  authHeader,
			"apiKeyHeader":         apiKeyHeader,
			"scopes":               scopes,
			"initiatedFromGateway": true,
		},
	}
	if len(subTypeConfiguration) > 0 {
		data["data"].(map[string]interface{})["subtypeConfiguration"] = subTypeConfiguration
	}
	if apiCPEvent.API.SandEndpoint == constants.EmptyString || apiCPEvent.API.SandEndpoint == constants.NullString {
		delete(data["data"].(map[string]interface{})["endpointConfig"].(map[string]interface{}), constants.EndpointTypeSandbox)
	}
	if apiCPEvent.API.ProdEndpoint == constants.EmptyString || apiCPEvent.API.ProdEndpoint == constants.NullString {
		delete(data["data"].(map[string]interface{})["endpointConfig"].(map[string]interface{}), constants.EndpointTypeProduction)
	}
	if apiCPEvent.API.CORSPolicy != nil {
		data["data"].(map[string]interface{})["corsConfiguration"] = map[string]interface{}{
			"corsConfigurationEnabled":      true,
			"accessControlAllowOrigins":     apiCPEvent.API.CORSPolicy.AccessControlAllowOrigins,
			"accessControlAllowCredentials": apiCPEvent.API.CORSPolicy.AccessControlAllowCredentials,
			"accessControlAllowHeaders":     apiCPEvent.API.CORSPolicy.AccessControlAllowHeaders,
			"accessControlAllowMethods":     apiCPEvent.API.CORSPolicy.AccessControlAllowMethods,
			"accessControlExposeHeaders":    apiCPEvent.API.CORSPolicy.AccessControlExposeHeaders,
		}
	}

	maxTps := make(map[string]interface{})

	if len(maxTps) > 0 {
		data["data"].(map[string]interface{})["maxTps"] = maxTps
	}
	logger.LoggerUtils.Infof("Prepared yaml : %+v", data)
	definition := apiCPEvent.API.Definition
	if strings.EqualFold(apiCPEvent.API.APIType, constants.APITypeRest) {
		openAPI, errConvertYaml := ConvertYAMLToMap(definition)
		if errConvertYaml == nil {
			if paths, ok := openAPI["paths"].(map[interface{}]interface{}); ok {
				for path, pathContent := range paths {
					if pathContentMap, ok := pathContent.(map[interface{}]interface{}); ok {
						for verb, verbContent := range pathContentMap {
							for _, operation := range operations {
								if strings.EqualFold(path.(string), operation.Target) && strings.EqualFold(verb.(string), operation.Verb) {
									if verbContentMap, ok := verbContent.(map[interface{}]interface{}); ok {
										if len(operation.Scopes) > 0 {
											verbContentMap["security"] = []map[string][]string{
												{
													constants.SecuritySchemeDefault: operation.Scopes,
												},
											}
										}
										verbContentMap[constants.XAuthTypeField] = constants.DefaultAuthType
									}
									break
								}
							}
						}
					}
				}
			}
			scopesForOpenAPIComponents := make(map[string]string, len(scopes))
			for _, scopeWrapper := range scopes {
				scopesForOpenAPIComponents[scopeWrapper.Scope.Name] = constants.EmptyString
			}

			components, ok := openAPI["components"].(map[interface{}]interface{})
			if !ok {
				components = make(map[interface{}]interface{})
			}
			securitySchemes, ok := components["securitySchemes"].(map[interface{}]interface{})
			if !ok {
				securitySchemes = make(map[interface{}]interface{})
			}

			securitySchemes[constants.SecuritySchemeDefault] = map[interface{}]interface{}{
				"type": constants.SecurityTypeOAuth2,
				"flows": map[interface{}]interface{}{
					constants.SecurityFlowImplicit: map[interface{}]interface{}{
						"authorizationUrl":        constants.AuthorizationURLDefault,
						"scopes":                  scopesForOpenAPIComponents,
						constants.XScopesBindings: scopesForOpenAPIComponents,
					},
				},
			}

			components["securitySchemes"] = securitySchemes
			openAPI["components"] = components

			yamlBytes, err := yaml.Marshal(&openAPI)
			if err != nil {
				logger.LoggerUtils.Errorf("Error while converting openAPI struct to yaml content. openAPI struct: %+v", openAPI)
			} else {
				logger.LoggerUtils.Debugf("Created openAPI yaml: %s", string(yamlBytes))
				definition = string(yamlBytes)
			}
		}
	}

	dataArr := make([]map[string]interface{}, 0, len(apimEndpoints))

	var endpointsData map[string]interface{}
	if prodCount > 1 || sandCount > 1 {
		endpointsData = map[string]interface{}{
			"type":    constants.YAMLTypeEndpoints,
			"version": constants.DefaultYAMLAPIVersion,
			"data":    dataArr,
		}
	}

	requestOperationPolicies := make([]types.OperationPolicy, 0)
	data["data"].(map[string]interface{})["apiPolicies"] = types.OperationPolicies{
		Request: requestOperationPolicies,
	}
	yamlBytes, _ := yaml.Marshal(data)
	logger.LoggerUtils.Debugf("API Yaml: %+v", data)
	logger.LoggerUtils.Debugf("Endpoint Yaml: %v", endpointsData)
	endpointBytes, _ := yaml.Marshal(endpointsData)
	return string(yamlBytes), definition, string(endpointBytes)
}

func extractOperations(event types.APICPEvent, apimEndpoints []types.APIMEndpoint) ([]types.APIOperation, []types.ScopeWrapper, error) {
	apiOperations := make([]types.APIOperation, 0)
	requestOperationPolicies := make([]types.OperationPolicy, 0)
	responseOperationPolicies := make([]types.OperationPolicy, 0)
	scopewrappers := make(map[string]types.ScopeWrapper)

	if strings.ToUpper(event.API.APIType) == constants.APITypeGraphQL {
		apiOperations = make([]types.APIOperation, 0, len(event.API.Operations))
		for _, operation := range event.API.Operations {
			apiOp := types.APIOperation{
				Target:           operation.Path,
				Verb:             operation.Verb,
				AuthType:         constants.DefaultAuthType,
				ThrottlingPolicy: constants.DefaultThrottlingPolicy,
			}
			apiOperations = append(apiOperations, apiOp)
		}
	} else if strings.ToUpper(event.API.APIType) == strings.ToUpper(constants.APITypeRest) {
		var openAPIPaths types.OpenAPIPaths
		openAPI := event.API.Definition
		if err := yaml.Unmarshal([]byte(openAPI), &openAPIPaths); err != nil {
			return nil, nil, err
		}

		for path, operations := range openAPIPaths.Paths {
			for verb := range operations {
				ptrToOperationFromDP := findMatchingKongOperation(path, verb, event.API.Operations)
				if ptrToOperationFromDP == nil {
					continue
				}
				operationFromDP := *ptrToOperationFromDP
				scopes := operationFromDP.Scopes
				for _, scope := range scopes {
					scopewrappers[scope] = types.ScopeWrapper{
						Scope: types.Scope{
							Name:        scope,
							DisplayName: scope,
							Description: scope,
						},
						Shared: false,
					}
				}
				// Process filters
				for _, operationLevelFilter := range operationFromDP.Filters {
					switch filter := operationLevelFilter.(type) {
					// Header modification policies
					case *types.APKHeaders:
						requestHeaders := filter.RequestHeaders
						// Add headers
						if len(requestHeaders.AddHeaders) > 0 {
							logger.LoggerUtils.Debugf("Processing request filter for header addition")
							for _, requestHeader := range requestHeaders.AddHeaders {
								operationPolicy := types.OperationPolicy{
									PolicyName:    constants.AddHeader,
									PolicyVersion: constants.V1,
									Parameters: types.Header{
										Name:  requestHeader.Name,
										Value: requestHeader.Value,
									},
								}
								requestOperationPolicies = append(requestOperationPolicies, operationPolicy)
							}
						}

						// Remove headers
						if len(requestHeaders.RemoveHeaders) > 0 {
							logger.LoggerUtils.Debugf("Processing request filter for header removal")
							for _, requestHeader := range requestHeaders.RemoveHeaders {
								operationPolicy := types.OperationPolicy{
									PolicyName:    constants.RemoveHeader,
									PolicyVersion: constants.V1,
									Parameters: types.Header{
										Name: requestHeader,
									},
								}
								requestOperationPolicies = append(responseOperationPolicies, operationPolicy)
							}
						}

						responseHeaders := filter.ResponseHeaders
						// Add headers
						if len(responseHeaders.AddHeaders) > 0 {
							logger.LoggerUtils.Debugf("Processing response filter for header addition")
							for _, responseHeader := range responseHeaders.AddHeaders {
								operationPolicy := types.OperationPolicy{
									PolicyName:    constants.AddHeader,
									PolicyVersion: constants.V1,
									Parameters: types.Header{
										Name:  responseHeader.Name,
										Value: responseHeader.Value,
									},
								}
								responseOperationPolicies = append(responseOperationPolicies, operationPolicy)
							}
						}

						// Remove headers
						if len(responseHeaders.RemoveHeaders) > 0 {
							logger.LoggerUtils.Debugf("Processing response filter for header removal")
							for _, responseHeader := range responseHeaders.RemoveHeaders {
								operationPolicy := types.OperationPolicy{
									PolicyName:    constants.RemoveHeader,
									PolicyVersion: constants.V1,
									Parameters: types.Header{
										Name: responseHeader,
									},
								}
								responseOperationPolicies = append(responseOperationPolicies, operationPolicy)
							}
						}
					// Mirror request
					case *types.APKMirrorRequest:
						logger.LoggerUtils.Debugf("Processing request filter for request mirroring")
						for _, url := range filter.URLs {
							operationPolicy := types.OperationPolicy{
								PolicyName:    constants.MirrorRequest,
								PolicyVersion: constants.V1,
								Parameters: types.MirrorRequest{
									URL: url,
								},
							}
							requestOperationPolicies = append(requestOperationPolicies, operationPolicy)
						}

					// Redirect request
					case *types.APKRedirectRequest:
						logger.LoggerUtils.Debugf("Processing request filter for request redirection")
						operationPolicy := types.OperationPolicy{
							PolicyName:    constants.RedirectRequest,
							PolicyVersion: constants.V1,
							Parameters: types.MirrorRequest{
								URL: filter.URL,
							},
						}
						requestOperationPolicies = append(requestOperationPolicies, operationPolicy)

					default:
						logger.LoggerUtils.Errorf("Unknown filter type ")
					}
				}

				apiOp := types.APIOperation{
					Target:           path,
					Verb:             verb,
					AuthType:         constants.DefaultAuthType,
					ThrottlingPolicy: constants.DefaultThrottlingPolicy,
					Scopes:           scopes,
					OperationPolicies: types.OperationPolicies{
						Request:  requestOperationPolicies,
						Response: responseOperationPolicies,
					},
				}
				apiOperations = append(apiOperations, apiOp)
			}
		}
		scopeWrapperSlice := make([]types.ScopeWrapper, 0, len(scopewrappers))
		for _, value := range scopewrappers {
			scopeWrapperSlice = append(scopeWrapperSlice, value)
		}
		return apiOperations, scopeWrapperSlice, nil
	}
	return make([]types.APIOperation, 0), make([]types.ScopeWrapper, 0), nil
}

func findMatchingKongOperation(path string, verb string, operations []types.OperationFromDP) *types.OperationFromDP {
	processedPath := processOpenAPIPath(path)
	for _, operationFromDP := range operations {
		if strings.EqualFold(operationFromDP.Verb, verb) {
			if matchRegex(operationFromDP.Path, processedPath) {
				return &operationFromDP
			}
		}
	}
	return nil
}

func removeVersionSuffix(str1, str2 string) string {
	if strings.HasSuffix(str1, str2) {
		return strings.TrimSuffix(str1, fmt.Sprintf("%s%s", constants.SlashString, str2))
	}
	return str1
}

func createAdditionalProperties(data map[string]string) []types.AdditionalProperty {
	if len(data) == 0 {
		return make([]types.AdditionalProperty, 0)
	}

	properties := make([]types.AdditionalProperty, 0, len(data))
	for key, value := range data {
		entry := types.AdditionalProperty{
			Name:    key,
			Value:   value,
			Display: false,
		}
		properties = append(properties, entry)
	}
	return properties
}

func matchRegex(regexStr string, targetStr string) bool {
	regexPattern, err := regexp.Compile(regexStr)
	if err != nil {
		logger.LoggerUtils.Errorf("Error compiling regex pattern '%s': %v", regexStr, err)
		return false
	}
	return regexPattern.MatchString(targetStr)
}

func processOpenAPIPath(path string) string {
	re := regexp.MustCompile(constants.PathParameterRegex)
	return re.ReplaceAllString(path, constants.PathParameterReplace)
}

func ConvertYAMLToMap(yamlString string) (map[string]interface{}, error) {
	var yamlData map[string]interface{}
	err := yaml.Unmarshal([]byte(yamlString), &yamlData)
	if err != nil {
		logger.LoggerUtils.Errorf("Error while converting openAPI yaml to map: Error: %+v. \n openAPI yaml", err)
		return nil, err
	}
	return yamlData, nil
}

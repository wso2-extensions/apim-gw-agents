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

package transformer

import (
	"strings"

	v1 "github.com/kong/kubernetes-configuration/api/configuration/v1"
	eventHub "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/constants"
	httpGenerator "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/pkg/generators/http"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/pkg/utils"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/types"
	apimTransformer "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/transformer"
	logger "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/loggers"
	pkgConstants "github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/pkg/constants"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// GenerateCR handles the generation k8s artifacts
func GenerateCR(api string, organizationID string, apiUUID string) *K8sArtifacts {
	logger.LoggerUtils.Debugf("GenerateCR|Starting CR generation|API:%s Org:%s\n", apiUUID, organizationID)

	kongPlugins := make([]string, 0)
	var apkConf types.APKConf
	err := yaml.Unmarshal([]byte(api), &apkConf)
	if err != nil {
		logger.LoggerUtils.Errorf("Error while converting apk conf yaml to apk conf type: Error: %+v. \n", err)
	}
	apiUniqueID := GetUniqueIDForAPI(apkConf.Name, apkConf.Version, organizationID)
	k8sArtifact := K8sArtifacts{APIName: apkConf.Name, APIUUID: apiUUID, HTTPRoutes: make(map[string]*gwapiv1.HTTPRoute), Services: make(map[string]*corev1.Service), KongPlugins: map[string]*v1.KongPlugin{}}

	// create endpoints
	createdEndpoints := utils.GetEndpoints(apkConf)

	// handle authentications
	authentications := *apkConf.Authentication
	for _, authentication := range authentications {
		if !authentication.Enabled {
			continue
		}

		// OAuth2 JWT Plugin (for OAuth2 jwt authentication)
		if authentication.AuthType == pkgConstants.OAuth2 {
			kongJwtPlugin := createAndAddJWTPlugin(&k8sArtifact, nil, "api", authentication)
			// * Only in Kong Enterprise
			// kongJwtPlugin.Ordering = &kong.PluginOrdering{
			// 	Before: map[string][]string{
			// 		"access": {"acl"},
			// 	},
			// }

			kongPlugins = append(kongPlugins, kongJwtPlugin.ObjectMeta.Name)
		}
		// OAuth2 JWT Plugin (for OAuth2 jwt authentication)
		if authentication.AuthType == pkgConstants.APIKey {
			kongJwtPlugin := createAndAddAPIKeyPlugin(&k8sArtifact, nil, "api", authentication)
			// * Only in Kong Enterprise
			// kongJwtPlugin.Ordering = &kong.PluginOrdering{
			// 	Before: map[string][]string{
			// 		"access": {"acl"},
			// 	},
			// }

			kongPlugins = append(kongPlugins, kongJwtPlugin.ObjectMeta.Name)
		}
	}

	// create ratelimit policies
	if apkConf.RateLimit != nil {
		rateLimitConfig := KongPluginConfig{
			"limit_by": "service",
		}
		PrepareRateLimit(&rateLimitConfig, apkConf.RateLimit.Unit, apkConf.RateLimit.RequestsPerUnit)
		kongRateLimitPlugin := GenerateKongPlugin(nil, kongRateLimitingPluginName, "api", rateLimitConfig, true)

		k8sArtifact.KongPlugins[kongRateLimitPlugin.ObjectMeta.Name] = kongRateLimitPlugin
		kongPlugins = append(kongPlugins, kongRateLimitPlugin.ObjectMeta.Name)
		logger.LoggerUtils.Debugf("GenerateCR|Rate limit plugin added|%s\n", kongRateLimitPlugin.ObjectMeta.Name)
	}

	// create cors configurations
	if apkConf.CorsConfig != nil {
		apkCorsConf := apkConf.CorsConfig

		corsConfig := KongPluginConfig{
			"origins":     apkCorsConf.AccessControlAllowOrigins,
			"credentials": apkCorsConf.AccessControlAllowCredentials,
			"headers":     apkCorsConf.AccessControlAllowHeaders,
			"methods":     apkCorsConf.AccessControlAllowMethods,
		}
		kongCorsPlugin := GenerateKongPlugin(nil, kongCorsPluginName, "api", corsConfig, apkCorsConf.CORSConfigurationEnabled)

		k8sArtifact.KongPlugins[kongCorsPlugin.ObjectMeta.Name] = kongCorsPlugin
		kongPlugins = append(kongPlugins, kongCorsPlugin.ObjectMeta.Name)
		logger.LoggerUtils.Debugf("GenerateCR|CORS plugin added|%s\n", kongCorsPlugin.ObjectMeta.Name)
	}

	// HTTPRoute
	// generate production http routes
	if endpoints, ok := createdEndpoints[constants.ProductionType]; ok {
		generateHTTPRoutes(&k8sArtifact, &apkConf, organizationID, endpoints, constants.ProductionType, apiUniqueID, kongPlugins)
		logger.LoggerUtils.Debugf("GenerateCR|Production HTTPRoutes generated|%d endpoints\n", len(endpoints))
	}
	// generate sandbox http routes
	if endpoints, ok := createdEndpoints[constants.SandboxType]; ok {
		generateHTTPRoutes(&k8sArtifact, &apkConf, organizationID, endpoints, constants.SandboxType, apiUniqueID, kongPlugins)
		logger.LoggerUtils.Debugf("GenerateCR|Sandbox HTTPRoutes generated|%d endpoints\n", len(endpoints))
	}

	logger.LoggerUtils.Infof("GenerateCR|CR generation completed|HTTPRoutes:%d Services:%d Plugins:%d\n",
		len(k8sArtifact.HTTPRoutes), len(k8sArtifact.Services), len(k8sArtifact.KongPlugins))
	return &k8sArtifact
}

// UpdateCRS cr update
func UpdateCRS(k8sArtifact *K8sArtifacts, environments *[]apimTransformer.Environment, organizationID string, apiUUID string, revisionID string, namespace string, configuredRateLimitPoliciesMap map[string]eventHub.RateLimitPolicy) {
	logger.LoggerUtils.Debugf("UpdateCRS|Starting CR update|API:%s Revision:%s Environments:%d\n",
		apiUUID, revisionID, len(*environments))

	organizationHash := generateSHA1Hash(organizationID)

	// generate Cors Configurations for the gateway
	// origins := []string{}
	// logger.LoggerMessaging.Infof("env :\n%+v\n", environments)
	// for _, environment := range *environments {
	// 	vhost := environment.Vhost
	// 	origins = append(origins, vhost)
	// }
	// corsConfig := KongPluginConfig{
	// 	"origins": origins,
	// }
	// corsPlugin := GenerateCorsPlugin(nil, "api", corsConfig)
	// k8sArtifact.KongPlugins[corsPlugin.ObjectMeta.Name] = corsPlugin

	for _, httproute := range k8sArtifact.HTTPRoutes {
		httproute.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
		httproute.ObjectMeta.Labels[k8sAPIUuidField] = apiUUID
		httproute.ObjectMeta.Labels[k8sRevisionField] = revisionID
		// update hostnames
		for _, environment := range *environments {
			vhost := environment.Vhost

			if httproute.ObjectMeta.Labels[k8sAPIEnvironmentField] == constants.ProductionType {
				httproute.Spec.Hostnames = []gwapiv1.Hostname{gwapiv1.Hostname(vhost)}
			}
			if httproute.ObjectMeta.Labels[k8sAPIEnvironmentField] == constants.SandboxType {
				httproute.Spec.Hostnames = []gwapiv1.Hostname{gwapiv1.Hostname("sandbox." + vhost)}
			}
		}
	}
	for _, service := range k8sArtifact.Services {
		service.ObjectMeta.Labels = make(map[string]string)
		service.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
		service.ObjectMeta.Labels[k8sAPIUuidField] = apiUUID
		service.ObjectMeta.Labels[k8sRevisionField] = revisionID
	}
	for _, kongPlugin := range k8sArtifact.KongPlugins {
		kongPlugin.ObjectMeta.Labels = make(map[string]string)
		kongPlugin.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
		kongPlugin.ObjectMeta.Labels[k8sAPIUuidField] = apiUUID
		kongPlugin.ObjectMeta.Labels[k8sRevisionField] = revisionID
	}
}

// generateHTTPRoutes handles the generation of http route resources from apk conf
func generateHTTPRoutes(k8sArtifact *K8sArtifacts, apkConf *types.APKConf, organizationID string, endpoints []types.EndpointDetails, endpointType string, uniqueID string, kongPlugins []string) {
	logger.LoggerUtils.Debugf("Starting HTTPRoute generation - API Name: %s, API UUID: %s, Organization ID: %s, Endpoint Type: %s, Unique ID: %s, Kong Plugins: %v, Endpoints: %+v, APK Config Name: %s, APK Config Version: %s, APK Config Base Path: %s",
		k8sArtifact.APIName, k8sArtifact.APIUUID, organizationID, endpointType, uniqueID, kongPlugins, endpoints, apkConf.Name, apkConf.Version, apkConf.BasePath)

	// ACL Plugin (for subscription)
	if apkConf.SubscriptionValidation {
		apiEnvironmentGroup := GenerateACLGroupName(k8sArtifact.APIName, endpointType)
		allowList := []string{apiEnvironmentGroup}
		kongACLPlugin := createAndAddACLPlugin(k8sArtifact, nil, "api", endpointType, allowList)
		// * Only in Kong Enterprise
		// kongACLPlugin.Ordering = &kong.PluginOrdering{
		// 	After: map[string][]string{
		// 		"access": {"jwt"},
		// 	},
		// }
		kongPlugins = append(kongPlugins, kongACLPlugin.ObjectMeta.Name)
		logger.LoggerUtils.Debugf("ACL plugin added for subscription validation - API Name: %s, Endpoint Type: %s, Plugin Name: %s, API Environment Group: %s, Allow List: %v",
			k8sArtifact.APIName, endpointType, kongACLPlugin.ObjectMeta.Name, apiEnvironmentGroup, allowList)
	}

	gen := httpGenerator.Generator()
	organization := types.Organization{
		Name: organizationID,
	}
	gatewayConfigurations := types.GatewayConfigurations{
		Name: k8sIngressClassName,
	}

	operationsArray := prepareOperationsArray(apkConf)
	for i, operations := range operationsArray {
		logger.LoggerUtils.Debugf("Processing operations array - Index: %d, Operations: %+v, Organization ID: %s, Gateway Name: %s, Listener Name: %s",
			i, operations, organizationID, gatewayConfigurations.Name, gatewayConfigurations.ListenerName)
		httpK8sArtifact, err := gen.GenerateHTTPRoute(*apkConf, organization, gatewayConfigurations, operations, &endpoints, endpointType, uniqueID, i)
		if err != nil {
			logger.LoggerUtils.Errorf("Failed to generate HTTPRoute - API Name: %s, API UUID: %s, Organization ID: %s, Endpoint Type: %s, Operations Index: %d, Error: %v",
				k8sArtifact.APIName, k8sArtifact.APIUUID, organizationID, endpointType, i, err)
		} else {
			routeKongPlugins := kongPlugins
			httpRoute := httpK8sArtifact.HTTPRoute
			httpRoute.Spec.ParentRefs[0].SectionName = nil
			// initialize labels structure and add environment type
			if httpRoute.ObjectMeta.Labels == nil {
				httpRoute.ObjectMeta.Labels = make(map[string]string)
			}
			httpRoute.ObjectMeta.Labels[k8sAPIEnvironmentField] = endpointType

			// prepare OPTIONS HTTPRoute
			optionsHTTPRoute := prepareOptionsHTTPRoute(httpRoute)
			k8sArtifact.HTTPRoutes[optionsHTTPRoute.ObjectMeta.Name] = optionsHTTPRoute

			// handle ratelimit configuration if httproute has only one operation
			for _, operation := range operations {
				// prepare base path and operation path
				basePath := utils.GeneratePath(apkConf.BasePath, apkConf.Version)
				operationTarget := "/*"
				if operation.Target != "" {
					operationTarget = operation.Target
				}

				// create and add a ratelimit plugin
				if operation.RateLimit != nil {
					rateLimitConfig := KongPluginConfig{
						"limit_by": "path",
						"path":     utils.RetrievePathPrefix(operationTarget, basePath),
					}
					PrepareRateLimit(&rateLimitConfig, operation.RateLimit.Unit, operation.RateLimit.RequestsPerUnit)
					rateLimitPlugin := GenerateKongPlugin(&operation, kongRateLimitingPluginName, "path", rateLimitConfig, true)
					k8sArtifact.KongPlugins[rateLimitPlugin.ObjectMeta.Name] = rateLimitPlugin

					routeKongPlugins = append(routeKongPlugins, rateLimitPlugin.ObjectMeta.Name)
					logger.LoggerUtils.Debugf("Operation rate limit plugin added - API Name: %s, Operation Target: %s, Base Path: %s, Plugin Name: %s, Rate Limit Unit: %s, Requests Per Unit: %d, Path Prefix: %s",
						k8sArtifact.APIName, operationTarget, basePath, rateLimitPlugin.ObjectMeta.Name, operation.RateLimit.Unit, operation.RateLimit.RequestsPerUnit, utils.RetrievePathPrefix(operationTarget, basePath))
				}

				// create and add endpoint security configurations for production environment
				// if endpointType == constants.ProductionType && operation.EndpointConfigurations.Production != nil {
				// 	endpointConfiguration := operation.EndpointConfigurations.Production

				// }
				// create and add endpoint security configurations for sandbox environment
				// if endpointType == constants.SanboxType && operation.EndpointConfigurations.Sandbox != nil {
				// 	endpointConfiguration := operation.EndpointConfigurations.Production

				// }
			}

			// store the services into k8s artifacts and add Kong-specific annotations
			for key, service := range httpK8sArtifact.Services {
				if service.ObjectMeta.Annotations == nil {
					service.ObjectMeta.Annotations = make(map[string]string)
				}
				kongAnnotations := map[string]string{
					"konghq.com/protocol": utils.GetProtocol(endpoints[0].URL),
				}
				for kongKey, kongValue := range kongAnnotations {
					service.ObjectMeta.Annotations[kongKey] = kongValue
				}

				k8sArtifact.Services[key] = service
			}

			// update httproute annotation
			annotationMap := map[string]string{
				"konghq.com/strip-path": "true",
				"konghq.com/plugins":    strings.Join(routeKongPlugins, ","),
			}
			updateHTTPRouteAnnotations(httpRoute, annotationMap)

			// store httproute in k8s artifacts
			httpRoute.Labels["routeType"] = "api"
			k8sArtifact.HTTPRoutes[httpRoute.ObjectMeta.Name] = httpRoute
			logger.LoggerUtils.Debugf("HTTPRoute stored successfully - Route Name: %s, API Name: %s, Endpoint Type: %s, Route Kong Plugins: %v, Annotations: %v",
				httpRoute.ObjectMeta.Name, k8sArtifact.APIName, endpointType, routeKongPlugins, annotationMap)
		}
	}

	logger.LoggerUtils.Infof("HTTPRoute generation completed - API Name: %s, API UUID: %s, Endpoint Type: %s, Total Operations Arrays: %d, Total HTTPRoutes: %d, Total Services: %d",
		k8sArtifact.APIName, k8sArtifact.APIUUID, endpointType, len(operationsArray), len(k8sArtifact.HTTPRoutes), len(k8sArtifact.Services))
}

func prepareOptionsHTTPRoute(httpRoute *gwapiv1.HTTPRoute) *gwapiv1.HTTPRoute {
	logger.LoggerUtils.Debugf("Preparing OPTIONS HTTPRoute|Original:%s\n", httpRoute.Name)

	optionsHttpRoute := httpRoute.DeepCopy()
	optionsHttpRoute.Name = optionsHttpRoute.Name + "-options"
	optionsHttpRoute.Labels["routeType"] = "options"

	// update httproute annotation
	annotationMap := map[string]string{
		"konghq.com/strip-path": "true",
	}
	updateHTTPRouteAnnotations(optionsHttpRoute, annotationMap)

	routeRuleMethod := gwapiv1.HTTPMethod("OPTIONS")
	// change all route matches to OPTIONS
	for i, rule := range optionsHttpRoute.Spec.Rules {
		for j := range rule.Matches {
			optionsHttpRoute.Spec.Rules[i].Matches[j].Method = &routeRuleMethod
		}
	}

	return optionsHttpRoute
}

func prepareOperationsArray(apkConf *types.APKConf) [][]types.Operation {
	logger.LoggerUtils.Debugf("Preparing operations array|TotalOps:%d\n", len(*apkConf.Operations))

	specialOps := []types.Operation{}
	normalOps := []types.Operation{}

	// separate special and normal operations
	for _, operation := range *apkConf.Operations {
		if operation.RateLimit != nil || operation.OperationPolicies != nil || operation.EndpointConfigurations != nil {
			specialOps = append(specialOps, operation)
		} else {
			normalOps = append(normalOps, operation)
		}
	}

	specialOpsLen := len(specialOps)
	normalOpsLen := len(normalOps)

	// initialize operationsArray with the correct size
	operationsArray := GenerateOperationsMatrix(specialOpsLen, normalOpsLen, 7)

	row := 0
	// place special operations (one per row)
	for _, operation := range specialOps {
		operationsArray[row][0] = operation
		row++
	}

	// place normal operations (up to 7 per row)
	column := 0
	for _, operation := range normalOps {
		operationsArray[row][column] = operation
		column++
		if column >= 7 {
			row++
			column = 0
		}
	}

	return operationsArray
}

// createAndAddACLPlugin handles the Kong ACL credential plugin generation and adding to k8s resources
func createAndAddACLPlugin(k8sArtifact *K8sArtifacts, operation *types.Operation, targetRef string, environment string, allowList []string) *v1.KongPlugin {
	logger.LoggerUtils.Debugf("Creating ACL plugin|TargetRef:%s Environment:%s\n", targetRef, environment)

	config := KongPluginConfig{
		"allow": allowList,
	}
	targetRef = k8sArtifact.APIUUID + "-" + targetRef + "-" + environment
	aclPlugin := GenerateKongPlugin(operation, kongACLPluginName, targetRef, config, true)
	k8sArtifact.KongPlugins[aclPlugin.ObjectMeta.Name] = aclPlugin
	return aclPlugin
}

// createAndAddJWTPlugin handles the Kong JWT credential plugin generation and adding to k8s resources
func createAndAddJWTPlugin(k8sArtifact *K8sArtifacts, operation *types.Operation, targetRef string, authentication types.AuthConfiguration) *v1.KongPlugin {
	logger.LoggerUtils.Debugf("Creating JWT plugin|TargetRef:%s Enabled:%v\n", targetRef, authentication.Enabled)

	headerNames := []string{}
	queryParamNames := []string{}
	if authentication.HeaderEnabled {
		headerNames = append(headerNames, authentication.HeaderName)
	} else if authentication.Enabled {
		headerNames = append(headerNames, "Authorization")
	}

	if authentication.QueryParamEnable {
		queryParamNames = append(queryParamNames, authentication.QueryParamName)
	}

	config := KongPluginConfig{
		"run_on_preflight": false,
		"key_claim_name":   "client_id",
		"claims_to_verify": []string{
			"exp",
		},
		"header_names":    headerNames,
		"uri_param_names": queryParamNames,
	}
	targetRef = k8sArtifact.APIUUID + "-" + targetRef
	jwtPlugin := GenerateKongPlugin(operation, kongJwtAuthPluginName, targetRef, config, authentication.Enabled)
	k8sArtifact.KongPlugins[jwtPlugin.ObjectMeta.Name] = jwtPlugin
	return jwtPlugin
}

// createAndAddAPIKeyPlugin handles the Kong API Key credential plugin generation and adding to k8s resources
func createAndAddAPIKeyPlugin(k8sArtifact *K8sArtifacts, operation *types.Operation, targetRef string, authentication types.AuthConfiguration) *v1.KongPlugin {
	logger.LoggerUtils.Debugf("Creating API Key plugin|TargetRef:%s Enabled:%v\n", targetRef, authentication.Enabled)

	keyNames := []string{}
	if authentication.HeaderName != "" {
		keyNames = append(keyNames, authentication.HeaderName)
	}
	if authentication.QueryParamName != "" {
		keyNames = append(keyNames, authentication.QueryParamName)
	}

	config := KongPluginConfig{
		"run_on_preflight": false,
		"key_names":        keyNames,
		"key_in_header":    authentication.HeaderEnabled,
		"key_in_query":     authentication.QueryParamEnable,
	}
	targetRef = k8sArtifact.APIUUID + "-" + targetRef
	keyPlugin := GenerateKongPlugin(operation, kongKeyAuthPluginName, targetRef, config, authentication.Enabled)
	k8sArtifact.KongPlugins[keyPlugin.ObjectMeta.Name] = keyPlugin
	return keyPlugin
}

// updateHTTPRouteAnnotations updates the annotations of httproutes
func updateHTTPRouteAnnotations(httpRoute *gwapiv1.HTTPRoute, annotations map[string]string) {
	logger.LoggerUtils.Debugf("Updating HTTPRoute annotations|Route:%s Annotations:%d\n",
		httpRoute.Name, len(annotations))

	httpRoute.Annotations = make(map[string]string, len(annotations))
	for key, annotation := range annotations {
		httpRoute.Annotations[key] = annotation
	}
}

// CreateConsumer handles the Kong consumer generation
func CreateConsumer(applicationUUID string, environment string) *v1.KongConsumer {
	logger.LoggerUtils.Debugf("Creating Kong consumer|App:%s Env:%s\n", applicationUUID, environment)

	consumer := v1.KongConsumer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "KongConsumer",
			APIVersion: "configuration.konghq.com/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: GenerateConsumerName(applicationUUID, environment),
			Annotations: map[string]string{
				"kubernetes.io/ingress.class": k8sIngressClassName,
			},
			Labels: make(map[string]string, 0),
		},
		Username: generateSHA1Hash(applicationUUID + environment),
	}
	consumer.Labels[k8APPUuidField] = applicationUUID
	if environment != "" {
		consumer.Labels[k8sAPIEnvironmentField] = environment
	}
	return &consumer
}

// GenerateK8sCredentialSecret handles the k8s secret generation for kong credentials
func GenerateK8sCredentialSecret(applicationUUID string, identifier string, credentialName string, data map[string]string) *corev1.Secret {
	logger.LoggerUtils.Debugf("Generating credential secret|App:%s Credential:%s\n",
		applicationUUID, credentialName)

	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: GenerateSecretName(applicationUUID, identifier, credentialName),
			Labels: map[string]string{
				"konghq.com/credential": credentialName,
			},
		},
		StringData: data,
	}
	secret.Labels[k8APPUuidField] = applicationUUID
	return &secret
}

// GenerateK8sSecret handles the k8s secret generation
func GenerateK8sSecret(name string, labels map[string]string, data map[string]string) *corev1.Secret {
	logger.LoggerUtils.Debugf("Generating k8s secret|Name:%s Labels:%d\n", name, len(labels))

	secret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   PrepareSecretName(name),
			Labels: labels,
		},
		StringData: data,
	}
	return &secret
}

// GenerateKongPlugin handles the Kong plugin generation
func GenerateKongPlugin(operation *types.Operation, pluginName string, targetRef string, config KongPluginConfig, enabled bool) *v1.KongPlugin {
	logger.LoggerUtils.Debugf("Generating Kong plugin|Plugin:%s Enabled:%v\n", pluginName, enabled)

	return &v1.KongPlugin{
		TypeMeta: metav1.TypeMeta{
			Kind:       "KongPlugin",
			APIVersion: "configuration.konghq.com/v1",
		},
		PluginName: pluginName,
		ObjectMeta: metav1.ObjectMeta{
			Name: GeneratePluginCRName(operation, targetRef, pluginName),
		},
		Disabled: !enabled,
		Config: apiextensionsv1.JSON{
			Raw: GenerateJSON(config),
		},
	}
}

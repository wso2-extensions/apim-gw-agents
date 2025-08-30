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

package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	discoverPkg "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/discovery"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/managementserver"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/loggers"
)

// handleAddHttpRouteResource handles the addition of an HTTPRoute
func handleAddHttpRouteResource(route *unstructured.Unstructured) {
	loggers.LoggerWatcher.Infof("Processing new HTTPRoute addition: %s/%s (Generation: %d, ResourceVersion: %s)",
		route.GetNamespace(), route.GetName(), route.GetGeneration(), route.GetResourceVersion())

	serviceNames := getHTTPRouteReferencedServices(route)
	for _, serviceName := range serviceNames {
		ReconcileAPI(route.GetNamespace(), serviceName)
	}
}

// handleUpdateHttpRouteResource handles the update of an HTTPRoute
func handleUpdateHttpRouteResource(_, route *unstructured.Unstructured) {
	loggers.LoggerWatcher.Infof("Processing HTTPRoute modification: %s/%s (Generation: %d, ResourceVersion: %s)",
		route.GetNamespace(), route.GetName(), route.GetGeneration(), route.GetResourceVersion())

	serviceNames := getHTTPRouteReferencedServices(route)
	for _, serviceName := range serviceNames {
		ReconcileAPI(route.GetNamespace(), serviceName)
	}
}

// handleDeleteHttpRouteResource handles the deletion of an HTTPRoute
func handleDeleteHttpRouteResource(route *unstructured.Unstructured) {
	loggers.LoggerWatcher.Infof("Processing HTTPRoute deletion: %s/%s (Generation: %d, ResourceVersion: %s)",
		route.GetNamespace(), route.GetName(), route.GetGeneration(), route.GetResourceVersion())

	serviceNames := getHTTPRouteReferencedServices(route)
	for _, serviceName := range serviceNames {
		ReconcileAPI(route.GetNamespace(), serviceName)
	}
}

func updateHTTPRouteLabels(u *unstructured.Unstructured, labelsToSet map[string]string) {
	updateResourceLabels(u, constants.HTTPRouteGVR, constants.HTTPRouteKind, labelsToSet)
}

// buildAPIFromHTTPRoutesAndService constructs an discoverPkg.API from a list of HTTPRoutes
func buildAPIFromHTTPRoutesAndService(service *unstructured.Unstructured, httpRoutes []*unstructured.Unstructured, apiVersion string, kongAPIUUID string) managementserver.API {
	loggers.LoggerWatcher.Debugf("Building API from HTTPRoutes - UUID: %s, Version: %s, Route count: %d", kongAPIUUID, apiVersion, len(httpRoutes))

	api := managementserver.API{
		APIUUID:          kongAPIUUID,
		APIName:          fmt.Sprintf("%s%s", constants.APIPrefix, kongAPIUUID),
		APIVersion:       apiVersion,
		IsDefaultVersion: true,
		APIType:          constants.DefaultAPIType,
	}

	generateAndAttachAPIDefinition(&api, httpRoutes, kongAPIUUID)
	updateAPIFromService(&api, service)
	for _, u := range httpRoutes {
		updateAPIFromHTTPRoute(&api, u)
	}
	return api
}

// generateAndAttachAPIDefinition generates the OpenAPI definition for an API and attaches it
func generateAndAttachAPIDefinition(api *managementserver.API, httpRoutes []*unstructured.Unstructured, kongAPIUUID string) {
	conf, _ := config.ReadConfigs()
	apiDefinition, err := discoverPkg.GenerateOpenAPIDefinition(httpRoutes, kongAPIUUID, conf)
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to generate OpenAPI definition for API %s: %v", kongAPIUUID, err)
		return
	}

	data, err := json.Marshal(apiDefinition)
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to convert API definition to JSON bytes for API %s: %v", kongAPIUUID, err)
		return
	}

	api.Definition = string(data)
}

// updateAPIFromHTTPRoute merges HTTPRoute data into an existing discoverPkg.API
func updateAPIFromHTTPRoute(api *managementserver.API, u *unstructured.Unstructured) {
	loggers.LoggerWatcher.Debugf("Updating API from HTTPRoute|%s/%s\n", u.GetNamespace(), u.GetName())

	env, _ := u.GetLabels()[constants.EnvironmentLabel]

	hostnames, hasHostnames, err := unstructured.NestedSlice(u.Object, constants.SpecField, constants.HostnamesField)
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to access hostnames for HTTPRoute %s/%s: %v", u.GetNamespace(), u.GetName(), err)
		return
	}

	if hasHostnames && len(hostnames) > 0 {
		if hostname, ok := hostnames[0].(string); ok {

			effectiveEnv := constants.EnvironmentProduction
			if env == constants.EnvironmentSandbox {
				effectiveEnv = env
			}

			switch effectiveEnv {
			case constants.EnvironmentProduction:
				if api.Vhost == constants.EmptyString {
					api.Vhost = hostname
				}
			case constants.EnvironmentSandbox:
				if api.SandVhost == constants.EmptyString {
					api.SandVhost = hostname
				}
			}
		}
	}
	newOps := extractOperations(u)
	for _, newOp := range newOps {
		if !operationExists(api.Operations, newOp) {
			api.Operations = append(api.Operations, newOp)
		}
	}

	api.BasePath = extractBasePath(api.Operations)

	if plugins, ok := u.GetAnnotations()[constants.KongPluginsAnnotation]; ok {
		pluginList := strings.Split(plugins, ",")
		for _, pluginName := range pluginList {
			pluginName = strings.TrimSpace(pluginName)
			if pluginName == constants.EmptyString {
				continue
			}
			kongPlugin := FetchKongPlugin(u.GetNamespace(), pluginName)
			if kongPlugin == nil {
				loggers.LoggerWatcher.Warnf("Failed to fetch KongPlugin %s for HTTPRoute %s/%s", pluginName, u.GetNamespace(), u.GetName())
				continue
			}
			pluginType, found, _ := unstructured.NestedString(kongPlugin.Object, constants.PluginField)
			if !found {
				loggers.LoggerWatcher.Warnf("KongPlugin %s has no plugin field", pluginName)
				continue
			}
			switch pluginType {
			case constants.CORSPlugin:
				api.CORSPolicy = extractCORSPolicyFromKongPlugin(kongPlugin)
			}
		}
	}
}

// FetchKongPlugin retrieves a KongPlugin CR by name
func FetchKongPlugin(namespace, name string) *unstructured.Unstructured {
	loggers.LoggerWatcher.Debugf("Fetching KongPlugin|%s/%s\n", namespace, name)

	kongPlugin, err := CRWatcher.DynamicClient.Resource(constants.KongPluginGVR).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		loggers.LoggerWatcher.Errorf("Error fetching KongPlugin %s/%s: %v", namespace, name, err)
		return nil
	}
	return kongPlugin
}

// extractOperations pulls operations from HTTPRoute rules
func extractOperations(httpRoute *unstructured.Unstructured) []managementserver.OperationFromDP {
	loggers.LoggerWatcher.Debugf("Extracting operations from HTTPRoute|%s/%s\n", httpRoute.GetNamespace(), httpRoute.GetName())

	rules, found, err := unstructured.NestedSlice(httpRoute.Object, constants.SpecField, constants.RulesField)
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to access rules for HTTPRoute %s/%s: %v", httpRoute.GetNamespace(), httpRoute.GetName(), err)
		return nil
	}
	if !found || len(rules) == 0 {
		loggers.LoggerWatcher.Debugf("No rules found for HTTPRoute %s/%s", httpRoute.GetNamespace(), httpRoute.GetName())
		return nil
	}
	var operations []managementserver.OperationFromDP

	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}
		matches, found, err := unstructured.NestedSlice(ruleMap, constants.MatchesField)
		if err != nil || !found {
			continue
		}
		for _, match := range matches {
			matchMap, ok := match.(map[string]interface{})
			if !ok {
				continue
			}

			path := extractPathFromMatch(matchMap)
			verb := extractVerbFromMatch(matchMap)
			operation := managementserver.OperationFromDP{
				Path:   path,
				Verb:   verb,
				Scopes: []string{},
			}
			operations = append(operations, operation)
		}
	}
	return operations
}

// extractPathFromMatch safely extracts path from match map
func extractPathFromMatch(matchMap map[string]interface{}) string {
	if pathObj, found := matchMap[constants.PathField]; found {
		if pathMap, ok := pathObj.(map[string]interface{}); ok {
			if val, ok := pathMap[constants.ValueField].(string); ok && val != constants.EmptyString {
				return val
			}
		}
	}
	return constants.EmptyString
}

// extractVerbFromMatch safely extracts HTTP verb from match map
func extractVerbFromMatch(matchMap map[string]interface{}) string {
	if method, ok := matchMap[constants.MethodField].(string); ok && method != constants.EmptyString {
		return method
	}
	return constants.DefaultHTTPMethod
}

// operationExists checks if an operation is already in the list
func operationExists(ops []managementserver.OperationFromDP, newOp managementserver.OperationFromDP) bool {
	for _, op := range ops {
		if op.Path == newOp.Path && op.Verb == newOp.Verb {
			return true
		}
	}
	return false
}

// extractBasePath finds a common prefix among all operation paths
func extractBasePath(operations []managementserver.OperationFromDP) string {
	loggers.LoggerWatcher.Debugf("Extracting base path|%d operations\n", len(operations))

	var paths []string
	for _, op := range operations {
		paths = append(paths, op.Path)
	}
	if len(paths) == 0 {
		return constants.DefaultBasePath
	}
	return findCommonPrefix(paths)
}

// findCommonPrefix computes the longest common prefix among paths
func findCommonPrefix(paths []string) string {
	loggers.LoggerWatcher.Debugf("Finding common prefix|%d paths\n", len(paths))

	if len(paths) == 0 {
		return constants.DefaultBasePath
	}
	if len(paths) == 1 {
		parts := strings.Split(paths[0], constants.PathSeparator)
		if len(parts) > constants.MinPathParts {
			return constants.PathSeparator + parts[1]
		}
		return paths[0]
	}

	prefix := paths[0]
	for _, path := range paths[1:] {
		for !strings.HasPrefix(path, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == constants.EmptyString {
				return constants.DefaultBasePath
			}
		}
	}
	parts := strings.Split(prefix, constants.PathSeparator)
	if len(parts) > constants.MinPathParts {
		return constants.PathSeparator + parts[1]
	}
	return prefix
}

// extractCORSPolicyFromKongPlugin pulls CORS details from a KongPlugin
func extractCORSPolicyFromKongPlugin(kongPlugin *unstructured.Unstructured) *managementserver.CORSPolicy {
	loggers.LoggerWatcher.Debugf("Extracting CORS policy from KongPlugin: %s/%s", kongPlugin.GetNamespace(), kongPlugin.GetName())

	cors := &managementserver.CORSPolicy{
		AccessControlAllowCredentials: constants.DefaultCORSCredentials,
		AccessControlAllowOrigins:     []string{},
		AccessControlAllowMethods:     []string{},
		AccessControlAllowHeaders:     []string{},
	}
	if config, found, _ := unstructured.NestedMap(kongPlugin.Object, constants.ConfigField); found {
		if origins, ok := config[constants.CORSOriginsField].([]interface{}); ok {
			cors.AccessControlAllowOrigins = make([]string, len(origins))
			for i, o := range origins {
				if str, ok := o.(string); ok {
					cors.AccessControlAllowOrigins[i] = str
				}
			}
		}
		if methods, ok := config[constants.CORSMethodsField].([]interface{}); ok {
			cors.AccessControlAllowMethods = make([]string, len(methods))
			for i, m := range methods {
				if str, ok := m.(string); ok {
					cors.AccessControlAllowMethods[i] = str
				}
			}
		}
		if headers, ok := config[constants.CORSHeadersField].([]interface{}); ok {
			cors.AccessControlAllowHeaders = make([]string, len(headers))
			for i, m := range headers {
				if str, ok := m.(string); ok {
					cors.AccessControlAllowHeaders[i] = str
				}
			}
		}
		if credentials, ok := config[constants.CORSCredentialsField].(bool); ok {
			cors.AccessControlAllowCredentials = credentials
		}
	}
	return cors
}

// updateResourceLabels updates multiple labels on a resource
func updateResourceLabels(resource *unstructured.Unstructured, gvr schema.GroupVersionResource, resourceType string, labelsToSet map[string]string) {
	loggers.LoggerWatcher.Debugf("Updating %s labels on %s/%s", resourceType, resource.GetNamespace(), resource.GetName())

	for attempt := 0; attempt < constants.MaxRetries; attempt++ {
		loggers.LoggerWatcher.Debugf("Attempt %d: fetching latest version of %s %s/%s", attempt+1, resourceType, resource.GetNamespace(), resource.GetName())
		latest, err := CRWatcher.DynamicClient.Resource(gvr).Namespace(resource.GetNamespace()).Get(context.Background(), resource.GetName(), metav1.GetOptions{})
		if err != nil {
			loggers.LoggerWatcher.Errorf("Failed to fetch latest %s %s/%s on attempt %d: %v", resourceType, resource.GetNamespace(), resource.GetName(), attempt+1, err)
			if attempt < constants.MaxRetries {
				time.Sleep(time.Duration((attempt+1)*constants.RetryDelayMultiplier) * time.Millisecond)
				continue
			}
			return
		}

		labels, _, _ := unstructured.NestedStringMap(latest.Object, constants.MetadataField, constants.LabelsField)
		if labels == nil {
			labels = make(map[string]string)
		}
		maps.Copy(labels, labelsToSet)
		unstructured.SetNestedStringMap(latest.Object, labels, constants.MetadataField, constants.LabelsField)

		_, err = CRWatcher.DynamicClient.Resource(gvr).Namespace(latest.GetNamespace()).Update(context.Background(), latest, metav1.UpdateOptions{})
		if err != nil {
			if strings.Contains(err.Error(), constants.ObjectModifiedError) {
				loggers.LoggerWatcher.Warnf("%s %s/%s was modified during update, retrying attempt %d: %v", resourceType, latest.GetNamespace(), latest.GetName(), attempt+1, err)
				if attempt < constants.MaxRetries {
					time.Sleep(time.Duration((attempt+1)*constants.RetryDelayMultiplier) * time.Millisecond)
					continue
				}
			} else {
				loggers.LoggerWatcher.Errorf("Failed to update %s %s/%s (non-conflict error): %v", resourceType, latest.GetNamespace(), latest.GetName(), err)
				return
			}
		} else {
			loggers.LoggerWatcher.Infof("Successfully updated labels on %s %s/%s", resourceType, latest.GetNamespace(), latest.GetName())
			return
		}
	}
	loggers.LoggerWatcher.Errorf("Failed to update %s %s/%s after %d retry attempts due to resource version conflicts",
		resourceType, resource.GetNamespace(), resource.GetName(), constants.MaxRetries)
}

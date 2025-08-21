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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"

	discoverPkg "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/discovery"
	loggers "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/loggers"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/managementserver"
)

// InitializeHTTPRoutesState fetches all existing HTTPRoutes and populates discoverPkg.APIMap
func InitializeHTTPRoutesState() {
	gvr := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
	list, err := CRWatcher.DynamicClient.Resource(gvr).Namespace("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to list HTTPRoutes in namespace default: %v", err)
		return
	}

	// Group HTTPRoutes by apiUUID
	routesByUUID := make(map[string][]*unstructured.Unstructured)
	for i := range list.Items {
		route := &list.Items[i]

		// If to hide the API in CP
		showInCP, found := route.GetLabels()["showInCP"]
		if found && showInCP == "false" {
			continue
		}

		apiUUID, found := route.GetLabels()["apiUUID"]
		if !found {
			// Generate apiUUID for routes without it
			apiUUID = uuid.New().String()
			loggers.LoggerWatcher.Infof("Generated apiUUID %s for existing HTTPRoute %s/%s", apiUUID, route.GetNamespace(), route.GetName())
			updateHTTPRouteLabel(route, "apiUUID", apiUUID)
		}

		routesByUUID[apiUUID] = append(routesByUUID[apiUUID], route)
	}

	// Build discoverPkg.API for each apiUUID group
	apiMutex.Lock()
	defer apiMutex.Unlock()
	for apiUUID, routes := range routesByUUID {
		// Check revisionID consistency
		revisionID := ""
		apiVersion := "v1"
		needsRevisionUpdate := false
		for _, route := range routes {
			// Check for api version in route labels
			routeAPIVersion, found := route.GetLabels()["apiVersion"]
			if found {
				apiVersion = routeAPIVersion
			}

			if rev, found := route.GetLabels()["revisionID"]; found {
				if revisionID == "" {
					revisionID = rev
				} else if revisionID != rev {
					needsRevisionUpdate = true // Mismatch detected
					break
				}
			} else {
				needsRevisionUpdate = true // Missing revisionID
				break
			}
		}

		api := buildAPIFromHTTPRoutes(routes, apiVersion, apiUUID)
		discoverPkg.APIHashMap[apiUUID] = computeAPIHash(api)

		if needsRevisionUpdate || revisionID == "" {
			revisionID = generateRevisionID()
			api.RevisionID = revisionID
			for _, route := range routes {
				updateHTTPRouteLabel(route, "revisionID", revisionID)
			}
			loggers.LoggerWatcher.Debugf("Revision ID updated: %s", revisionID)
		} else {
			api.RevisionID = revisionID
			loggers.LoggerWatcher.Debugf("Using existing revision ID: %s", revisionID)
		}

		discoverPkg.APIMap[apiUUID] = api
		loggers.LoggerWatcher.Infof("Initialized discoverPkg.API %s with %d HTTPRoutes", apiUUID, len(routes))
	}
	loggers.LoggerWatcher.Debugf("HTTPRoutes state initialization completed with %d APIs", len(routesByUUID))
}

// handleAddHttpRouteResource handles the addition of an HTTPRoute
func handleAddHttpRouteResource(u *unstructured.Unstructured) {
	loggers.LoggerWatcher.Debugf("Processing new HTTPRoute: %s/%s", u.GetNamespace(), u.GetName())

	// If to hide the API in CP
	showInCP, found := u.GetLabels()["showInCP"]
	if found && showInCP == "false" {
		return
	}

	apiUUID, found := u.GetLabels()["apiUUID"]
	if !found {
		apiUUID = uuid.New().String()
		loggers.LoggerWatcher.Infof("Generated apiUUID %s for HTTPRoute %s/%s", apiUUID, u.GetNamespace(), u.GetName())
		updateHTTPRouteLabel(u, "apiUUID", apiUUID)
	}

	apiVersion, found := u.GetLabels()["apiVersion"]
	if !found {
		apiVersion = "v1"
		loggers.LoggerWatcher.Infof("Generated apiVersion %s for HTTPRoute %s/%s", apiVersion, u.GetNamespace(), u.GetName())
		updateHTTPRouteLabel(u, "apiVersion", apiVersion)
	}

	apiMutex.Lock()
	defer apiMutex.Unlock()

	existingAPI, apiExists := discoverPkg.APIMap[apiUUID]
	revisionID, hasRevision := u.GetLabels()["revisionID"]

	if apiExists && hasRevision && revisionID == existingAPI.RevisionID {
		loggers.LoggerWatcher.Infof("HTTPRoute %s/%s already processed for discoverPkg.API %s with revisionID %s, skipping", u.GetNamespace(), u.GetName(), apiUUID, revisionID)
		return
	}

	// Fetch all HTTPRoutes with this apiUUID and rebuild discoverPkg.API if first time or revisionID mismatch
	httpRoutes := fetchAllHTTPRoutesWithAPIUUID(u.GetNamespace(), apiUUID)
	api := buildAPIFromHTTPRoutes(httpRoutes, apiVersion, apiUUID)
	newHash := computeAPIHash(api)
	currentHash := ""
	if apiExists {
		currentHash = discoverPkg.APIHashMap[apiUUID]
	}

	// Only update if discoverPkg.API is new or changed
	if !apiExists || currentHash != newHash {
		revisionID := generateRevisionID()
		api.RevisionID = revisionID
		discoverPkg.APIHashMap[apiUUID] = newHash
		discoverPkg.APIMap[apiUUID] = api

		discoverPkg.QueueEvent(managementserver.CreateEvent, api, u.GetName(), u.GetNamespace())
		// Update revisionID label on all related HTTPRoutes
		for _, route := range httpRoutes {
			updateHTTPRouteLabel(route, "revisionID", revisionID)
		}
	} else {
		loggers.LoggerWatcher.Infof("discoverPkg.API %s unchanged after adding %s/%s, skipping CP update", apiUUID, u.GetNamespace(), u.GetName())
	}
}

// handleUpdateHTTPRouteResource handles the update of an HTTPRoute
func handleUpdateHTTPRouteResource(_, newU *unstructured.Unstructured) {
	loggers.LoggerWatcher.Debugf("Processing HTTPRoute update|%s/%s\n", newU.GetNamespace(), newU.GetName())

	// If to hide the API in CP
	showInCP, found := newU.GetLabels()["showInCP"]
	if found && showInCP == "false" {
		return
	}

	apiUUID, found := newU.GetLabels()["apiUUID"]
	if !found {
		loggers.LoggerWatcher.Warnf("HTTPRoute %s/%s has no apiUUID label, treating as new", newU.GetNamespace(), newU.GetName())
		handleAddHttpRouteResource(newU)
		return
	}

	apiMutex.Lock()
	defer apiMutex.Unlock()

	api, exists := discoverPkg.APIMap[apiUUID]
	if !exists {
		loggers.LoggerWatcher.Warnf("discoverPkg.API %s not found for HTTPRoute %s/%s, treating as new", apiUUID, newU.GetNamespace(), newU.GetName())
		handleAddHttpRouteResource(newU)
		return
	}

	// Update discoverPkg.API incrementally
	updateAPIFromHTTPRoute(&api, newU)
	newHash := computeAPIHash(api)
	apiHash := discoverPkg.APIHashMap[api.APIUUID]
	if apiHash != newHash {
		revisionID := generateRevisionID()
		api.RevisionID = revisionID
		discoverPkg.APIHashMap[apiUUID] = newHash
		discoverPkg.APIMap[apiUUID] = api
		discoverPkg.QueueEvent(managementserver.CreateEvent, api, newU.GetName(), newU.GetNamespace())
		updateHTTPRouteLabel(newU, "revisionID", revisionID)
		loggers.LoggerWatcher.Infof("API updated|UUID:%s Revision:%s\n", apiUUID, revisionID)
	} else {
		loggers.LoggerWatcher.Infof("discoverPkg.API %s unchanged after updating %s/%s, skipping CP update", apiUUID, newU.GetNamespace(), newU.GetName())
	}
}

// handleDeleteHttpRouteResource handles the deletion of an HTTPRoute
func handleDeleteHttpRouteResource(u *unstructured.Unstructured) {
	loggers.LoggerWatcher.Debugf("Processing HTTPRoute deletion|%s/%s\n", u.GetNamespace(), u.GetName())

	apiUUID, found := u.GetLabels()["apiUUID"]
	if !found {
		loggers.LoggerWatcher.Warnf("HTTPRoute %s/%s has no apiUUID label, skipping deletion", u.GetNamespace(), u.GetName())
		return
	}

	apiMutex.Lock()
	defer apiMutex.Unlock()

	apiHash, exists := discoverPkg.APIHashMap[apiUUID]
	if !exists {
		loggers.LoggerWatcher.Warnf("discoverPkg.APIHash %s not found for deleted HTTPRoute %s/%s", apiUUID, u.GetNamespace(), u.GetName())
	} else {
		delete(discoverPkg.APIHashMap, apiUUID)
		loggers.LoggerWatcher.Warnf("discoverPkg.APIHash %s deleted", apiHash)
	}

	api, exists := discoverPkg.APIMap[apiUUID]
	if !exists {
		loggers.LoggerWatcher.Warnf("discoverPkg.API %s not found for deleted HTTPRoute %s/%s", apiUUID, u.GetNamespace(), u.GetName())
		return
	}
	delete(discoverPkg.APIMap, apiUUID)

	discoverPkg.QueueEvent(managementserver.DeleteEvent, api, u.GetName(), u.GetNamespace())
	loggers.LoggerWatcher.Warnf("discoverPkg.API %s deleted", apiUUID)
}

// fetchAllHTTPRoutesWithAPIUUID fetches all HTTPRoutes with a given apiUUID
func fetchAllHTTPRoutesWithAPIUUID(namespace, apiUUID string) []*unstructured.Unstructured {
	loggers.LoggerWatcher.Debugf("Fetching HTTPRoutes with apiUUID|%s\n", apiUUID)

	gvr := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
	selector := labels.SelectorFromSet(map[string]string{"apiUUID": apiUUID})
	list, err := CRWatcher.DynamicClient.Resource(gvr).Namespace(namespace).List(context.Background(), metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to fetch HTTPRoutes with apiUUID %s in namespace %s: %v", apiUUID, namespace, err)
		return []*unstructured.Unstructured{}
	}
	items := make([]*unstructured.Unstructured, len(list.Items))
	for i := range list.Items {
		// If to hide the API in CP
		showInCP, found := list.Items[i].GetLabels()["showInCP"]
		if found && showInCP == "false" {
			continue
		}

		items[i] = &list.Items[i]
	}
	return items
}

// buildAPIFromHTTPRoutes constructs an discoverPkg.API from a list of HTTPRoutes
func buildAPIFromHTTPRoutes(httpRoutes []*unstructured.Unstructured, apiVersion string, apiUUID string) managementserver.API {
	loggers.LoggerWatcher.Debugf("Building API from HTTPRoutes|UUID:%s Routes:%d\n", apiUUID, len(httpRoutes))

	api := managementserver.API{
		APIUUID:          apiUUID,
		APIName:          fmt.Sprintf("api-%s", apiUUID),
		APIVersion:       apiVersion,
		IsDefaultVersion: true,
		APIType:          "rest",
	}

	apiDef, err := discoverPkg.GenerateOpenAPIDefinition(httpRoutes, apiUUID)
	if err == nil {
		data, err := json.Marshal(apiDef)
		if err != nil {
			loggers.LoggerWatcher.Error("Failed to convert api definition to bytes")
		} else {
			api.Definition = string(data)
		}
	}

	for _, u := range httpRoutes {
		updateAPIFromHTTPRoute(&api, u)
	}
	return api
}

// updateAPIFromHTTPRoute merges HTTPRoute data into an existing discoverPkg.API
func updateAPIFromHTTPRoute(api *managementserver.API, u *unstructured.Unstructured) {
	loggers.LoggerWatcher.Debugf("Updating API from HTTPRoute|%s/%s\n", u.GetNamespace(), u.GetName())

	// If to hide the API in CP
	showInCP, found := u.GetLabels()["showInCP"]
	if found && showInCP == "false" {
		loggers.LoggerWatcher.Debugf("HTTPRoute hidden from CP, skipping|%s/%s\n", u.GetNamespace(), u.GetName())
		return
	}

	// Set display name if exists
	apiName, found := u.GetLabels()["apiName"]
	if found && apiName != "" {
		api.APIName = apiName
	}

	// Set api version if exists
	apiVersion, found := u.GetLabels()["apiVersion"]
	if found && apiVersion != "" {
		api.APIVersion = apiVersion
	}

	// Set environment (default to "production" if not found)
	env, found := u.GetLabels()["environment"]
	if !found {
		env = "production"
		updateHTTPRouteLabel(u, "environment", env)
	}
	// Set organization
	organization, found := u.GetLabels()["organization"]
	if found {
		api.Organization = organization
	}

	// Access spec.hostnames directly from unstructured data
	hostnames, found, err := unstructured.NestedSlice(u.Object, "spec", "hostnames")
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to access hostnames for HTTPRoute %s/%s: %v", u.GetNamespace(), u.GetName(), err)
		return
	}

	// Update environment-specific fields
	if found && len(hostnames) > 0 {
		if hostname, ok := hostnames[0].(string); ok {
			switch env {
			case "production":
				if api.Vhost == "" {
					api.Vhost = hostname
				}
			case "sandbox":
				if api.SandVhost == "" {
					api.SandVhost = hostname
				}
			}
		}
	}
	// Aggregate operations
	newOps := extractOperations(u)
	for _, newOp := range newOps {
		if !operationExists(api.Operations, newOp) {
			api.Operations = append(api.Operations, newOp)
		}
	}

	// Update BasePath based on all operations
	api.BasePath = extractBasePath(api.Operations)

	// Process plugins from annotations
	if plugins, ok := u.GetAnnotations()["konghq.com/plugins"]; ok {
		pluginList := strings.Split(plugins, ",")
		for _, pluginName := range pluginList {
			pluginName = strings.TrimSpace(pluginName)
			if pluginName == "" {
				continue
			}
			kongPlugin := fetchKongPlugin(u.GetNamespace(), pluginName)
			if kongPlugin == nil {
				loggers.LoggerWatcher.Warnf("Failed to fetch KongPlugin %s for HTTPRoute %s/%s", pluginName, u.GetNamespace(), u.GetName())
				continue
			}
			pluginType, found, _ := unstructured.NestedString(kongPlugin.Object, "plugin")
			if !found {
				loggers.LoggerWatcher.Warnf("KongPlugin %s has no plugin field", pluginName)
				continue
			}
			switch pluginType {
			case "cors":
				api.CORSPolicy = extractCORSPolicyFromKongPlugin(kongPlugin)
			}
		}
	}
}

// fetchKongPlugin retrieves a KongPlugin CR by name
func fetchKongPlugin(namespace, name string) *unstructured.Unstructured {
	loggers.LoggerWatcher.Debugf("Fetching KongPlugin|%s/%s\n", namespace, name)

	gvr := schema.GroupVersionResource{
		Group:    "configuration.konghq.com",
		Version:  "v1",
		Resource: "kongplugins",
	}
	kongPlugin, err := CRWatcher.DynamicClient.Resource(gvr).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		loggers.LoggerWatcher.Errorf("Error fetching KongPlugin %s/%s: %v", namespace, name, err)
		return nil
	}
	return kongPlugin
}

// extractOperations pulls operations from HTTPRoute rules
func extractOperations(httpRoute *unstructured.Unstructured) []managementserver.OperationFromDP {
	loggers.LoggerWatcher.Debugf("Extracting operations from HTTPRoute|%s/%s\n", httpRoute.GetNamespace(), httpRoute.GetName())

	var operations []managementserver.OperationFromDP

	// Access spec.rules from unstructured data
	rules, found, err := unstructured.NestedSlice(httpRoute.Object, "spec", "rules")
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to access rules for HTTPRoute %s/%s: %v", httpRoute.GetNamespace(), httpRoute.GetName(), err)
		return operations
	}
	if !found || len(rules) == 0 {
		loggers.LoggerWatcher.Debugf("No rules found for HTTPRoute %s/%s", httpRoute.GetNamespace(), httpRoute.GetName())
		return operations
	}

	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}
		matches, found, err := unstructured.NestedSlice(ruleMap, "matches")
		if err != nil || !found {
			continue
		}
		for _, match := range matches {
			matchMap, ok := match.(map[string]interface{})
			if !ok {
				continue
			}

			// Extract path
			path := ""
			if pathObj, found := matchMap["path"]; found {
				if pathMap, ok := pathObj.(map[string]interface{}); ok {
					if val, ok := pathMap["value"].(string); ok {
						path = val
					}
				}
			}

			// Extract method (verb)
			verb := "GET" // Default
			if method, ok := matchMap["method"].(string); ok {
				verb = method
			}

			operations = append(operations, managementserver.OperationFromDP{
				Path:   path,
				Verb:   verb,
				Scopes: []string{},
			})
		}
	}
	return operations
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
		return "/"
	}
	return findCommonPrefix(paths)
}

// findCommonPrefix computes the longest common prefix among paths
func findCommonPrefix(paths []string) string {
	loggers.LoggerWatcher.Debugf("Finding common prefix|%d paths\n", len(paths))

	if len(paths) == 0 {
		return "/"
	}
	if len(paths) == 1 {
		parts := strings.Split(paths[0], "/")
		if len(parts) > 2 {
			return "/" + parts[1]
		}
		return paths[0]
	}

	prefix := paths[0]
	for _, path := range paths[1:] {
		for !strings.HasPrefix(path, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return "/"
			}
		}
	}
	parts := strings.Split(prefix, "/")
	if len(parts) > 2 {
		return "/" + parts[1]
	}
	return prefix
}

// extractCORSPolicyFromKongPlugin pulls CORS details from a KongPlugin
func extractCORSPolicyFromKongPlugin(kongPlugin *unstructured.Unstructured) *managementserver.CORSPolicy {
	loggers.LoggerWatcher.Debugf("Extracting CORS policy|%s\n", kongPlugin.GetName())

	cors := &managementserver.CORSPolicy{
		AccessControlAllowCredentials: false,
		AccessControlAllowOrigins:     []string{},
		AccessControlAllowMethods:     []string{},
		AccessControlAllowHeaders:     []string{},
	}
	if config, found, _ := unstructured.NestedMap(kongPlugin.Object, "config"); found {
		if origins, ok := config["origins"].([]interface{}); ok {
			cors.AccessControlAllowOrigins = make([]string, len(origins))
			for i, o := range origins {
				if str, ok := o.(string); ok {
					cors.AccessControlAllowOrigins[i] = str
				}
			}
		}
		if methods, ok := config["methods"].([]interface{}); ok {
			cors.AccessControlAllowMethods = make([]string, len(methods))
			for i, m := range methods {
				if str, ok := m.(string); ok {
					cors.AccessControlAllowMethods[i] = str
				}
			}
		}
		if headers, ok := config["headers"].([]interface{}); ok {
			cors.AccessControlAllowHeaders = make([]string, len(headers))
			for i, m := range headers {
				if str, ok := m.(string); ok {
					cors.AccessControlAllowHeaders[i] = str
				}
			}
		}
		if credentials, ok := config["credentials"].(bool); ok {
			cors.AccessControlAllowCredentials = credentials
		}
	}
	return cors
}

// extractRateLimitFromKongPlugin pulls rate limit details from a KongPlugin
func extractRateLimitFromKongPlugin(kongPlugin *unstructured.Unstructured) *managementserver.AIRL {
	loggers.LoggerWatcher.Debugf("Extracting rate limit|%s\n", kongPlugin.GetName())

	rl := &managementserver.AIRL{
		TimeUnit: "min", // Default to "min" as per allowedTimeUnits
	}
	if config, found, _ := unstructured.NestedMap(kongPlugin.Object, "config"); found {
		for unit, mappedUnit := range allowedTimeUnits {
			if count, ok := config[unit].(int64); ok {
				count32 := uint32(count)
				rl.RequestCount = &count32
				rl.TimeUnit = mappedUnit
				break // Stop after finding the first valid time unit
			}
		}
	}
	return rl
}

// computeAPIHash generates a hash of the discoverPkg.API struct for comparison
func computeAPIHash(api managementserver.API) string {
	data := fmt.Sprintf("%v%v%v%v%v", api.Operations, api.CORSPolicy, api.ProdAIRL, api.SandAIRL, api.Environment)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generateRevisionID creates a unique revision ID
func generateRevisionID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// updateHTTPRouteLabel updates a label on the HTTPRoute
func updateHTTPRouteLabel(u *unstructured.Unstructured, key, value string) {
	loggers.LoggerWatcher.Debugf("Updating HTTPRoute label|%s=%s\n", key, value)

	labels, found, _ := unstructured.NestedMap(u.Object, "metadata", "labels")
	if !found {
		labels = make(map[string]interface{})
	}
	labels[key] = value
	unstructured.SetNestedMap(u.Object, labels, "metadata", "labels")

	gvr := schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "httproutes"}
	_, err := CRWatcher.DynamicClient.Resource(gvr).Namespace(u.GetNamespace()).Update(context.Background(), u, metav1.UpdateOptions{})
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to update HTTPRoute %s/%s with label %s: %v", u.GetNamespace(), u.GetName(), key, err)
	} else {
		loggers.LoggerWatcher.Infof("Updated HTTPRoute %s/%s with label %s: %s", u.GetNamespace(), u.GetName(), key, value)
	}
}

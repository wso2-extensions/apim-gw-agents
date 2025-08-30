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
	"fmt"
	"strings"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	loggers "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/loggers"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// OpenAPI represents a simplified OpenAPI 3.0 specification
type OpenAPI struct {
	OpenAPI string              `json:"openapi"`
	Info    info                `json:"info"`
	Servers []server            `json:"servers,omitempty"`
	Paths   map[string]pathItem `json:"paths"`
}

type info struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type server struct {
	URL string `json:"url"`
}

type pathItem struct {
	Get    *operationDef `json:"get,omitempty"`
	Post   *operationDef `json:"post,omitempty"`
	Put    *operationDef `json:"put,omitempty"`
	Delete *operationDef `json:"delete,omitempty"`
	Patch  *operationDef `json:"patch,omitempty"`
}

type operationDef struct {
	Summary   string              `json:"summary"`
	Responses map[string]response `json:"responses"`
}

type response struct {
	Description string `json:"description"`
}

// GenerateOpenAPIDefinition generates an OpenAPI 3.0 definition from a set of HTTPRoutes
func GenerateOpenAPIDefinition(httpRoutes []*unstructured.Unstructured, apiUUID string, conf *config.Config) (OpenAPI, error) {
	openAPI := OpenAPI{
		OpenAPI: "3.0.0",
		Info: info{
			Title:   fmt.Sprintf("API Definition for %s", apiUUID),
			Version: "1.0.0", // Default version, could be derived from labels or annotations
		},
		Paths: make(map[string]pathItem),
	}

	// Collect servers (hostnames) from all HTTPRoutes
	var servers []server
	serverSet := make(map[string]struct{})
	var allPaths []string // To collect paths for basePath extraction
	httpsPort := conf.DataPlane.GatewayHTTPSPort
	for _, route := range httpRoutes {
		hostnames, found, err := unstructured.NestedSlice(route.Object, "spec", "hostnames")
		if err != nil {
			loggers.LoggerWatcher.Errorf("Failed to access hostnames for HTTPRoute %s/%s: %v", route.GetNamespace(), route.GetName(), err)
			continue
		}
		if found {
			for _, hostname := range hostnames {
				if h, ok := hostname.(string); ok && h != "" {
					if _, exists := serverSet[h]; !exists {
						var serverURL string
						if httpsPort != 0 && httpsPort != 443 {
							serverURL = fmt.Sprintf("https://%s:%d", h, httpsPort)
						} else {
							serverURL = fmt.Sprintf("https://%s", h)
						}
						servers = append(servers, server{URL: serverURL})
						serverSet[h] = struct{}{}
					}
				}
			}
		}

		// Collect paths for basePath extraction
		rules, found, err := unstructured.NestedSlice(route.Object, "spec", "rules")
		if err != nil {
			loggers.LoggerWatcher.Errorf("Failed to access rules for HTTPRoute %s/%s: %v", route.GetNamespace(), route.GetName(), err)
			continue
		}
		if !found {
			continue
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

				path := ""
				if pathObj, found := matchMap["path"]; found {
					if pathMap, ok := pathObj.(map[string]interface{}); ok {
						if val, ok := pathMap["value"].(string); ok {
							path = val
						}
					}
				}
				if path == "" {
					path = "/"
				}
				allPaths = append(allPaths, path)
			}
		}
	}

	// Extract basePath from all collected paths
	basePath := extractBasePathFromPaths(allPaths)
	if basePath == "" || basePath == "/" {
		basePath = "" // Avoid duplicating "/" in server URLs
	}

	// Update servers with basePath
	if len(servers) > 0 {
		for i := range servers {
			servers[i].URL = fmt.Sprintf("%s%s", servers[i].URL, basePath)
		}
		openAPI.Servers = servers
	}

	// Extract paths and operations, stripping basePath
	for _, route := range httpRoutes {
		rules, found, err := unstructured.NestedSlice(route.Object, "spec", "rules")
		if err != nil {
			loggers.LoggerWatcher.Errorf("Failed to access rules for HTTPRoute %s/%s: %v", route.GetNamespace(), route.GetName(), err)
			continue
		}
		if !found {
			continue
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
				if path == "" {
					path = "/"
				}

				// Strip basePath from the operation path
				relativePath := path
				if basePath != "" && strings.HasPrefix(path, basePath) {
					relativePath = strings.TrimPrefix(path, basePath)
					if relativePath == "" {
						relativePath = "/"
					}
				}

				// Extract method (verb)
				verb := "GET" // Default
				if method, ok := matchMap["method"].(string); ok {
					verb = strings.ToUpper(method)
				}

				// Create or update PathItem
				openAPIPathItem, exists := openAPI.Paths[relativePath]
				if !exists {
					openAPIPathItem = pathItem{}
				}

				// Define a basic operation
				op := &operationDef{
					Summary: fmt.Sprintf("%s operation on %s", verb, path),
					Responses: map[string]response{
						"200": {Description: "Successful response"},
					},
				}

				// Assign operation to the appropriate HTTP method
				switch verb {
				case "GET":
					openAPIPathItem.Get = op
				case "POST":
					openAPIPathItem.Post = op
				case "PUT":
					openAPIPathItem.Put = op
				case "DELETE":
					openAPIPathItem.Delete = op
				case "PATCH":
					openAPIPathItem.Patch = op
				default:
					loggers.LoggerWatcher.Warnf("Unsupported HTTP method %s for path %s in HTTPRoute %s/%s", verb, path, route.GetNamespace(), route.GetName())
					continue
				}

				openAPI.Paths[relativePath] = openAPIPathItem
			}
		}
	}

	return openAPI, nil
}

// extractBasePathFromPaths finds a common prefix among all paths
func extractBasePathFromPaths(paths []string) string {
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

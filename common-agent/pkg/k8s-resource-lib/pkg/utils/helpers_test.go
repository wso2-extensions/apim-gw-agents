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

package utils

import (
	"fmt"
	"testing"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/types"

	"github.com/stretchr/testify/assert"
)

func TestGetHost(t *testing.T) {
	tests := []struct {
		name     string
		endpoint types.Endpoint
		expected string
	}{
		{"HTTP URL", types.EndpointURL("http://example.com:8080/path"), "example.com"},
		{"HTTPS URL", types.EndpointURL("https://example.com:8443/path"), "example.com"},
		{"K8s Service", types.K8sService{Name: "service", Namespace: "default", Protocol: "http", Port: "80"}, "service.default.svc.cluster.local"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := GetHost(tt.endpoint)
			assert.Equal(t, tt.expected, host)
		})
	}
}

func TestGetPort(t *testing.T) {
	tests := []struct {
		name     string
		endpoint interface{}
		expected int
	}{
		{"HTTP URL", "http://example.com:8080/path", 8080},
		{"HTTPS URL", "https://example.com:8443/path", 8443},
		{"HTTP URL without port", "http://example.com/path", 80},
		{"HTTPS URL without port", "https://example.com/path", 443},
		{"K8s Service", types.K8sService{Name: "service", Namespace: "default", Protocol: "http", Port: "80"}, 80},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := GetPort(tt.endpoint)
			assert.Equal(t, tt.expected, port)
		})
	}
}

func TestGetProtocol(t *testing.T) {
	tests := []struct {
		name     string
		endpoint interface{}
		expected string
	}{
		{"HTTP URL", "http://example.com/path", "http"},
		{"HTTPS URL", "https://example.com/path", "https"},
		{"K8s Service with protocol", types.K8sService{Name: "service", Namespace: "default", Protocol: "http", Port: "80"}, "http"},
		{"K8s Service without protocol", types.K8sService{Name: "service", Namespace: "default", Port: "80"}, "http"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protocol := GetProtocol(tt.endpoint)
			assert.Equal(t, tt.expected, protocol)
		})
	}
}

func TestGetPath(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{"HTTP URL with path", "http://example.com:8080/path/to/resource", "/path/to/resource"},
		{"HTTPS URL with path", "https://example.com:8443/path/to/resource", "/path/to/resource"},
		{"HTTP URL without path", "http://example.com:8080", ""},
		{"HTTPS URL without path", "https://example.com:8443", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := GetPath(tt.url)
			assert.Equal(t, tt.expected, path)
		})
	}
}

func TestRetrievePathPrefix(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		basePath  string
		expected  string
	}{
		{"Root operation", "/", "/base", "/"},
		{"Wildcard operation", "/*", "/base", "/(.*)"},
		{"Path with param", "/resource/{id}", "/base", "/base/resource/(.*)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := RetrievePathPrefix(tt.operation, tt.basePath)
			assert.Equal(t, tt.expected, prefix)
		})
	}
}

func TestGeneratePrefixMatch(t *testing.T) {
	tests := []struct {
		name           string
		basePath       string
		endpointToUse  []types.EndpointDetails
		operation      types.Operation
		expectedPrefix string
	}{
		{"Root operation", "/anything", []types.EndpointDetails{types.EndpointDetails{ServiceEntry: false}}, types.Operation{Target: "/"}, "/anything/"},
		{"Wildcard operation", "/", []types.EndpointDetails{types.EndpointDetails{ServiceEntry: false}}, types.Operation{Target: "/*"}, "/\\1"},
		{"Path with param", "/anything/get", []types.EndpointDetails{types.EndpointDetails{ServiceEntry: false}}, types.Operation{Target: "/resource/{id}"}, "/anything/get/resource/\\1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := GeneratePrefixMatch(tt.endpointToUse, tt.operation, tt.basePath)
			fmt.Println(prefix)
			assert.Equal(t, tt.expectedPrefix, prefix)
		})
	}
}

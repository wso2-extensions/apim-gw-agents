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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{"Leading and ending slashes", "/example/path/", "example/path"},
		{"Leading slash", "/example/path", "example/path"},
		{"Ending slash", "example/path/", "example/path"},
		{"No leading or ending slashes", "example/path", "example/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractedPath := ExtractPath(tt.path)
			assert.Equal(t, tt.expected, extractedPath)
		})
	}
}

func TestGeneratePath(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		expected string
	}{
		{"Single path", []string{"petstore"}, "/petstore"},
		{"Multiple paths", []string{"petstore", "pet", "get"}, "/petstore/pet/get"},
		{"Leading and trailing slashes", []string{"/petstore/", "/pet/", "/get/"}, "/petstore/pet/get"},
		{"Empty strings", []string{"", "petstore", "", "pet", "get", ""}, "/petstore/pet/get"},
		{"Only slashes", []string{"/", "//", "///"}, "/"},
		{"Mix of empty and valid paths", []string{"", "api", "", "v1", "users"}, "/api/v1/users"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GeneratePath(tt.paths...)
			if result != tt.expected {
				t.Errorf("GeneratePath(%v) = %q; want %q", tt.paths, result, tt.expected)
			}
		})
	}
}

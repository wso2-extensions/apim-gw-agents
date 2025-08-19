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
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Define testResourcesDir
var testResourcesDir = "../../resources/test-resources/"

// Read HTTPk8Json file
var httpFilePath = filepath.Join(testResourcesDir, "httpk8Json.json")
var httpBytes, _ = os.ReadFile(httpFilePath)
var HTTPk8Json = string(httpBytes)

// Read GQLk8Json file
var gqlFilePath = filepath.Join(testResourcesDir, "gqlk8Json.json")
var gqlBytes, _ = os.ReadFile(gqlFilePath)
var GQLk8Json = string(gqlBytes)

var sampleK8Artifacts = []string{HTTPk8Json, GQLk8Json}

func TestAPIArtifactDecoding(t *testing.T) {
	apiFiles := make(map[string]*zip.File)
	testResourcesDir := "../../resources/test-resources/"
	files, err := os.ReadDir(testResourcesDir)
	if err != nil {
		t.Fatal("Error reading directory:", err)
		return
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".zip" {
			zipPath := filepath.Join(testResourcesDir, file.Name())
			zipFileBytes, err := os.ReadFile(zipPath)
			if err != nil {
				t.Logf("Error reading zip file %s: %v", file.Name(), err)
				continue
			}

			zipReader, err := zip.NewReader(bytes.NewReader(zipFileBytes), int64(len(zipFileBytes)))
			if err != nil {
				t.Logf("Error creating zip reader for file %s: %v", file.Name(), err)
				continue
			}

			for _, file := range zipReader.File {
				apiFiles[file.Name] = file
			}
			if err != nil {
				t.Errorf("Error while reading zip: %v", err)

			}
			deploymentJSON, exists := apiFiles["deployments.json"]
			if !exists {
				t.Errorf("deployments.json not found")

			}
			deploymentJSONBytes, err := ReadContent(deploymentJSON)
			assert.NotNil(t, deploymentJSONBytes)
			assert.NoError(t, err)
			assert.IsType(t, []byte{}, deploymentJSONBytes)

			deploymentDescriptor, err := ProcessDeploymentDescriptor(deploymentJSONBytes)

			assert.NotNil(t, deploymentDescriptor)
			assert.NoError(t, err)
			assert.IsType(t, &DeploymentDescriptor{}, deploymentDescriptor)
			apiDeployments := deploymentDescriptor.Data.Deployments
			if apiDeployments != nil {
				for _, apiDeployment := range *apiDeployments {
					apiZip, exists := apiFiles[apiDeployment.APIFile]
					if exists {
						artifact, decodingError := DecodeAPIArtifact(apiZip)
						if decodingError != nil {
							t.Errorf("Error while decoding the API Project Artifact: %v", decodingError)

						}
						assert.NotNil(t, artifact)
						assert.NoError(t, err)
						assert.IsType(t, &APIArtifact{}, artifact)
					}
				}
			}
		}
	}
}

func TestAPKConfGeneration(t *testing.T) {
	testResourcesDir := "../../resources/test-resources/Base/"
	files, err := os.ReadDir(testResourcesDir)
	if err != nil {
		t.Fatal("Error reading directory:", err)
		return
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".zip" {
			zipPath := filepath.Join(testResourcesDir, file.Name())
			zipFileBytes, err := os.ReadFile(zipPath)
			if err != nil {
				t.Logf("Error reading zip file %s: %v", file.Name(), err)
				continue
			}

			zipReader, err := zip.NewReader(bytes.NewReader(zipFileBytes), int64(len(zipFileBytes)))
			if err != nil {
				t.Logf("Error creating zip reader for file %s: %v", file.Name(), err)
				continue
			}

			for _, zipFile := range zipReader.File {
				apiArtifact, err := DecodeAPIArtifact(zipFile)
				if err != nil {
					t.Logf("Error decoding API artifact from %s: %v", zipFile.Name, err)
					continue
				}
				assert.NotNil(t, apiArtifact)
				assert.NoError(t, err)
				assert.IsType(t, &APIArtifact{}, apiArtifact)

				apkConf, apiUUID, revisionID, configuredRateLimitPoliciesMap, endpointSecurityData, _, _, _, apkErr := GenerateConf(apiArtifact.APIJson, apiArtifact.CertArtifact, apiArtifact.Endpoints, "default", "Default")

				assert.NoError(t, apkErr)
				assert.NotEmpty(t, apkConf)
				assert.NotEqual(t, "null", apiUUID)
				assert.NotEqual(t, uint32(0), revisionID)
				assert.NotNil(t, configuredRateLimitPoliciesMap)
				assert.IsType(t, []EndpointSecurityConfig{}, endpointSecurityData) // Need to be refined maybe
			}
		}
	}
}

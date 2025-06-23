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
	"encoding/json"
	"log"
	"os"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/types"
	"gopkg.in/yaml.v2"
)

// ReadAPKConf reads the APK configuration from the file
func ReadAPKConf(configFile string) *types.APKConf {
	var apkConf types.APKConf

	yamlFile, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &apkConf)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	return &apkConf
}

// APKConfToJSON converts the APK configuration to JSON
func APKConfToJSON(apkConf *types.APKConf) []byte {
	jsonBytes, err := json.MarshalIndent(apkConf, "", " ")
	if err != nil {
		log.Fatalf("Failed to marshal APK configuration to JSON: %v", err)
	}

	return jsonBytes
}

// APKConfToYAML converts the APK configuration to YAML
func APKConfToYAML(apkConf *types.APKConf) []byte {
	yamlBytes, err := yaml.Marshal(apkConf)
	if err != nil {
		log.Fatalf("Failed to marshal APK configuration to YAML: %v", err)
	}

	return yamlBytes
}

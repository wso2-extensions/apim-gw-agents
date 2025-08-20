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

package transformer

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/types"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/loggers"
)

var allowedTimeUnits = map[string]string{"min": "minute", "hours": "hour", "days": "day", "Minute": "minute", "Hour": "hour", "Day": "day"}

// GetUniqueIDForAPI will generate a unique ID for newly created APIs
func GetUniqueIDForAPI(name, version, organization string) string {
	loggers.LoggerUtils.Debugf("Generating unique ID|Name:%s Version:%s Org:%s\n", name, version, organization)

	concatenatedString := strings.Join([]string{organization, name, version}, "-")
	hash := sha1.New()
	hash.Write([]byte(concatenatedString))
	hashedValue := hash.Sum(nil)
	return hex.EncodeToString(hashedValue)
}

// GenerateOperationsMatrix creates a 2D array for operations
func GenerateOperationsMatrix(specialOps int, normalOps int, maxColumns int) [][]types.Operation {
	loggers.LoggerUtils.Debugf("Creating operations matrix|Special:%d Normal:%d MaxCols:%d\n",
		specialOps, normalOps, maxColumns)

	// special operations need their own rows
	totalRows := specialOps + ((normalOps + maxColumns - 1) / maxColumns)
	operationsArray := make([][]types.Operation, totalRows)
	row := 0
	// allocate special operations rows (1 operation per row)
	for i := 0; i < specialOps; i++ {
		operationsArray[row] = make([]types.Operation, 1)
		row++
	}
	// allocate normal operations (maxColumns per row)
	for row < totalRows {
		columnsInRow := min(maxColumns, normalOps)
		operationsArray[row] = make([]types.Operation, columnsInRow)
		normalOps -= columnsInRow
		row++
	}
	return operationsArray
}

// GeneratePluginCRName generates a reference name for a plugin based on the operation, target reference, and plugin name.
func GeneratePluginCRName(operation *types.Operation, targetRef string, pluginName string) string {
	loggers.LoggerUtils.Debugf("Generating plugin CR name|Plugin:%s TargetRef:%s\n", pluginName, targetRef)

	concatenatedString := pluginName
	if operation != nil {
		operationTargetHash := fmt.Sprintf("%x", sha1.Sum([]byte(operation.Target+operation.Verb)))
		concatenatedString = concatenatedString + "-" + operationTargetHash
		return "resource-" + concatenatedString + "-" + targetRef
	}
	serviceTargetHash := fmt.Sprintf("%x", sha1.Sum([]byte(pluginName+targetRef)))
	concatenatedString = concatenatedString + "-" + serviceTargetHash
	return "route-" + concatenatedString + "-" + targetRef
}

// GeneratePolicyCRName generates a reference name for a policy plugin.
func GeneratePolicyCRName(policName string, tenantDomain string, pluginName string, policyType string) string {
	loggers.LoggerUtils.Debugf("Generating policy CR name|Policy:%s Type:%s\n", policName, policyType)

	serviceTargetHash := fmt.Sprintf("%x", sha1.Sum([]byte(policName+tenantDomain+pluginName)))
	return policyType + "-" + serviceTargetHash + "-" + pluginName
}

// GenerateConsumerName generates a reference name for a consumer
func GenerateConsumerName(applicationUUID string, environment string) string {
	loggers.LoggerUtils.Debugf("Generating consumer name|App:%s Env:%s\n", applicationUUID, environment)

	consumerHash := fmt.Sprintf("%x", sha1.Sum([]byte(applicationUUID+environment)))
	return "consumer-" + consumerHash + "-" + environment
}

// GenerateSecretName generates a reference name for a k8s secret
func GenerateSecretName(applicationUUID string, apiUUID string, secretType string) string {
	loggers.LoggerUtils.Debugf("Generating secret name|App:%s API:%s Type:%s\n", applicationUUID, apiUUID, secretType)

	return "secret-" + generateSHA1Hash(applicationUUID+apiUUID) + "-" + secretType
}

// GenerateACLGroupName generates a kong acl API group name
func GenerateACLGroupName(apiName string, environment string) string {
	loggers.LoggerUtils.Debugf("Generating ACL group name|API:%s Env:%s\n", apiName, environment)

	return "api-" + generateSHA1Hash(apiName) + "-" + environment
}

// GenerateJSON converts go struct to json
func GenerateJSON(data KongPluginConfig) []byte {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		loggers.LoggerUtils.Errorf("Failed to generate json. Error: %v", err)
	}
	return jsonBytes
}

// PrepareRateLimit adds the corresponding rate limit name and values to kong plugin config
func PrepareRateLimit(rateLimitConfig *KongPluginConfig, unit string, requestsPerUnit int) {
	loggers.LoggerUtils.Debugf("Preparing rate limit|Unit:%s Requests:%d\n", unit, requestsPerUnit)

	// Add corresponding rate limit configuration
	if unitName, ok := allowedTimeUnits[unit]; ok {
		(*rateLimitConfig)[unitName] = requestsPerUnit
	} else {
		loggers.LoggerUtils.Errorf("Time unit value not found: %v", unit)
	}
}

// generateSHA1Hash returns the SHA1 hash for the given string
func generateSHA1Hash(input string) string {
	h := sha1.New() /* #nosec */
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

// PrepareSecretName converts string for a k8s secret
func PrepareSecretName(name string) string {
	loggers.LoggerUtils.Debugf("Preparing secret name|Input:%s\n", name)

	lowercaseString := strings.ToLower(name)
	result := strings.ReplaceAll(lowercaseString, " ", "-")
	return result
}

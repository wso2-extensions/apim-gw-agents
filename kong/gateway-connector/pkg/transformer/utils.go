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
	"strings"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib/types"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/loggers"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
)

// GetUniqueIDForAPI will generate a unique ID for newly created APIs
func GetUniqueIDForAPI(name, version, organization string) string {
	loggers.LoggerUtils.Debugf("Generating unique ID|Name:%s Version:%s Org:%s\n", name, version, organization)

	concatenatedString := strings.Join([]string{organization, name, version}, constants.DashSeparatorString)
	return generateSHA1Hash(concatenatedString)
}

// GenerateOperationsMatrix creates a 2D array for operations
func GenerateOperationsMatrix(specialOps int, normalOps int, maxColumns int) [][]types.Operation {
	loggers.LoggerUtils.Debugf("Creating operations matrix|Special:%d Normal:%d MaxCols:%d\n",
		specialOps, normalOps, maxColumns)

	if specialOps < 0 || normalOps < 0 || maxColumns <= 0 {
		return nil
	}
	totalRows := specialOps + ((normalOps + maxColumns - 1) / maxColumns)
	operationsArray := make([][]types.Operation, totalRows)

	row := 0
	// Allocate special operations rows (1 operation per row)
	for i := 0; i < specialOps; i++ {
		operationsArray[row] = make([]types.Operation, 1)
		row++
	}

	// Allocate normal operations (maxColumns per row)
	remainingOps := normalOps
	for row < totalRows {
		columnsInRow := min(maxColumns, remainingOps)
		operationsArray[row] = make([]types.Operation, columnsInRow)
		remainingOps -= columnsInRow
		row++
	}
	return operationsArray
}

// GeneratePluginCRName generates a reference name for a plugin based on the operation, target reference, and plugin name.
func GeneratePluginCRName(operation *types.Operation, targetRef string, pluginName string) string {
	loggers.LoggerUtils.Debugf("Generating plugin CR name|Plugin:%s TargetRef:%s\n", pluginName, targetRef)

	if operation != nil {
		operationTargetHash := generateSHA1Hash(operation.Target + operation.Verb)
		concatenatedString := pluginName + constants.DashSeparatorString + operationTargetHash
		return constants.ResourcePrefix + concatenatedString + constants.DashSeparatorString + targetRef
	}

	serviceTargetHash := generateSHA1Hash(pluginName + targetRef)
	concatenatedString := pluginName + constants.DashSeparatorString + serviceTargetHash
	return constants.RoutePrefix + concatenatedString + constants.DashSeparatorString + targetRef
}

// GeneratePolicyCRName generates a reference name for a policy plugin.
func GeneratePolicyCRName(policyName string, tenantDomain string, pluginName string, policyType string) string {
	loggers.LoggerUtils.Debugf("Generating policy CR name|Policy:%s Type:%s\n", policyName, policyType)

	serviceTargetHash := generateSHA1Hash(policyName + tenantDomain + pluginName)
	return policyType + constants.DashSeparatorString + serviceTargetHash + constants.DashSeparatorString + pluginName
}

// GenerateConsumerName generates a reference name for a consumer
func GenerateConsumerName(applicationUUID string, environment string) string {
	loggers.LoggerUtils.Debugf("Generating consumer name|App:%s Env:%s\n", applicationUUID, environment)

	consumerHash := generateSHA1Hash(applicationUUID + environment)
	return constants.ConsumerPrefix + consumerHash + constants.DashSeparatorString + environment
}

// GenerateSecretName generates a reference name for a k8s secret
func GenerateSecretName(applicationUUID string, apiUUID string, secretType string) string {
	loggers.LoggerUtils.Debugf("Generating secret name|App:%s API:%s Type:%s\n", applicationUUID, apiUUID, secretType)

	return constants.SecretPrefix + generateSHA1Hash(applicationUUID+apiUUID) + constants.DashSeparatorString + secretType
}

// GenerateACLGroupName generates a kong acl API group name
func GenerateACLGroupName(apiName string, environment string) string {
	loggers.LoggerUtils.Debugf("Generating ACL group name|API:%s Env:%s\n", apiName, environment)

	return constants.APIPrefix + generateSHA1Hash(apiName) + constants.DashSeparatorString + environment
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
func PrepareRateLimit(rateLimitConfig *KongPluginConfig, unit string, unitTime int, requestCount int) {
	loggers.LoggerUtils.Debugf("Preparing rate limit|Unit:%s Requests:%d\n", unit, requestCount)

	unitLower := strings.ToLower(unit)
	var matchedUnit string
	for k := range constants.TransformerTimeUnits {
		if strings.ToLower(k) == unitLower {
			matchedUnit = k
			break
		}
	}
	requestsPerUnit := requestCount / unitTime

	if matchedUnit != constants.EmptyString {
		unitName := constants.TransformerTimeUnits[matchedUnit]
		(*rateLimitConfig)[unitName] = requestsPerUnit
	} else {
		loggers.LoggerUtils.Errorf("Time unit value not found: %v", unit)
	}
}

// generateSHA1Hash returns the SHA1 hash for the given string
func generateSHA1Hash(input string) string {
	h := sha1.New()
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

// PrepareSecretName converts string for a k8s secret
func PrepareSecretName(name string) string {
	loggers.LoggerUtils.Debugf("Preparing secret name|Input:%s\n", name)

	lowercaseString := strings.ToLower(name)
	result := strings.ReplaceAll(lowercaseString, constants.SpaceString, constants.DashSeparatorString)
	return result
}

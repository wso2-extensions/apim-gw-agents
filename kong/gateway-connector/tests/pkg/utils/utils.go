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
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/tests/pkg/constants"
)

// GetConfigGeneratorURL returns the API configuration generator URL.
func GetConfigGeneratorURL() string {
	return fmt.Sprintf("https://%s:%s/%sapis/generate-configuration",
		constants.DefaultAPIHost, constants.DefaultGWPort, constants.DefaultAPIConfigurator)
}

// GetK8ResourceGeneratorURL returns the Kubernetes resource generator URL.
func GetK8ResourceGeneratorURL() string {
	return fmt.Sprintf("https://%s:%s/%sapis/generate-k8s-resources?organization=carbon.super",
		constants.DefaultAPIHost, constants.DefaultGWPort, constants.DefaultAPIConfigurator)
}

// GetAPIDeployerURL returns the API deployer URL.
func GetAPIDeployerURL() string {
	return fmt.Sprintf("https://%s:%s/%sapis/deploy",
		constants.DefaultAPIHost, constants.DefaultGWPort, constants.DefaultAPIDeployer)
}

// ExtractToken extracts the access token from an HTTP response.
func ExtractToken(resp *http.Response) (string, error) {
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error accessing token URL: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	token := gjson.GetBytes(body, "access_token").String()
	if token == "" {
		return "", fmt.Errorf("missing key [access_token] in response")
	}
	return token, nil
}

// ResolveVariables replaces placeholders like ${variableName} with values from the store.
func ResolveVariables(input string, valueStore map[string]interface{}) string {
	re := regexp.MustCompile(`\${([^}]*)}`)
	return re.ReplaceAllStringFunc(input, func(match string) string {
		varName := strings.Trim(match, "${}")
		if value, ok := valueStore[varName]; ok {
			return fmt.Sprintf("%v", value)
		}
		return match // Keep placeholder if no value found
	})
}

// GetAPIMConfigGeneratorURL returns the APIM configuration generator URL.
func GetAPIMConfigGeneratorURL() string {
	return fmt.Sprintf("https://%s:%s/%sapis/generate-configuration",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIConfigurator)
}

// GetDCREndpointURL returns the DCR endpoint URL.
func GetDCREndpointURL() string {
	return fmt.Sprintf("https://%s:%s/%s",
		constants.DefaultAPIMIDPHost, constants.DefaultAPIMGWPort, constants.DefaultDCREP)
}

// GetAPIMTokenEndpointURL returns the APIM token endpoint URL.
func GetAPIMTokenEndpointURL() string {
	return fmt.Sprintf("https://%s:%s/%s",
		constants.DefaultAPIMIDPHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMTokenEP)
}

// GetAPIMAPIDeployerURL returns the APIM API deployer URL.
func GetAPIMAPIDeployerURL() string {
	return fmt.Sprintf("https://%s:%s/%sapis/deploy",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIDeployer)
}

// GetImportAPIURL returns the API import URL.
func GetImportAPIURL() string {
	return fmt.Sprintf("https://%s:%s/%sapis/import-openapi",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIDeployer)
}

// GetAPIRevisionURL returns the API revision URL for a given API UUID.
func GetAPIRevisionURL(apiUUID string) string {
	return fmt.Sprintf("https://%s:%s/%sapis/%s/revisions",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIDeployer, apiUUID)
}

// GetAPIChangeLifecycleURL returns the API lifecycle change URL for a given API UUID.
func GetAPIChangeLifecycleURL(apiUUID string) string {
	return fmt.Sprintf("https://%s:%s/%sapis/change-lifecycle?action=Publish&apiId=%s",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIDeployer, apiUUID)
}

// GetApplicationCreateURL returns the application creation URL.
func GetApplicationCreateURL() string {
	return fmt.Sprintf("https://%s:%s/%sapplications",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultDevportal)
}

// GetGenerateKeysURL returns the key generation URL for a given application ID.
func GetGenerateKeysURL(applicationID string) string {
	return fmt.Sprintf("https://%s:%s/%sapplications/%s/generate-keys",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultDevportal, applicationID)
}

// GetOauthKeysURL returns the OAuth keys URL for a given application ID.
func GetOauthKeysURL(applicationID string) string {
	return fmt.Sprintf("https://%s:%s/%sapplications/%s/oauth-keys",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultDevportal, applicationID)
}

// GetKeyManagerURL returns the key manager URL.
func GetKeyManagerURL() string {
	return fmt.Sprintf("https://%s:%s/%skey-managers",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultDevportal)
}

// GetSubscriptionURL returns the subscription URL.
func GetSubscriptionURL() string {
	return fmt.Sprintf("https://%s:%s/%ssubscriptions",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultDevportal)
}

// GetAccessTokenGenerationURL returns the access token generation URL.
func GetAccessTokenGenerationURL(applicationID, oauthKeyID string) string {
	return fmt.Sprintf("https://%s:%s/%sapplications/%s/oauth-keys/%s/generate-token",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultDevportal, applicationID, oauthKeyID)
}

// GetAPIRevisionDeploymentURL returns the API revision deployment URL.
func GetAPIRevisionDeploymentURL(apiUUID, revisionID string) string {
	return fmt.Sprintf("https://%s:%s/%sapis/%s/deploy-revision?revisionId=%s",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIDeployer, apiUUID, revisionID)
}

// GetAPIUnDeployerURL returns the API undeployer URL for a given API ID.
func GetAPIUnDeployerURL(apiID string) string {
	if apiID != "" {
		return fmt.Sprintf("https://%s:%s/%sapis/%s",
			constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIDeployer, apiID)
	}

	return fmt.Sprintf("https://%s:%s/%sapis/undeploy",
		constants.DefaultAPIHost, constants.DefaultGWPort, constants.DefaultAPIDeployer)
}

// GetGQLSchemaValidatorURL returns the GraphQL schema validator URL.
func GetGQLSchemaValidatorURL() string {
	return fmt.Sprintf("https://%s/%sapis/validate-graphql-schema",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMAPIDeployer)
}

// GetGQLImportAPIURL returns the GraphQL API import URL.
func GetGQLImportAPIURL() string {
	return fmt.Sprintf("https://%s:%s/%sapis/import-graphql-schema",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIDeployer)
}

// GetAPISearchEndpoint returns the API search endpoint URL.
func GetAPISearchEndpoint(queryValue string) string {
	return fmt.Sprintf("https://%s:%s/%ssearch?query=content:%s",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIDeployer, queryValue)
}

// GetAPINewVersionCreationURL returns the new API version creation URL.
func GetAPINewVersionCreationURL() string {
	return fmt.Sprintf("https://%s:%s/%sapis/copy-api",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIDeployer)
}

// GetAPIThrottlingConfigEndpoint returns the throttling config endpoint URL.
func GetAPIThrottlingConfigEndpoint() string {
	return fmt.Sprintf("https://%s:%s/%sthrottling/policies/advanced",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAdminportal)
}

// GetSubscriptionBlockingURL returns the subscription blocking URL.
func GetSubscriptionBlockingURL(subscriptionID string) string {
	return fmt.Sprintf("https://%s:%s/%ssubscriptions/block-subscription?subscriptionId=%s&blockState=BLOCKED",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIDeployer, subscriptionID)
}

// GetInternalKeyGenerationEndpoint returns the internal key generation endpoint URL.
func GetInternalKeyGenerationEndpoint(apiUUID string) string {
	return fmt.Sprintf("https://%s:%s/%sapis/%s/generate-key",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMGWPort, constants.DefaultAPIMAPIDeployer, apiUUID)
}

// GetClientCertUpdateEndpoint returns the client certificate update endpoint URL.
func GetClientCertUpdateEndpoint(apiUUID string) string {
	return fmt.Sprintf("https://%s/%sapis/%s/client-certificates",
		constants.DefaultAPIMAPIHost, constants.DefaultAPIMAPIDeployer, apiUUID)
}

// ExtractID extracts the "id" field from a JSON payload.
func ExtractID(payload string) (string, error) {
	result := gjson.Get(payload, "id")
	if !result.Exists() {
		return "", fmt.Errorf("missing 'id' in JSON payload")
	}
	return result.String(), nil
}

// ExtractApplicationID extracts the "applicationId" field from a JSON payload.
func ExtractApplicationID(payload string) (string, error) {
	result := gjson.Get(payload, "applicationId")
	if !result.Exists() {
		return "", fmt.Errorf("missing 'applicationId' in JSON payload")
	}
	return result.String(), nil
}

// ExtractKeyManagerID extracts the first "id" from the "list" array in a JSON payload.
func ExtractKeyManagerID(payload string) (string, error) {
	result := gjson.Get(payload, "list.0.id")
	if !result.Exists() {
		return "", fmt.Errorf("missing 'list[0].id' in JSON payload")
	}
	return result.String(), nil
}

// ExtractOAuthMappingID finds the "keyMappingId" matching the given ID in the "list" array.
func ExtractOAuthMappingID(payload, keyMappingID string) (string, error) {
	list := gjson.Get(payload, "list")
	if !list.Exists() {
		return "", fmt.Errorf("missing 'list' in JSON payload")
	}

	for _, item := range list.Array() {
		currentID := item.Get("keyMappingId").String()
		if currentID == keyMappingID {
			return currentID, nil
		}
	}
	return "", nil // Return empty string if not found, as per Java null
}

// ExtractKeys extracts a specified key from a JSON payload.
func ExtractKeys(payload, key string) (string, error) {
	result := gjson.Get(payload, key)
	if !result.Exists() {
		return "", fmt.Errorf("missing '%s' in JSON payload", key)
	}
	return result.String(), nil
}

// ExtractBasicToken extracts client ID and secret from a response and returns a base64-encoded token.
func ExtractBasicToken(resp *http.Response) (string, error) {
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error accessing token URL: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	clientID := gjson.GetBytes(body, "clientId").String()
	clientSecret := gjson.GetBytes(body, "clientSecret").String()
	if clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("missing 'clientId' or 'clientSecret' in response")
	}

	token := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	return token, nil
}

// ExtractValidStatus extracts the "isValid" field from a JSON payload.
func ExtractValidStatus(payload string) (bool, error) {
	result := gjson.Get(payload, "isValid")
	if !result.Exists() {
		return false, fmt.Errorf("missing 'isValid' in JSON payload")
	}
	return result.Bool(), nil
}

// ExtractApplicationUUID extracts the "applicationId" from the first item in the "list" array if count is 1.
func ExtractApplicationUUID(payload string) (string, error) {
	count := gjson.Get(payload, "count").Int()
	if count != 1 {
		return "", nil // Return empty string if count != 1, as per Java null
	}

	result := gjson.Get(payload, "list.0.applicationId")
	if !result.Exists() {
		return "", fmt.Errorf("missing 'list[0].applicationId' in JSON payload")
	}
	return result.String(), nil
}

// // ExtractAPIUUID extracts the "id" from the first item in the "list" array if count is 1.
// func ExtractAPIUUID(payload string) (string, error) {
// 	count := gjson.Get(payload, "count").Int()
// 	if count != 1 {
// 		return "", nil // Return empty string if count != 1, as per Java null
// 	}

// 	result := gjson.Get(payload, "list.0.id")
// 	if !result.Exists() {
// 		return "", fmt.Errorf("missing 'list[0].id' in JSON payload")
// 	}
// 	return result.String(), nil
// }

// ExtractAPIUUID extracts the "id" from the first item in the "list" array if count is 1.
func ExtractAPIUUID(payload string) (string, error) {
	count := gjson.Get(payload, "count").Int()
	if count < 1 {
		return "", fmt.Errorf("no items found in the list")
	}

	// If count is 1, return the first item's ID
	if count == 1 {
		result := gjson.Get(payload, "list.0.id")
		if !result.Exists() {
			return "", fmt.Errorf("missing 'list[0].id' in JSON payload")
		}
		return result.String(), nil
	}

	// If count > 1, filter the list by "type": "API"
	filtered := gjson.Get(payload, "list").Array()
	var apiItems []gjson.Result

	for _, item := range filtered {
		if item.Get("type").String() == "API" {
			apiItems = append(apiItems, item)
		}
	}

	// If no API items found or more than one exists, return an error
	if len(apiItems) == 0 {
		return "", fmt.Errorf("no items with type 'API' found in the list")
	} else if len(apiItems) > 1 {
		return "", fmt.Errorf("multiple items with type 'API' found in the list")
	}

	// Return the id of the first (and only) filtered API item
	apiID := apiItems[0].Get("id")
	if !apiID.Exists() {
		return "", fmt.Errorf("missing 'id' in the filtered API item")
	}

	return apiID.String(), nil
}

// AddFileToMultipart function to add a file to the multipart form data
func AddFileToMultipart(writer *multipart.Writer, fieldname, filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("error opening file %s: %v", filepath, err)
	}
	defer file.Close()

	part, err := writer.CreateFormFile(fieldname, filepath)
	if err != nil {
		return fmt.Errorf("error creating form file for %s: %v", fieldname, err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("error copying file content for %s: %v", fieldname, err)
	}

	return nil
}

// ResponseEntityBodyToString reads the response body and converts it to a string.
func ResponseEntityBodyToString(resp *http.Response) (string, error) {
	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return "", err
	}

	// Close the response body after reading
	defer resp.Body.Close()

	// Return the response body as a string
	return string(body), nil
}

// ContainsInteger checks if a slice contains a given integer value
func ContainsInteger(slice []int, item int) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// OpenFile opens a file given its file path and returns the *os.File
func OpenFile(filePath string) *os.File {
	// Open the file in read-only mode
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Open file error: %v", err)
		return nil
	}

	return file
}

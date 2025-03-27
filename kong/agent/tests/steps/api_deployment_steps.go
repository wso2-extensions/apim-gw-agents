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

package steps

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"time"

	"github.com/cucumber/godog"
	"github.com/wso2-extensions/apim-gw-agents/kong/agent/tests/pkg/constants"
	"github.com/wso2-extensions/apim-gw-agents/kong/agent/tests/pkg/utils"
)

// APIDeploymentSteps registers all step definitions for API deployment scenarios.
func APIDeploymentSteps(s *godog.ScenarioContext, ctx *utils.SharedContext) {
	s.Step(`^I use the Payload file "([^"]*)"$`, func(file string) error { return iUseThePayloadFile(ctx, file) })
	s.Step(`^I use the OAS URL "([^"]*)"$`, func(url string) error { return iUseTheOASURL(ctx, url) })
	s.Step(`^make the import API Creation request using OAS "([^"]*)"$`, func(method string) error {
		return makeImportAPICreationRequest(ctx, method)
	})
	s.Step(`^make the API Revision Deployment request$`, func() error { return makeAPIRevisionDeploymentRequest(ctx) })

	s.Step(`^make the Change Lifecycle request$`, func() error { return makeChangeLifecycleRequest(ctx) })

	s.Step(`^make the Application Creation request with the name "([^"]*)"$`, func(name string) error {
		return makeApplicationCreationRequest(ctx, name)
	})
	s.Step(`^I have a KeyManager$`, func() error { return iHaveAKeyManager(ctx) })
	s.Step(`^make the Generate Keys request$`, func() error { return makeGenerateKeysRequest(ctx) })
	s.Step(`^make the Subscription request$`, func() error { return makeSubscriptionRequest(ctx) })
	s.Step(`^I get "([^"]*)" oauth keys for application$`, func(env string) error {
		return getOAuthKeysForApplication(ctx, env)
	})
	s.Step(`^make the Access Token Generation request for "([^"]*)"$`, func(env string) error {
		return makeAccessTokenGenerationRequest(ctx, env)
	})

	s.Step(`^I delete the application "([^"]*)" from devportal$`, func(name string) error {
		return makeApplicationDeletionRequest(ctx, name)
	})
	s.Step(`^I find the apiUUID of the API created with the name "([^"]*)"$`, func(name string) error {
		return findAPIUUIDUsingName(ctx, name)
	})
	s.Step(`^I undeploy the selected API$`, func() error { return iUndeployTheAPI(ctx) })

	s.Step(`^I use the api crs files "([^"]*)" in resources$`, func(path string) error { return iUseTheApiCRsFiles(ctx, path) })
	s.Step(`^I apply the K8Artifacts belongs to that API$`, func() error { return iApplyTheK8ArtifactsBelongsToThatAPI(ctx) })
	s.Step(`^I undeploy the API in api crs path$`, func() error { return iUndeployTheAPIInApiCrsPath(ctx) })
	s.Step(`^I set new API throttling policy allowing "([^"]*)" requests per every "([^"]*)" minute$`, func(requestCount string, unitTime string) error {
		return addNewCustomThrottlingPolicy(ctx, requestCount, unitTime)
	})
	s.Step(`^I delete the created API throttling policy$`, func() error {
		return deleteThrottlingPolicy(ctx)
	})
	s.Step(`^the definition file "([^"]*)"$`, func(definitionFileName string) error {
		return iHaveTheDefinitionFile(ctx, definitionFileName)
	})

}

// iHaveTheAPIPayloadFile loads the API payload file by its name.
func iUseThePayloadFile(ctx *utils.SharedContext, payloadFileName string) error {
	// Get the file path using the payload file name
	payloadFilePath := fmt.Sprintf("./tests/%s", payloadFileName)
	_, err := os.Stat(payloadFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", payloadFilePath)
		}
		return err
	}

	// Store the file path in the context
	ctx.AddStoreValue("payloadFile", payloadFilePath)

	return nil
}

// iUseTheOASURL sets the OpenAPI Specification (OAS) URL for the test.
func iUseTheOASURL(ctx *utils.SharedContext, url string) error {
	ctx.AddStoreValue("OASURL", url)
	return nil
}

// makeImportAPICreationRequest handles API import request based on definition type (URL or File)
func makeImportAPICreationRequest(ctx *utils.SharedContext, definitionType string) error {
	httpclient := ctx.GetHTTPClient()
	headers := map[string]string{
		constants.RequestHeaders.Authorization: "Bearer " + ctx.GetPublisherAccessToken(),
		constants.RequestHeaders.Host:          constants.DefaultAPIMAPIHost,
	}

	// Retrieve necessary values from context store
	payloadFilePath := ctx.GetStoreValue("payloadFile").(string)
	if payloadFilePath == "" {
		return fmt.Errorf("payloadFile not found in context store")
	}

	var fileParts []utils.MultipartFilePart
	if definitionType == "URL" {
		oasURL := ctx.GetStoreValue("OASURL").(string)
		if oasURL == "" {
			return fmt.Errorf("OASURL not found in context store")
		}
		fmt.Println("OAS URL:", oasURL)
		fileParts = []utils.MultipartFilePart{
			{Name: "url", File: nil, Text: oasURL}, // URL as text field
			{Name: "additionalProperties", File: utils.OpenFile(payloadFilePath)},
		}
	} else if definitionType == "File" {
		definitionFile := ctx.GetStoreValue("definitionFile").(string)
		if definitionFile == "" {
			return fmt.Errorf("definitionFile not found in context store")
		}
		fmt.Println("OAS File:", definitionFile)
		fileParts = []utils.MultipartFilePart{
			{Name: "file", File: utils.OpenFile(definitionFile)},
			{Name: "additionalProperties", File: utils.OpenFile(payloadFilePath)},
		}
	} else {
		return fmt.Errorf("invalid definition type: %s", definitionType)
	}

	// Send HTTP request
	resp, err := httpclient.DoPostWithMultipartFiles(utils.GetImportAPIURL(), fileParts, headers)

	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		return err
	}
	ctx.SetResponseBody(body)

	apiUUID, err := utils.ExtractID(body)
	if err != nil {
		return fmt.Errorf("error extracting API UUID from response body: %v", err)
	}

	ctx.SetApiUUID(apiUUID)
	time.Sleep(3 * time.Second)
	return nil
}

// makeAPIRevisionDeploymentRequest makes a request to deploy an API revision.
func makeAPIRevisionDeploymentRequest(ctx *utils.SharedContext) error {
	httpclient := ctx.GetHTTPClient()
	apiUUID := ctx.GetApiUUID()
	fmt.Printf("API UUID: %s", apiUUID)

	// Prepare payload for revision creation
	payload := "{\"description\":\"Initial Revision\"}"
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetPublisherAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	// Make the API revision request
	apiRevisionURL := utils.GetAPIRevisionURL(apiUUID)
	response, err := httpclient.DoPost(apiRevisionURL, headers, payload, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		return fmt.Errorf("failed to create API revision: %v", err)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}

	// Extract and store revision UUID from the response
	revisionUUID, err := utils.ExtractID(string(body))
	if err != nil {
		return fmt.Errorf("error extracting revision UUID from body: %v", err)
	}
	ctx.SetRevisionUUID(revisionUUID)

	// Sleep for 3 seconds to simulate the delay
	time.Sleep(3 * time.Second)

	payload2 := "[{\"name\": \"Default\", \"vhost\": \"default.gw.wso2.com\", \"displayOnDevportal\": true}]"

	// Make the API revision deployment request
	apiRevisionDeploymentURL := utils.GetAPIRevisionDeploymentURL(apiUUID, revisionUUID)
	response2, err := httpclient.DoPost(apiRevisionDeploymentURL, headers, payload2, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		return fmt.Errorf("failed to deploy API revision: %v", err)
	}

	fmt.Printf("Response: %+v", response2)
	ctx.SetResponse(response2)

	// Sleep for 3 seconds to simulate the delay
	time.Sleep(3 * time.Second)

	return nil
}

// makeChangeLifecycleRequest sends a request to change the lifecycle of an API.
func makeChangeLifecycleRequest(ctx *utils.SharedContext) error {
	httpclient := ctx.GetHTTPClient()
	apiUUID := ctx.GetApiUUID()
	payload := ""

	// Prepare headers
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetPublisherAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	// Make the POST request
	url := utils.GetAPIChangeLifecycleURL(apiUUID)
	resp, err := httpclient.DoPost(url, headers, payload, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		return err
	}

	ctx.SetResponse(resp)
	time.Sleep(3 * time.Second)

	return nil
}

// makeApplicationCreationRequest creates a new application in the system
func makeApplicationCreationRequest(ctx *utils.SharedContext, applicationName string) error {
	httpclient := ctx.GetHTTPClient()
	fmt.Printf("Creating an application\n")
	payload := fmt.Sprintf("{\"name\":\"%s\",\"throttlingPolicy\":\"10PerMin\",\"description\":\"test app\",\"tokenType\":\"JWT\",\"groups\":null,\"attributes\":{}}", applicationName)

	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetDevportalAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	response, err := httpclient.DoPost(utils.GetApplicationCreateURL(), headers, payload, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		return err
	}

	ctx.SetResponse(response)
	responseBody, err := utils.ResponseEntityBodyToString(response)
	if err != nil {
		return err
	}
	ctx.SetResponseBody(responseBody)
	fmt.Printf("Response: %s\n", responseBody)

	applicationUUID, err := utils.ExtractApplicationID(responseBody)
	if err != nil {
		return err
	}
	ctx.SetApplicationUUID(applicationUUID)

	time.Sleep(3 * time.Second)

	return nil
}

// iHaveAKeyManager retrieves information about a key manager.
func iHaveAKeyManager(ctx *utils.SharedContext) error {
	httpclient := ctx.GetHTTPClient()
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetDevportalAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	// Make HTTP GET request
	resp, err := httpclient.DoGet(utils.GetKeyManagerURL(), headers)
	if err != nil {
		return err
	}

	// Set response and extract the key manager UUID
	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		return err
	}
	ctx.SetResponseBody(body)

	keyManagerUUID, err := utils.ExtractKeyManagerID(body)
	if err != nil {
		return err
	}
	ctx.SetKeyManagerUUID(keyManagerUUID)

	// Wait for the response processing
	time.Sleep(3 * time.Second)

	return nil
}

// makeGenerateKeysRequest generates keys for the given application and key manager.
func makeGenerateKeysRequest(ctx *utils.SharedContext) error {
	httpclient := ctx.GetHTTPClient()
	applicationUUID := ctx.GetApplicationUUID()
	keyManagerUUID := ctx.GetKeyManagerUUID()
	fmt.Printf("Key Manager UUID: %s\n", keyManagerUUID)
	fmt.Printf("Application UUID: %s\n", applicationUUID)

	// Prepare payloads for production and sandbox keys
	payloadForProdKeys := fmt.Sprintf(`{
		"keyType":"PRODUCTION",
		"grantTypesToBeSupported":["password","client_credentials"],
		"callbackUrl":"",
		"additionalProperties":{
			"application_access_token_expiry_time":"N/A",
			"user_access_token_expiry_time":"N/A",
			"refresh_token_expiry_time":"N/A",
			"id_token_expiry_time":"N/A",
			"pkceMandatory":"false",
			"pkceSupportPlain":"false",
			"bypassClientCredentials":"false"
		},
		"keyManager":"%s",
		"validityTime":3600,
		"scopes":["default"]
	}`, keyManagerUUID)

	payloadForSandboxKeys := fmt.Sprintf(`{
		"keyType":"SANDBOX",
		"grantTypesToBeSupported":["password","client_credentials"],
		"callbackUrl":"",
		"additionalProperties":{
			"application_access_token_expiry_time":"N/A",
			"user_access_token_expiry_time":"N/A",
			"refresh_token_expiry_time":"N/A",
			"id_token_expiry_time":"N/A",
			"pkceMandatory":"false",
			"pkceSupportPlain":"false",
			"bypassClientCredentials":"false"
		},
		"keyManager":"%s",
		"validityTime":3600,
		"scopes":["default"]
	}`, keyManagerUUID)

	// Prepare headers
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetDevportalAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	// Send request for production keys
	resp, err := httpclient.DoPost(utils.GetGenerateKeysURL(applicationUUID), headers, payloadForProdKeys, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		return err
	}

	// Process response for production keys
	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		return err
	}
	ctx.SetResponseBody(body)

	prodConsumerSecret, err := utils.ExtractKeys(body, "consumerSecret")
	if err != nil {
		return err
	}
	ctx.SetConsumerSecret(prodConsumerSecret, "production")

	prodConsumerKey, err := utils.ExtractKeys(body, "consumerKey")
	if err != nil {
		return err
	}
	ctx.SetConsumerKey(prodConsumerKey, "production")

	prodKeyMappingId, err := utils.ExtractKeys(body, "keyMappingId")
	if err != nil {
		return err
	}
	ctx.SetKeyMappingID(prodKeyMappingId, "production")

	// Wait for response processing
	time.Sleep(3 * time.Second)

	// Send request for sandbox keys
	resp2, err := httpclient.DoPost(utils.GetGenerateKeysURL(applicationUUID), headers, payloadForSandboxKeys, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		return err
	}

	// Process response for sandbox keys
	ctx.SetResponse(resp2)
	body2, err := utils.ResponseEntityBodyToString(resp2)
	if err != nil {
		return err
	}
	ctx.SetResponseBody(body2)

	sandConsumerSecret, err := utils.ExtractKeys(body2, "consumerSecret")
	if err != nil {
		return err
	}
	ctx.SetConsumerSecret(sandConsumerSecret, "sandbox")

	sandConsumerKey, err := utils.ExtractKeys(body2, "consumerKey")
	if err != nil {
		return err
	}
	ctx.SetConsumerKey(sandConsumerKey, "sandbox")

	sandKeyMappingId, err := utils.ExtractKeys(body2, "keyMappingId")
	if err != nil {
		return err
	}
	ctx.SetKeyMappingID(sandKeyMappingId, "sandbox")

	// Wait for response processing
	time.Sleep(3 * time.Second)

	return nil
}

// makeSubscriptionRequest makes a subscription request for the application and API.
func makeSubscriptionRequest(ctx *utils.SharedContext) error {
	httpclient := ctx.GetHTTPClient()
	applicationUUID := ctx.GetApplicationUUID()
	apiUUID := ctx.GetApiUUID()
	fmt.Printf("API UUID: %s\n", apiUUID)
	fmt.Printf("Application UUID: %s\n", applicationUUID)

	// Prepare the payload for the subscription request
	payload := fmt.Sprintf(`{
		"apiId":"%s",
		"applicationId":"%s",
		"throttlingPolicy":"Unlimited"
	}`, apiUUID, applicationUUID)

	// Prepare headers
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetDevportalAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	// Send the subscription request
	resp, err := httpclient.DoPost(utils.GetSubscriptionURL(), headers, payload, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		return err
	}

	// Process the response
	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		return err
	}
	ctx.SetResponseBody(body)

	subscriptionId, err := utils.ExtractKeys(body, "subscriptionId")
	if err != nil {
		return err
	}
	ctx.SetSubscriptionID(subscriptionId)

	// Log the extracted subscription ID
	fmt.Printf("Extracted subscription ID: %s\n", ctx.GetSubscriptionID())

	// Wait for response processing
	time.Sleep(3 * time.Second)

	return nil
}

// getOAuthKeysForApplication retrieves OAuth keys for an application based on the provided type ("production" or "sandbox").
func getOAuthKeysForApplication(ctx *utils.SharedContext, keyType string) error {
	httpclient := ctx.GetHTTPClient()
	applicationUUID := ctx.GetApplicationUUID()

	// Set the key type based on the input ("production" or "sandbox")
	if keyType != "production" {
		keyType = "sandbox"
	}

	// Prepare headers
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetDevportalAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost
	headers[constants.RequestHeaders.ContentType] = constants.ContentTypes.ApplicationJSON

	// Make GET request
	resp, err := httpclient.DoGet(utils.GetOauthKeysURL(applicationUUID), headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Store response and extract OAuth key UUID
	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		return err
	}
	ctx.SetResponseBody(body)
	oauthKeyUUID, err := utils.ExtractOAuthMappingID(body, ctx.GetKeyMappingID(keyType))
	if err != nil {
		return err
	}
	ctx.SetOauthKeyUUID(oauthKeyUUID)

	// Wait for the response to settle
	time.Sleep(3 * time.Second)

	return nil
}

// makeAccessTokenGenerationRequest generates an access token for the application based on the provided key type ("production" or "sandbox").
func makeAccessTokenGenerationRequest(ctx *utils.SharedContext, keyType string) error {
	httpclient := ctx.GetHTTPClient()
	applicationUUID := ctx.GetApplicationUUID()
	oauthKeyUUID := ctx.GetOauthKeyUUID()

	// Determine the key type (either "production" or "sandbox")
	if keyType != "production" {
		keyType = "sandbox"
	}

	// Fetch consumer secret for the specified key type
	consumerSecret := ctx.GetConsumerSecret(keyType)

	// Log the values
	fmt.Printf("Generating keys for: %s", keyType)
	fmt.Printf("Application UUID: %s", applicationUUID)
	fmt.Printf("Oauth Key UUID: %s", oauthKeyUUID)

	// Prepare the payload for access token generation
	payload := fmt.Sprintf("{\"consumerSecret\":\"%s\",\"validityPeriod\":3600,\"revokeToken\":null,"+
		"\"scopes\":[\"write:pets\",\"read:pets\",\"query:hero\"],\"additionalProperties\":{\"id_token_expiry_time\":3600,"+
		"\"application_access_token_expiry_time\":3600,\"user_access_token_expiry_time\":3600,\"bypassClientCredentials\":false,"+
		"\"pkceMandatory\":false,\"pkceSupportPlain\":false,\"refresh_token_expiry_time\":86400}}", consumerSecret)

	// Set headers
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetDevportalAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	// Make the POST request for access token generation
	resp, err := httpclient.DoPost(utils.GetAccessTokenGenerationURL(applicationUUID, oauthKeyUUID), headers, payload, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Handle the response
	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		return err
	}
	ctx.SetResponseBody(body)

	// Extract access token and store it
	accessToken, err := utils.ExtractKeys(body, "accessToken")
	if err != nil {
		return err
	}
	ctx.SetApiAccessToken(accessToken)
	ctx.AddStoreValue("accessToken", accessToken)

	// Log the access token
	fmt.Printf("Access Token: %s", ctx.GetApiAccessToken())

	// Wait for the response to settle
	time.Sleep(3 * time.Second)

	return nil
}

// makeApplicationDeletionRequest searches for an application by name and deletes it.
func makeApplicationDeletionRequest(ctx *utils.SharedContext, applicationName string) error {
	fmt.Println("Fetching the applications")

	httpclient := ctx.GetHTTPClient()
	headers := map[string]string{
		constants.RequestHeaders.Authorization: "Bearer " + ctx.GetDevportalAccessToken(),
		constants.RequestHeaders.Host:          constants.DefaultAPIMAPIHost,
	}

	// Construct the query parameters
	queryParams := url.Values{}
	queryParams.Add("query", applicationName)

	// Build the search URL
	appSearchURL := fmt.Sprintf("%s?%s", utils.GetApplicationCreateURL(), queryParams.Encode())

	// Perform GET request to search for the application
	appSearchResponse, err := httpclient.DoGet(appSearchURL, headers)
	if err != nil {
		return err
	}

	ctx.SetResponse(appSearchResponse)
	searchResp, err := utils.ResponseEntityBodyToString(appSearchResponse)
	if err != nil {
		return nil
	}
	ctx.SetResponseBody(searchResp)

	// Extract application UUID
	applicationUUID, err := utils.ExtractApplicationUUID(ctx.GetResponseBody())
	if applicationUUID == "" || err != nil {
		return fmt.Errorf("failed to extract application UUID")
	}

	// Perform DELETE request to delete the application
	deleteURL := fmt.Sprintf("%s/%s", utils.GetApplicationCreateURL(), applicationUUID)
	deleteResponse, err := httpclient.DoDelete(deleteURL, headers)
	if err != nil {
		return err
	}

	ctx.SetResponse(deleteResponse)
	delResp, err := utils.ResponseEntityBodyToString(deleteResponse)
	if err != nil {
		return nil
	}
	ctx.SetResponseBody(delResp)

	// Wait for 3 seconds
	time.Sleep(3 * time.Second)

	return nil
}

// findAPIUUIDUsingName searches for an API by name and retrieves its UUID.
func findAPIUUIDUsingName(ctx *utils.SharedContext, apiName string) error {
	fmt.Println("Fetching the APIs")
	httpclient := ctx.GetHTTPClient()

	headers := map[string]string{
		constants.RequestHeaders.Authorization: "Bearer " + ctx.GetPublisherAccessToken(),
		constants.RequestHeaders.Host:          constants.DefaultAPIMAPIHost,
	}

	// Perform GET request to search for the API
	apiSearchURL := utils.GetAPISearchEndpoint(apiName)
	apiSearchResponse, err := httpclient.DoGet(apiSearchURL, headers)
	if err != nil {
		return err
	}

	ctx.SetResponse(apiSearchResponse)
	searchResp, err := utils.ResponseEntityBodyToString(apiSearchResponse)
	if err != nil {
		return err
	}
	ctx.SetResponseBody(searchResp)

	// Extract API UUID
	apiUUID, err := utils.ExtractAPIUUID(ctx.GetResponseBody())
	if apiUUID == "" || err != nil {
		return fmt.Errorf("failed to extract API UUID")
	}

	ctx.SetApiUUID(apiUUID)

	// Wait for 3 seconds
	time.Sleep(3 * time.Second)

	return nil
}

// iUndeployTheAPI deletes the API using its UUID.
func iUndeployTheAPI(ctx *utils.SharedContext) error {
	fmt.Printf("API UUID to be deleted: %s\n", ctx.GetApiUUID())
	httpclient := ctx.GetHTTPClient()

	headers := map[string]string{
		constants.RequestHeaders.Authorization: "Bearer " + ctx.GetPublisherAccessToken(),
		constants.RequestHeaders.Host:          constants.DefaultAPIMAPIHost,
	}

	// Perform DELETE request to undeploy the API
	apiUndeployURL := utils.GetAPIUnDeployerURL(ctx.GetApiUUID())
	response, err := httpclient.DoDelete(apiUndeployURL, headers)
	if err != nil {
		return err
	}

	ctx.SetResponse(response)
	resp, err := utils.ResponseEntityBodyToString(response)
	if err != nil {
		return err
	}
	ctx.SetResponseBody(resp)

	// Wait for 3 seconds
	time.Sleep(3 * time.Second)

	return nil
}

// iUseTheApiCRsFiles sets the API CRs containing folder path.
func iUseTheApiCRsFiles(ctx *utils.SharedContext, crPath string) error {
	// Get the file path using the payload file name
	payloadFilePath := fmt.Sprintf("./tests/%s", crPath)
	_, err := os.Stat(payloadFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", payloadFilePath)
		}
		return err
	}

	// Store the file path in the context
	ctx.AddStoreValue("apiCRPath", payloadFilePath)

	return nil
}

// iApplyTheK8ArtifactsBelongsToThatAPI apply the k8s CRs to kubernetes cluster.
func iApplyTheK8ArtifactsBelongsToThatAPI(ctx *utils.SharedContext) error {
	apiCRPath := ctx.GetStoreValue("apiCRPath").(string)
	if apiCRPath == "" {
		return fmt.Errorf("API CR path not found in context store")
	}

	// Execute `kubectl apply -f .` in the given path
	cmd := exec.Command("kubectl", "apply", "-f", ".")
	cmd.Dir = apiCRPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to apply Kubernetes artifacts: %v\nOutput: %s", err, string(output))
	}

	fmt.Printf("Successfully applied Kubernetes artifacts:\n%s\n", string(output))
	return nil
}

// iUndeployTheAPIInApiCrsPath removes the k8s CRs from kubernetes cluster.
func iUndeployTheAPIInApiCrsPath(ctx *utils.SharedContext) error {
	apiCRPath := ctx.GetStoreValue("apiCRPath").(string)
	if apiCRPath == "" {
		return fmt.Errorf("API CR path not found in context store")
	}

	// Execute `kubectl apply -f .` in the given path
	cmd := exec.Command("kubectl", "delete", "-f", ".")
	cmd.Dir = apiCRPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove Kubernetes artifacts: %v\nOutput: %s", err, string(output))
	}

	fmt.Printf("Successfully removed Kubernetes artifacts:\n%s\n", string(output))
	return nil
}

// addNewCustomThrottlingPolicy sets a new API throttling policy allowing a specified number of requests per minute.
func addNewCustomThrottlingPolicy(ctx *utils.SharedContext, requestCount, unitTime string) error {
	httpclient := ctx.GetHTTPClient()
	payload := fmt.Sprintf(`{
        "policyName": "TestRatelimit",
        "description": "Test description",
        "conditionalGroups": [],
        "defaultLimit": {
            "requestCount": {
                "timeUnit": "min",
                "unitTime": %s,
                "requestCount": %s
            },
            "type": "REQUESTCOUNTLIMIT",
            "bandwidth": null
        }
    }`, unitTime, requestCount)

	headers := map[string]string{
		constants.RequestHeaders.Authorization: "Bearer " + ctx.GetAdminAccessToken(),
		constants.RequestHeaders.Host:          constants.DefaultAPIMAPIHost,
	}

	resp, err := httpclient.DoPost(
		utils.GetAPIThrottlingConfigEndpoint(),
		headers,
		payload,
		constants.ContentTypes.ApplicationJSON,
	)
	if err != nil {
		return fmt.Errorf("error setting API throttling policy: %v", err)
	}

	ctx.SetResponse(resp)
	responseBody, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}

	ctx.SetResponseBody(responseBody)
	policyID, err := utils.ExtractKeys(responseBody, "policyId")
	if err != nil {
		return fmt.Errorf("error extracting policy ID: %v", err)
	}
	ctx.SetPolicyID(policyID)

	time.Sleep(3 * time.Second)
	return nil
}

// deleteThrottlingPolicy deletes the created API throttling policy using the stored policy ID.
func deleteThrottlingPolicy(ctx *utils.SharedContext) error {
	httpclient := ctx.GetHTTPClient()
	headers := map[string]string{
		constants.RequestHeaders.Authorization: "Bearer " + ctx.GetAdminAccessToken(),
		constants.RequestHeaders.Host:          constants.DefaultAPIMAPIHost,
	}

	policyID := ctx.GetPolicyID()
	fmt.Printf("PolicyID to be deleted: %s\n", policyID)

	uri := utils.GetAPIThrottlingConfigEndpoint() + "/" + policyID
	httpResponse, err := httpclient.DoDelete(uri, headers)
	if err != nil {
		return err
	}

	ctx.SetResponse(httpResponse)
	responseBody, err := utils.ResponseEntityBodyToString(httpResponse)

	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}

	ctx.SetResponseBody(responseBody)
	time.Sleep(3 * time.Second)
	return nil
}

// iHaveTheDefinitionFile loads the definition file from the given file name.
func iHaveTheDefinitionFile(ctx *utils.SharedContext, definitionFile string) error {
	definitionFilePath := fmt.Sprintf("./tests/%s", definitionFile)
	ctx.AddStoreValue("definitionFile", definitionFilePath)
	return nil
}

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

package steps

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"time"

	"github.com/cucumber/godog"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/tests/pkg/constants"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/tests/pkg/utils"
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
	fmt.Println("=== Starting makeImportAPICreationRequest ===")
	fmt.Printf("Definition Type: %s\n", definitionType)

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
	fmt.Printf("Payload File Path: %s\n", payloadFilePath)

	var fileParts []utils.MultipartFilePart
	if definitionType == "URL" {
		oasURL := ctx.GetStoreValue("OASURL").(string)
		if oasURL == "" {
			return fmt.Errorf("OASURL not found in context store")
		}
		fmt.Printf("OAS URL: %s\n", oasURL)
		fileParts = []utils.MultipartFilePart{
			{Name: "url", File: nil, Text: oasURL}, // URL as text field
			{Name: "additionalProperties", File: utils.OpenFile(payloadFilePath)},
		}
	} else if definitionType == "File" {
		definitionFile := ctx.GetStoreValue("definitionFile").(string)
		if definitionFile == "" {
			return fmt.Errorf("definitionFile not found in context store")
		}
		fmt.Printf("OAS File: %s\n", definitionFile)
		fileParts = []utils.MultipartFilePart{
			{Name: "file", File: utils.OpenFile(definitionFile)},
			{Name: "additionalProperties", File: utils.OpenFile(payloadFilePath)},
		}
	} else {
		return fmt.Errorf("invalid definition type: %s", definitionType)
	}

	// Print request details
	url := utils.GetImportAPIURL()
	fmt.Printf("Request URL: %s\n", url)
	fmt.Printf("Request Headers: %+v\n", headers)
	fmt.Printf("Access Token: %s\n", ctx.GetPublisherAccessToken())
	fmt.Printf("File Parts Count: %d\n", len(fileParts))
	for i, part := range fileParts {
		fmt.Printf("File Part %d - Name: %s, Text: %s\n", i, part.Name, part.Text)
	}

	// Send HTTP request
	resp, err := httpclient.DoPostWithMultipartFiles(url, fileParts, headers)

	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	// Print response details
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Response Headers: %+v\n", resp.Header)

	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	fmt.Printf("Response Body: %s\n", body)
	ctx.SetResponseBody(body)

	apiUUID, err := utils.ExtractID(body)
	if err != nil {
		fmt.Printf("Error extracting API UUID: %v\n", err)
		return fmt.Errorf("error extracting API UUID from response body: %v", err)
	}

	fmt.Printf("Extracted API UUID: %s\n", apiUUID)
	ctx.SetApiUUID(apiUUID)

	fmt.Println("=== makeImportAPICreationRequest completed successfully ===")
	time.Sleep(3 * time.Second)
	return nil
}

// makeAPIRevisionDeploymentRequest makes a request to deploy an API revision.
func makeAPIRevisionDeploymentRequest(ctx *utils.SharedContext) error {
	fmt.Println("=== Starting makeAPIRevisionDeploymentRequest ===")

	httpclient := ctx.GetHTTPClient()
	apiUUID := ctx.GetApiUUID()
	fmt.Printf("API UUID: %s\n", apiUUID)

	// Prepare payload for revision creation
	payload := "{\"description\":\"Initial Revision\"}"
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetPublisherAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	// Print request details for revision creation
	apiRevisionURL := utils.GetAPIRevisionURL(apiUUID)
	fmt.Printf("Revision Creation Request URL: %s\n", apiRevisionURL)
	fmt.Printf("Revision Creation Request Headers: %+v\n", headers)
	fmt.Printf("Revision Creation Request Payload: %s\n", payload)
	fmt.Printf("Access Token: %s\n", ctx.GetPublisherAccessToken())

	// Make the API revision request
	response, err := httpclient.DoPost(apiRevisionURL, headers, payload, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		fmt.Printf("Error creating API revision: %v\n", err)
		return fmt.Errorf("failed to create API revision: %v", err)
	}

	// Print revision creation response details
	fmt.Printf("Revision Creation Response Status: %s\n", response.Status)
	fmt.Printf("Revision Creation Response Status Code: %d\n", response.StatusCode)
	fmt.Printf("Revision Creation Response Headers: %+v\n", response.Header)

	body, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Error reading revision creation response body: %v\n", err)
		return fmt.Errorf("error reading response body: %v", err)
	}

	fmt.Printf("Revision Creation Response Body: %s\n", string(body))

	// Extract and store revision UUID from the response
	revisionUUID, err := utils.ExtractID(string(body))
	if err != nil {
		fmt.Printf("Error extracting revision UUID: %v\n", err)
		return fmt.Errorf("error extracting revision UUID from body: %v", err)
	}

	fmt.Printf("Extracted Revision UUID: %s\n", revisionUUID)
	ctx.SetRevisionUUID(revisionUUID)

	// Sleep for 3 seconds to simulate the delay
	time.Sleep(3 * time.Second)

	payload2 := fmt.Sprintf(`[{"name": "%s", "vhost": "%s", "displayOnDevportal": true}]`, constants.GatewayName, constants.GatewayVHost)

	// Print request details for revision deployment
	apiRevisionDeploymentURL := utils.GetAPIRevisionDeploymentURL(apiUUID, revisionUUID)
	fmt.Printf("Revision Deployment Request URL: %s\n", apiRevisionDeploymentURL)
	fmt.Printf("Revision Deployment Request Headers: %+v\n", headers)
	fmt.Printf("Revision Deployment Request Payload: %s\n", payload2)

	// Make the API revision deployment request
	response2, err := httpclient.DoPost(apiRevisionDeploymentURL, headers, payload2, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		fmt.Printf("Error deploying API revision: %v\n", err)
		return fmt.Errorf("failed to deploy API revision: %v", err)
	}

	// Print revision deployment response details
	fmt.Printf("Revision Deployment Response Status: %s\n", response2.Status)
	fmt.Printf("Revision Deployment Response Status Code: %d\n", response2.StatusCode)
	fmt.Printf("Revision Deployment Response Headers: %+v\n", response2.Header)

	// Read and log response body
	body2, err := utils.ResponseEntityBodyToString(response2)
	if err == nil {
		fmt.Printf("Revision Deployment Response Body: %s\n", body2)
	}

	ctx.SetResponse(response2)

	fmt.Println("=== makeAPIRevisionDeploymentRequest completed successfully ===")

	// Sleep for 3 seconds to simulate the delay
	time.Sleep(3 * time.Second)

	return nil
}

// makeChangeLifecycleRequest sends a request to change the lifecycle of an API.
func makeChangeLifecycleRequest(ctx *utils.SharedContext) error {
	fmt.Println("=== Starting makeChangeLifecycleRequest ===")

	httpclient := ctx.GetHTTPClient()
	apiUUID := ctx.GetApiUUID()
	fmt.Printf("API UUID: %s\n", apiUUID)

	payload := ""

	// Prepare headers
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetPublisherAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	// Print request details
	url := utils.GetAPIChangeLifecycleURL(apiUUID)
	fmt.Printf("Request URL: %s\n", url)
	fmt.Printf("Request Headers: %+v\n", headers)
	fmt.Printf("Request Payload: %s\n", payload)
	fmt.Printf("Access Token: %s\n", ctx.GetPublisherAccessToken())

	// Make the POST request
	resp, err := httpclient.DoPost(url, headers, payload, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		fmt.Printf("Error making lifecycle change request: %v\n", err)
		return err
	}

	// Print response details
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Response Headers: %+v\n", resp.Header)

	// Read and log response body
	body, err := utils.ResponseEntityBodyToString(resp)
	if err == nil {
		fmt.Printf("Response Body: %s\n", body)
	}

	ctx.SetResponse(resp)

	fmt.Println("=== makeChangeLifecycleRequest completed successfully ===")
	time.Sleep(3 * time.Second)

	return nil
}

// makeApplicationCreationRequest creates a new application in the system
func makeApplicationCreationRequest(ctx *utils.SharedContext, applicationName string) error {
	fmt.Println("=== Starting makeApplicationCreationRequest ===")

	httpclient := ctx.GetHTTPClient()
	fmt.Printf("Creating an application with name: %s\n", applicationName)
	payload := fmt.Sprintf("{\"name\":\"%s\",\"throttlingPolicy\":\"10PerMin\",\"description\":\"test app\",\"tokenType\":\"JWT\",\"groups\":null,\"attributes\":{}}", applicationName)

	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetDevportalAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	// Print request details
	url := utils.GetApplicationCreateURL()
	fmt.Printf("Request URL: %s\n", url)
	fmt.Printf("Request Headers: %+v\n", headers)
	fmt.Printf("Request Payload: %s\n", payload)
	fmt.Printf("Access Token: %s\n", ctx.GetDevportalAccessToken())

	response, err := httpclient.DoPost(url, headers, payload, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		fmt.Printf("Error making POST request: %v\n", err)
		return err
	}

	// Print response details
	fmt.Printf("Response Status: %s\n", response.Status)
	fmt.Printf("Response Status Code: %d\n", response.StatusCode)
	fmt.Printf("Response Headers: %+v\n", response.Header)

	ctx.SetResponse(response)
	responseBody, err := utils.ResponseEntityBodyToString(response)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}
	ctx.SetResponseBody(responseBody)
	fmt.Printf("Response Body: %s\n", responseBody)

	applicationUUID, err := utils.ExtractApplicationID(responseBody)
	if err != nil {
		fmt.Printf("Error extracting application UUID: %v\n", err)
		return err
	}

	fmt.Printf("Extracted Application UUID: %s\n", applicationUUID)
	ctx.SetApplicationUUID(applicationUUID)

	fmt.Println("=== makeApplicationCreationRequest completed successfully ===")
	time.Sleep(3 * time.Second)

	return nil
}

// iHaveAKeyManager retrieves information about a key manager.
func iHaveAKeyManager(ctx *utils.SharedContext) error {
	fmt.Println("=== Starting iHaveAKeyManager ===")

	httpclient := ctx.GetHTTPClient()
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetDevportalAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	// Print request details
	url := utils.GetKeyManagerURL()
	fmt.Printf("Request URL: %s\n", url)
	fmt.Printf("Request Headers: %+v\n", headers)
	fmt.Printf("Access Token: %s\n", ctx.GetDevportalAccessToken())

	// Make HTTP GET request
	resp, err := httpclient.DoGet(url, headers)
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return err
	}

	// Print response details
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Response Headers: %+v\n", resp.Header)

	// Set response and extract the key manager UUID
	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	fmt.Printf("Response Body: %s\n", body)
	ctx.SetResponseBody(body)

	keyManagerUUID, err := utils.ExtractKeyManagerID(body)
	if err != nil {
		fmt.Printf("Error extracting key manager UUID: %v\n", err)
		return err
	}

	fmt.Printf("Extracted Key Manager UUID: %s\n", keyManagerUUID)
	ctx.SetKeyManagerUUID(keyManagerUUID)

	fmt.Println("=== iHaveAKeyManager completed successfully ===")

	// Wait for the response processing
	time.Sleep(3 * time.Second)

	return nil
}

// makeGenerateKeysRequest generates keys for the given application and key manager.
func makeGenerateKeysRequest(ctx *utils.SharedContext) error {
	fmt.Println("=== Starting makeGenerateKeysRequest ===")

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

	// Print request details for production keys
	prodURL := utils.GetGenerateKeysURL(applicationUUID)
	fmt.Printf("Production Keys Request URL: %s\n", prodURL)
	fmt.Printf("Production Keys Request Headers: %+v\n", headers)
	fmt.Printf("Production Keys Request Payload: %s\n", payloadForProdKeys)
	fmt.Printf("Access Token: %s\n", ctx.GetDevportalAccessToken())

	// Send request for production keys
	resp, err := httpclient.DoPost(prodURL, headers, payloadForProdKeys, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		fmt.Printf("Error generating production keys: %v\n", err)
		return err
	}

	// Print production keys response details
	fmt.Printf("Production Keys Response Status: %s\n", resp.Status)
	fmt.Printf("Production Keys Response Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Production Keys Response Headers: %+v\n", resp.Header)

	// Process response for production keys
	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		fmt.Printf("Error reading production keys response body: %v\n", err)
		return err
	}

	fmt.Printf("Production Keys Response Body: %s\n", body)
	ctx.SetResponseBody(body)

	prodConsumerSecret, err := utils.ExtractKeys(body, "consumerSecret")
	if err != nil {
		fmt.Printf("Error extracting production consumer secret: %v\n", err)
		return err
	}
	fmt.Printf("Production Consumer Secret: %s\n", prodConsumerSecret)
	ctx.SetConsumerSecret(prodConsumerSecret, "production")

	prodConsumerKey, err := utils.ExtractKeys(body, "consumerKey")
	if err != nil {
		fmt.Printf("Error extracting production consumer key: %v\n", err)
		return err
	}
	fmt.Printf("Production Consumer Key: %s\n", prodConsumerKey)
	ctx.SetConsumerKey(prodConsumerKey, "production")

	prodKeyMappingId, err := utils.ExtractKeys(body, "keyMappingId")
	if err != nil {
		fmt.Printf("Error extracting production key mapping ID: %v\n", err)
		return err
	}
	fmt.Printf("Production Key Mapping ID: %s\n", prodKeyMappingId)
	ctx.SetKeyMappingID(prodKeyMappingId, "production")

	// Wait for response processing
	time.Sleep(3 * time.Second)

	// Print request details for sandbox keys
	fmt.Printf("Sandbox Keys Request URL: %s\n", prodURL) // Same URL
	fmt.Printf("Sandbox Keys Request Headers: %+v\n", headers)
	fmt.Printf("Sandbox Keys Request Payload: %s\n", payloadForSandboxKeys)

	// Send request for sandbox keys
	resp2, err := httpclient.DoPost(prodURL, headers, payloadForSandboxKeys, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		fmt.Printf("Error generating sandbox keys: %v\n", err)
		return err
	}

	// Print sandbox keys response details
	fmt.Printf("Sandbox Keys Response Status: %s\n", resp2.Status)
	fmt.Printf("Sandbox Keys Response Status Code: %d\n", resp2.StatusCode)
	fmt.Printf("Sandbox Keys Response Headers: %+v\n", resp2.Header)

	// Process response for sandbox keys
	ctx.SetResponse(resp2)
	body2, err := utils.ResponseEntityBodyToString(resp2)
	if err != nil {
		fmt.Printf("Error reading sandbox keys response body: %v\n", err)
		return err
	}

	fmt.Printf("Sandbox Keys Response Body: %s\n", body2)
	ctx.SetResponseBody(body2)

	sandConsumerSecret, err := utils.ExtractKeys(body2, "consumerSecret")
	if err != nil {
		fmt.Printf("Error extracting sandbox consumer secret: %v\n", err)
		return err
	}
	fmt.Printf("Sandbox Consumer Secret: %s\n", sandConsumerSecret)
	ctx.SetConsumerSecret(sandConsumerSecret, "sandbox")

	sandConsumerKey, err := utils.ExtractKeys(body2, "consumerKey")
	if err != nil {
		fmt.Printf("Error extracting sandbox consumer key: %v\n", err)
		return err
	}
	fmt.Printf("Sandbox Consumer Key: %s\n", sandConsumerKey)
	ctx.SetConsumerKey(sandConsumerKey, "sandbox")

	sandKeyMappingId, err := utils.ExtractKeys(body2, "keyMappingId")
	if err != nil {
		fmt.Printf("Error extracting sandbox key mapping ID: %v\n", err)
		return err
	}
	fmt.Printf("Sandbox Key Mapping ID: %s\n", sandKeyMappingId)
	ctx.SetKeyMappingID(sandKeyMappingId, "sandbox")

	fmt.Println("=== makeGenerateKeysRequest completed successfully ===")

	// Wait for response processing
	time.Sleep(3 * time.Second)

	return nil
}

// makeSubscriptionRequest makes a subscription request for the application and API.
func makeSubscriptionRequest(ctx *utils.SharedContext) error {
	fmt.Println("=== Starting makeSubscriptionRequest ===")

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

	// Print request details
	url := utils.GetSubscriptionURL()
	fmt.Printf("Request URL: %s\n", url)
	fmt.Printf("Request Headers: %+v\n", headers)
	fmt.Printf("Request Payload: %s\n", payload)
	fmt.Printf("Access Token: %s\n", ctx.GetDevportalAccessToken())

	// Send the subscription request
	resp, err := httpclient.DoPost(url, headers, payload, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		fmt.Printf("Error making subscription request: %v\n", err)
		return err
	}

	// Print response details
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Response Headers: %+v\n", resp.Header)

	// Process the response
	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	fmt.Printf("Response Body: %s\n", body)
	ctx.SetResponseBody(body)

	subscriptionId, err := utils.ExtractKeys(body, "subscriptionId")
	if err != nil {
		fmt.Printf("Error extracting subscription ID: %v\n", err)
		return err
	}
	ctx.SetSubscriptionID(subscriptionId)

	// Log the extracted subscription ID
	fmt.Printf("Extracted subscription ID: %s\n", ctx.GetSubscriptionID())

	fmt.Println("=== makeSubscriptionRequest completed successfully ===")

	// Wait for response processing
	time.Sleep(3 * time.Second)

	return nil
}

// getOAuthKeysForApplication retrieves OAuth keys for an application based on the provided type ("production" or "sandbox").
func getOAuthKeysForApplication(ctx *utils.SharedContext, keyType string) error {
	fmt.Println("=== Starting getOAuthKeysForApplication ===")

	httpclient := ctx.GetHTTPClient()
	applicationUUID := ctx.GetApplicationUUID()

	// Set the key type based on the input ("production" or "sandbox")
	if keyType != "production" {
		keyType = "sandbox"
	}

	fmt.Printf("Key Type: %s\n", keyType)
	fmt.Printf("Application UUID: %s\n", applicationUUID)

	// Prepare headers
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetDevportalAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost
	headers[constants.RequestHeaders.ContentType] = constants.ContentTypes.ApplicationJSON

	// Print request details
	url := utils.GetOauthKeysURL(applicationUUID)
	fmt.Printf("Request URL: %s\n", url)
	fmt.Printf("Request Headers: %+v\n", headers)
	fmt.Printf("Access Token: %s\n", ctx.GetDevportalAccessToken())

	// Make GET request
	resp, err := httpclient.DoGet(url, headers)
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Print response details
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Response Headers: %+v\n", resp.Header)

	// Store response and extract OAuth key UUID
	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	fmt.Printf("Response Body: %s\n", body)
	ctx.SetResponseBody(body)

	keyMappingID := ctx.GetKeyMappingID(keyType)
	fmt.Printf("Key Mapping ID for %s: %s\n", keyType, keyMappingID)

	oauthKeyUUID, err := utils.ExtractOAuthMappingID(body, keyMappingID)
	if err != nil {
		fmt.Printf("Error extracting OAuth key UUID: %v\n", err)
		return err
	}

	fmt.Printf("Extracted OAuth Key UUID: %s\n", oauthKeyUUID)
	ctx.SetOauthKeyUUID(oauthKeyUUID)

	fmt.Println("=== getOAuthKeysForApplication completed successfully ===")

	// Wait for the response to settle
	time.Sleep(3 * time.Second)

	return nil
}

// makeAccessTokenGenerationRequest generates an access token for the application based on the provided key type ("production" or "sandbox").
func makeAccessTokenGenerationRequest(ctx *utils.SharedContext, keyType string) error {
	fmt.Println("=== Starting makeAccessTokenGenerationRequest ===")

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
	fmt.Printf("Generating keys for: %s\n", keyType)
	fmt.Printf("Application UUID: %s\n", applicationUUID)
	fmt.Printf("OAuth Key UUID: %s\n", oauthKeyUUID)
	fmt.Printf("Consumer Secret: %s\n", consumerSecret)

	// Prepare the payload for access token generation
	payload := fmt.Sprintf("{\"consumerSecret\":\"%s\",\"validityPeriod\":3600,\"revokeToken\":null,"+
		"\"scopes\":[\"write:pets\",\"read:pets\",\"query:hero\"],\"additionalProperties\":{\"id_token_expiry_time\":3600,"+
		"\"application_access_token_expiry_time\":3600,\"user_access_token_expiry_time\":3600,\"bypassClientCredentials\":false,"+
		"\"pkceMandatory\":false,\"pkceSupportPlain\":false,\"refresh_token_expiry_time\":86400}}", consumerSecret)

	// Set headers
	headers := map[string]string{}
	headers[constants.RequestHeaders.Authorization] = "Bearer " + ctx.GetDevportalAccessToken()
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMAPIHost

	// Print request details
	url := utils.GetAccessTokenGenerationURL(applicationUUID, oauthKeyUUID)
	fmt.Printf("Request URL: %s\n", url)
	fmt.Printf("Request Headers: %+v\n", headers)
	fmt.Printf("Request Payload: %s\n", payload)
	fmt.Printf("Access Token: %s\n", ctx.GetDevportalAccessToken())

	// Make the POST request for access token generation
	resp, err := httpclient.DoPost(url, headers, payload, constants.ContentTypes.ApplicationJSON)
	if err != nil {
		fmt.Printf("Error generating access token: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Print response details
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Response Headers: %+v\n", resp.Header)

	// Handle the response
	ctx.SetResponse(resp)
	body, err := utils.ResponseEntityBodyToString(resp)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	fmt.Printf("Response Body: %s\n", body)
	ctx.SetResponseBody(body)

	// Extract access token and store it
	accessToken, err := utils.ExtractKeys(body, "accessToken")
	if err != nil {
		fmt.Printf("Error extracting access token: %v\n", err)
		return err
	}
	ctx.SetApiAccessToken(accessToken)
	ctx.AddStoreValue("accessToken", accessToken)

	// Log the access token
	fmt.Printf("Generated Access Token: %s\n", ctx.GetApiAccessToken())

	fmt.Println("=== makeAccessTokenGenerationRequest completed successfully ===")

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

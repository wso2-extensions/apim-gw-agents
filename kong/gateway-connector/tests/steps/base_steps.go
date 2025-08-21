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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/tests/pkg/constants"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/tests/pkg/utils"
)

func BaseSteps(s *godog.ScenarioContext, ctx *utils.SharedContext) {
	s.Step(`^The system is ready$`, func() error { return theSystemIsReady(ctx) })
	s.Step(`^I have a DCR application$`, func() error { return iHaveADCRApplication(ctx) })
	s.Step(`^I have a valid Publisher access token$`, func() error { return iHaveValidPublisherAccessToken(ctx) })
	s.Step(`^the response status code should be (\d+)$`, func(code int) error { return theResponseStatusCodeShouldBe(ctx, code) })
	s.Step(`^the response body should contain "([^"]*)"$`, func(content string) error {
		return theResponseBodyShouldContain(ctx, content)
	})
	s.Step(`^the response body should contain key "([^"]*)" and value "([^"]*)"$`, func(key string, value string) error {
		return theResponseBodyShouldContainKeyValue(ctx, key, value)
	})
	s.Step(`^I wait for (\d+) seconds$`, func(seconds int) error { return waitForSeconds(seconds) })
	s.Step(`^I have a valid Devportal access token$`, func() error { return iHaveValidDevportalAccessToken(ctx) })
	s.Step(`^I set headers$`, func(table *godog.Table) error { return setHeaders(ctx, table) })
	s.Step(`^I send "([^"]*)" request to "([^"]*)" with body "([^"]*)"$`, func(method, url, body string) error {
		return sendHttpRequest(ctx, method, url, body)
	})
	s.Step(`^I eventually receive (\d+) response code, not accepting$`, func(code int, table *godog.Table) error {
		return iHaveEventualSuccess(ctx, code, table)
	})
	s.Step(`^I have a valid Adminportal access token$`, func() error { return iHaveValidAdminPortalAccessToken(ctx) })
	s.Step(`^I wait for next minute strictly$`, func() error {
		return waitForNextMinuteStrictly()
	})

}

// theSystemIsReady checks if the system is ready to proceed with tests.
func theSystemIsReady(ctx *utils.SharedContext) error {
	return nil
}

// iHaveADCRApplication sets up a Dynamic Client Registration (DCR) application.
func iHaveADCRApplication(ctx *utils.SharedContext) error {
	httpclient := ctx.GetHTTPClient()
	url := utils.GetDCREndpointURL()

	// Prepare headers
	credentials := base64.StdEncoding.EncodeToString([]byte("admin:admin"))
	headers := map[string]string{
		"Host":          constants.DefaultAPIMIDPHost,
		"Authorization": "Basic " + credentials,
	}

	// Prepare request body
	dcrRequest := map[string]string{
		"callbackUrl": "www.google.lk",
		"clientName":  "rest_api_publisher",
		"owner":       "admin",
		"grantType":   "client_credentials password refresh_token",
		"saasApp":     "true",
	}
	requestBody, err := json.Marshal(dcrRequest)
	if err != nil {
		return err
	}

	// Make HTTP request
	resp, err := httpclient.DoPost(url, headers, string(requestBody), constants.ContentTypes.ApplicationJSON)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Extract and store the basic auth token
	basicAuthToken, err := utils.ExtractBasicToken(resp)
	if err != nil {
		return err
	}
	ctx.SetBasicAuthToken(basicAuthToken)
	ctx.AddStoreValue("publisherBasicAuthToken", basicAuthToken)

	return nil
}

// iHaveValidPublisherAccessToken gets a valid publisher access token.
func iHaveValidPublisherAccessToken(ctx *utils.SharedContext) error {
	httpclient := ctx.GetHTTPClient()

	// Prepare headers
	basicAuthHeader := "Basic " + ctx.GetBasicAuthToken()
	headers := map[string]string{}
	headers[constants.RequestHeaders.Host] = constants.DefaultAPIMIDPHost
	headers[constants.RequestHeaders.Authorization] = basicAuthHeader

	// Prepare the form data for the POST request
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("username", "admin")
	data.Set("password", "admin")
	data.Set("scope", "apim:api_view apim:api_create apim:api_publish apim:api_delete apim:api_manage apim:api_import_export apim:subscription_manage apim:client_certificates_add apim:client_certificates_update")

	// Send the POST request to get the token
	resp, err := httpclient.DoPost(
		utils.GetAPIMTokenEndpointURL(),
		headers,
		data.Encode(),
		constants.ContentTypes.ApplicationXWWWFormURLEncoded)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Extract and store the publisher access token from the response
	publisherAccessToken, err := utils.ExtractToken(resp)
	if err != nil {
		return err
	}

	ctx.SetPublisherAccessToken(publisherAccessToken)
	ctx.AddStoreValue("publisherAccessToken", publisherAccessToken)

	return nil
}

// theResponseStatusCodeShouldBe checks if the response status code matches the expected status code.
func theResponseStatusCodeShouldBe(ctx *utils.SharedContext, expectedStatusCode int) error {
	// Get the actual status code from the response
	resp := ctx.GetResponse()
	if resp == nil {
		return fmt.Errorf("response is nil: no HTTP response available to check status code")
	}

	actualStatusCode := resp.StatusCode

	// Close the response body
	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("error closing response body: %v", err)
	}

	// Assert that the actual status code matches the expected one
	if actualStatusCode != expectedStatusCode {
		return fmt.Errorf("expected status code %d but got %d", expectedStatusCode, actualStatusCode)
	}
	return nil
}

// theResponseBodyShouldContain checks if the response body contains the expected text.
func theResponseBodyShouldContain(ctx *utils.SharedContext, expectedText string) error {
	// Get the response body from the context
	responseBody := ctx.GetResponseBody()

	// Check if the response body contains the expected text
	if !strings.Contains(responseBody, expectedText) {
		return fmt.Errorf("expected response body to contain: %s, but got: %s", expectedText, responseBody)
	}

	return nil
}

// theResponseBodyShouldContainKeyValue checks if the response body contains the expected json key pair value.
func theResponseBodyShouldContainKeyValue(ctx *utils.SharedContext, key string, value string) error {
	// Get the response body from the context
	responseBody := ctx.GetResponseBody()
	expectedText := fmt.Sprintf("\"%v\":\"%v\"", key, value)

	// Check if the response body contains the expected text
	if !strings.Contains(responseBody, expectedText) {
		return fmt.Errorf("expected response body to contain: %s, but got: %s", expectedText, responseBody)
	}

	return nil
}

// waitForMinute waits for the given number of minutes.
func waitForMinute(minute int) error {
	time.Sleep(time.Duration(minute) * time.Minute)
	return nil
}

// waitForSeconds waits for the given number of seconds.
func waitForSeconds(seconds int) error {
	time.Sleep(time.Duration(seconds) * time.Second)
	return nil
}

// iHaveValidDevportalAccessToken retrieves a valid Devportal access token.
func iHaveValidDevportalAccessToken(ctx *utils.SharedContext) error {
	httpclient := ctx.GetHTTPClient()

	// Log basic auth header
	fmt.Printf("Basic Auth Header: %v", ctx.GetBasicAuthToken())

	// Prepare headers
	basicAuthHeader := "Basic " + ctx.GetBasicAuthToken()
	headers := map[string]string{
		constants.RequestHeaders.Host:          constants.DefaultAPIMIDPHost,
		constants.RequestHeaders.Authorization: basicAuthHeader,
	}

	// Prepare request body
	payload := "grant_type=password&username=admin&password=admin&scope=apim:app_manage apim:sub_manage apim:subscribe"

	// Make POST request to get the access token
	resp, err := httpclient.DoPost(utils.GetAPIMTokenEndpointURL(), headers, payload, constants.ContentTypes.ApplicationXWWWFormURLEncoded)
	if err != nil {
		return err
	}

	// Extract and store the token
	devportalAccessToken, err := utils.ExtractToken(resp)
	if err != nil {
		return err
	}
	ctx.SetDevportalAccessToken(devportalAccessToken)
	ctx.AddStoreValue("devportalAccessToken", devportalAccessToken)

	// Log the devportal access token
	fmt.Printf("Devportal Access Token: %v", devportalAccessToken)

	return nil
}

// setHeaders sets headers from a godog.Table.
func setHeaders(ctx *utils.SharedContext, table *godog.Table) error {
	// Iterate over each row in the table (ignoring the header row)
	for _, row := range table.Rows[0:] {
		// Extract the key and value from the columns in the row
		key := row.Cells[0].Value
		value := row.Cells[1].Value

		// Resolve variables in both key and value
		key = utils.ResolveVariables(key, ctx.GetValueStore())
		value = utils.ResolveVariables(value, ctx.GetValueStore())
		// Add the resolved key-value pair to the context headers
		ctx.AddHeader(key, value)
	}

	return nil
}

// sendHttpRequest sends an HTTP request based on the given method, URL, and body.
func sendHttpRequest(ctx *utils.SharedContext, httpMethod, url, body string) error {
	httpclient := ctx.GetHTTPClient()

	// Resolve any variables in the body
	body = utils.ResolveVariables(body, ctx.GetValueStore())

	// Close previous response if it's not already closed
	if ctx.GetResponse() != nil {
		ctx.GetResponse().Body.Close()
	}

	// Determine the HTTP method and send the corresponding request
	switch strings.ToLower(httpMethod) {
	case strings.ToLower(constants.CurlOption.HttpMethodGet):
		// GET request
		response, err := httpclient.DoGet(url, ctx.GetHeaders())
		if err != nil {
			return err
		}
		ctx.SetResponse(response)
		bodyResponse, err := utils.ResponseEntityBodyToString(response)
		if err != nil {
			return err
		}
		ctx.SetResponseBody(bodyResponse)

	case strings.ToLower(constants.CurlOption.HttpMethodPost):
		// POST request
		response, err := httpclient.DoPost(url, ctx.GetHeaders(), body, constants.ContentTypes.ApplicationJSON)
		if err != nil {
			return err
		}
		ctx.SetResponse(response)
		bodyResponse, err := utils.ResponseEntityBodyToString(response)
		if err != nil {
			return err
		}
		ctx.SetResponseBody(bodyResponse)

	case strings.ToLower(constants.CurlOption.HttpMethodPut):
		// PUT request
		response, err := httpclient.DoPut(url, ctx.GetHeaders(), body, constants.ContentTypes.ApplicationJSON)
		if err != nil {
			return err
		}
		ctx.SetResponse(response)
		bodyResponse, err := utils.ResponseEntityBodyToString(response)
		if err != nil {
			return err
		}
		ctx.SetResponseBody(bodyResponse)

	case strings.ToLower(constants.CurlOption.HttpMethodDelete):
		// DELETE request
		response, err := httpclient.DoDelete(url, ctx.GetHeaders())
		if err != nil {
			return err
		}
		ctx.SetResponse(response)
		bodyResponse, err := utils.ResponseEntityBodyToString(response)
		if err != nil {
			return err
		}
		ctx.SetResponseBody(bodyResponse)

	case strings.ToLower(constants.CurlOption.HttpMethodOptions):
		// OPTIONS request
		response, err := httpclient.DoOptions(url, ctx.GetHeaders(), "", "")
		if err != nil {
			return err
		}
		ctx.SetResponse(response)
	}

	return nil
}

// eventualSuccess checks if the response eventually returns the expected status code
func eventualSuccess(ctx *utils.SharedContext, statusCode int, nonAcceptableCodes []int) error {
	httpclient := ctx.GetHTTPClient()
	currentStatusCode := ctx.GetResponse().StatusCode

	// Check if the current response matches the expected status code
	if currentStatusCode == statusCode {
		// Assertion is true, no action required
		return nil
	}

	// If the status code is different, attempt to get a consistent response
	response, err := httpclient.ExecuteLastRequestForEventualConsistentResponse(statusCode, nonAcceptableCodes)

	if err != nil {
		return fmt.Errorf("failed to get consistent response: %v", err)
	}

	// Set the response in the shared context
	ctx.SetResponse(response)

	// Check if the status code is now correct
	if response.StatusCode != statusCode {
		return fmt.Errorf("expected status code %d but got %d", statusCode, response.StatusCode)
	}

	return nil
}

// Eventual success step for Cucumber
func iHaveEventualSuccess(ctx *utils.SharedContext, statusCode int, dataTable *godog.Table) error {
	// Convert the DataTable into a slice of integers (nonAcceptableCodes)
	nonAcceptableCodes := make([]int, 0)
	for _, row := range dataTable.Rows {
		if len(row.Cells) > 0 {
			code, err := strconv.Atoi(row.Cells[0].Value)
			if err != nil {
				return fmt.Errorf("failed to convert string to int: %v", err)
			}
			nonAcceptableCodes = append(nonAcceptableCodes, code)
		}
	}

	// Call the eventualSuccess function
	return eventualSuccess(ctx, statusCode, nonAcceptableCodes)
}

// iHaveValidAdminPortalAccessToken retrieves a valid Admin Portal access token and stores it in the shared context.
func iHaveValidAdminPortalAccessToken(ctx *utils.SharedContext) error {
	fmt.Println("Basic Auth Header:", ctx.GetBasicAuthToken())
	httpclient := ctx.GetHTTPClient()

	headers := map[string]string{
		constants.RequestHeaders.Host:          constants.DefaultAPIMIDPHost,
		constants.RequestHeaders.Authorization: "Basic " + ctx.GetBasicAuthToken(),
	}

	requestBody := "grant_type=password&username=admin&password=admin&scope=apim:app_manage apim:admin_tier_view apim:admin_tier_manage"

	resp, err := httpclient.DoPost(
		utils.GetAPIMTokenEndpointURL(),
		headers,
		requestBody,
		constants.ContentTypes.ApplicationXWWWFormURLEncoded,
	)
	if err != nil {
		return fmt.Errorf("error fetching Admin Portal access token: %v", err)
	}

	token, err := utils.ExtractToken(resp)
	if err != nil {
		return fmt.Errorf("error extracting Admin Portal token: %v", err)
	}

	ctx.SetAdminAccessToken(token)
	ctx.AddStoreValue("adminportalAccessToken", token)
	fmt.Println("Admin Access Token:", token)

	return nil
}

// waitForNextMinuteStrictly waits until the next minute strictly before proceeding.
func waitForNextMinuteStrictly() error {
	now := time.Now()
	nextMinute := now.Truncate(time.Minute).Add(time.Minute)
	secondsToWait := time.Until(nextMinute).Seconds()

	time.Sleep(time.Duration(secondsToWait+5) * time.Second)
	fmt.Printf("Current time: %s\n", time.Now().Format(time.RFC3339))
	return nil
}

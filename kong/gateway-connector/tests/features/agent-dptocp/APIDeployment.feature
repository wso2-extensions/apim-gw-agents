Feature: API Deploying in DP to CP Flow

  Scenario: Deploy a REST API to Kong DP and invoke it using APIM Devportal
    Given The system is ready
    When I use the api crs files "artifacts/api_crs" in resources
    Then I apply the K8Artifacts belongs to that API
    Then I wait for 30 seconds
    And I have a DCR application
    And I have a valid Publisher access token
    Then I find the apiUUID of the API created with the name "my-new-api"
    Then the response status code should be 200
    And the response body should contain "my-new-api"
    And make the Change Lifecycle request
    Then the response status code should be 200
    And I have a valid Devportal access token
    And make the Application Creation request with the name "SampleApp"
    Then the response status code should be 201
    And the response body should contain "SampleApp"
    And I have a KeyManager
    And make the Generate Keys request
    Then the response status code should be 200
    And the response body should contain "consumerKey"
    And the response body should contain "consumerSecret"
    And make the Subscription request
    Then the response status code should be 201
    And the response body should contain "Unlimited"
    And I get "production" oauth keys for application
    Then the response status code should be 200
    And make the Access Token Generation request for "production"
    Then the response status code should be 200
    And the response body should contain "accessToken"
    Then I set headers
      | Authorization | bearer ${accessToken} |
    And I send "GET" request to "https://kong.wso2.com:8443/httpbin/1.0.0/get" with body ""
    And I eventually receive 200 response code, not accepting
      | 429 |
    And the response body should contain "https://kong.wso2.com/get"
    And I send "POST" request to "https://kong.wso2.com:8443/httpbin/1.0.0/post" with body ""
    And I eventually receive 200 response code, not accepting
      | 429 |
    And the response body should contain "https://kong.wso2.com/post"

  Scenario Outline: Undeploy API
    Given The system is ready
    When I undeploy the API in api crs path
    And I have a DCR application
    And I have a valid Devportal access token
    Then I delete the application "SampleApp" from devportal
    Then the response status code should be 200
    And I have a valid Publisher access token
    Then I find the apiUUID of the API created with the name "my-new-api"
    Then I undeploy the selected API
    Then the response status code should be 200

    Examples:
      | apiID         | expectedStatusCode |
      | endpoint-test |                202 |

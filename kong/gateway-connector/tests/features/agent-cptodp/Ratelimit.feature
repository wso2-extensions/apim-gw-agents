Feature: Testing Ratelimit feature

  Background:
    Given The system is ready

  Scenario: Testing API level rate limiiting for REST API
    And I have a DCR application
    And I have a valid Adminportal access token
    Then I set new API throttling policy allowing "2" requests per every "1" minute
    Then the response status code should be 201
    And I have a valid Publisher access token
    When I use the Payload file "artifacts/payloads/ratelimit_api.json"
    When the definition file "artifacts/definitions/employees_api.json"
    And make the import API Creation request using OAS "File"
    Then the response status code should be 201
    And the response body should contain "SimpleRateLimitAPI"
    And make the API Revision Deployment request
    Then the response status code should be 201
    Then I wait for 40 seconds
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
      | Authorization | Bearer ${accessToken} |
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl/3.14/employee" with body ""
    And I eventually receive 200 response code, not accepting
      | 429 |
      | 401 |
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl/3.14/employee" with body ""
    Then the response status code should be 200
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl/3.14/employee" with body ""
    Then the response status code should be 429
    Then I wait for next minute strictly
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl/3.14/employee" with body ""
    Then the response status code should be 200

  Scenario: Undeploy the created REST API
    And I have a DCR application
    And I have a valid Devportal access token
    Then I delete the application "SampleApp" from devportal
    Then the response status code should be 200
    And I have a valid Publisher access token
    Then I find the apiUUID of the API created with the name "SimpleRateLimitAPI"
    Then I undeploy the selected API
    Then the response status code should be 200
    Then I wait for 10 seconds
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl/3.14/employee" with body ""
    Then the response status code should be 404
    And I send "GET" request to "https://sandbox.kong.wso2.com:8443/simple-rl/3.14/employee" with body ""
    Then the response status code should be 404
    And I have a valid Adminportal access token
    Then I delete the created API throttling policy

  Scenario: Testing Resource level rate limiiting for REST API
    And I have a DCR application
    And I have a valid Adminportal access token
    Then I set new API throttling policy allowing "2" requests per every "1" minute
    Then the response status code should be 201
    And I have a valid Publisher access token
    When I use the Payload file "artifacts/payloads/resource_level_rl.json"
    When the definition file "artifacts/definitions/employee_with_rl_r.json"
    And make the import API Creation request using OAS "File"
    Then the response status code should be 201
    And the response body should contain "SimpleRateLimitResourceLevelAPI"
    And the response body should contain key "throttlingPolicy" and value "TestRatelimit"
    And make the API Revision Deployment request
    Then the response status code should be 201
    Then I wait for 40 seconds
    And make the Change Lifecycle request
    Then the response status code should be 200
    And I have a valid Devportal access token
    And make the Application Creation request with the name "ResourceLevelApp"
    Then the response status code should be 201
    And the response body should contain "ResourceLevelApp"
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
      | Authorization | Bearer ${accessToken} |
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl-r/3.14/employee" with body ""
    And I eventually receive 200 response code, not accepting
      | 429 |
      | 401 |
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl-r/3.14/employee" with body ""
    Then the response status code should be 200
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl-r/3.14/employee" with body ""
    Then the response status code should be 429
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl-r/3.14/employee" with body ""
    Then the response status code should be 429
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl-r/3.14/withoutrl" with body ""
    Then the response status code should be 200
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl-r/3.14/withoutrl" with body ""
    Then the response status code should be 200
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl-r/3.14/withoutrl" with body ""
    Then the response status code should be 200
    Then I wait for next minute strictly
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl-r/3.14/employee" with body ""
    Then the response status code should be 200
    And I send "GET" request to "https://kong.wso2.com:8443/simple-rl-r/3.14/employee" with body ""
    Then the response status code should be 200

  Scenario: Undeploy the created REST API
    And I have a DCR application
    And I have a valid Devportal access token
    Then I delete the application "ResourceLevelApp" from devportal
    Then the response status code should be 200
    And I have a valid Publisher access token
    Then I find the apiUUID of the API created with the name "SimpleRateLimitResourceLevelAPI"
    Then I undeploy the selected API
    Then the response status code should be 200
    And I have a valid Adminportal access token
    Then I delete the created API throttling policy

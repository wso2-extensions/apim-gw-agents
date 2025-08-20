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

package constants

// Constants defines global constants used across the test suite.
const (
	// Default hosts and endpoints
	DefaultAPIHost             = "api.am.wso2.com"
	DefaultGWPort              = "8000"
	DefaultTokenEP             = "oauth2/token"
	DefaultAPIConfigurator     = "api/configurator/1.2.0/"
	DefaultAPIDeployer         = "api/deployer/1.2.0/"
	AccessToken                = "accessToken"
	EmptyString                = ""
	APICreateScope             = "apk:api_create"
	SpaceString                = " "
	SubscriptionBasicAuthToken = "Basic NDVmMWM1YzgtYTkyZS0xMWVkLWFmYTEtMDI0MmFjMTIwMDAyOjRmYmQ2MmVjLWE5MmUtMTFlZC1hZmExLTAyNDJhYzEyMDAwMg=="
	GatewayName                = "kong_k8s_gw"
	GatewayVHost               = "kong.wso2.com"

	// APIM-specific defaults
	DefaultAPIMIDPHost         = "am.wso2.com"
	DefaultAPIMAPIHost         = "am.wso2.com"
	DefaultAPIMGWPort          = ""
	DefaultAPIMTokenEP         = "oauth2/token"
	DefaultDCREP               = "client-registration/v0.17/register"
	DefaultAPIMAPIConfigurator = "api/configurator/1.2.0/"
	DefaultAPIMAPIDeployer     = "api/am/publisher/v4/"
	DefaultDevportal           = "api/am/devportal/v3/"
	DefaultAdminportal         = "api/am/admin/v4/"
	DefaultAPIMHost            = "apim.wso2.com"
)

// RequestHeaders defines constants for HTTP request headers.
var RequestHeaders = struct {
	Host          string
	Authorization string
	ContentType   string
}{
	Host:          "Host",
	Authorization: "Authorization",
	ContentType:   "Content-Type",
}

// ContentTypes defines constants for content types.
var ContentTypes = struct {
	ApplicationJSON               string
	ApplicationXWWWFormURLEncoded string
	MultipartFormData             string
	ApplicationOctetStream        string
	ApplicationZip                string
	TextPlain                     string
	ApplicationCACert             string
}{
	ApplicationJSON:               "application/json",
	ApplicationXWWWFormURLEncoded: "application/x-www-form-urlencoded",
	MultipartFormData:             "multipart/form-data",
	ApplicationOctetStream:        "application/octet-stream",
	ApplicationZip:                "application/zip",
	TextPlain:                     "text/plain",
	ApplicationCACert:             "application/x-x509-ca-cert",
}

// CurlOption represents HTTP methods.
var CurlOption = struct {
	HttpMethodGet     string
	HttpMethodPost    string
	HttpMethodPut     string
	HttpMethodDelete  string
	HttpMethodOptions string
}{
	HttpMethodGet:     "GET",
	HttpMethodPost:    "POST",
	HttpMethodPut:     "PUT",
	HttpMethodDelete:  "DELETE",
	HttpMethodOptions: "OPTIONS",
}

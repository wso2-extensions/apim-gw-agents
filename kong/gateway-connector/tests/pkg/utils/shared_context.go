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
	"net/http"
	"sync"
)

// SharedContext holds the state for test scenarios.
type SharedContext struct {
	httpClient            *SimpleHTTPClient
	accessToken           string
	response              *http.Response
	responseBody          string
	publisherAccessToken  string
	devportalAccessToken  string
	adminAccessToken      string
	basicAuthToken        string
	apiUUID               string
	revisionUUID          string
	applicationUUID       string
	keyManagerUUID        string
	oauthKeyUUID          string
	consumerSecret        string // Production consumer secret
	consumerKey           string // Production consumer key
	sandboxConsumerSecret string
	sandboxConsumerKey    string
	prodKeyMappingID      string
	sandboxKeyMappingID   string
	apiAccessToken        string
	definitionValidStatus bool
	subscriptionID        string
	internalKey           string
	policyID              string
	valueStore            map[string]interface{}
	headers               map[string]string
	grpcStatusCode        int
	grpcErrorCode         int

	// Mutex for thread-safe lazy initialization of httpClient
	mu sync.Mutex
}

// NewSharedContext creates a new instance of SharedContext with initialized maps.
func NewSharedContext() *SharedContext {
	client := NewSimpleHTTPClient()
	return &SharedContext{
		httpClient: client,
		valueStore: make(map[string]interface{}),
		headers:    make(map[string]string),
	}
}

// GetHTTPClient lazily initializes and returns the HTTP client.
func (ctx *SharedContext) GetHTTPClient() *SimpleHTTPClient {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.httpClient == nil {
		ctx.httpClient = NewSimpleHTTPClient()
	}
	return ctx.httpClient
}

// GetGrpcStatusCode returns the gRPC status code.
func (ctx *SharedContext) GetGrpcStatusCode() int {
	return ctx.grpcStatusCode
}

// SetGrpcStatusCode sets the gRPC status code.
func (ctx *SharedContext) SetGrpcStatusCode(code int) {
	ctx.grpcStatusCode = code
}

// GetAccessToken returns the access token.
func (ctx *SharedContext) GetAccessToken() string {
	return ctx.accessToken
}

// SetAccessToken sets the access token.
func (ctx *SharedContext) SetAccessToken(token string) {
	ctx.accessToken = token
}

// GetResponse returns the HTTP response.
func (ctx *SharedContext) GetResponse() *http.Response {
	return ctx.response
}

// SetResponse sets the HTTP response.
func (ctx *SharedContext) SetResponse(resp *http.Response) {
	ctx.response = resp
}

// GetStoreValue retrieves a value from the value store.
func (ctx *SharedContext) GetStoreValue(key string) interface{} {
	return ctx.valueStore[key]
}

// AddStoreValue adds a value to the value store.
func (ctx *SharedContext) AddStoreValue(key string, value interface{}) {
	ctx.valueStore[key] = value
}

// GetValueStore returns a read-only view of the value store.
func (ctx *SharedContext) GetValueStore() map[string]interface{} {
	storeCopy := make(map[string]interface{})
	for k, v := range ctx.valueStore {
		storeCopy[k] = v
	}
	return storeCopy
}

// GetHeaders returns a read-only view of the headers.
func (ctx *SharedContext) GetHeaders() map[string]string {
	headersCopy := make(map[string]string)
	for k, v := range ctx.headers {
		headersCopy[k] = v
	}
	return headersCopy
}

// AddHeader adds a header to the headers map.
func (ctx *SharedContext) AddHeader(key, value string) {
	ctx.headers[key] = value
}

// RemoveHeader removes a header from the headers map.
func (ctx *SharedContext) RemoveHeader(key string) {
	delete(ctx.headers, key)
}

// GetResponseBody returns the response body.
func (ctx *SharedContext) GetResponseBody() string {
	return ctx.responseBody
}

// SetResponseBody sets the response body.
func (ctx *SharedContext) SetResponseBody(body string) {
	ctx.responseBody = body
}

// GetPublisherAccessToken returns the publisher access token.
func (ctx *SharedContext) GetPublisherAccessToken() string {
	return ctx.publisherAccessToken
}

// SetPublisherAccessToken sets the publisher access token.
func (ctx *SharedContext) SetPublisherAccessToken(token string) {
	ctx.publisherAccessToken = token
}

// GetDevportalAccessToken returns the Devportal access token.
func (ctx *SharedContext) GetDevportalAccessToken() string {
	return ctx.devportalAccessToken
}

// SetDevportalAccessToken sets the Devportal access token.
func (ctx *SharedContext) SetDevportalAccessToken(token string) {
	ctx.devportalAccessToken = token
}

// GetAdminAccessToken returns the admin access token.
func (ctx *SharedContext) GetAdminAccessToken() string {
	return ctx.adminAccessToken
}

// SetAdminAccessToken sets the admin access token.
func (ctx *SharedContext) SetAdminAccessToken(token string) {
	ctx.adminAccessToken = token
}

// GetBasicAuthToken returns the basic auth token.
func (ctx *SharedContext) GetBasicAuthToken() string {
	return ctx.basicAuthToken
}

// SetBasicAuthToken sets the basic auth token.
func (ctx *SharedContext) SetBasicAuthToken(token string) {
	ctx.basicAuthToken = token
}

// GetApiUUID returns the API UUID.
func (ctx *SharedContext) GetApiUUID() string {
	return ctx.apiUUID
}

// SetApiUUID sets the API UUID.
func (ctx *SharedContext) SetApiUUID(uuid string) {
	ctx.apiUUID = uuid
}

// GetRevisionUUID returns the revision UUID.
func (ctx *SharedContext) GetRevisionUUID() string {
	return ctx.revisionUUID
}

// SetRevisionUUID sets the revision UUID.
func (ctx *SharedContext) SetRevisionUUID(uuid string) {
	ctx.revisionUUID = uuid
}

// GetApplicationUUID returns the application UUID.
func (ctx *SharedContext) GetApplicationUUID() string {
	return ctx.applicationUUID
}

// SetApplicationUUID sets the application UUID.
func (ctx *SharedContext) SetApplicationUUID(uuid string) {
	ctx.applicationUUID = uuid
}

// GetKeyManagerUUID returns the key manager UUID.
func (ctx *SharedContext) GetKeyManagerUUID() string {
	return ctx.keyManagerUUID
}

// SetKeyManagerUUID sets the key manager UUID.
func (ctx *SharedContext) SetKeyManagerUUID(uuid string) {
	ctx.keyManagerUUID = uuid
}

// GetOauthKeyUUID returns the OAuth key UUID.
func (ctx *SharedContext) GetOauthKeyUUID() string {
	return ctx.oauthKeyUUID
}

// SetOauthKeyUUID sets the OAuth key UUID.
func (ctx *SharedContext) SetOauthKeyUUID(uuid string) {
	ctx.oauthKeyUUID = uuid
}

// GetAPIInternalKey returns the internal API key.
func (ctx *SharedContext) GetAPIInternalKey() string {
	return ctx.internalKey
}

// SetAPIInternalKey sets the internal API key.
func (ctx *SharedContext) SetAPIInternalKey(key string) {
	ctx.internalKey = key
}

// GetConsumerSecret returns the consumer secret based on key type.
func (ctx *SharedContext) GetConsumerSecret(keyType string) string {
	switch keyType {
	case "production":
		return ctx.consumerSecret
	case "sandbox":
		return ctx.sandboxConsumerSecret
	default:
		return ""
	}
}

// SetConsumerSecret sets the consumer secret based on key type.
func (ctx *SharedContext) SetConsumerSecret(secret, keyType string) {
	switch keyType {
	case "production":
		ctx.consumerSecret = secret
	case "sandbox":
		ctx.sandboxConsumerSecret = secret
	}
}

// GetConsumerKey returns the consumer key based on key type.
func (ctx *SharedContext) GetConsumerKey(keyType string) string {
	switch keyType {
	case "production":
		return ctx.consumerKey
	case "sandbox":
		return ctx.sandboxConsumerKey
	default:
		return ""
	}
}

// SetConsumerKey sets the consumer key based on key type.
func (ctx *SharedContext) SetConsumerKey(key, keyType string) {
	switch keyType {
	case "production":
		ctx.consumerKey = key
	case "sandbox":
		ctx.sandboxConsumerKey = key
	}
}

// GetKeyMappingID returns the key mapping ID based on key type.
func (ctx *SharedContext) GetKeyMappingID(keyType string) string {
	switch keyType {
	case "production":
		return ctx.prodKeyMappingID
	case "sandbox":
		return ctx.sandboxKeyMappingID
	default:
		return ""
	}
}

// SetKeyMappingID sets the key mapping ID based on key type.
func (ctx *SharedContext) SetKeyMappingID(id, keyType string) {
	switch keyType {
	case "production":
		ctx.prodKeyMappingID = id
	case "sandbox":
		ctx.sandboxKeyMappingID = id
	}
}

// GetApiAccessToken returns the API access token.
func (ctx *SharedContext) GetApiAccessToken() string {
	return ctx.apiAccessToken
}

// SetApiAccessToken sets the API access token.
func (ctx *SharedContext) SetApiAccessToken(token string) {
	ctx.apiAccessToken = token
}

// GetDefinitionValidStatus returns the definition valid status.
func (ctx *SharedContext) GetDefinitionValidStatus() bool {
	return ctx.definitionValidStatus
}

// SetDefinitionValidStatus sets the definition valid status.
func (ctx *SharedContext) SetDefinitionValidStatus(status bool) {
	ctx.definitionValidStatus = status
}

// GetSubscriptionID returns the subscription ID.
func (ctx *SharedContext) GetSubscriptionID() string {
	return ctx.subscriptionID
}

// SetSubscriptionID sets the subscription ID.
func (ctx *SharedContext) SetSubscriptionID(id string) {
	ctx.subscriptionID = id
}

// GetPolicyID returns the policy ID.
func (ctx *SharedContext) GetPolicyID() string {
	return ctx.policyID
}

// SetPolicyID sets the policy ID.
func (ctx *SharedContext) SetPolicyID(id string) {
	ctx.policyID = id
}

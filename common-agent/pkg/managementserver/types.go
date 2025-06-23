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

package managementserver

// Subscription for struct subscription
type Subscription struct {
	SubStatus     string         `json:"subStatus,omitempty"`
	UUID          string         `json:"uuid,omitempty"`
	Organization  string         `json:"organization,omitempty"`
	SubscribedAPI *SubscribedAPI `json:"subscribedApi,omitempty"`
	TimeStamp     int64          `json:"timeStamp,omitempty"`
	RateLimit     string         `json:"rateLimit,omitempty"`
}

// SubscriptionList for struct list of applications
type SubscriptionList struct {
	List []Subscription `json:"list"`
}

// SubscribedAPI for struct subscribedAPI
type SubscribedAPI struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// SecurityScheme for struct securityScheme
type SecurityScheme struct {
	SecurityScheme        string `json:"securityScheme,omitempty"`
	ApplicationIdentifier string `json:"applicationIdentifier,omitempty"`
	KeyType               string `json:"keyType,omitempty"`
	EnvID                 string `json:"envID,omitempty"`
}

// APICPEvent holds data of a specific API event from adapter
type APICPEvent struct {
	Event EventType `json:"event"`
	API   API       `json:"payload"`
}

// EventType is the type of api event. One of (CREATE, UPDATE, DELETE)
type EventType string

const (
	// CreateEvent is create api event
	CreateEvent EventType = "CREATE"
	// DeleteEvent is delete api event
	DeleteEvent EventType = "DELETE"
)

// API holds the api data from adapter api event
type API struct {
	APIUUID                string                  `json:"apiUUID"`
	APIName                string                  `json:"apiName"`
	APIVersion             string                  `json:"apiVersion"`
	IsDefaultVersion       bool                    `json:"isDefaultVersion"`
	Definition             string                  `json:"definition"`
	APIType                string                  `json:"apiType"`
	APISubType             string                  `json:"apiSubType"`
	BasePath               string                  `json:"basePath"`
	Organization           string                  `json:"organization"`
	SystemAPI              bool                    `json:"systemAPI"`
	APIProperties          map[string]string       `json:"apiProperties,omitempty"`
	Environment            string                  `json:"environment,omitempty"`
	RevisionID             string                  `json:"revisionID"`
	SandEndpoint           string                  `json:"sandEndpoint"`
	SandEndpointSecurity   EndpointSecurity        `json:"sandEndpointSecurity"`
	ProdEndpoint           string                  `json:"prodEndpoint"`
	ProdEndpointSecurity   EndpointSecurity        `json:"prodEndpointSecurity"`
	EndpointProtocol       string                  `json:"endpointProtocol"`
	CORSPolicy             *CORSPolicy             `json:"cORSPolicy"`
	Vhost                  string                  `json:"vhost"`
	SandVhost              string                  `json:"sandVhost"`
	SecurityScheme         []string                `json:"securityScheme"`
	AuthHeader             string                  `json:"authHeader"`
	APIKeyHeader           string                  `json:"apiKeyHeader"`
	Operations             []OperationFromDP       `json:"operations"`
	SandAIRL               *AIRL                   `json:"sandAIRL"`
	ProdAIRL               *AIRL                   `json:"prodAIRL"`
	AIConfiguration        AIConfiguration         `json:"aiConfiguration"`
	MultiEndpoints         APIEndpoints            `json:"multiEndpoints"`
	AIModelBasedRoundRobin *AIModelBasedRoundRobin `json:"modelBasedRoundRobin"`
}

// AIModelBasedRoundRobin holds the model based round robin configurations
type AIModelBasedRoundRobin struct {
	OnQuotaExceedSuspendDuration int             `json:"onQuotaExceedSuspendDuration,omitempty"`
	ProductionModels             []AIModelWeight `json:"productionModels"`
	SandboxModels                []AIModelWeight `json:"sandboxModels"`
}

// AIModelWeight holds the model configurations
type AIModelWeight struct {
	Model    string `json:"model"`
	Endpoint string `json:"endpoint"`
	Weight   int    `json:"weight,omitempty"`
}

// APIMEndpoint holds the endpoint data from adapter api event
type APIMEndpoint struct {
	EndpointUUID    string             `json:"endpointUuid" yaml:"endpointUuid"`
	EndpointName    string             `json:"endpointName" yaml:"endpointName"`
	EndpointConfig  APIMEndpointConfig `json:"endpointConfig" yaml:"endpointConfig"`
	DeploymentStage string             `json:"deploymentStage" yaml:"deploymentStage"`
}

// APIMEndpointConfig holds the endpoint configuration data from adapter api event
type APIMEndpointConfig struct {
	EndpointType        string               `json:"endpoint_type" yaml:"endpoint_type"`
	SandboxEndpoints    Endpoints            `json:"sandbox_endpoints" yaml:"sandbox_endpoints"`
	ProductionEndpoints Endpoints            `json:"production_endpoints" yaml:"production_endpoints"`
	EndpointSecurity    APIMEndpointSecurity `json:"endpoint_security" yaml:"endpoint_security"`
}

// APIMEndpointSecurity holds the endpoint security data from adapter api event
type APIMEndpointSecurity struct {
	Sandbox    SecurityConfig `json:"sandbox" yaml:"sandbox"`
	Production SecurityConfig `json:"production" yaml:"production"`
}

// SecurityConfig holds the security configuration data from adapter api event
type SecurityConfig struct {
	APIKeyValue                      string                 `json:"apiKeyValue" yaml:"apiKeyValue"`
	APIKeyIdentifier                 string                 `json:"apiKeyIdentifier" yaml:"apiKeyIdentifier"`
	APIKeyIdentifierType             string                 `json:"apiKeyIdentifierType" yaml:"apiKeyIdentifierType"`
	Type                             string                 `json:"type" yaml:"type"`
	Username                         string                 `json:"username" yaml:"username"`
	Password                         string                 `json:"password" yaml:"password"`
	Enabled                          bool                   `json:"enabled" yaml:"enabled"`
	AdditionalProperties             map[string]interface{} `json:"additionalProperties" yaml:"additionalProperties"`
	CustomParameters                 map[string]interface{} `json:"customParameters" yaml:"customParameters"`
	ConnectionTimeoutDuration        float64                `json:"connectionTimeoutDuration" yaml:"connectionTimeoutDuration"`
	SocketTimeoutDuration            float64                `json:"socketTimeoutDuration" yaml:"socketTimeoutDuration"`
	ConnectionRequestTimeoutDuration float64                `json:"connectionRequestTimeoutDuration" yaml:"connectionRequestTimeoutDuration"`
}

// Endpoints holds the endpoint URLs
type Endpoints struct {
	URL string `json:"url" yaml:"url"`
}

// EndpointConfig holds endpoint-specific settings.
type EndpointConfig struct { // "prod" or "sand"
	URL             string
	SecurityType    string
	SecurityEnabled bool
	APIKeyName      string
	APIKeyIn        string
	APIKeyValue     string
	BasicUsername   string
	BasicPassword   string
}

// APIEndpoints holds the common protocol and a list of endpoint configurations.
type APIEndpoints struct {
	Protocol      string
	ProdEndpoints []EndpointConfig
	SandEndpoints []EndpointConfig
}

// AIRL holds AI ratelimit related data
type AIRL struct {
	PromptTokenCount     *uint32 `json:"promptTokenCount"`
	CompletionTokenCount *uint32 `json:"CompletionTokenCount"`
	TotalTokenCount      *uint32 `json:"totalTokenCount"`
	TimeUnit             string  `json:"timeUnit"`
	RequestCount         *uint32 `json:"requestCount"`
}

// EndpointSecurity holds the endpoint security information
type EndpointSecurity struct {
	Enabled       bool   `json:"enabled"`
	SecurityType  string `json:"securityType"`
	APIKeyName    string `json:"apiKeyName"`
	APIKeyValue   string `json:"apiKeyValue"`
	APIKeyIn      string `json:"apiKeyIn"`
	BasicUsername string `json:"basicUsername"`
	BasicPassword string `json:"basicPassword"`
}

// AIConfiguration holds the AI configuration
type AIConfiguration struct {
	LLMProviderID         string `json:"llmProviderID"`
	LLMProviderName       string `json:"llmProviderName"`
	LLMProviderAPIVersion string `json:"llmProviderApiVersion"`
}

// APKHeaders contains the request and response header modifier information
type APKHeaders struct {
	Policy
	RequestHeaders  APKHeaderModifier `json:"requestHeaders"`
	ResponseHeaders APKHeaderModifier `json:"responseHeaders"`
}

// APKHeaderModifier contains header modifier values
type APKHeaderModifier struct {
	AddHeaders    []APKHeader `json:"addHeaders"`
	RemoveHeaders []string    `json:"removeHeaders"`
}

// APKHeader contains the header information
type APKHeader struct {
	Name  string `json:"headerName" yaml:"headerName"`
	Value string `json:"headerValue,omitempty" yaml:"headerValue,omitempty"`
}

// OperationFromDP holds the path, verb, throttling and interceptor policy
type OperationFromDP struct {
	Path                   string                  `json:"path"`
	Verb                   string                  `json:"verb"`
	Scopes                 []string                `json:"scopes"`
	Filters                []Filter                `json:"filters"`
	AIModelBasedRoundRobin *AIModelBasedRoundRobin `json:"aiModelBasedRoundRobin"`
}

// Policy holds the policy name and version
type Policy struct {
	PolicyName    string `json:"policyName"`
	PolicyVersion string `json:"policyVersion"`
}

// Filter interface is used to define the type of parameters that can be used in an operation policy
type Filter interface {
	GetPolicyName() string
	GetPolicyVersion() string
	isFilter()
}

// GetPolicyName returns the name of the policy sent to the APIM
func (p *Policy) GetPolicyName() string {
	return p.PolicyName
}

// GetPolicyVersion returns the version of the policy sent to the APIM
func (p *Policy) GetPolicyVersion() string {
	return p.PolicyVersion
}

func (h APKHeaders) isFilter() {}

// APKRedirectRequest defines the parameters of a redirect request policy sent from the APK
type APKRedirectRequest struct {
	Policy
	URL string `json:"url"`
}

func (r APKRedirectRequest) isFilter() {}

// APKMirrorRequest defines the parameters of a mirror request policy sent from the APK
type APKMirrorRequest struct {
	Policy
	URLs []string `json:"urls"`
}

func (m APKMirrorRequest) isFilter() {}

// CORSPolicy hold cors configs
type CORSPolicy struct {
	AccessControlAllowCredentials bool     `json:"accessControlAllowCredentials,omitempty"`
	AccessControlAllowHeaders     []string `json:"accessControlAllowHeaders,omitempty"`
	AccessControlAllowOrigins     []string `json:"accessControlAllowOrigins,omitempty"`
	AccessControlExposeHeaders    []string `json:"accessControlExposeHeaders,omitempty"`
	AccessControlMaxAge           *int     `json:"accessControlMaxAge,omitempty"`
	AccessControlAllowMethods     []string `json:"accessControlAllowMethods,omitempty"`
}

// APIOperation represents the desired struct format for each API operation
type APIOperation struct {
	ID                string            `yaml:"id"`
	Target            string            `yaml:"target"`
	Verb              string            `yaml:"verb"`
	AuthType          string            `yaml:"authType"`
	ThrottlingPolicy  string            `yaml:"throttlingPolicy"`
	Scopes            []string          `yaml:"scopes"`
	UsedProductIDs    []string          `yaml:"usedProductIds"`
	OperationPolicies OperationPolicies `yaml:"operationPolicies"`
}

// OperationPolicies contains the request, response and fault policies for an operation
type OperationPolicies struct {
	Request  []OperationPolicy `yaml:"request"`
	Response []OperationPolicy `yaml:"response"`
	Fault    []string          `yaml:"fault"`
}

// OperationPolicy represents the desired struct format for an Operation Policy
type OperationPolicy struct {
	PolicyName    string           `yaml:"policyName"`
	PolicyVersion string           `yaml:"policyVersion"`
	PolicyID      string           `yaml:"policyId,omitempty"`
	PolicyType    string           `yaml:"policyType,omitempty"`
	Parameters    FilterParameters `yaml:"parameters"`
}

// FilterParameters interface is used to define the type of parameters that can be used in an operation policy.
type FilterParameters interface {
	isFilterParameters()
}

func (m WeightedRoundRobinConfigs) isFilterParameters() {}

// WeightedRoundRobinConfigs holds any additional parameter data for a RequestPolicy
type WeightedRoundRobinConfigs struct {
	WeightedRoundRobinConfigs string `yaml:"weightedRoundRobinConfigs"`
}

func (m ModelBasedRoundRobinConfig) isFilterParameters() {}

// ModelConfig holds the configuration details of a model
type ModelConfig struct {
	Model      string `json:"model" yaml:"model"`
	EndpointID string `json:"endpointId" yaml:"endpointId"`
	Weight     int    `json:"weight" yaml:"weight"`
}

// ModelBasedRoundRobinConfig holds the configuration details of the transformer
type ModelBasedRoundRobinConfig struct {
	Production      []ModelConfig `json:"production" yaml:"production"`
	Sandbox         []ModelConfig `json:"sandbox" yaml:"sandbox"`
	SuspendDuration string        `json:"suspendDuration" yaml:"suspendDuration"`
}

func (h Header) isFilterParameters() {}

// Header contains the request and response header modifier information
type Header struct {
	Name  string `json:"headerName" yaml:"headerName"`
	Value string `json:"headerValue,omitempty" yaml:"headerValue,omitempty"`
}

// RedirectRequest contains the url to send the redirected request
type RedirectRequest struct {
	URL string `json:"url"`
}

func (r RedirectRequest) isFilterParameters() {}

// MirrorRequest contains the url to mirror the request to
type MirrorRequest struct {
	URL string `json:"url"`
}

func (m MirrorRequest) isFilterParameters() {}

// OpenAPIPaths represents the structure of the OpenAPI specification YAML file
type OpenAPIPaths struct {
	Paths map[string]map[string]interface{} `yaml:"paths"`
}

// Operation represents the structure of an operation within the OpenAPI specification
type Operation struct {
	XAuthType        string `yaml:"x-auth-type"`
	XThrottlingTier  string `yaml:"x-throttling-tier"`
	XWSO2AppSecurity struct {
		SecurityTypes []string `yaml:"security-types"`
		Optional      bool     `yaml:"optional"`
	} `yaml:"x-wso2-application-security"`
}

// AdditionalProperty represents additional properties of the API
type AdditionalProperty struct {
	Name    string
	Value   string
	Display bool
}

// ScopeWrapper to hold scope sonfigs
type ScopeWrapper struct {
	Scope  Scope `yaml:"scope"`
	Shared bool  `yaml:"shared"`
}

// Scope to hold scope config
type Scope struct {
	Name        string   `yaml:"name"`
	DisplayName string   `yaml:"displayName"`
	Description string   `yaml:"description"`
	Bindings    []string `yaml:"bindings"`
}

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

import "k8s.io/apimachinery/pkg/runtime/schema"

// Kubernetes Group Version Resources for Kong Gateway Connector
var (
	// GVRs defines the Kubernetes Group Version Resources to watch
	GVRs = []schema.GroupVersionResource{
		HTTPRouteGVR,
		ServiceGVR,
	}

	// HTTPRouteGVR defines the HTTPRoute GroupVersionResource
	HTTPRouteGVR = schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Version:  "v1",
		Resource: "httproutes",
	}

	// ServiceGVR defines the Service GroupVersionResource
	ServiceGVR = schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "services",
	}

	// NodesGVR defines the Nodes GroupVersionResource
	NodesGVR = schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "nodes",
	}

	// KongPluginGVR defines the KongPlugin GroupVersionResource
	KongPluginGVR = schema.GroupVersionResource{
		Group:    "configuration.konghq.com",
		Version:  "v1",
		Resource: "kongplugins",
	}
)

// Kubernetes API Versions
const (
	KongAPIVersion = "configuration.konghq.com/v1"
	CoreAPIVersion = "v1"
)

// Kubernetes Resource Kinds
const (
	HTTPRouteKind    = "HTTPRoute"
	ServiceKind      = "Service"
	KongConsumerKind = "KongConsumer"
	SecretKind       = "Secret"
	KongPluginKind   = "KongPlugin"
)

// Time unit keys and values for Kong Gateway configurations
const (
	// Time unit keys (input) - primary forms
	TimeUnitMinute = "minute"
	TimeUnitHour   = "hour"
	TimeUnitDay    = "day"
	TimeUnitMonth  = "month"
	TimeUnitYear   = "year"

	// Time unit keys (input) - alternative forms
	TimeUnitMin     = "min"
	TimeUnitMinutes = "minutes"
	TimeUnitHours   = "hours"
	TimeUnitDays    = "days"
	TimeUnitMonths  = "months"
	TimeUnitYears   = "years"

	// Time unit values (output/mapped)
	TimeValueMin    = "min"
	TimeValueHours  = "hours"
	TimeValueDays   = "days"
	TimeValueMonths = "months"
	TimeValueYears  = "years"
)

// Time units mapping for Kong Gateway configurations (from discovery to Kong format)
var AllowedTimeUnits = map[string]string{
	TimeUnitMinute: TimeValueMin,
	TimeUnitHour:   TimeValueHours,
	TimeUnitDay:    TimeValueDays,
	TimeUnitMonth:  TimeValueMonths,
	TimeUnitYear:   TimeValueYears,
}

// Time units mapping for transformer (from various inputs to normalized format)
var TransformerTimeUnits = map[string]string{
	TimeUnitMin:     TimeUnitMinute,
	TimeUnitMinutes: TimeUnitMinute,
	TimeUnitMinute:  TimeUnitMinute,
	TimeUnitHours:   TimeUnitHour,
	TimeUnitHour:    TimeUnitHour,
	TimeUnitDays:    TimeUnitDay,
	TimeUnitDay:     TimeUnitDay,
	TimeUnitMonths:  TimeUnitMonth,
	TimeUnitMonth:   TimeUnitMonth,
	TimeUnitYears:   TimeUnitYear,
	TimeUnitYear:    TimeUnitYear,
}

// Kubernetes Object Paths
const (
	SpecField        = "spec"
	HostnamesField   = "hostnames"
	ConfigField      = "config"
	MetadataField    = "metadata"
	LabelsField      = "labels"
	AnnotationsField = "annotations"
	RulesField       = "rules"
	MatchesField     = "matches"
	PathField        = "path"
	ValueField       = "value"
	MethodField      = "method"
	PluginField      = "plugin"
	GroupField       = "group"
	AllowField       = "allow"
)

// Label keys used throughout the Kong Gateway Connector
const (
	// API related labels
	APIUUIDLabel      = "apiUUID"
	KongAPIUUIDLabel  = "kongAPIUUID"
	APIVersionLabel   = "apiVersion"
	APINameLabel      = "apiName"
	RevisionIDLabel   = "revisionID"
	ShowInCPLabel     = "showInCP"
	EnvironmentLabel  = "environment"
	OrganizationLabel = "organization"

	// Application related labels
	ApplicationUUIDLabel = "applicationUUID"
	TypeLabel            = "type"

	// Kong plugin related labels
	PluginTypeLabel = "plugin"

	// CP related labels
	K8sInitiatedFromField = "InitiateFrom"
	RouteTypeField        = "routeType"

	// Route Type Values
	APIRouteType     = "api"
	OptionsRouteType = "options"

	// HTTPRoute Backend Reference Fields
	BackendRefsField = "backendRefs"
	NameField        = "name"
	KindField        = "kind"
)

// Default values used in Kong Gateway Connector
const (
	DefaultAPIVersion       = "v1"
	DefaultEnvironment      = "production"
	DefaultAPIType          = "rest"
	DefaultTimeUnit         = "min"
	DefaultHTTPMethod       = "GET"
	DefaultBasePath         = "/"
	DefaultEnvironmentLabel = "Default"
	DefaultKongNamespace    = "kong"
	DefaultIngressClassName = "kong"
	DefaultKongAgentName    = "Kong"
	DefaultShowInCPFalse    = "false"
	DefaultOperationTarget  = "/*"
	DefaultStripPathValue   = "true"
	DefaultAuthHeader       = "Authorization"
	DefaultAPIKeyHeader     = "ApiKey"
	EnvironmentProduction   = "production"
	EnvironmentSandbox      = "sandbox"
)

// Policy Types
const (
	APIPolicyType          = "API"
	SubscriptionPolicyType = "SUBSCRIPTION"
)

// Kong Plugin Types
const (
	CORSPlugin         = "cors"
	RateLimitingPlugin = "rate-limiting"
	ACLPlugin          = "acl"
	KeyAuthPlugin      = "key-auth"
	JWTPlugin          = "jwt"
)

// Kong Plugin Configuration Fields
const (
	PluginLimitByField = "limit_by"
	PluginPathField    = "path"
)

// Kong Annotations
const (
	KongPluginsAnnotation   = "konghq.com/plugins"
	KongCredentialLabel     = "konghq.com/credential"
	KongStripPathAnnotation = "konghq.com/strip-path"
	KubernetesIngressClass  = "kubernetes.io/ingress.class"
)

// JWT Plugin Configuration
const (
	// JWT Plugin Default Values
	JWTRunOnPreflight    = false
	JWTKeyClaimName      = "client_id"
	JWTDefaultHeaderName = "Authorization"

	// JWT Plugin Config Fields
	JWTRunOnPreflightField = "run_on_preflight"
	JWTKeyClaimNameField   = "key_claim_name"
	JWTClaimsToVerifyField = "claims_to_verify"
	JWTHeaderNamesField    = "header_names"
	JWTUriParamNamesField  = "uri_param_names"

	// JWT Claims
	JWTExpClaim = "exp"
)

// API Key Plugin Configuration
const (
	// API Key Plugin Default Values
	APIKeyRunOnPreflight = false

	// API Key Plugin Config Fields
	APIKeyRunOnPreflightField = "run_on_preflight"
	APIKeyKeyNamesField       = "key_names"
	APIKeyKeyInHeaderField    = "key_in_header"
	APIKeyKeyInQueryField     = "key_in_query"
)

// Credential Types
const (
	ACLCredentialType = "acl"
	JWTCredentialType = "jwt"
)

// Authentication Types
const (
	OAuth2AuthenticationType = "OAuth2"
	APIKeyAuthenticationType = "APIKey"
	MTLSAuthenticationType   = "mTLS"
	JWTAuthenticationType    = "JWT"
)

// Subscription States
const (
	SubscriptionStateBlocked         = "BLOCKED"
	SubscriptionStateProdOnlyBlocked = "PROD_ONLY_BLOCKED"
	SubscriptionStateUnblocked       = "UNBLOCKED"
)

// Subscription Policy Names
const (
	UnlimitedPolicyName = "Unlimited"
)

// CORS Policy Fields
const (
	CORSOriginsField     = "origins"
	CORSMethodsField     = "methods"
	CORSHeadersField     = "headers"
	CORSCredentialsField = "credentials"
)

// Default CORS Values
const (
	DefaultCORSCredentials = false
)

// JWT Algorithm and Secret Keys
const (
	RS256Algorithm    = "RS256"
	PublicKeyField    = "public_key"
	AlgorithmField    = "algorithm"
	KeyField          = "key"
	RSAPublicKeyField = "rsa_public_key"
	IssuerSecretType  = "issuer"
)

// Certificate Types
const (
	PEMCertificateType = "PEM"
	PublicKeyType      = "PUBLIC KEY"
)

// Key Manager Configuration Fields
const (
	IssuerField = "issuer"
)

// Subscription Policy Types
const (
	SubscriptionTypeKey = "subscription"
	RateLimitingTypeKey = "rate-limiting"
)

// Quota Types
const (
	AIAPIQuotaType   = "aiApiQuota"
	RequestCountType = "requestCount"
	EventCountType   = "eventCount"
)

// Rate Limit Configuration
const (
	ServiceLimitBy    = "service"
	PathLimitBy       = "path"
	ConsumerLimitBy   = "consumer"
	PolicyTypeKey     = "policy"
	SubscriberTypeKey = "subscriber"
)

// HTTP Methods
const (
	HTTPMethodOptions = "OPTIONS"
)

// Route Naming
const (
	OptionsSuffix = "options"
	APISuffix     = "api"
)

// Default Values
const (
	SandboxHostPrefix = "sandbox."
)

// Path Processing Constants
const (
	PathSeparator = "/"
	MinPathParts  = 2
)

// Origin Values
const (
	ControlPlaneOrigin = "CP"
)

// EmptyString represents an empty string constant for consistent usage
const (
	EmptyString         = ""
	NullString          = "null"
	CommaString         = ","
	SlashString         = "/"
	SpaceString         = " "
	DashSeparatorString = "-"
	EqualString         = "="
)

// Transformer Name Prefixes
const (
	ResourcePrefix = "resource-"
	RoutePrefix    = "route-"
	ConsumerPrefix = "consumer-"
	SecretPrefix   = "secret-"
	APIPrefix      = "api-"
	PolicyPrefix   = "policy-"
)

// Retry Configuration
const (
	MaxRetries                              = 3
	RetryDelayMultiplier                    = 100
	KongCRTaskName                          = "UpdateKongCR"
	HTTPRouteUpdateTaskName                 = "updateHTTPRouteLabel"
	UpdateConsumerPluginAnnotationTask      = "UpdateKongConsumerPluginAnnotation"
	AddApplicationKeyTaskName               = "UpdateKongConsumerCredential-AddApplicationKey"
	RemoveApplicationKeyTaskName            = "UpdateKongConsumerCredential-RemoveApplicationKey"
	UpdateConsumerCredentialTask            = "UpdateKongConsumerCredential"
	UpdateConsumerCredentialBlockedTask     = "UpdateKongConsumerCredential-BLOCKED"
	UpdateConsumerCredentialProdBlockedTask = "UpdateKongConsumerCredential-PROD_ONLY_BLOCKED"
	UpdateConsumerCredentialUnblockedTask   = "UpdateKongConsumerCredential-UNBLOCKED"
	UpdateConsumerCredentialRemoveTask      = "UpdateKongConsumerCredential-Remove"
)

// Error Messages
const (
	ObjectModifiedError        = "the object has been modified"
	UnmarshalErrorApplication  = "Error occurred while unmarshalling Application event data"
	UnmarshalErrorAPI          = "Error occurred while unmarshalling API event data"
	UnmarshalErrorLifecycle    = "Error occurred while unmarshalling Lifecycle event data"
	UnmarshalErrorPolicy       = "Error occurred while unmarshalling Policy event data"
	UnmarshalErrorAIProvider   = "Error occurred while unmarshalling AI Provider event data"
	UnmarshalErrorScope        = "Error occurred while unmarshalling Scope event data"
	UnmarshalErrorSubscription = "Error occurred while unmarshalling Subscription event data"
)

// Network and Service Constants
const (
	// Protocols
	HTTPProtocol  = "http"
	HTTPSProtocol = "https"

	// Standard Ports
	HTTPPort  = 80
	HTTPSPort = 443

	// Service Types
	ServiceTypeExternalName = "ExternalName"
	ServiceTypeNodePort     = "NodePort"
	ServiceTypeLoadBalancer = "LoadBalancer"
	ServiceTypeClusterIP    = "ClusterIP"

	// Kong Annotations
	KongProtocolAnnotation = "konghq.com/protocol"

	// Service Spec Paths
	ServiceSpecType         = "type"
	ServiceSpecPorts        = "ports"
	ServiceSpecExternalName = "externalName"

	// Port Fields
	PortField     = "port"
	NodePortField = "nodePort"

	// LoadBalancer Status Paths
	StatusPath           = "status"
	LoadBalancerPath     = "loadBalancer"
	LoadBalancerIngress  = "ingress"
	IngressHostnameField = "hostname"
	IngressIPField       = "ip"

	// Node Address Types
	NodeExternalIPType = "ExternalIP"
	NodeInternalIPType = "InternalIP"

	// Node Status Paths
	NodeStatusAddresses = "addresses"
	AddressTypeField    = "type"
	AddressValueField   = "address"

	// Service DNS Template
	ServiceDNSTemplate = "%s.%s.svc.cluster.local"
)

// API Configuration Constants
const (
	// API Types
	APITypeHTTP         = "HTTP"
	APITypeGraphQL      = "GRAPHQL"
	APITypeRest         = "rest"
	APITypeGraphQLInput = "GraphQL"

	// Endpoint Types
	EndpointTypeSandbox    = "sandbox_endpoints"
	EndpointTypeProduction = "production_endpoints"

	// Default Values
	DefaultProvider         = "admin"
	DefaultLifeCycleStatus  = "CREATED"
	DefaultCacheTimeout     = 300
	DefaultThrottlingPolicy = "Unlimited"
	DefaultAuthType         = "Application & Application User"
	DefaultYAMLAPIVersion   = "v4.5.0"

	// Transport Protocols
	TransportHTTP  = "http"
	TransportHTTPS = "https"

	// Gateway Configuration
	GatewayTypeKong  = "Kong"
	GatewayVendorExt = "external"

	// Security Schemes
	SecurityTypeOAuth2      = "oauth2"
	SecurityFlowImplicit    = "implicit"
	SecuritySchemeDefault   = "default"
	AuthorizationURLDefault = "https://test.com"

	// YAML Structure Types
	YAMLTypeAPI       = "api"
	YAMLTypeEndpoints = "endpoints"

	// OpenAPI Extensions
	XAuthTypeField  = "x-auth-type"
	XScopesBindings = "x-scopes-bindings"

	// Configuration Keys
	ConfigKeySubtype       = "subtype"
	ConfigKeyConfiguration = "_configuration"

	// Regular Expression
	PathParameterRegex   = `{[^}]+}`
	PathParameterReplace = "hardcode"

	// APIM Mediation constants
	AddHeader       = "apkAddHeader"
	RemoveHeader    = "apkRemoveHeader"
	MirrorRequest   = "apkMirrorRequest"
	RedirectRequest = "apkRedirectRequest"

	// Version constants
	V1 = "v1"
)

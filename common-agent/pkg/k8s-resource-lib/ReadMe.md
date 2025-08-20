# Kubernetes Resource Generator Library

This Go library provides a framework for generating Kubernetes Gateway API-specific resources, including HTTPRoute and gRPC resources. The library offers default implementations for generating various components of these resources while allowing developers to override specific methods to suit their use cases.

## Features

- Generate Kubernetes resources for HTTP and gRPC configurations.
- Support for generating HTTPRoute and gRPC-specific Custom Resources (CRs).
- Flexible method overriding for custom implementations.
- Default implementations for common resource generation tasks.

## Installation

To use the library, include it in your Go project by running the following command:

```bash
go get -u "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib"
```

Ensure that the library and its dependencies are properly vendored in your project.

## Usage

### Initializing the Generator

#### HTTPRoute Generator

Create an instance of the HTTPRoute generator:

```go
import http_generator "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib/pkg/generators/http"

gen := http_generator.Generator()
```

#### gRPC Generator

Create an instance of the gRPC generator:

```go
import grpc_generator "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/k8s-resource-lib/pkg/generators/grpc"

gen := grpc_generator.Generator()
```

These initialize the respective generators with default implementations for all functions.

### Generating HTTPRoute Resources

Use the HTTPRoute generator to create an HTTPRoute by calling the desired methods:

```go
httpRoute, err := gen.GenerateHTTPRoute(*apkConf, organization, gatewayConfig, *apkConf.Operations, &endpoint, constants.ProductionType, "unique-route-id", 1)
if err != nil {
    log.Fatalf("Failed to generate HTTP route: %v", err)
}
```

### Generating gRPC Resources

Similarly, use the gRPC generator to create gRPC-specific resources:

```go
grpcResource, err := gen.GenerateGRPCRoute(*apkConf, organization, gatewayConfig, *apkConf.Operations, &endpoint, constants.ProductionType, "unique-grpc-id")
if err != nil {
    log.Fatalf("Failed to generate gRPC resource: %v", err)
}
```

### Overriding Default Implementations

To customize the behavior of the generator, you can override specific methods:

#### HTTPRoute Example

```go
gen := http_generator.Generator()
gen.GenerateHTTPRouteRules = myCustomHttpRouteRuleImplementation
```

#### gRPC Example

```go
gen := grpc_generator.Generator()
gen.GenerateGRPCRouteRules = myCustomGrpcRouteRuleImplementation
```

This allows you to replace the default implementations with your own.

### Example

Examples of using the library are available in the following files:

- `examples/http/main.go`: Demonstrates HTTPRoute generation.
- `examples/grpc/main.go`: Demonstrates gRPC resource generation.

## API Reference

### HTTPRoute Generator Functions

```go
// GenerateHTTPRouteRules generates HTTP route rules based on the provided APK configuration, operations, and endpoint details.
GenerateHTTPRouteRules(k8sArtifacts, apkConf types.APKConf, operations []types.Operation, endpoint *types.EndpointDetails, endpointType string) ([]gwapiv1.HTTPRouteRule, error)
// GenerateHTTPRouteRule generates a single HTTP route rule based on the provided APK configuration, operation, and endpoint details.
GenerateHTTPRouteRule(k8sArtifacts, apkConf types.APKConf, operation types.Operation, endpoint *types.EndpointDetails, endpointType string) (*gwapiv1.HTTPRouteRule, error)
// GenerateAndRetrieveParentRefs generates and retrieves parent references based on the provided gateway configurations and unique ID.
GenerateAndRetrieveParentRefs(gatewayConfig types.GatewayConfigurations, uniqueID string) []gwapiv1.ParentReference
// GenerateHTTPRouteFilters generates HTTP route filters based on the provided APK configuration, endpoint details, operation, and endpoint type.
GenerateHTTPRouteFilters(k8sArtifacts, apkConf types.APKConf, endpointToUse types.EndpointDetails, operation types.Operation, endpointType string) ([]gwapiv1.HTTPRouteFilter, bool)
// ExtractHTTPRouteFilter extracts HTTP route filters based on the provided APK configuration, endpoint details, operation, and operation policies.
ExtractHTTPRouteFilter(k8sArtifacts, apkConf *types.APKConf, endpoint types.EndpointDetails, operation types.Operation, operationPolicies []types.OperationPolicy, isRequest bool) ([]gwapiv1.HTTPRouteFilter, bool)
// GetHostNames retrieves host names based on the provided APK configuration, endpoint type, and organization.
GetHostNames(apkConf types.APKConf, endpointType string, organization types.Organization) []gwapiv1.Hostname
// RetrieveHTTPMatches retrieves HTTP route matches based on the provided APK configuration and operation.
RetrieveHTTPMatches(apkConf types.APKConf, operation types.Operation) ([]gwapiv1.HTTPRouteMatch, error)
// RetrieveHTTPMatch retrieves a single HTTP route match based on the provided APK configuration and operation.
RetrieveHTTPMatch(apkConf types.APKConf, operation types.Operation) (gwapiv1.HTTPRouteMatch, error)
// GenerateHTTPBackEndRef generates HTTP backend references based on the provided endpoint details, operation, and endpoint type.
GenerateHTTPBackEndRef(k8sArtifacts, endpoint types.EndpointDetails, operation types.Operation, endpointType string) []gwapiv1.HTTPBackendRef
// GenerateService generates a K8s service based on the provided configurations..
GenerateService(k8sArtifacts, endpoint types.EndpointDetails, operation types.Operation, endpointType string) corev1.Service
```

### gRPC Generator Functions

```go
// GenerateGRPCRouteRules generates gRPC route rules based on the provided APK configuration, operations, and endpoint details.
GenerateGRPCRouteRules(apkConf, operations, endpoint, endpointType) ([]gwapiv1.GRPCRouteRule, error)
// GenerateGRPCRouteRule generates a single gRPC route rule based on the provided APK configuration, operation, and endpoint details.
GenerateGRPCRouteRule(apkConf, operation, endpoint, endpointType) (*gwapiv1.GRPCRouteRule, error)
// GenerateAndRetrieveParentRefs generates and retrieves parent references based on the provided gateway configurations and unique ID.
GenerateAndRetrieveParentRefs(gatewayConfig, uniqueID) []gwapiv1.ParentReference
// GetHostNames retrieves host names based on the provided APK configuration, endpoint type, and organization.
GetHostNames(apkConf, endpointType, organization) []gwapiv1.Hostname
// RetrieveGRPCMatches retrieves gRPC route matches based on the provided operation.
RetrieveGRPCMatches(operation) []gwapiv1.GRPCRouteMatch
// RetrieveGRPCMatch retrieves a single gRPC route match based on the provided operation.
RetrieveGRPCMatch(operation) gwapiv1.GRPCRouteMatch
// GenerateGRPCBackEndRef generates gRPC backend references based on the provided endpoint details and operation.
GenerateGRPCBackEndRef(endpoint, operation) []gwapiv1.GRPCBackendRef
```

### Function: `Generator`

Creates and initializes a new generator instance with default implementations for HTTP or gRPC resources.

## Directory Structure

- `pkg/generators/http`: Contains HTTPRoute-specific generator logic.
- `pkg/generators/grpc`: Contains gRPC-specific generator logic.

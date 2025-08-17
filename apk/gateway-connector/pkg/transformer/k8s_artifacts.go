package transformer

import (
	gatewayv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	dpv2alpha1 "github.com/wso2/apk/common-go-libs/apis/dp/v2alpha1"
	corev1 "k8s.io/api/core/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gwapiv1a3 "sigs.k8s.io/gateway-api/apis/v1alpha3"
)

// K8sArtifacts k8s artifact representation of API
type K8sArtifacts struct {
	RouteMetadata          map[string]*dpv2alpha1.RouteMetadata
	HTTPRoutes             map[string]*gwapiv1.HTTPRoute
	HTTPRouteFilters       map[string]*gatewayv1alpha1.HTTPRouteFilter
	SecurityPolicies       map[string]*gatewayv1alpha1.SecurityPolicy
	Backends               map[string]*gatewayv1alpha1.Backend
	BackendTLSPolicies     map[string]*gwapiv1a3.BackendTLSPolicy
	RoutePolicies          map[string]*dpv2alpha1.RoutePolicy
	EnvoyExtensionPolicies map[string]*gatewayv1alpha1.EnvoyExtensionPolicy
	BackendTrafficPolicies map[string]*gatewayv1alpha1.BackendTrafficPolicy
	GRPCRoutes             map[string]*gwapiv1a2.GRPCRoute
	ConfigMaps             map[string]*corev1.ConfigMap
	Secrets                map[string]*corev1.Secret
}

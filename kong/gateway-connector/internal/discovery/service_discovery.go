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

package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/google/uuid"
	discoverPkg "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/discovery"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/managementserver"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/loggers"
)

// ReconcileAPI is the single point of logic for creating/updating an API in the control plane.
func ReconcileAPI(namespace, serviceName string) {
	loggers.LoggerWatcher.Infof("Reconciling API for Service %s/%s", namespace, serviceName)

	apiMutex.Lock()
	defer apiMutex.Unlock()

	service := FetchServiceByName(namespace, serviceName)
	if service == nil {
		loggers.LoggerWatcher.Warnf("Cannot reconcile API for Service %s/%s, as it could not be fetched.", namespace, serviceName)
		return
	}

	if shouldSkipResource(service) {
		loggers.LoggerWatcher.Infof("Skipping reconciliation for Service %s/%s as it's marked to be ignored.", namespace, serviceName)
		return
	}

	httpRoutes := FetchAllHTTPRoutesWithServiceName(namespace, serviceName)

	if len(httpRoutes) == 0 {
		loggers.LoggerWatcher.Infof("No associated HTTPRoutes for Service %s/%s.", namespace, serviceName)
		kongAPIUUID, hasKongAPIUUID := service.GetLabels()[constants.KongAPIUUIDLabel]
		if hasKongAPIUUID {
			loggers.LoggerWatcher.Infof("Service  %s/%s has KongAPIUUID: %s. Deleting corresponding API if it exists.", namespace, serviceName, kongAPIUUID)
			if api, exists := discoverPkg.APIMap[kongAPIUUID]; exists {
				delete(discoverPkg.APIMap, kongAPIUUID)
				delete(discoverPkg.APIHashMap, kongAPIUUID)
				discoverPkg.QueueEvent(managementserver.DeleteEvent, api, serviceName, namespace, constants.DefaultKongAgentName)
				loggers.LoggerWatcher.Infof("Deleted API %s corresponding to Service %s/%s due to no more HTTPRoutes.", kongAPIUUID, namespace, serviceName)
			}
		}
		return
	}

	// At this point, we have a service and at least one route, so we build the API.
	kongAPIUUID := getOrGenerateKongAPIUUID(service, nil)
	apiVersion := getAPIVersion(service, nil)

	desiredAPI := buildAPIFromHTTPRoutesAndService(service, httpRoutes, apiVersion, kongAPIUUID)
	newHash := computeAPIHash(desiredAPI)

	currentHash, apiExists := discoverPkg.APIHashMap[kongAPIUUID]

	if !apiExists || currentHash != newHash {
		loggers.LoggerWatcher.Infof("API %s has changed (new hash: %s). Updating...", kongAPIUUID, newHash)

		revisionID := generateRevisionID()
		desiredAPI.RevisionID = revisionID

		serviceLabels := map[string]string{
			constants.RevisionIDLabel:  revisionID,
			constants.KongAPIUUIDLabel: kongAPIUUID,
			constants.APINameLabel:     desiredAPI.APIName,
		}
		if _, found := service.GetLabels()[constants.EnvironmentLabel]; !found {
			serviceLabels[constants.EnvironmentLabel] = constants.EnvironmentProduction
		}
		updateServiceLabels(service, serviceLabels)

		for _, route := range httpRoutes {
			routeLabels := map[string]string{
				constants.RevisionIDLabel:  revisionID,
				constants.KongAPIUUIDLabel: kongAPIUUID,
				constants.APINameLabel:     desiredAPI.APIName,
			}
			if _, found := route.GetLabels()[constants.EnvironmentLabel]; !found {
				routeLabels[constants.EnvironmentLabel] = constants.DefaultEnvironment
			}
			updateHTTPRouteLabels(route, routeLabels)
		}

		discoverPkg.APIHashMap[kongAPIUUID] = newHash
		discoverPkg.APIMap[kongAPIUUID] = desiredAPI
		discoverPkg.QueueEvent(managementserver.CreateEvent, desiredAPI, serviceName, namespace, constants.DefaultKongAgentName)

		loggers.LoggerWatcher.Infof("Successfully reconciled and updated API %s for Service %s/%s", kongAPIUUID, namespace, serviceName)
	} else {
		loggers.LoggerWatcher.Infof("API %s is unchanged (hash match). Skipping update.", kongAPIUUID)
	}
}

// InitializeServicesState fetches all existing Services and populates serviceMap
func InitializeServicesState(namespace string) {
	loggers.LoggerWatcher.Infof("Starting Services state initialization")

	if namespace == constants.EmptyString {
		loggers.LoggerWatcher.Error("Namespace cannot be empty for Services state initialization")
		return
	}

	if CRWatcher == nil || CRWatcher.DynamicClient == nil {
		loggers.LoggerWatcher.Error("CRWatcher or DynamicClient is not initialized")
		return
	}

	serviceList, err := CRWatcher.DynamicClient.Resource(constants.ServiceGVR).Namespace(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to list Services in namespace %s: %v", namespace, err)
		return
	}

	if len(serviceList.Items) == 0 {
		loggers.LoggerWatcher.Infof("No Services found in namespace %s", namespace)
		return
	}

	for i := range serviceList.Items {
		if !IsControlPlaneInitiated(&serviceList.Items[i]) {
			ReconcileAPI(namespace, serviceList.Items[i].GetName())
		}
	}

	loggers.LoggerWatcher.Infof("Completed Services state initialization for namespace %s, processed %d services", namespace, len(serviceList.Items))
}

// handleAddServiceResource handles the addition of a Service
func handleAddServiceResource(service *unstructured.Unstructured) {
	loggers.LoggerWatcher.Infof("Processing new Service addition: %s/%s (Generation: %d, ResourceVersion: %s)",
		service.GetNamespace(), service.GetName(), service.GetGeneration(), service.GetResourceVersion())
	ReconcileAPI(service.GetNamespace(), service.GetName())
}

// handleUpdateServiceResource handles the update of an Service
func handleUpdateServiceResource(_, service *unstructured.Unstructured) {
	loggers.LoggerWatcher.Infof("Processing Service modification: %s/%s (Generation: %d, ResourceVersion: %s)",
		service.GetNamespace(), service.GetName(), service.GetGeneration(), service.GetResourceVersion())
	ReconcileAPI(service.GetNamespace(), service.GetName())
}

// handleDeleteServiceResource handles the deletion of an Service
func handleDeleteServiceResource(service *unstructured.Unstructured) {
	loggers.LoggerWatcher.Infof("Processing Service deletion: %s/%s (Generation: %d, ResourceVersion: %s)",
		service.GetNamespace(), service.GetName(), service.GetGeneration(), service.GetResourceVersion())

	kongAPIUUID, hasKongAPIUUID := service.GetLabels()[constants.KongAPIUUIDLabel]
	if !hasKongAPIUUID {
		loggers.LoggerWatcher.Warnf("Deleted Service %s/%s has no kongAPIUUID label, cannot delete corresponding API.",
			service.GetNamespace(), service.GetName())
		return
	}

	apiMutex.Lock()
	defer apiMutex.Unlock()

	if api, exists := discoverPkg.APIMap[kongAPIUUID]; exists {
		delete(discoverPkg.APIMap, kongAPIUUID)
		delete(discoverPkg.APIHashMap, kongAPIUUID)
		discoverPkg.QueueEvent(managementserver.DeleteEvent, api, service.GetName(), service.GetNamespace(), constants.DefaultKongAgentName)
		loggers.LoggerWatcher.Infof("Successfully processed %s/%s service deletion - API %s removed from system",
			service.GetNamespace(), service.GetName(), kongAPIUUID)
	}
}

// shouldSkipResource checks if a resource should be skipped based on labels
func shouldSkipResource(resource *unstructured.Unstructured) bool {
	if resource == nil {
		return true
	}

	showInCP, hasShowInCP := resource.GetLabels()[constants.ShowInCPLabel]
	return hasShowInCP && showInCP == constants.DefaultShowInCPFalse
}

// getOrGenerateKongAPIUUID gets existing API UUID from service or generates a new one
func getOrGenerateKongAPIUUID(service, httpRoute *unstructured.Unstructured) string {

	kongAPIUUID, hasKongAPIUUID := service.GetLabels()[constants.KongAPIUUIDLabel]
	if !hasKongAPIUUID {
		kongAPIUUID = uuid.New().String()
		loggers.LoggerWatcher.Infof("Generated kongAPIUUID %s for HTTPRoute %s/%s", kongAPIUUID, service.GetNamespace(), service.GetName())
	}
	return kongAPIUUID
}

// getAPIVersion gets existing API version from service or sets default
func getAPIVersion(service, httpRoute *unstructured.Unstructured) string {

	apiVersion, hasApiVersion := service.GetLabels()[constants.APIVersionLabel]
	if !hasApiVersion {
		apiVersion = constants.DefaultAPIVersion
	}
	return apiVersion
}

// computeAPIHash generates a hash of the discoverPkg.API struct for comparison
func computeAPIHash(api managementserver.API) string {
	data := fmt.Sprintf("%v%v%v%v%v%v%v", api.APIName, api.Operations, api.CORSPolicy, api.ProdAIRL, api.SandAIRL, api.Environment, api.ProdEndpoint)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generateRevisionID creates a unique revision ID
func generateRevisionID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func updateServiceLabels(u *unstructured.Unstructured, labelsToSet map[string]string) {
	updateResourceLabels(u, constants.ServiceGVR, constants.ServiceKind, labelsToSet)
}

// updateAPIFromService merges Service data into an existing discoverPkg.API
func updateAPIFromService(api *managementserver.API, service *unstructured.Unstructured) {
	loggers.LoggerWatcher.Debugf("Updating API from Service|%s/%s\n", service.GetNamespace(), service.GetName())

	apiName, apiNameFound := service.GetLabels()[constants.APINameLabel]
	if apiNameFound && apiName != constants.EmptyString {
		api.APIName = apiName
	} else {
		api.APIName = service.GetName()
	}

	if organization, found := service.GetLabels()[constants.OrganizationLabel]; found {
		api.Organization = organization
	}

	endpoint := generateServiceEndpoint(service)
	if endpoint != constants.EmptyString {
		loggers.LoggerWatcher.Debugf("Generated endpoint: %s for Service %s/%s", endpoint, service.GetNamespace(), service.GetName())
		api.ProdEndpoint = endpoint
	}
}

// generateServiceEndpoint generates the endpoint URL based on service type and configuration
func generateServiceEndpoint(service *unstructured.Unstructured) string {

	var port int64
	if ports, found, err := unstructured.NestedSlice(service.Object, constants.SpecField, constants.ServiceSpecPorts); err == nil && found && len(ports) > 0 {
		loggers.LoggerWatcher.Debugf("Found %d port(s) for Service %s/%s, using the first one", len(ports), service.GetNamespace(), service.GetName())
		if portMap, ok := ports[0].(map[string]interface{}); ok {
			if portValue, found, err := unstructured.NestedInt64(portMap, constants.PortField); err == nil && found {
				port = portValue
				loggers.LoggerWatcher.Debugf("Found port: %d for Service %s/%s", port, service.GetNamespace(), service.GetName())
			}
		}
	}

	protocol := constants.HTTPProtocol
	if port == constants.HTTPSPort {
		protocol = constants.HTTPSProtocol
	}
	if annotations := service.GetAnnotations(); annotations != nil {
		if prot, found := annotations[constants.KongProtocolAnnotation]; found && prot != constants.EmptyString {
			protocol = prot
			loggers.LoggerWatcher.Debugf("Found protocol annotation: %s for Service %s/%s", protocol, service.GetNamespace(), service.GetName())
		}
	}

	var serviceType string
	if svcType, found, err := unstructured.NestedString(service.Object, constants.SpecField, constants.ServiceSpecType); err == nil && found && svcType != constants.EmptyString {
		serviceType = svcType
		loggers.LoggerWatcher.Debugf("Found service type: %s for Service %s/%s", serviceType, service.GetNamespace(), service.GetName())
	}

	var host string
	var finalPort string

	switch serviceType {
	case constants.ServiceTypeExternalName:
		if externalName, found, err := unstructured.NestedString(service.Object, constants.SpecField, constants.ServiceSpecExternalName); err == nil && found && externalName != constants.EmptyString {
			loggers.LoggerWatcher.Debugf("Found externalName: %s for Service %s/%s", externalName, service.GetNamespace(), service.GetName())
			host = externalName
		} else {
			loggers.LoggerWatcher.Warnf("ExternalName service %s/%s has no externalName specified", service.GetNamespace(), service.GetName())
			return constants.EmptyString
		}

	case constants.ServiceTypeNodePort:
		if ports, found, err := unstructured.NestedSlice(service.Object, constants.SpecField, constants.ServiceSpecPorts); err == nil && found && len(ports) > 0 {
			if portMap, ok := ports[0].(map[string]interface{}); ok {
				if nodePort, found, err := unstructured.NestedInt64(portMap, constants.NodePortField); err == nil && found {
					port = nodePort
					loggers.LoggerWatcher.Debugf("Found nodePort: %d for Service %s/%s", nodePort, service.GetNamespace(), service.GetName())
				}
			}
		}

		nodeIP := getNodeIP()
		if nodeIP != constants.EmptyString {
			host = nodeIP
			loggers.LoggerWatcher.Debugf("Using node IP: %s for NodePort service %s/%s", nodeIP, service.GetNamespace(), service.GetName())
		} else {
			loggers.LoggerWatcher.Warnf("Could not determine node IP for NodePort service %s/%s", service.GetNamespace(), service.GetName())
			return constants.EmptyString
		}

	case constants.ServiceTypeLoadBalancer:
		if status, found, err := unstructured.NestedMap(service.Object, constants.StatusPath); err == nil && found {
			if lbStatus, found, err := unstructured.NestedMap(status, constants.LoadBalancerPath); err == nil && found {
				if ingress, found, err := unstructured.NestedSlice(lbStatus, constants.LoadBalancerIngress); err == nil && found && len(ingress) > 0 {
					var hostnames, ips []string

					for i, ing := range ingress {
						if ingressMap, ok := ing.(map[string]interface{}); ok {
							if hostname, found := ingressMap[constants.IngressHostnameField].(string); found && hostname != constants.EmptyString {
								hostnames = append(hostnames, hostname)
								loggers.LoggerWatcher.Debugf("Found LoadBalancer hostname: %s (ingress %d) for Service %s/%s", hostname, i, service.GetNamespace(), service.GetName())
							}
							if ip, found := ingressMap[constants.IngressIPField].(string); found && ip != constants.EmptyString {
								ips = append(ips, ip)
								loggers.LoggerWatcher.Debugf("Found LoadBalancer IP: %s (ingress %d) for Service %s/%s", ip, i, service.GetNamespace(), service.GetName())
							}
						}
					}

					if len(hostnames) > 0 {
						host = hostnames[0]
						loggers.LoggerWatcher.Infof("Selected LoadBalancer hostname: %s from %d available hostnames: %v", host, len(hostnames), hostnames)
					} else if len(ips) > 0 {
						host = ips[0]
						loggers.LoggerWatcher.Infof("Selected LoadBalancer IP: %s from %d available IPs: %v", host, len(ips), ips)
					}
				}
			}
		}

		if host == constants.EmptyString {
			loggers.LoggerWatcher.Warnf("LoadBalancer service %s/%s has no external address available yet", service.GetNamespace(), service.GetName())
			return constants.EmptyString
		}

	case constants.ServiceTypeClusterIP:
	default:
		host = fmt.Sprintf(constants.ServiceDNSTemplate, service.GetName(), service.GetNamespace())
	}

	if (protocol == constants.HTTPProtocol && port == constants.HTTPPort) || (protocol == constants.HTTPSProtocol && port == constants.HTTPSPort) {
		finalPort = constants.EmptyString
	} else if port > 0 {
		finalPort = fmt.Sprintf(":%d", port)
	}

	if host == constants.EmptyString {
		return constants.EmptyString
	}

	return fmt.Sprintf("%s://%s%s", protocol, host, finalPort)
}

// getNodeIP retrieves the external or internal IP of the first available node
func getNodeIP() string {
	loggers.LoggerWatcher.Debugf("Fetching node IP addresses for NodePort service")

	list, err := CRWatcher.DynamicClient.Resource(constants.NodesGVR).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to list nodes: %v", err)
		return constants.EmptyString
	}

	if len(list.Items) == 0 {
		loggers.LoggerWatcher.Warnf("No nodes found in the cluster")
		return constants.EmptyString
	}

	var externalIPs, internalIPs []string

	for _, node := range list.Items {
		if addresses, found, err := unstructured.NestedSlice(node.Object, constants.StatusPath, constants.NodeStatusAddresses); err == nil && found {
			var nodeExternalIP, nodeInternalIP string

			for _, addr := range addresses {
				if addrMap, ok := addr.(map[string]interface{}); ok {
					addrType, typeOk := addrMap[constants.AddressTypeField].(string)
					addrValue, valueOk := addrMap[constants.AddressValueField].(string)

					if typeOk && valueOk {
						switch addrType {
						case constants.NodeExternalIPType:
							nodeExternalIP = addrValue
						case constants.NodeInternalIPType:
							if nodeInternalIP == constants.EmptyString {
								nodeInternalIP = addrValue
							}
						}
					}
				}
			}

			if nodeExternalIP != constants.EmptyString {
				externalIPs = append(externalIPs, nodeExternalIP)
				loggers.LoggerWatcher.Debugf("Found external IP: %s for node %s", nodeExternalIP, node.GetName())
			}
			if nodeInternalIP != constants.EmptyString {
				internalIPs = append(internalIPs, nodeInternalIP)
				loggers.LoggerWatcher.Debugf("Found internal IP: %s for node %s", nodeInternalIP, node.GetName())
			}
		}
	}

	if len(externalIPs) > 0 {
		selectedIP := externalIPs[0]
		loggers.LoggerWatcher.Debugf("Selected external IP: %s from %d available external IPs: %v", selectedIP, len(externalIPs), externalIPs)
		return selectedIP
	}
	if len(internalIPs) > 0 {
		selectedIP := internalIPs[0]
		loggers.LoggerWatcher.Debugf("Selected internal IP: %s from %d available internal IPs: %v", selectedIP, len(internalIPs), internalIPs)
		return selectedIP
	}

	loggers.LoggerWatcher.Warnf("No suitable IP address found for any node")
	return constants.EmptyString
}

// FetchAllHTTPRoutesWithServiceName fetches all HTTPRoutes that reference a specific service name in their backendRefs
func FetchAllHTTPRoutesWithServiceName(namespace, serviceName string) []*unstructured.Unstructured {
	loggers.LoggerWatcher.Infof("Fetching all HTTPRoutes that reference service: %s in namespace: %s", serviceName, namespace)

	list, err := CRWatcher.DynamicClient.Resource(constants.HTTPRouteGVR).Namespace(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to list HTTPRoutes in namespace %s: %v", namespace, err)
		return []*unstructured.Unstructured{}
	}

	var matchingRoutes []*unstructured.Unstructured

	for i := range list.Items {
		route := &list.Items[i]

		if shouldSkipResource(route) {
			continue
		}

		if httpRouteReferencesService(route, serviceName) {
			matchingRoutes = append(matchingRoutes, route)
			loggers.LoggerWatcher.Debugf("HTTPRoute %s/%s references service %s", route.GetNamespace(), route.GetName(), serviceName)
		} else {
			loggers.LoggerWatcher.Debugf("HTTPRoute %s/%s does not reference service %s", route.GetNamespace(), route.GetName(), serviceName)
		}
	}

	return matchingRoutes
}

// httpRouteReferencesService checks if an HTTPRoute references a specific service in its backendRefs
func httpRouteReferencesService(httpRoute *unstructured.Unstructured, serviceName string) bool {
	serviceNames := getHTTPRouteReferencedServices(httpRoute)
	return slices.Contains(serviceNames, serviceName)
}

// getHTTPRouteReferencedServices returns all service names that an HTTPRoute references in its backendRefs
func getHTTPRouteReferencedServices(httpRoute *unstructured.Unstructured) []string {
	loggers.LoggerWatcher.Debugf("Getting all service references from HTTPRoute %s/%s", httpRoute.GetNamespace(), httpRoute.GetName())
	var serviceNames []string
	rules, found, err := unstructured.NestedSlice(httpRoute.Object, constants.SpecField, constants.RulesField)
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to access rules for HTTPRoute %s/%s: %v", httpRoute.GetNamespace(), httpRoute.GetName(), err)
		return serviceNames
	}
	if !found || len(rules) == 0 {
		loggers.LoggerWatcher.Debugf("No rules found for HTTPRoute %s/%s", httpRoute.GetNamespace(), httpRoute.GetName())
		return serviceNames
	}

	for ruleIndex, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			loggers.LoggerWatcher.Debugf("Rule %d in HTTPRoute %s/%s is not a map, skipping", ruleIndex, httpRoute.GetNamespace(), httpRoute.GetName())
			continue
		}

		backendRefsSlice, found, err := unstructured.NestedSlice(ruleMap, constants.BackendRefsField)
		if err != nil || !found {
			loggers.LoggerWatcher.Debugf("No backendRefs found in rule %d for HTTPRoute %s/%s", ruleIndex, httpRoute.GetNamespace(), httpRoute.GetName())
			continue
		}

		for backendIndex, backend := range backendRefsSlice {
			backendMap, ok := backend.(map[string]interface{})
			if !ok {
				loggers.LoggerWatcher.Debugf("BackendRef %d in rule %d is not a map, skipping", backendIndex, ruleIndex)
				continue
			}

			if name, ok := backendMap[constants.NameField].(string); ok {
				kind := constants.ServiceKind
				if k, ok := backendMap[constants.KindField].(string); ok {
					kind = k
				}

				if kind == constants.ServiceKind {
					found := false
					for _, existing := range serviceNames {
						if existing == name {
							found = true
							break
						}
					}
					if !found {
						serviceNames = append(serviceNames, name)
						loggers.LoggerWatcher.Debugf("Found service reference: %s in HTTPRoute %s/%s (rule %d, backendRef %d)",
							name, httpRoute.GetNamespace(), httpRoute.GetName(), ruleIndex, backendIndex)
					}
				}
			}
		}
	}

	loggers.LoggerWatcher.Debugf("HTTPRoute %s/%s references %d services: %v", httpRoute.GetNamespace(), httpRoute.GetName(), len(serviceNames), serviceNames)
	return serviceNames
}

// FetchServiceByName retrieves a specific Service by name from a given namespace
func FetchServiceByName(namespace, serviceName string) *unstructured.Unstructured {
	loggers.LoggerWatcher.Debugf("Fetching Service: %s in namespace: %s", serviceName, namespace)

	service, err := CRWatcher.DynamicClient.Resource(constants.ServiceGVR).Namespace(namespace).Get(context.Background(), serviceName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			loggers.LoggerWatcher.Debugf("Service %s/%s not found. It may have been deleted.", namespace, serviceName)
		} else {
			loggers.LoggerWatcher.Errorf("Error fetching Service %s/%s: %v", namespace, serviceName, err)
		}
		return nil
	}

	loggers.LoggerWatcher.Infof("Successfully fetched Service %s/%s (Generation: %d, ResourceVersion: %s)",
		namespace, serviceName, service.GetGeneration(), service.GetResourceVersion())

	if service.GetName() == serviceName {
		loggers.LoggerWatcher.Debugf("Service name verification passed: %s", serviceName)
		return service
	} else {
		loggers.LoggerWatcher.Warnf("Service name mismatch: expected %s, got %s", serviceName, service.GetName())
		return nil
	}
}

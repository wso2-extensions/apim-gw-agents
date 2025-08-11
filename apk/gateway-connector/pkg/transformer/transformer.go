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

/*
 * Package "transformer" contains functions related to converting
 * API project to apk-conf and generating and modifying CRDs belonging to
 * a particular API.
 */

package transformer

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"io"
	"mime/multipart"
	"net/http"

	gatewayv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	eventHub "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/transformer"

	dpv2alpha1 "github.com/wso2/apk/common-go-libs/apis/dp/v2alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gwapiv1a3 "sigs.k8s.io/gateway-api/apis/v1alpha3"

	logger "github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/pkg/loggers"
	k8Yaml "sigs.k8s.io/yaml"

	"gopkg.in/yaml.v2"
)

// GenerateCRs takes the .apk-conf, api definition, vHost and the organization for a particular API and then generate and returns
// the relavant CRD set as a zip
func GenerateCRs(apkConf string, apiDefinition string, certContainer transformer.CertContainer, k8ResourceGenEndpoint string, organizationID string) (*K8sArtifacts, error) {
	k8sArtifact := K8sArtifacts{HTTPRoutes: make(map[string]*gwapiv1.HTTPRoute), Backends: make(map[string]*gatewayv1alpha1.Backend), ConfigMaps: make(map[string]*corev1.ConfigMap), Secrets: make(map[string]*corev1.Secret), RouteMetadata: make(map[string]*dpv2alpha1.RouteMetadata), SecurityPolicies: make(map[string]*gatewayv1alpha1.SecurityPolicy), BackendTLSPolicies: make(map[string]*gwapiv1a3.BackendTLSPolicy), RoutePolicies: make(map[string]*dpv2alpha1.RoutePolicy), EnvoyExtensionPolicies: make(map[string]*gatewayv1alpha1.EnvoyExtensionPolicy), BackendTrafficPolicies: make(map[string]*gatewayv1alpha1.BackendTrafficPolicy), GRPCRoutes: make(map[string]*gwapiv1a2.GRPCRoute)}
	if apkConf == "" {
		logger.LoggerTransformer.Error("Empty apk-conf parameter provided. Unable to generate CRDs.")
		return nil, errors.New("Error: APK-Conf can't be empty")
	}

	if apiDefinition == "" {
		logger.LoggerTransformer.Error("Empty api definition provided. Unable to generate CRDs.")
		return nil, errors.New("Error: API Definition can't be empty")
	}

	// Create a buffer to store the request body
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// Add apkConfiguration field and store the passed APK Conf file
	if err := writer.WriteField("apkConfiguration", apkConf); err != nil {
		logger.LoggerTransformer.Error("Error writing apkConfiguration field:", err)
		return nil, err
	}

	// Add apiDefinition field and store the passed API Definition file
	if err := writer.WriteField("definitionFile", apiDefinition); err != nil {
		logger.LoggerTransformer.Error("Error writing definitionFile field:", err)
		return nil, err
	}

	// Close the multipart writer
	writer.Close()

	k8sResourceEndpointWithOrg := k8ResourceGenEndpoint + "?organization=" + organizationID

	// Create the HTTP request
	request, err := http.NewRequest(postHTTPMethod, k8sResourceEndpointWithOrg, &requestBody)
	if err != nil {
		logger.LoggerTransformer.Error("Error creating HTTP request:", err)
		return nil, err
	}

	// Set the Content-Type header
	request.Header.Set(contentTypeHeader, writer.FormDataContentType())
	// Certificate validation is turned off as linkerd would be used for mTLS between the two components
	tr := &http.Transport{
		/* #nosec */
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Make the request
	client := &http.Client{Transport: tr}

	response, err := client.Do(request)
	if err != nil {
		logger.LoggerTransformer.Error("Error making HTTP request:", err)
		return nil, err
	}

	defer response.Body.Close()

	// Check the HTTP status code
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		logger.LoggerTransformer.Errorf("HTTP request failed with status code: %d", response.StatusCode)
		return nil, fmt.Errorf("HTTP request failed with status code: %v", response.Body)
	}

	//Extracting response body to get the CRD zipfile
	body, err := io.ReadAll(response.Body)
	if err != nil {
		logger.LoggerTransformer.Error("Error reading response body:", err)
		panic(err)
	}
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		logger.LoggerTransformer.Error("Unable to transform the initial CRDs:", err)
		return nil, err
	}
	for _, zipFile := range zipReader.File {
		fileReader, err := zipFile.Open()
		if err != nil {
			logger.LoggerTransformer.Errorf("Failed to open YAML file inside zip: %v", err)
			return nil, err
		}
		defer fileReader.Close()

		yamlData, err := io.ReadAll(fileReader)
		if err != nil {
			logger.LoggerTransformer.Errorf("Failed to read YAML file inside zip: %v", err)
			return nil, err
		}

		var crdData map[string]interface{}
		if err := yaml.Unmarshal(yamlData, &crdData); err != nil {
			logger.LoggerTransformer.Errorf("Failed to unmarshal YAML data to parse the Kind: %v", err)
			return nil, err
		}

		kind, ok := crdData["kind"].(string)
		if !ok {
			logger.LoggerTransformer.Errorf("Kind attribute not found in the given yaml file.")
			return nil, err
		}

		switch kind {
		case "HTTPRoute":
			var httpRoute gwapiv1.HTTPRoute
			err = k8Yaml.Unmarshal(yamlData, &httpRoute)
			if err != nil {
				logger.LoggerSync.Errorf("Error unmarshaling HTTPRoute YAML: %v", err)
				continue
			}
			k8sArtifact.HTTPRoutes[httpRoute.ObjectMeta.Name] = &httpRoute

		case "Backend":
			var backend gatewayv1alpha1.Backend
			err = k8Yaml.Unmarshal(yamlData, &backend)
			if err != nil {
				logger.LoggerSync.Errorf("Error unmarshaling Backend YAML: %v", err)
				continue
			}
			k8sArtifact.Backends[backend.ObjectMeta.Name] = &backend

		case "ConfigMap":
			var configMap corev1.ConfigMap
			err = k8Yaml.Unmarshal(yamlData, &configMap)
			if err != nil {
				logger.LoggerSync.Errorf("Error unmarshaling ConfigMap YAML: %v", err)
				continue
			}
			k8sArtifact.ConfigMaps[configMap.ObjectMeta.Name] = &configMap

		case "Secret":
			var secret corev1.Secret
			err = k8Yaml.Unmarshal(yamlData, &secret)
			if err != nil {
				logger.LoggerSync.Errorf("Error unmarshaling Secret YAML: %v", err)
				continue
			}
			k8sArtifact.Secrets[secret.Name] = &secret

		case "SecurityPolicy":
			var securityPolicy gatewayv1alpha1.SecurityPolicy
			err = k8Yaml.Unmarshal(yamlData, &securityPolicy)
			if err != nil {
				logger.LoggerSync.Errorf("Error unmarshaling SecurityPolicy YAML: %v", err)
				continue
			}
			k8sArtifact.SecurityPolicies[securityPolicy.Name] = &securityPolicy

		case "BackendTrafficPolicy":
			var backendTrafficPolicy gatewayv1alpha1.BackendTrafficPolicy
			err = k8Yaml.Unmarshal(yamlData, &backendTrafficPolicy)
			if err != nil {
				logger.LoggerSync.Errorf("Error unmarshaling BackendTrafficPolicy YAML: %v", err)
				continue
			}
			k8sArtifact.BackendTrafficPolicies[backendTrafficPolicy.Name] = &backendTrafficPolicy

		case "BackendTLSPolicy":
			var backendTLSPolicy gwapiv1a3.BackendTLSPolicy
			err = k8Yaml.Unmarshal(yamlData, &backendTLSPolicy)
			if err != nil {
				logger.LoggerSync.Errorf("Error unmarshaling BackendTLSPolicy YAML: %v", err)
				continue
			}
			k8sArtifact.BackendTLSPolicies[backendTLSPolicy.Name] = &backendTLSPolicy

		case "RoutePolicy":
			var routePolicy dpv2alpha1.RoutePolicy
			err = k8Yaml.Unmarshal(yamlData, &routePolicy)
			if err != nil {
				logger.LoggerSync.Errorf("Error unmarshaling RoutePolicy YAML: %v", err)
				continue
			}
			k8sArtifact.RoutePolicies[routePolicy.Name] = &routePolicy

		case "EnvoyExtensionPolicy":
			var envoyExtensionPolicy gatewayv1alpha1.EnvoyExtensionPolicy
			err = k8Yaml.Unmarshal(yamlData, &envoyExtensionPolicy)
			if err != nil {
				logger.LoggerSync.Errorf("Error unmarshaling EnvoyExtensionPolicy YAML: %v", err)
				continue
			}
			k8sArtifact.EnvoyExtensionPolicies[envoyExtensionPolicy.Name] = &envoyExtensionPolicy

		case "RouteMetadata":
			var routeMetadata dpv2alpha1.RouteMetadata
			err = k8Yaml.Unmarshal(yamlData, &routeMetadata)
			if err != nil {
				logger.LoggerSync.Errorf("Error unmarshaling RouteMetadata YAML: %v", err)
				continue
			}
			k8sArtifact.RouteMetadata[routeMetadata.Name] = &routeMetadata

		case "GRPCRoute":
			var grpcRoute gwapiv1a2.GRPCRoute
			err = k8Yaml.Unmarshal(yamlData, &grpcRoute)
			if err != nil {
				logger.LoggerSync.Errorf("Error unmarshaling GRPCRoute YAML: %v", err)
				continue
			}
			k8sArtifact.GRPCRoutes[grpcRoute.Name] = &grpcRoute
		default:
			logger.LoggerSync.Errorf("[!]Unknown Kind parsed from the YAML File: %v", kind)
		}
	}
	// Create ConfigMap to store the cert data if mTLS has enabled
	if certContainer.ClientCertObj.CertAvailable {
		createConfigMaps(certContainer.ClientCertObj.ClientCertFiles, &k8sArtifact)
	}

	// Create ConfigMap to store the cert data if endpoint security has enabled
	if certContainer.EndpointCertObj.CertAvailable {
		createConfigMaps(certContainer.EndpointCertObj.EndpointCertFiles, &k8sArtifact)
	}

	createEndpointSecrets(certContainer.SecretData, &k8sArtifact)

	return &k8sArtifact, nil
}

// UpdateCRS cr update
func UpdateCRS(k8sArtifact *K8sArtifacts, environments *[]transformer.Environment, organizationID string, apiUUID string, revisionID string, namespace string, configuredRateLimitPoliciesMap map[string]eventHub.RateLimitPolicy) {
	addOrganization(k8sArtifact, organizationID)
	addRevisionAndAPIUUID(k8sArtifact, apiUUID, revisionID)
	// Create a in-memory map to store routemeta names and their associated deployemnt envs
	deploymentTypeMap := make(map[string]string)
	for _, routemetadata := range k8sArtifact.RouteMetadata {
		routemetaName := routemetadata.Name
		if deploymentTypeMap[routemetaName] == "" {
			deploymentTypeMap[routemetaName] = routemetadata.Spec.API.Environment
			logger.LoggerTransformer.Infof("RouteMetadata Name: %s | Deployment Type: %s", routemetadata.Name, routemetadata.Spec.API.Environment)
		} else {
			if deploymentTypeMap[routemetaName] != routemetadata.Spec.API.Environment {
				logger.LoggerTransformer.Errorf("Environment mismatch for RouteMetadata: %s", routemetaName)
			}
		}
	}

	for _, environment := range *environments {
		replaceVhost(k8sArtifact, environment.Vhost, environment.Type)
	}
	// addRateLimitPolicyNames(k8sArtifact, configuredRateLimitPoliciesMap)
}

func replaceVhost(k8sArtifact *K8sArtifacts, vhost string, deploymentType string) {
	// Append sandbox. part to available vhost to generate sandbox vhost
	// Need to check whether the httproute refer to sandbox routemeta or production routemeta
	for _, httproute := range k8sArtifact.HTTPRoutes {
		for _, rule := range httproute.Spec.Rules {
			for _, filter := range rule.Filters {
				if filter.Type == "ExtensionRef" && filter.ExtensionRef != nil && filter.ExtensionRef.Kind == "RouteMetadata" {
					if filter.ExtensionRef.Name == "sandbox" {
						httproute.Spec.Hostnames = []gwapiv1.Hostname{gwapiv1.Hostname("sandbox." + vhost)}
					} else {
						httproute.Spec.Hostnames = []gwapiv1.Hostname{gwapiv1.Hostname(vhost)}
					}
				}
			}
		}
	}
	// TODO: GQLRoutes are not supported in the new envoy config. Check if there any additional
	// modifications are needed for that
}

// addOrganization will take the API CR and change the organization to the one passed inside
// the deploymemt descriptor
func addOrganization(k8sArtifact *K8sArtifacts, organization string) {
	organizationHash := generateSHA1Hash(organization)
	for _, routemetadata := range k8sArtifact.RouteMetadata {
		routemetadata.Spec.API.Organization = organization
		routemetadata.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
	}
	for _, httproutes := range k8sArtifact.HTTPRoutes {
		httproutes.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
	}
	for _, securitypolicy := range k8sArtifact.SecurityPolicies {
		securitypolicy.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
	}
	for _, backend := range k8sArtifact.Backends {
		backend.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
	}
	for _, backendTLSPolicy := range k8sArtifact.BackendTLSPolicies {
		backendTLSPolicy.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
	}
	for _, routePolicy := range k8sArtifact.RoutePolicies {
		routePolicy.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
	}
	for _, envoyExtensionPolicy := range k8sArtifact.EnvoyExtensionPolicies {
		envoyExtensionPolicy.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
	}
	for _, backendTrafficPolicy := range k8sArtifact.BackendTrafficPolicies {
		backendTrafficPolicy.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
	}
	for _, grpcRoute := range k8sArtifact.GRPCRoutes {
		grpcRoute.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
	}
	for _, configMap := range k8sArtifact.ConfigMaps {
		configMap.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
	}
	for _, secret := range k8sArtifact.Secrets {
		secret.ObjectMeta.Labels[k8sOrganizationField] = organizationHash
	}
}

// addRevisionAndAPIUUID will add the API ID and the revision field attributes to the API CR
func addRevisionAndAPIUUID(k8sArtifact *K8sArtifacts, apiID string, revisionID string) {
	for _, routemetadata := range k8sArtifact.RouteMetadata {
		routemetadata.ObjectMeta.Labels[k8APIUuidField] = apiID
		routemetadata.ObjectMeta.Labels[k8RevisionField] = revisionID
	}
}

// addRateLimitPolicyNames will add the rate limit policy names to the respective CRs
// func addRateLimitPolicyNames(k8sArtifact *K8sArtifacts, configuredRateLimitPoliciesMap map[string]eventHub.RateLimitPolicy) {
// 	logger.LoggerTransformer.Infof("Rate Limit Policies: %v", configuredRateLimitPoliciesMap)
// 	for _, rateLimitPolicy := range k8sArtifact.RateLimitPolicies {
// 		if strings.Contains(rateLimitPolicy.Name, "api-") {
// 			rateLimitPolicy.ObjectMeta.Labels[k8sRateLimitPolicyNameField] = generateSHA1Hash(configuredRateLimitPoliciesMap["API"].Name)
// 			logger.LoggerTransformer.Infof("Rate Limit Policy Name: %v", rateLimitPolicy.ObjectMeta.Labels[k8sRateLimitPolicyNameField])
// 		} else if strings.Contains(rateLimitPolicy.Name, "resource-") {
// 			rateLimitPolicy.ObjectMeta.Labels[k8sRateLimitPolicyNameField] = generateSHA1Hash(configuredRateLimitPoliciesMap["Resource"].Name)
// 			logger.LoggerTransformer.Infof("Rate Limit Policy Name: %v", rateLimitPolicy.ObjectMeta.Labels[k8sRateLimitPolicyNameField])
// 		}
// 	}
// }

// generateSHA1Hash returns the SHA1 hash for the given string
func generateSHA1Hash(input string) string {
	h := sha1.New() /* #nosec */
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

// createConfigMaps returns a marshalled yaml of ConfigMap kind after adding the given values
func createConfigMaps(certFiles map[string]string, k8sArtifact *K8sArtifacts) {
	apiName := getAPINameFromRouteMetadata(k8sArtifact)
	for confKey, confValue := range certFiles {
		pathSegments := strings.Split(confKey, ".")
		configName := pathSegments[0]

		//TODO: Have to take the version, namespace as parameters instead of hardcoding
		cm := corev1.ConfigMap{}
		cm.APIVersion = "v1"
		cm.Kind = "ConfigMap"
		cm.ObjectMeta.Name = apiName + "-" + configName

		if cm.ObjectMeta.Labels == nil {
			cm.ObjectMeta.Labels = make(map[string]string)
		}

		if cm.Data == nil {
			cm.Data = make(map[string]string)
		}
		apimCert := confValue
		// Remove "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----" strings
		pemCert := strings.ReplaceAll(apimCert, "-----BEGIN CERTIFICATE-----", "")
		pemCert = strings.ReplaceAll(pemCert, "-----END CERTIFICATE-----", "")
		pemCert = strings.TrimSpace(pemCert)
		// Decode the Base64 encoded certificate content
		decodedCert, err := base64.StdEncoding.DecodeString(pemCert)
		logger.LoggerTransformer.Debugf("Decoded Certificate: %v", decodedCert)
		if err != nil {
			logger.LoggerTransformer.Errorf("Error decoding the certificate: %v", err)
		}
		cm.Data[confKey] = string(decodedCert)
		certConfigMap := &cm

		logger.LoggerTransformer.Debugf("New ConfigMap Data: %v", *certConfigMap)
		k8sArtifact.ConfigMaps[certConfigMap.ObjectMeta.Name] = certConfigMap
	}
}

// createEndpointSecrets creates and links the secret CRs need to be created for handling the endpoint security
func createEndpointSecrets(secretDataList []transformer.EndpointSecurityConfig, k8sArtifact *K8sArtifacts) {
	apiName := getAPINameFromRouteMetadata(k8sArtifact)
	createSecret := func(environment string, username, password string, apiKeyValue string, securityType string, endpointUUID string) {
		var secret corev1.Secret
		if securityType == "apikey" {
			secret = corev1.Secret{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      strings.Join([]string{apiName, generateSHA1Hash(endpointUUID), environment, "secret"}, "-"),
					Namespace: "default", //This shouold be changed to get it from configs ->Ex: k8sArtifact.API.Namespace
					Labels:    make(map[string]string),
				},
				Data: map[string][]byte{
					"apiKey": []byte(apiKeyValue),
				},
			}
		} else {
			secret = corev1.Secret{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      strings.Join([]string{apiName, generateSHA1Hash(endpointUUID), environment, "secret"}, "-"),
					Namespace: "default", //This shouold be changed to get it from configs ->Ex: k8sArtifact.API.Namespace
					Labels:    make(map[string]string),
				},
				Data: map[string][]byte{
					"username": []byte(username),
					"password": []byte(password),
				},
			}
		}
		logger.LoggerTransformer.Debugf("New Secret Data for %s: %v", environment, secret)
		k8sArtifact.Secrets[secret.ObjectMeta.Name] = &secret
	}

	for _, secretData := range secretDataList {
		if secretData.Production.Enabled {
			createSecret("production", secretData.Production.Username, secretData.Production.Password, secretData.Production.APIKeyValue, secretData.Production.Type, secretData.Production.EndpointUUID)
		}
		if secretData.Sandbox.Enabled {
			createSecret("sandbox", secretData.Sandbox.Username, secretData.Sandbox.Password, secretData.Sandbox.APIKeyValue, secretData.Sandbox.Type, secretData.Sandbox.EndpointUUID)
		}
	}
}

// Get API name from any RouteMetadata in the map
func getAPINameFromRouteMetadata(k8sArtifact *K8sArtifacts) string {
	for _, routeMetadata := range k8sArtifact.RouteMetadata {
		if routeMetadata != nil && routeMetadata.Spec.API.Name != "" {
			return routeMetadata.Spec.API.Name
		}
	}
	return "" // fallback if no RouteMetadata found
}

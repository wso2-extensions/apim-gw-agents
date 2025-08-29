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

/*
 * Package "synchronizer" contains artifacts relate to fetching APIs and
 * API related updates from the control plane event-hub.
 * This file contains functions to retrieve APIs and API updates.
 */

package synchronizer

import (
	"fmt"
	"time"

	k8sclient "github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/internal/loggers"
	synchronizer "github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/internal/utils"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/cache"
	eventhubTypes "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub/types"
	sync "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/synchronizer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	retryCount int = 5
)

var retryAttempt int

// FetchKeyManagersOnStartUp pulls the Key managers calling to the API manager
func FetchKeyManagersOnStartUp(c client.Client) {
	// Read configurations and derive the eventHub details
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		// This has to be error. For debugging purpose info
		logger.LoggerSynchronizer.Errorf("Error reading configs: %v", errReadConfig)
	}

	// Initialize the cache to store the key manager details
	kmCache := cache.GetKeyManagerCacheInstance()
	if kmCache == nil {
		logger.LoggerSynchronizer.Error("Failed to initialize KeyManager cache")
		return
	}
	logger.LoggerSynchronizer.Info("KeyManager cache initialized")

	resolvedKeyManagers, errorMsg := sync.FetchKeyManagersOnStartUp(c)
	if resolvedKeyManagers != nil {
		if len(resolvedKeyManagers) == 0 && errorMsg != "" {
			go retryFetchData(conf, errorMsg, c)
		} else {
			// Populate cache with initial data
			for _, km := range resolvedKeyManagers {
				backendName, hostname, backendPort, namespace := synchronizer.GetBackendConfigForKM(km)

				kmCache.AddOrUpdateKeyManager(&cache.KMCacheObject{
					ResolvedKM:          &km,
					K8sBackendName:      backendName,
					K8sBackendPort:      backendPort,
					K8sBackendNamespace: namespace,
				})
				//!!!TODO: Update the logic to sync with KM and dataplane
				err := CreateOrUpdateBackendAndBackendTLSForKMs(km, backendPort, backendName, namespace, hostname, c)
				if err != nil {
					logger.LoggerSynchronizer.Errorf("Error creating backend and backend TLS for KM: %+v", err)
				}
			}

			logger.LoggerSynchronizer.Infof("Populated KM cache with %d entries on startup", len(resolvedKeyManagers))
			// applyAllKeyManagerConfiguration(c, resolvedKeyManagers)
		}
	}
}

func retryFetchData(conf *config.Config, errorMessage string, c client.Client) {
	logger.LoggerSynchronizer.Debugf("Time Duration for retrying: %v",
		conf.ControlPlane.RetryInterval*time.Second)
	time.Sleep(conf.ControlPlane.RetryInterval * time.Second)
	FetchKeyManagersOnStartUp(c)
	retryAttempt++
	if retryAttempt >= retryCount {
		logger.LoggerSynchronizer.Error(errorMessage)
		return
	}
}

// CreateBackendAndBackendTLSForKMs creates the backend and backend TLS for the given key manager
func CreateOrUpdateBackendAndBackendTLSForKMs(km eventhubTypes.ResolvedKeyManager, backendPort int, backendName, namespace, hostname string, c client.Client) error {
	kmBackendCR := k8sclient.GenerateKMBackendCR(km, backendPort, backendName, namespace, hostname)
	logger.LoggerSynchronizer.Debugf("Generated KM Backend CR: %+v\n", kmBackendCR)
	if kmBackendCR == nil {
		return fmt.Errorf("failed to generate KM Backend CR for KM: %+v", km)
	}
	// Deploy Backend CR and get its UID
	backendUID, err := k8sclient.DeployBackendCR(kmBackendCR, nil, c)
	if err != nil {
		return fmt.Errorf("failed to deploy Backend CR for KM %s: %v", km.Name, err)
	}
	ownerRef := &metav1.OwnerReference{
		APIVersion: "gateway.envoyproxy.io/v1alpha1",
		Kind:       "Backend",
		Name:       backendName,
		UID:        backendUID,
	}

	kmBackendTLSCR, kmBackendSecretCR := k8sclient.GenerateKMBackendTLSCR(km, backendName, namespace, hostname)
	logger.LoggerSynchronizer.Debugf("Generated KM Backend TLS CR: %+v\n", kmBackendTLSCR)
	logger.LoggerSynchronizer.Debugf("Generated KM Backend Secret CR: %+v\n", kmBackendSecretCR)
	k8sclient.DeployBackendTLSPolicyCR(kmBackendTLSCR, ownerRef, c)
	if kmBackendSecretCR != nil {
		k8sclient.DeploySecretCR(kmBackendSecretCR, ownerRef, c)
	}
	logger.LoggerSynchronizer.Infof("Successfully created backend and backend TLS for KM: %+v", km.Name)
	return nil
}

// func applyAllKeyManagerConfiguration(c client.Client, resolvedKeyManagers []eventhubTypes.ResolvedKeyManager) error {
// 	logger.LoggerSynchronizer.Info("ApplyAllKeyManagerConfiguration function called...")
// 	tokenIssuersFromK8s, _, err := retrieveAllTokenIssuers(c, "")
// 	if err != nil {
// 		return err
// 	}
// 	clonedTokenIssuerListFromK8s := make([]dpv1alpha2.TokenIssuer, len(tokenIssuersFromK8s))
// 	copy(clonedTokenIssuerListFromK8s, tokenIssuersFromK8s)
// 	clonedTokenIssuers := make([]eventhubTypes.ResolvedKeyManager, len(resolvedKeyManagers))
// 	copy(clonedTokenIssuers, resolvedKeyManagers)
// 	newTokenissuers := make([]eventhubTypes.ResolvedKeyManager, 0)
// 	sameTokenissuers := make([]eventhubTypes.ResolvedKeyManager, 0)
// 	for _, tokenIssuer := range clonedTokenIssuers {
// 		found := false
// 		unFilteredTokenIssuersFRomK8s := make([]dpv1alpha2.TokenIssuer, 0)
// 		for _, tokenIssuersFromK8s := range clonedTokenIssuerListFromK8s {
// 			if tokenIssuer.UUID == tokenIssuersFromK8s.Name {
// 				sameTokenissuers = append(sameTokenissuers, tokenIssuer)
// 				found = true
// 				continue // Preiously this was break
// 			}
// 			unFilteredTokenIssuersFRomK8s = append(unFilteredTokenIssuersFRomK8s, tokenIssuersFromK8s)
// 		}
// 		clonedTokenIssuerListFromK8s = unFilteredTokenIssuersFRomK8s
// 		if !found {
// 			newTokenissuers = append(newTokenissuers, tokenIssuer)
// 		}
// 	}
// 	for _, tokenIssuer := range newTokenissuers {
// 		// !!!TODO: NEED TO ADD THE LOGIC
// 		// err := k8sclient.CreateAndUpdateTokenIssuersCR(tokenIssuer, c)
// 		// if err != nil {
// 		// 	return err
// 		// }
// 		logger.LoggerSynchronizer.Debugf("Token Issuer created: %v", tokenIssuer)
// 	}
// 	for _, tokenIssuer := range sameTokenissuers {
// 		// !!!TODO: NEED TO ADD THE LOGIC
// 		// err := k8sclient.UpdateTokenIssuersCR(tokenIssuer, c)
// 		// if err != nil {
// 		// 	return err
// 		// }
// 		logger.LoggerSynchronizer.Debugf("Token Issuer updated: %v", tokenIssuer)
// 	}
// 	logger.LoggerSynchronizer.Debugf("Deleted Token Issuers from K8s: %v", clonedTokenIssuerListFromK8s)
// 	for _, tokenissuer := range clonedTokenIssuerListFromK8s {
// 		// !!!TODO: NEED TO ADD THE LOGIC
// 		// err := k8sclient.DeleteTokenIssuerCR(c, tokenissuer)
// 		// if err != nil {
// 		// 	return err
// 		// }
// 		logger.LoggerSynchronizer.Debugf("Token Issuer deleted: %v", tokenissuer)
// 	}
// 	return nil
// }

// func retrieveAllTokenIssuers(c client.Client, nextToken string) ([]dpv1alpha2.TokenIssuer, string, error) {
// 	conf, _ := config.ReadConfigs()
// 	tokenIssuerList := dpv1alpha2.TokenIssuerList{}
// 	resolvedTokenIssuerList := make([]dpv1alpha2.TokenIssuer, 0)
// 	var err error
// 	// Convert the label selector string into a labels.Selector
// 	labelSelector := labels.SelectorFromSet(labels.Set{"InitiateFrom": "CP"})
// 	opts := &client.ListOptions{
// 		Namespace:     conf.DataPlane.Namespace,
// 		LabelSelector: labelSelector,
// 	}
// 	if nextToken == "" {
// 		err = c.List(context.Background(), &tokenIssuerList, opts)
// 	} else {
// 		opts.Continue = nextToken
// 		err = c.List(context.Background(), &tokenIssuerList, opts)
// 	}
// 	if err != nil {
// 		logger.LoggerSynchronizer.ErrorC(logging.PrintError(logging.Error1102, logging.CRITICAL, "Failed to get application from k8s %v", err.Error()))
// 		return nil, "", err
// 	}
// 	resolvedTokenIssuerList = append(resolvedTokenIssuerList, tokenIssuerList.Items...)
// 	if tokenIssuerList.Continue != "" {
// 		tempTokenIssuerList, _, err := retrieveAllTokenIssuers(c, tokenIssuerList.Continue)
// 		if err != nil {
// 			return nil, "", err
// 		}
// 		resolvedTokenIssuerList = append(resolvedTokenIssuerList, tempTokenIssuerList...)
// 	}
// 	return resolvedTokenIssuerList, tokenIssuerList.Continue, nil
// }

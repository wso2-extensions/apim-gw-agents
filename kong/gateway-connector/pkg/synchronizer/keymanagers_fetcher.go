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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"time"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	eventhubTypes "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub/types"
	synchronizer "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/synchronizer"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	k8sclient "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/k8sClient"
	logger "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/loggers"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/transformer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var retryAttempt int

// FetchKeyManagersOnStartUp pulls the Key managers calling to the API manager
func FetchKeyManagersOnStartUp(c client.Client) {
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		logger.LoggerSynchronizer.Errorf("Error reading configs: %v", errReadConfig)
	}

	resolvedKeyManagers, errorMsg := synchronizer.FetchKeyManagersOnStartUp(c)
	if resolvedKeyManagers != nil {
		if len(resolvedKeyManagers) == 0 && errorMsg != constants.EmptyString {
			go retryFetchData(conf, errorMsg, c)
		} else {
			applyAllKeyManagerConfiguration(c, resolvedKeyManagers)
		}
	}
}

func retryFetchData(conf *config.Config, errorMessage string, c client.Client) {
	logger.LoggerSynchronizer.Debugf("Time Duration for retrying: %v",
		conf.ControlPlane.RetryInterval*time.Second)
	time.Sleep(conf.ControlPlane.RetryInterval * time.Second)
	FetchKeyManagersOnStartUp(c)
	retryAttempt++
	if retryAttempt > constants.MaxRetries {
		logger.LoggerSynchronizer.Error(errorMessage)
		return
	}
}

func applyAllKeyManagerConfiguration(c client.Client, resolvedKeyManagers []eventhubTypes.ResolvedKeyManager) error {
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		logger.LoggerSynchronizer.Errorf("Error reading configs: %v", errReadConfig)
	}

	for _, resolvedKeyManager := range resolvedKeyManagers {
		if resolvedKeyManager.KeyManagerConfig.CertificateType == constants.PEMCertificateType {
			err := CreateAndDeployKeyManagerSecret(resolvedKeyManager, conf, c)
			if err != nil {
				logger.LoggerSynchronizer.Errorf("Failed to create and deploy key manager secret for %s: %v", resolvedKeyManager.Name, err)
				continue
			}
		}
	}
	return nil
}

// CreateAndDeployKeyManagerSecret creates and deploys a Kubernetes secret for the given key manager
func CreateAndDeployKeyManagerSecret(resolvedKeyManager eventhubTypes.ResolvedKeyManager, conf *config.Config, c client.Client) error {
	publicKey, err := ExtractPublicKey(resolvedKeyManager.KeyManagerConfig.CertificateValue)
	if err != nil || publicKey == constants.EmptyString {
		return err
	}

	config := map[string]string{
		constants.IssuerField:    resolvedKeyManager.KeyManagerConfig.Issuer,
		constants.PublicKeyField: publicKey,
	}
	secretLabels := map[string]string{
		constants.TypeLabel: constants.IssuerSecretType,
	}
	keyManagerSecret := transformer.GenerateK8sSecret(resolvedKeyManager.Name, secretLabels, config)
	keyManagerSecret.Namespace = conf.DataPlane.Namespace
	k8sclient.DeploySecretCR(keyManagerSecret, c)
	logger.LoggerSynchronizer.Infof("Successfully deployed key manager secret for: %s", resolvedKeyManager.Name)
	return nil
}

// ExtractPublicKey takes a PEM encoded certificate as input and returns the public key as a string
func ExtractPublicKey(encodedPemCert string) (string, error) {
	pemCert, err := base64.StdEncoding.DecodeString(encodedPemCert)
	if err != nil {
		logger.LoggerSynchronizer.Errorf("Failed to decode certificate: %v", err)
		return constants.EmptyString, err
	}

	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		logger.LoggerSynchronizer.Error("Failed to parse PEM block containing the certificate")
		return constants.EmptyString, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.LoggerSynchronizer.Errorf("Failed to parse certificate: %v", err)
		return constants.EmptyString, err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		logger.LoggerSynchronizer.Errorf("Failed to marshal public key: %v", err)
		return constants.EmptyString, err
	}

	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  constants.PublicKeyType,
		Bytes: publicKeyBytes,
	})

	return string(pubKeyPem), nil
}

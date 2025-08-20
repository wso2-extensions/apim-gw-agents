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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	pkgAuth "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/auth"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub"
	eventhubTypes "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/eventhub/types"
	logger "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/loggers"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/tlsutils"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	keyManagersEndpoint string = "internal/data/v1/keymanagers"
)

// FetchKeyManagersOnStartUp pulls the Key managers calling to the API manager
// API Manager returns a .zip file as a response and this function
// returns a byte slice of that ZIP file.
func FetchKeyManagersOnStartUp(c client.Client) ([]eventhubTypes.ResolvedKeyManager, string) {
	logger.LoggerSync.Info("Fetching KeyManagers from Control Plane.")

	// Read configurations and derive the eventHub details
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		// This has to be error. For debugging purpose info
		logger.LoggerSync.Errorf("Error reading configs: %v", errReadConfig)
	}
	// Populate data from the config
	ehConfigs := conf.ControlPlane
	ehURL := ehConfigs.ServiceURL
	// If the eventHub URL is configured with trailing slash
	if strings.HasSuffix(ehURL, "/") {
		ehURL += keyManagersEndpoint
	} else {
		ehURL += "/" + keyManagersEndpoint
	}
	logger.LoggerSync.Debugf("Fetching KeyManagers from the URL %v: ", ehURL)

	ehUname := ehConfigs.Username
	ehPass := ehConfigs.Password
	basicAuth := "Basic " + pkgAuth.GetBasicAuth(ehUname, ehPass)

	// Check if TLS is enabled
	skipSSL := ehConfigs.SkipSSLVerification

	// Create a HTTP request
	req, err := http.NewRequest("GET", ehURL, nil)
	if err != nil {
		logger.LoggerSync.Errorf("Error while creating http request for Key Manager Endpoint : %v", err)
	}

	var queryParamMap map[string]string

	if queryParamMap != nil && len(queryParamMap) > 0 {
		q := req.URL.Query()
		// Making necessary query parameters for the request
		for queryParamKey, queryParamValue := range queryParamMap {
			q.Add(queryParamKey, queryParamValue)
		}
		req.URL.RawQuery = q.Encode()
	}
	// Setting authorization header
	req.Header.Set(Authorization, basicAuth)

	//Todo: Need to set ALL when APIM Fix is available
	req.Header.Set("xWSO2Tenant", "ALL")

	// Make the request
	logger.LoggerSync.Debug("Sending the control plane request")
	resp, err := tlsutils.InvokeControlPlane(req, skipSSL)
	var errorMsg string
	if err != nil {
		errorMsg = "Error occurred while calling the REST API: " + keyManagersEndpoint
		return make([]eventhubTypes.ResolvedKeyManager, 0), errorMsg
	}
	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		errorMsg = "Error occurred while reading the response received for: " + keyManagersEndpoint
		return make([]eventhubTypes.ResolvedKeyManager, 0), errorMsg
	}

	if resp.StatusCode == http.StatusOK {
		var keyManagers []eventhubTypes.KeyManager
		err := json.Unmarshal(responseBytes, &keyManagers)
		if err != nil {
			errorMsg := fmt.Sprintf("Error occurred while unmarshelling Key Managers event data %v", err)
			return nil, errorMsg
		}
		logger.LoggerSync.Debugf("Key Managers received: %+v", keyManagers)
		resolvedKeyManagers := eventhub.MarshalKeyManagers(&keyManagers)
		return resolvedKeyManagers, ""
	}

	errorMsg = "Failed to fetch data! " + keyManagersEndpoint + " responded with " +
		strconv.Itoa(resp.StatusCode)
	return make([]eventhubTypes.ResolvedKeyManager, 0), errorMsg
}

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

	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
)


// GetEnvLabel returns the environment label from the config
func GetEnvLabel() string {
	envID := "Default" // fallback default
	if conf, err := config.ReadConfigs(); err == nil && len(conf.ControlPlane.EnvironmentLabels) > 0 {
		envID = conf.ControlPlane.EnvironmentLabels[0] // Use the first environment label
		fmt.Printf("\nenvID from config: %s\n", envID)
	}
	return envID
}
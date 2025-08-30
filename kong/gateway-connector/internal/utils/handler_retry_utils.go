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

package utils

import (
	"strings"
	"time"

	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
	logger "github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/loggers"
)

// RetryKongCRUpdate retries Kong CR operations with exponential backoff for resource version conflicts
func RetryKongCRUpdate(operation func() error, operationName string, maxRetries int) error {

	if operationName == "" {
		operationName = constants.KongCRTaskName
	}

	if maxRetries <= 0 {
		maxRetries = constants.MaxRetries
	}

	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		err = operation()
		if err == nil {
			if attempt > 0 {
				logger.LoggerUtils.Infof("%s succeeded on retry attempt %d", operationName, attempt+1)
			} else {
				logger.LoggerUtils.Infof("%s succeeded on first attempt", operationName)
			}
			return nil
		}

		if strings.Contains(err.Error(), constants.ObjectModifiedError) {
			if attempt < maxRetries-1 {
				backoffDuration := time.Duration((attempt+1)*constants.RetryDelayMultiplier) * time.Millisecond
				logger.LoggerUtils.Warnf("%s failed due to resource version conflict, retrying in %v (attempt %d/%d): %v",
					operationName, backoffDuration, attempt+1, maxRetries, err)
				time.Sleep(backoffDuration)
				continue
			} else {
				logger.LoggerUtils.Errorf("%s failed after %d attempts due to resource version conflicts: %v",
					operationName, maxRetries, err)
			}
		} else {
			logger.LoggerUtils.Errorf("%s failed with non-retryable error: %v", operationName, err)
			break
		}
	}
	return err
}

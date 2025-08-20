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

// Package loggers contains the package references for log messages
// If a new package is introduced, the corresponding logger reference is need to be created as well.
package loggers

import (
	"github.com/sirupsen/logrus"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/logging"

	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

/* loggers should be initiated only for the main packages
 ********** Don't initiate loggers for sub packages ****************

When you add a new logger instance add the related package name as a constant
*/

// package name constants
const (
	pkgAgent     = "github.com/wso2-extensions/apim-gw-connectors/common-agent/internal/agent"
	pkgMessaging = "github.com/wso2-extensions/apim-gw-connectors/common-agent/internal/messaging"
	pkgUtils     = "github.com/wso2-extensions/apim-gw-connectors/common-agent/internal/utils"
)

// logger package references
var (
	LoggerMessaging logging.Log
	LoggerUtils     logging.Log
	LoggerAgent     logging.Log
)

func init() {
	log.SetLogger(zap.New(zap.UseDevMode(true)))
	UpdateLoggers()
}

// UpdateLoggers initializes the logger package references
func UpdateLoggers() {
	LoggerMessaging = logging.InitPackageLogger(pkgMessaging)
	LoggerUtils = logging.InitPackageLogger(pkgUtils)
	LoggerAgent = logging.InitPackageLogger(pkgAgent)
	logrus.Info("Updated loggers")
}

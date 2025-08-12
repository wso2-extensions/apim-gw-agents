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

// Package loggers contains the package references for log messages
// If a new package is introduced, the corresponding logger reference is need to be created as well.
package loggers

import (
	"github.com/sirupsen/logrus"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/logging"
)

/* loggers should be initiated only for the main packages
 ********** Don't initiate loggers for sub packages ****************

When you add a new logger instance add the related package name as a constant
*/

// package name constants
const (
	pkgMsg         = "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/messaging"
	pkgHealth      = "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/health"
	pkgTLSUtils    = "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/tlsutils"
	pkgUtils       = "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/utils"
	pkgMgtServer   = "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/managementserver"
	pkgTransformer = "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/transformer"
	pkgSync        = "github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/synchronizer"
	pkgWatcher     = "github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/watcher"
)

// logger package references
var (
	LoggerMsg         logging.Log
	LoggerHealth      logging.Log
	LoggerTLSUtils    logging.Log
	LoggerUtils       logging.Log
	LoggerMgtServer   logging.Log
	LoggerTransformer logging.Log
	LoggerSync        logging.Log
	LoggerWatcher     logging.Log
)

func init() {
	UpdateLoggers()
}

// UpdateLoggers initializes the logger package references
func UpdateLoggers() {
	LoggerMsg = logging.InitPackageLogger(pkgMsg)
	LoggerHealth = logging.InitPackageLogger(pkgHealth)
	LoggerTLSUtils = logging.InitPackageLogger(pkgTLSUtils)
	LoggerUtils = logging.InitPackageLogger(pkgUtils)
	LoggerMgtServer = logging.InitPackageLogger(pkgMgtServer)
	LoggerTransformer = logging.InitPackageLogger(pkgTransformer)
	LoggerSync = logging.InitPackageLogger(pkgSync)
	LoggerWatcher = logging.InitPackageLogger(pkgWatcher)
	logrus.Info("Updated loggers")
}

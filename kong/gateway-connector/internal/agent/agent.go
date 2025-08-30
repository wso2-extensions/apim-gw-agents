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

package agent

import (
	v1 "github.com/kong/kubernetes-configuration/api/configuration/v1"
	v1alpha1 "github.com/kong/kubernetes-configuration/api/configuration/v1alpha1"
	v1beta1 "github.com/kong/kubernetes-configuration/api/configuration/v1beta1"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/managementserver"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/discovery"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/internal/utils"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/pkg/synchronizer"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// PreRun prepares the agent environment and runs before Run.
func PreRun(conf *config.Config, scheme *runtime.Scheme) {
	utilruntime.Must(v1.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(v1beta1.AddToScheme(scheme))
}

// initializeKongIntegrations sets up Kong-specific integrations with the common agent
func initializeKongIntegrations() {
	kongAPIYamlCreator := utils.NewKongAPIYamlCreator()
	managementserver.SetAPIYamlCreator(kongAPIYamlCreator)
	loggers.LoggerAgent.Debugf("Successfully registered Kong API YAML creator with management server")

	kongCallback := &discovery.KongAPIImportCallback{}
	managementserver.RegisterAPIImportCallback(kongCallback)
	loggers.LoggerAgent.Debugf("Successfully registered Kong API import callback for discovery mode")
}

// Run handles any configurations that runs on agent start.
func Run(conf *config.Config, mgr manager.Manager) {
	loggers.LoggerAgent.Infof("Starting Kong agent")

	loggers.LoggerAgent.Infof("Initializing Kong-specific integrations")
	initializeKongIntegrations()

	loggers.LoggerAgent.Infof("Fetching rate limit policies from control plane")
	synchronizer.FetchRateLimitPoliciesOnEvent("", "", mgr.GetClient())

	loggers.LoggerAgent.Infof("Fetching subscription rate limit policies from control plane")
	synchronizer.FetchSubscriptionRateLimitPoliciesOnEvent("", "", mgr.GetClient(), true)

	loggers.LoggerAgent.Infof("Fetching key managers on startup")
	synchronizer.FetchKeyManagersOnStartUp(mgr.GetClient())

	loggers.LoggerAgent.Infof("Initializing Kong CR Watcher")
	if err := discovery.CRWatcher.Initialize(); err != nil {
		loggers.LoggerAgent.Errorf("Failed to initialize Kong CR Watcher: %v", err)
		return
	}

	loggers.LoggerAgent.Infof("Initializing HTTPRoutes and Services state")
	discovery.InitializeServicesState(conf.DataPlane.Namespace)

	loggers.LoggerAgent.Infof("Starting Kong CR Discovery")
	go discovery.CRWatcher.Watch()

	loggers.LoggerAgent.Infof("Kong agent startup completed successfully")
}

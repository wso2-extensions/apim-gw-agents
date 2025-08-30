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

// Package agent contains the implementation to start the agent
package agent

import (
	"flag"

	"github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/internal/eventhub"
	"github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/internal/synchronizer"
	"github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/pkg/managementserver"
	"github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector/pkg/utils"
	"github.com/wso2-extensions/apim-gw-connectors/common-agent/config"
	commonMgmt "github.com/wso2-extensions/apim-gw-connectors/common-agent/pkg/managementserver"

	gatewayv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	cpv1alpha2 "github.com/wso2/apk/common-go-libs/apis/cp/v1alpha2"
	dpv2alpha1 "github.com/wso2/apk/common-go-libs/apis/dp/v2alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwapiv1a2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gwapiv1a3 "sigs.k8s.io/gateway-api/apis/v1alpha3"
)

var (
	restPort uint
)

func init() {
	flag.UintVar(&restPort, "rest_port", 18001, "Rest server port")
}

// PreRun prepares the agent environment and runs before Run.
func PreRun(conf *config.Config, scheme *runtime.Scheme) {
	utilruntime.Must(cpv1alpha2.AddToScheme(scheme))
	utilruntime.Must(dpv2alpha1.AddToScheme(scheme))
	utilruntime.Must(gatewayv1alpha1.AddToScheme(scheme))
	utilruntime.Must(gwapiv1.Install(scheme))
	utilruntime.Must(gwapiv1a2.Install(scheme))
	utilruntime.Must(gwapiv1a3.Install(scheme))
}

// initializeAPKIntegrations sets up APK-specific integrations with the common agent
func initializeAPKIntegrations() {
	loggers.LoggerAgent.Info("Starting APK integrations initialization")
	apkAPIYamlCreator := utils.NewAPKAPIYamlCreator()
	commonMgmt.SetAPIYamlCreator(apkAPIYamlCreator)
}

// Run starts the GRPC server and Rest API server.
func Run(conf *config.Config, mgr manager.Manager) {
	loggers.LoggerAgent.Info("Starting APK Gateway Connector Agent...")
	AgentMode := conf.Agent.Mode
	loggers.LoggerAgent.Infof("Agent Mode: %s", AgentMode)
	initializeAPKIntegrations()

	go managementserver.StartInternalServer(restPort)

	// Load initial KM data from control plane
	synchronizer.FetchKeyManagersOnStartUp(mgr.GetClient())

	if AgentMode == "CPtoDP" {
		// Load initial Policy data from control plane
		synchronizer.FetchRateLimitPoliciesOnEvent("", "", mgr.GetClient())
	}
	// Load initial Subscription Rate Limit data from control plane
	synchronizer.FetchSubscriptionRateLimitPoliciesOnEvent("", "", mgr.GetClient(), true)
	// Load initial AI Provider data from control plane
	synchronizer.FetchAIProvidersOnEvent("", "", "", mgr.GetClient(), true)

	// Load initial data from control plane
	eventhub.LoadInitialData(conf, mgr.GetClient())
}

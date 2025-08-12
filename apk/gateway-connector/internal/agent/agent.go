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

// Package agent contains the implementation to start the agent
package agent

import (
	"flag"

	"github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/internal/eventhub"
	"github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/internal/synchronizer"
	"github.com/wso2-extensions/apim-gw-agents/apk/gateway-connector/pkg/managementserver"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	cpv1alpha2 "github.com/wso2/apk/common-go-libs/apis/cp/v1alpha2"
	dpv1alpha1 "github.com/wso2/apk/common-go-libs/apis/dp/v1alpha1"
	dpv1alpha2 "github.com/wso2/apk/common-go-libs/apis/dp/v1alpha2"
	dpv1alpha3 "github.com/wso2/apk/common-go-libs/apis/dp/v1alpha3"
	dpv1alpha4 "github.com/wso2/apk/common-go-libs/apis/dp/v1alpha4"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	restPort uint
)

func init() {
	flag.UintVar(&restPort, "rest_port", 18001, "Rest server port")
}

// PreRun prepares the agent environment and runs before Run.
func PreRun(conf *config.Config, scheme *runtime.Scheme) {
	utilruntime.Must(dpv1alpha1.AddToScheme(scheme))
	utilruntime.Must(dpv1alpha2.AddToScheme(scheme))
	utilruntime.Must(dpv1alpha3.AddToScheme(scheme))
	utilruntime.Must(cpv1alpha2.AddToScheme(scheme))
	utilruntime.Must(cpv1alpha2.AddToScheme(scheme))
	utilruntime.Must(dpv1alpha3.AddToScheme(scheme))
	utilruntime.Must(dpv1alpha4.AddToScheme(scheme))
}

// Run starts the GRPC server and Rest API server.
func Run(conf *config.Config, mgr manager.Manager) {
	AgentMode := conf.Agent.Mode

	go managementserver.StartInternalServer(restPort)

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

	// Load initial KM data from control plane
	synchronizer.FetchKeyManagersOnStartUp(mgr.GetClient())
}

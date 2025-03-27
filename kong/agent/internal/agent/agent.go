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
	v1 "github.com/kong/kubernetes-configuration/api/configuration/v1"
	v1alpha1 "github.com/kong/kubernetes-configuration/api/configuration/v1alpha1"
	v1beta1 "github.com/kong/kubernetes-configuration/api/configuration/v1beta1"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	"github.com/wso2-extensions/apim-gw-agents/kong/agent/internal/discovery"
	"github.com/wso2-extensions/apim-gw-agents/kong/agent/internal/loggers"
	"github.com/wso2-extensions/apim-gw-agents/kong/agent/pkg/synchronizer"
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

// Run handles any configurations that runs on agent start.
func Run(conf *config.Config, mgr manager.Manager) {
	AgentMode := conf.Agent.Mode

	if AgentMode == "CPtoDP" {
		// Load initial Policy data from control plane
		synchronizer.FetchRateLimitPoliciesOnEvent("", "", mgr.GetClient())
	}
	// Load initial Subscription Rate Limit data from control plane
	synchronizer.FetchSubscriptionRateLimitPoliciesOnEvent("", "", mgr.GetClient(), true)

	synchronizer.FetchKeyManagersOnStartUp(mgr.GetClient())

	if AgentMode == "DPtoCP" {
		loggers.LoggerAgent.Infof("Starting Kong CR Discovery...")
		discovery.CRWatcher.Watch()
		discovery.InitializeHTTPRoutesState()
	}
}

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

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cucumber/godog"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/tests/pkg/utils"
	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/tests/steps"
)

func runTestSuite(ctx *utils.SharedContext, path string) int {
	opts := godog.Options{
		Format: "progress",
		Paths:  []string{path},
	}

	return godog.TestSuite{
		Name:                 "api_tests",
		TestSuiteInitializer: func(suiteContext *godog.TestSuiteContext) {},
		ScenarioInitializer: func(s *godog.ScenarioContext) {
			steps.BaseSteps(s, ctx)
			steps.APIDeploymentSteps(s, ctx)
		},
		Options: &opts,
	}.Run()
}

// go run test_main.go --mode=CPtoDP
// go run test_main.go --mode=DPtoCP
func main() {
	mode := flag.String("mode", "", "Test mode: CPtoDP or DPtoCP")
	flag.Parse()

	ctx := utils.NewSharedContext()

	var status int

	switch *mode {
	case "CPtoDP":
		fmt.Println("Running tests for CPtoDP...")
		status = runTestSuite(ctx, "./tests/features/agent-cptodp")
	case "DPtoCP":
		fmt.Println("Running tests for DPtoCP...")
		status = runTestSuite(ctx, "./tests/features/agent-dptocp")
	default:
		fmt.Println("Invalid mode or missing mode. Use --mode=CPtoDP or --mode=DPtoCP")
		os.Exit(1)
	}

	if status != 0 {
		os.Exit(1)
	}
}

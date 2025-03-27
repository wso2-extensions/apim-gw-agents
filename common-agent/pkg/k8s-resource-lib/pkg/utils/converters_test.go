package utils

import (
	"testing"

	"encoding/json"
	"os"
	"reflect"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/k8s-resource-lib/types"
	"gopkg.in/yaml.v2"
)

func TestReadAPKConf(t *testing.T) {
	expected := &types.APKConf{
		Name:                   "EmployeeServiceAPI",
		Version:                "3.14",
		BasePath:               "/employees-info",
		Type:                   "REST",
		DefaultVersion:         false,
		SubscriptionValidation: false,
		EndpointConfigurations: &types.EndpointConfigurations{
			Production: &[]types.EndpointConfiguration{
				types.EndpointConfiguration{
					Endpoint: types.EndpointURL("http://employee-service:8080"),
				},
			},
		},
		RateLimit: &types.RateLimit{
			Unit:            "Minute",
			RequestsPerUnit: 5,
		},
		Authentication: &[]types.AuthConfiguration{
			{
				AuthType: "APIKey",
				Enabled:  true,
			},
		},
		Operations: &[]types.Operation{
			{Target: "/employees", Verb: "GET", Secured: true},
			{Target: "/employee", Verb: "POST", Secured: true},
			{Target: "/employee/{employeeId}", Verb: "PUT", Secured: true},
			{Target: "/employee/{employeeId}", Verb: "DELETE", Secured: true},
		},
	}

	yamlData, err := yaml.Marshal(expected)
	if err != nil {
		t.Fatalf("Failed to marshal expected APKConf: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "apkconf-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(yamlData); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}
	result := ReadAPKConf(tmpFile.Name())
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("ReadAPKConf() = %v, want %v", result, expected)
	}
}

func TestAPKConfToJSON(t *testing.T) {
	apkConf := &types.APKConf{
		Name:                   "EmployeeServiceAPI",
		Version:                "3.14",
		BasePath:               "/employees-info",
		Type:                   "REST",
		DefaultVersion:         false,
		SubscriptionValidation: false,
		EndpointConfigurations: &types.EndpointConfigurations{
			Production: &[]types.EndpointConfiguration{
				types.EndpointConfiguration{
					Endpoint: types.EndpointURL("http://employee-service:8080"),
				},
			},
		},
		RateLimit: &types.RateLimit{
			Unit:            "Minute",
			RequestsPerUnit: 5,
		},
		Authentication: &[]types.AuthConfiguration{
			{
				AuthType: "APIKey",
				Enabled:  true,
			},
		},
		Operations: &[]types.Operation{
			{Target: "/employees", Verb: "GET", Secured: true},
			{Target: "/employee", Verb: "POST", Secured: true},
			{Target: "/employee/{employeeId}", Verb: "PUT", Secured: true},
			{Target: "/employee/{employeeId}", Verb: "DELETE", Secured: true},
		},
	}

	expected, err := json.MarshalIndent(apkConf, "", " ")
	if err != nil {
		t.Fatalf("Failed to marshal expected APKConf to JSON: %v", err)
	}

	result := APKConfToJSON(apkConf)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("APKConfToJSON() = %s, want %s", result, expected)
	}
}

func TestAPKConfToYAML(t *testing.T) {
	apkConf := &types.APKConf{
		Name:                   "EmployeeServiceAPI",
		Version:                "3.14",
		BasePath:               "/employees-info",
		Type:                   "REST",
		DefaultVersion:         false,
		SubscriptionValidation: false,
		EndpointConfigurations: &types.EndpointConfigurations{
			Production: &[]types.EndpointConfiguration{
				types.EndpointConfiguration{
					Endpoint: types.EndpointURL("http://employee-service:8080"),
				},
			},
		},
		RateLimit: &types.RateLimit{
			Unit:            "Minute",
			RequestsPerUnit: 5,
		},
		Authentication: &[]types.AuthConfiguration{
			{
				AuthType: "APIKey",
				Enabled:  true,
			},
		},
		Operations: &[]types.Operation{
			{Target: "/employees", Verb: "GET", Secured: true},
			{Target: "/employee", Verb: "POST", Secured: true},
			{Target: "/employee/{employeeId}", Verb: "PUT", Secured: true},
			{Target: "/employee/{employeeId}", Verb: "DELETE", Secured: true},
		},
	}

	expected, err := yaml.Marshal(apkConf)
	if err != nil {
		t.Fatalf("Failed to marshal expected APKConf to YAML: %v", err)
	}

	result := APKConfToYAML(apkConf)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("APKConfToYAML() = %s, want %s", result, expected)
	}
}

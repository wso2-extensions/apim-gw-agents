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

package types

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

// UnmarshalYAML is a Custom unmarshal logic for EndpointConfiguration
func (ec *EndpointConfiguration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Use a raw map to read the YAML structure
	var raw struct {
		Endpoint       interface{}         `yaml:"endpoint"`
		EndCertificate EndpointCertificate `yaml:"certificate,omitempty"`
		EndSecurity    EndpointSecurity    `yaml:"endpointSecurity,omitempty"`
		AIRatelimit    AIRatelimit         `yaml:"aiRatelimit,omitempty"`
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}

	// Check the endpoint type
	switch v := raw.Endpoint.(type) {
	case string:
		ec.Endpoint = EndpointURL(v) // Assign as EndpointURL
	case map[interface{}]interface{}:
		var k8sService K8sService
		bytes, err := yaml.Marshal(v)
		if err != nil {
			return err
		}
		if err := yaml.Unmarshal(bytes, &k8sService); err != nil {
			return err
		}
		ec.Endpoint = k8sService // Assign as K8sService
	default:
		return fmt.Errorf("unsupported endpoint type: %T", v)
	}

	// Assign other fields
	ec.EndCertificate = raw.EndCertificate
	ec.EndSecurity = raw.EndSecurity
	ec.AIRatelimit = raw.AIRatelimit

	return nil
}

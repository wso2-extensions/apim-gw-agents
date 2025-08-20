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

package eventhub

import "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"

// MarshalKeyManagers is used to update the key managers during the startup where
// multiple key managers are pulled at once. And then it returns the KeyManagerMap.
func MarshalKeyManagers(keyManagersList *[]types.KeyManager) []types.ResolvedKeyManager {
	resourceMap := make([]types.ResolvedKeyManager, 0)
	for _, keyManager := range *keyManagersList {
		keyManagerSub := MarshalKeyManager(&keyManager)
		resourceMap = append(resourceMap, keyManagerSub)
	}
	return resourceMap
}

func marshalKeyManagrConfig(configuration map[string]interface{}) types.KeyManagerConfig {
	marshalledConfiguration := types.KeyManagerConfig{}
	if configuration["token_format_string"] != nil {
		marshalledConfiguration.TokenFormatString = configuration["token_format_string"].(string)
	}
	if configuration["issuer"] != nil {
		marshalledConfiguration.Issuer = configuration["issuer"].(string)
	}
	if configuration["ServerURL"] != nil {
		marshalledConfiguration.ServerURL = configuration["ServerURL"].(string)
	}
	if configuration["validation_enable"] != nil {
		marshalledConfiguration.ValidationEnable = configuration["validation_enable"].(bool)
	}
	if configuration["claim_mappings"] != nil {
		marshalledConfiguration.ClaimMappings = marshalClaimMappings(configuration["claim_mappings"].([]interface{}))
	}
	if configuration["grant_types"] != nil {
		marshalledConfiguration.GrantTypes = marshalGrantTypes(configuration["grant_types"].([]interface{}))
	}
	if configuration["OAuthConfigurations.EncryptPersistedTokens"] != nil {
		marshalledConfiguration.EncryptPersistedTokens = configuration["OAuthConfigurations.EncryptPersistedTokens"].(bool)
	}
	if configuration["enable_oauth_app_creation"] != nil {
		marshalledConfiguration.EnableOauthAppCreation = configuration["enable_oauth_app_creation"].(bool)
	}
	if configuration["VALIDITY_PERIOD"] != nil {
		marshalledConfiguration.ValidityPeriod = configuration["VALIDITY_PERIOD"].(string)
	}
	if configuration["enable_token_generation"] != nil {
		marshalledConfiguration.EnableTokenGeneration = configuration["enable_token_generation"].(bool)
	}
	if configuration["issuer"] != nil {
		marshalledConfiguration.Issuer = configuration["issuer"].(string)
	}
	if configuration["enable_map_oauth_consumer_apps"] != nil {
		marshalledConfiguration.EnableMapOauthConsumerApps = configuration["enable_map_oauth_consumer_apps"].(bool)
	}
	if configuration["enable_token_hash"] != nil {
		marshalledConfiguration.EnableTokenHash = configuration["enable_token_hash"].(bool)
	}
	if configuration["self_validate_jwt"] != nil {
		marshalledConfiguration.SelfValidateJwt = configuration["self_validate_jwt"].(bool)
	}
	if configuration["revoke_endpoint"] != nil {
		marshalledConfiguration.RevokeEndpoint = configuration["revoke_endpoint"].(string)
	}
	if configuration["enable_token_encryption"] != nil {
		marshalledConfiguration.EnableTokenEncryption = configuration["enable_token_encryption"].(bool)
	}
	if configuration["RevokeURL"] != nil {
		marshalledConfiguration.RevokeURL = configuration["RevokeURL"].(string)
	}
	if configuration["token_endpoint"] != nil {
		marshalledConfiguration.TokenURL = configuration["token_endpoint"].(string)
	}
	if configuration["certificate_type"] != nil {
		marshalledConfiguration.CertificateType = configuration["certificate_type"].(string)
	}
	if configuration["certificate_value"] != nil {
		marshalledConfiguration.CertificateValue = configuration["certificate_value"].(string)
	}
	if configuration["consumer_key_claim"] != nil {
		marshalledConfiguration.ConsumerKeyClaim = configuration["consumer_key_claim"].(string)
	}
	if configuration["scopes_claim"] != nil {
		marshalledConfiguration.ScopesClaim = configuration["scopes_claim"].(string)
	}
	return marshalledConfiguration
}
func marshalGrantTypes(grantTypes []interface{}) []string {
	resolvedGrantTypes := make([]string, 0)
	for _, grantType := range grantTypes {
		if resolvedGrantType, ok := grantType.(string); ok {
			resolvedGrantTypes = append(resolvedGrantTypes, resolvedGrantType)
		}
	}
	return resolvedGrantTypes

}
func marshalClaimMappings(claimMappings []interface{}) []types.Claim {
	resolvedClaimMappings := make([]types.Claim, 0)
	for _, claim := range claimMappings {
		if claimMap, ok := claim.(map[string]interface{}); ok {
			// Extract the remoteClaim and localClaim values from the map
			remoteClaim, hasRemote := claimMap["remoteClaim"].(string)
			localClaim, hasLocal := claimMap["localClaim"].(string)
			
			if hasRemote && hasLocal {
				resolvedClaim := types.Claim{
					RemoteClaim: remoteClaim,
					LocalClaim:  localClaim,
				}
				resolvedClaimMappings = append(resolvedClaimMappings, resolvedClaim)
			}
		}
	}
	return resolvedClaimMappings
}

// MarshalKeyManager is used to map Internal key manager
func MarshalKeyManager(keyManagerInternal *types.KeyManager) types.ResolvedKeyManager {
	return types.ResolvedKeyManager{
		UUID:             keyManagerInternal.UUID,
		Name:             keyManagerInternal.Name,
		Enabled:          keyManagerInternal.Enabled,
		Type:             keyManagerInternal.Type,
		Organization:     keyManagerInternal.Organization,
		TokenType:        keyManagerInternal.TokenType,
		KeyManagerConfig: marshalKeyManagrConfig(keyManagerInternal.Configuration),
	}
}

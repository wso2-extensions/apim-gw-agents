/*
 *
 * Copyright (c) 2025 WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.wso2.azure.gw.client;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.azure.core.http.rest.PagedIterable;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.resourcemanager.apimanagement.ApiManagementManager;
import com.azure.resourcemanager.apimanagement.models.ApiContract;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.azure.gw.client.util.AzureAPIUtil;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.FederatedAPIDiscovery;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.Environment;

import java.util.ArrayList;
import java.util.List;

/**
 * This class provides the implementation for the discovery of APIs from the Azure API Management Gateway.
 */
public class AzureFederatedAPIDiscovery implements FederatedAPIDiscovery {

    private static final Log log = LogFactory.getLog(AzureFederatedAPIDiscovery.class);

    private Environment environment;
    private String organization;

    private String resourceGroup;
    private String serviceName;
    private String hostName;
    private ApiManagementManager manager;
    HttpClient httpClient;

    @Override
    public void init(Environment environment, String organization)
            throws APIManagementException {
        log.info("Initializing Azure Gateway Deployer for environment: " + environment.getName());
        try {

            String tenantId = environment.getAdditionalProperties().get(AzureConstants.AZURE_ENVIRONMENT_TENANT_ID);
            String clientId = environment.getAdditionalProperties().get(AzureConstants.AZURE_ENVIRONMENT_CLIENT_ID);
            String clientSecret = environment.getAdditionalProperties()
                    .get(AzureConstants.AZURE_ENVIRONMENT_CLIENT_SECRET);
            String subscriptionId = environment.getAdditionalProperties()
                    .get(AzureConstants.AZURE_ENVIRONMENT_SUBSCRIPTION_ID);

            httpClient = new NettyAsyncHttpClientBuilder().build();

            TokenCredential cred = new ClientSecretCredentialBuilder()
                    .httpClient(httpClient)
                    .tenantId(tenantId)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .authorityHost(AzureEnvironment.AZURE.getActiveDirectoryEndpoint())
                    .build();

            AzureProfile profile = new AzureProfile(tenantId, subscriptionId, AzureEnvironment.AZURE);
            manager = ApiManagementManager.configure().withHttpClient(httpClient).authenticate(cred, profile);

            resourceGroup = environment.getAdditionalProperties().get(AzureConstants.AZURE_ENVIRONMENT_RESOURCE_GROUP);
            serviceName = environment.getAdditionalProperties().get(AzureConstants.AZURE_ENVIRONMENT_SERVICE_NAME);
            hostName = environment.getAdditionalProperties().get(AzureConstants.AZURE_ENVIRONMENT_HOSTNAME);

            this.environment = environment;
            this.organization = organization;

            if (tenantId == null || clientId == null || clientSecret == null || subscriptionId == null
            || resourceGroup == null || serviceName == null || hostName == null) {
                throw new APIManagementException("Missing required Azure environment configurations");
            }

            log.info("Initialization completed Azure Gateway Discovery for environment: " + environment.getName());

        } catch (Exception e) {
            throw new APIManagementException("Error occurred while initializing Azure Gateway Deployer", e);
        }
    }

    @Override
    public List<API> discoverAPI() {
        PagedIterable<ApiContract> apis = manager.apis().listByService(resourceGroup, serviceName);
        List<API> retrievedAPIs = new ArrayList<>();
        for (ApiContract api : apis) {
            try {
                String apiDefinition = AzureAPIUtil.getRestApiDefinition(manager, httpClient, api);
                API apiArtifact = AzureAPIUtil.restAPItoAPI(api, apiDefinition, organization, environment);
                retrievedAPIs.add(apiArtifact);
            } catch (APIManagementException e) {
                log.error("Error retrieving API definition for API: " + api.name(), e);
            }
        }
        return retrievedAPIs;
    }
}

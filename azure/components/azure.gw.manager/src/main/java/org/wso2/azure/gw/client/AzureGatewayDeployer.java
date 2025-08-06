/*
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
 */

package org.wso2.azure.gw.client;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.resourcemanager.apimanagement.ApiManagementManager;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.wso2.azure.gw.client.util.AzureAPIUtil;
import org.wso2.azure.gw.client.util.GatewayUtil;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.Environment;
import org.wso2.carbon.apimgt.api.model.GatewayAPIValidationResult;
import org.wso2.carbon.apimgt.api.model.GatewayDeployer;

public class AzureGatewayDeployer implements GatewayDeployer {

    private String resourceGroup;
    private String serviceName;
    private ApiManagementManager manager;

    @Override
    public void init(Environment environment) throws APIManagementException {
        String tenantId = environment.getAdditionalProperties().get(AzureConstants.AZURE_ENVIRONMENT_TENANT_ID);
        String clientId = environment.getAdditionalProperties().get(AzureConstants.AZURE_ENVIRONMENT_CLIENT_ID);
        String clientSecret = environment.getAdditionalProperties().get(AzureConstants.AZURE_ENVIRONMENT_CLIENT_SECRET);
        String subscriptionId = environment.getAdditionalProperties().get(AzureConstants.AZURE_ENVIRONMENT_SUBSCRIPTION_ID);

        HttpClient httpClient = new NettyAsyncHttpClientBuilder().build();

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
    }

    @Override
    public String getType() {
        return AzureConstants.AZURE_TYPE;
    }

    @Override
    public String deploy(API api, String externalReference) throws APIManagementException {
        return AzureAPIUtil.deployRestAPI(api, manager, resourceGroup, serviceName);
    }

    @Override
    public boolean undeploy(String s) throws APIManagementException {
        AzureAPIUtil.deleteDeployment(s, manager, resourceGroup, serviceName);
        return true;
    }

    @Override
    public GatewayAPIValidationResult validateApi(API api) throws APIManagementException {
        GatewayAPIValidationResult result = new GatewayAPIValidationResult();
        List<String> errorList = new ArrayList<>();

        errorList.add(GatewayUtil.validateAzureAPIEndpoint(GatewayUtil.getEndpointURL(api)));

        result.setValid(errorList.stream().allMatch(Objects::isNull));
        result.setErrors(errorList.stream().filter(Objects::nonNull).collect(Collectors.toList()));
        return result;
    }

    @Override
    public String getAPIExecutionURL(String externalReference) throws APIManagementException {
        StringBuilder resolvedUrl = new StringBuilder(AzureConstants.AZURE_API_EXECUTION_URL_TEMPLATE);

        //replace {service_name} placeHolder with actual Service Name
        int start = resolvedUrl.indexOf(AzureConstants.AZURE_API_EXECUTION_URL_TEMPLATE_SERVICE_NAME_PLACEHOLDER);
        if (start != -1) {
            resolvedUrl.replace(start, start +
                    AzureConstants.AZURE_API_EXECUTION_URL_TEMPLATE_SERVICE_NAME_PLACEHOLDER.length(), serviceName);
        }
        //replace {context} placeHolder with actual context
        JsonObject root = JsonParser.parseString(externalReference).getAsJsonObject();
        String context = root.get(AzureConstants.AZURE_EXTERNAL_REFERENCE_PATH).getAsString();
        start = resolvedUrl.indexOf(AzureConstants.AZURE_API_EXECUTION_URL_TEMPLATE_CONTEXT_PLACEHOLDER);
        if (start != -1) {
            resolvedUrl.replace(start, start +
                    AzureConstants.AZURE_API_EXECUTION_URL_TEMPLATE_CONTEXT_PLACEHOLDER.length(), context);
        }
        return resolvedUrl.toString();
    }

    @Override
    public void transformAPI(API api) throws APIManagementException {

    }
}

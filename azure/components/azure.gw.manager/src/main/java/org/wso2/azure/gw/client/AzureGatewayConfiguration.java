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

import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.azure.gw.client.util.AzureAPIUtil;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.GatewayAgentConfiguration;
import org.wso2.carbon.apimgt.api.model.GatewayPortalConfiguration;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


/**
 * This class contains the configurations related to Azure Gateway.
 */
@Component(
        name = "azure.external.gateway.configuration.component",
        immediate = true,
        service = GatewayAgentConfiguration.class
)
public class AzureGatewayConfiguration implements GatewayAgentConfiguration {
    private static final Log log = LogFactory.getLog(AzureAPIUtil.class);

    /**
     * Returns the Deployer classname.
     */
    @Override
    public String getImplementation() {
        return AzureGatewayDeployer.class.getName();
    }

    /**
     * Returns the configuration values required to connect to Azure API Management.
     */
    @Override
    public List<ConfigurationDto> getConnectionConfigurations() {
        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList.add(new ConfigurationDto(AzureConstants.AZURE_ENVIRONMENT_TENANT_ID, "Tenant ID", "input",
                "Directory (tenant) ID of your Microsoft Entra ID.", "", true, false,
                Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto(AzureConstants.AZURE_ENVIRONMENT_SUBSCRIPTION_ID, "Subscription ID", "input",
                "Azure subscription GUID that owns the APIM instance.", "", true, false,
                Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto(AzureConstants.AZURE_ENVIRONMENT_CLIENT_ID, "Client ID", "input",
                "Application (client) ID of the service principal used for Azure authentication.", "", true,
                false, Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto(AzureConstants.AZURE_ENVIRONMENT_CLIENT_SECRET, "Client Secret", "input",
                "Password/secret created for the service principal.", "", true, true,
                Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto(AzureConstants.AZURE_ENVIRONMENT_RESOURCE_GROUP, "Resource Group", "input",
                "The Azure resource group name containing the API Management service.", "", true, false,
                Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto(AzureConstants.AZURE_ENVIRONMENT_SERVICE_NAME, "APIM Service Name", "input",
                "The name of the Azure API Management service resource.", "", true, false,
                Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto(AzureConstants.AZURE_ENVIRONMENT_HOSTNAME, "APIM Host Name", "input",
                "The host name of the Azure API Management service resource.", "azure-api.net", true, false,
                Collections.emptyList(), false));

        return configurationDtoList;
    }

    /**
     * Returns the type of the gateway.
     */
    @Override
    public String getType() {
        return AzureConstants.AZURE_TYPE;
    }

    /**
     * Returns Azure Gateway feature catalog.
     *
     * @throws APIManagementException If there is an error reading the feature catalog JSON.
     */
    @Override
    public GatewayPortalConfiguration getGatewayFeatureCatalog() throws APIManagementException {
        try (InputStream inputStream = AzureGatewayConfiguration.class.getClassLoader()
                .getResourceAsStream(AzureConstants.GATEWAY_FEATURE_CATALOG_FILENAME)) {

            if (inputStream == null) {
                throw new APIManagementException("Gateway Feature Catalog JSON not found");
            }

            // Initialize Gson
            Gson gson = new Gson();

            InputStreamReader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
            JsonObject jsonObject = JsonParser.parseReader(reader).getAsJsonObject();

            JsonObject gatewayObject = jsonObject.getAsJsonObject(AzureConstants.AZURE_TYPE);

            List<String> apiTypes = gson.fromJson(gatewayObject.get("apiTypes"),
                    new TypeToken<List<String>>() { }.getType());
            JsonObject gatewayFeatures = gatewayObject.get("gatewayFeatures").getAsJsonObject();

            GatewayPortalConfiguration config = new GatewayPortalConfiguration();
            config.setGatewayType(AzureConstants.AZURE_TYPE);
            config.setSupportedAPITypes(apiTypes);
            config.setSupportedFeatures(gatewayFeatures);

            return config;
        } catch (Exception e) {
            throw new APIManagementException("Error occurred while reading Gateway Feature Catalog JSON", e);
        }
    }

    /**
     * Returns the hostname template for Azure API Management.
     *
     * @return The default hostname template.
     */
    @Override
    public String getDefaultHostnameTemplate() {
        return AzureConstants.AZURE_API_EXECUTION_URL_TEMPLATE;
    }
}

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

package org.wso2.azure.gw.client.util;

import com.azure.core.util.Context;
import com.azure.resourcemanager.apimanagement.ApiManagementManager;
import com.azure.resourcemanager.apimanagement.models.ApiContract;
import com.azure.resourcemanager.apimanagement.models.ContentFormat;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.wso2.azure.gw.client.AzureConstants;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;

/**
 * This class contains utility methods to interact with Azure API Gateway.
 */
public class AzureAPIUtil {
    private static final Log log = LogFactory.getLog(AzureAPIUtil.class);

    /**
     * Deploys an API to the Azure API Management Gateway.
     *
     * @param api          The API object containing the details to be deployed.
     * @param manager      The Azure ApiManagementManager instance for managing APIs.
     * @param resourceGroup The Azure resource group where the API will be deployed.
     * @param serviceName  The name of the Azure API Management service.
     * @return A JSON string containing the reference artifact with UUID and path, or null if deployment fails.
     */
    public static String deployRestAPI(API api, ApiManagementManager manager, String resourceGroup,
                                       String serviceName) {
        try {
            String openAPI = api.getSwaggerDefinition();

            String endpointConfig = api.getEndpointConfig();
            JSONParser parser = new JSONParser();
            JSONObject endpointConfigJson = (JSONObject) parser.parse(endpointConfig);
            JSONObject prodEndpoints = (JSONObject) endpointConfigJson.get("production_endpoints");
            String productionEndpoint = (String) prodEndpoints.get("url");
            productionEndpoint = productionEndpoint.endsWith("/") ?
                    productionEndpoint.substring(0, productionEndpoint.length() - 1) : productionEndpoint;

            ApiContract apiContract = manager.apis()
                    .define(api.getUuid())
                    .withExistingService(resourceGroup, serviceName)
                    .withDisplayName(api.getId().getApiName())
                    .withPath(api.getContext())
                    .withServiceUrl(productionEndpoint)
                    .withValue(openAPI)
                    .withFormat(ContentFormat.OPENAPI)
                    .create();
            log.info("API deployed successfully to Azure Gateway: " + api.getUuid());
            JsonObject referenceArtifact = new JsonObject();
            referenceArtifact.addProperty(AzureConstants.AZURE_EXTERNAL_REFERENCE_UUID, api.getUuid());
            referenceArtifact.addProperty(AzureConstants.AZURE_EXTERNAL_REFERENCE_PATH, api.getContext());
            Gson gson = new Gson();
            return gson.toJson(referenceArtifact);
        } catch (Exception e) {
            log.error("Error while deploying API to Azure Gateway: " + api.getId(), e);
            return null;
        }
    }

    /**
     * Deletes a deployed API from the Azure API Management Gateway.
     *
     * @param externalReference The external reference containing the UUID of the API to be deleted.
     * @param manager           The Azure ApiManagementManager instance for managing APIs.
     * @param resourceGroup     The Azure resource group where the API is deployed.
     * @param serviceName       The name of the Azure API Management service.
     * @return true
     * @throws APIManagementException If there is an error during the deletion process.
     */
    public static boolean deleteDeployment(String externalReference, ApiManagementManager manager, String resourceGroup,
                                           String serviceName) throws APIManagementException {
        JsonObject root = JsonParser.parseString(externalReference).getAsJsonObject();
        String uuid = root.get(AzureConstants.AZURE_EXTERNAL_REFERENCE_UUID).getAsString();
        manager.apis().delete(resourceGroup, serviceName, uuid, "*", true , Context.NONE);
        return true;
    }
}

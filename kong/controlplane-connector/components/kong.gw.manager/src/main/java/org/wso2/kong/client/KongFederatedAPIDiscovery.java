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

package org.wso2.kong.client;

import com.google.gson.JsonObject;

import feign.Feign;
import feign.RequestInterceptor;

import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import feign.slf4j.Slf4jLogger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.FederatedAPIDiscovery;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.APIIdentifier;
import org.wso2.carbon.apimgt.api.model.Environment;
import org.wso2.carbon.apimgt.api.model.Tier;
import org.wso2.carbon.apimgt.impl.kmclient.ApacheFeignHttpClient;
import org.wso2.kong.client.model.KongPlugin;
import org.wso2.kong.client.model.KongRoute;
import org.wso2.kong.client.model.KongService;
import org.wso2.kong.client.model.PagedResponse;
import org.wso2.kong.client.util.KongAPIUtil;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import static org.wso2.carbon.apimgt.impl.importexport.ImportExportConstants.DEPLOYMENT_NAME;
import static org.wso2.carbon.apimgt.impl.importexport.ImportExportConstants.DEPLOYMENT_VHOST;
import static org.wso2.carbon.apimgt.impl.importexport.ImportExportConstants.DISPLAY_ON_DEVPORTAL_OPTION;


/**
 * This class implements the FederatedAPIDiscovery interface to discover APIs from Kong Konnect.
 */
public class KongFederatedAPIDiscovery implements FederatedAPIDiscovery {

    private static final Log log = LogFactory.getLog(KongFederatedAPIDiscovery.class);

    private Environment environment;
    private KongKonnectApi apiGatewayClient;
    private String organization;
    private String adminURL;
    private String controlPlaneId;
    private String authToken;
    private JsonObject deploymentConfigObject;
    private List<String> apisDeployedInGatewayEnv;

    @Override
    public void init(Environment environment, String organization)
            throws APIManagementException {
        log.debug("Initializing AWS Gateway Deployer for environment: " + environment.getName());
        try {
            this.environment = environment;
            this.organization = organization;
            this.apisDeployedInGatewayEnv = apisDeployedInGatewayEnv;
            this.adminURL = environment.getAdditionalProperties().get(KongConstants.KONG_ADMIN_URL);
            this.controlPlaneId = environment.getAdditionalProperties().get(KongConstants.KONG_CONTROL_PLANE_ID);
            this.authToken = environment.getAdditionalProperties().get(KongConstants.KONG_AUTH_TOKEN);

            if (adminURL == null || controlPlaneId == null || authToken == null) {
                throw new APIManagementException("Missing required Kong environment configurations");
            }
            // Build Apache HttpClient (add timeouts/SSL as needed)
            CloseableHttpClient httpClient = HttpClients.custom().build();

            // Bearer token interceptor
            RequestInterceptor auth = template ->
                template.header("Authorization", "Bearer " + authToken);
            apiGatewayClient = Feign.builder()
                .client(new ApacheFeignHttpClient(httpClient))
                .encoder(new GsonEncoder())
                .decoder(new GsonDecoder())
                .logger(new Slf4jLogger(KongKonnectApi.class))
                .requestInterceptor(auth)
                .target(KongKonnectApi.class, adminURL);

            // Initialize the deployment configuration object
            this.deploymentConfigObject = new JsonObject();
            deploymentConfigObject.addProperty(DEPLOYMENT_NAME, environment.getName());
            deploymentConfigObject.addProperty(DEPLOYMENT_VHOST, environment.getVhosts().get(0).getHost());
            deploymentConfigObject.addProperty(DISPLAY_ON_DEVPORTAL_OPTION, true);
            log.debug("Initialization completed Kong Gateway Deployer for environment: " + environment.getName());
        } catch (Exception e) {
            throw new APIManagementException("Error occurred while initializing Kong Gateway Deployer", e);
        }
    }

    @Override
    public List<API> discoverAPI() {
        PagedResponse<KongService> servicesResp = apiGatewayClient.listServices(controlPlaneId, 100);
        List<KongService> services;
        if (servicesResp != null && servicesResp.getData() != null) {
            services = servicesResp.getData();
        } else {
            services = java.util.Collections.emptyList();
        }
        List<API> retrievedAPIs = new ArrayList<>();
        for (KongService svc : services) {
            PagedResponse<KongRoute> resp = apiGatewayClient.listRoutesByServiceId(controlPlaneId, svc.getId(), 100);
            List<KongRoute> routes = (resp != null && resp.getData() != null) ?
                    resp.getData() : java.util.Collections.emptyList();

            PagedResponse<KongPlugin> pluginsResp = apiGatewayClient.listPluginsByServiceId(
                    controlPlaneId, svc.getId(), 100);
            List<KongPlugin> plugins = (pluginsResp != null && pluginsResp.getData() != null)
                ? pluginsResp.getData() : java.util.Collections.<KongPlugin>emptyList();

            APIIdentifier apiId = new APIIdentifier("admin", svc.getName(), "v1");
            API api = new API(apiId);
            api.setDisplayName(svc.getName());
            api.setContext(svc.getName());
            api.setContextTemplate(svc.getName().toLowerCase().replace(" ", "-"));
            api.setUuid(svc.getId());
            api.setDescription("");
            api.setOrganization(organization);
            api.setRevision(false);

            if (svc.getUpdatedAt() != null) {
                api.setLastUpdated(Date.from(java.time.Instant.ofEpochSecond(svc.getUpdatedAt())));
            }
            if (svc.getCreatedAt() != null) {
                api.setCreatedTime(Long.toString(svc.getCreatedAt()));
            }

            api.setInitiatedFromGateway(true);
            api.setGatewayVendor("external");
            api.setGatewayType(environment.getGatewayType());

            String vhost = environment.getVhosts() != null && !environment.getVhosts().isEmpty()
                    ? environment.getVhosts().get(0).getHost() : "example.com";

            String apiDefinition = KongAPIUtil.buildOasFromRoutes(svc, routes, vhost);
            api.setSwaggerDefinition(apiDefinition);
            String endpoint = KongAPIUtil.buildEndpointUrl(svc.getProtocol(),
                    svc.getHost(), svc.getPort(), svc.getPath());
            api.setEndpointConfig(KongAPIUtil.buildEndpointConfigJson(endpoint, endpoint, false));
            api.setAvailableTiers(new HashSet<>(java.util.Collections.singleton(new Tier("Unlimited"))));

            for (KongPlugin plugin : plugins) {
                String pluginType = plugin.getName();
                if (pluginType.equals(KongConstants.KONG_CORS_PLUGIN_TYPE)) {
                    // Handle CORS plugin
                    api.setCorsConfiguration(KongAPIUtil.kongCorsToWso2Cors(plugin));
                } else if (pluginType.equals(KongConstants.KONG_RATELIMIT_PLUGIN_TYPE)) {
                    // Handle Rate Limiting plugin
                    api.setApiLevelPolicy(KongAPIUtil.kongRateLimitingToWso2Policy(plugin));
                }
            }

            retrievedAPIs.add(api);
        }
        return retrievedAPIs;
    }
}

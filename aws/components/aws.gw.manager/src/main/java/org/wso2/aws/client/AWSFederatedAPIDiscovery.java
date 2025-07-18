/*
 *
 * Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.aws.client;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.aws.client.util.AWSAPIUtil;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.Environment;
import org.wso2.carbon.apimgt.api.model.FederatedAPIDiscovery;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.common.mappings.ImportUtils;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.APIDTO;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.apigateway.ApiGatewayClient;
import software.amazon.awssdk.services.apigateway.model.RestApi;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.apimgt.impl.importexport.ImportExportConstants.DEPLOYMENT_ENVIRONMENTS;
import static org.wso2.carbon.apimgt.impl.importexport.ImportExportConstants.DEPLOYMENT_NAME;
import static org.wso2.carbon.apimgt.impl.importexport.ImportExportConstants.DEPLOYMENT_VHOST;
import static org.wso2.carbon.apimgt.impl.importexport.ImportExportConstants.DISPLAY_ON_DEVPORTAL_OPTION;
import static software.amazon.awssdk.services.ssm.model.NodeFilterKey.AGENT_TYPE;

public class AWSFederatedAPIDiscovery extends FederatedAPIDiscovery {
    private Environment environment;
    private ApiGatewayClient apiGatewayClient;
    private String region;
    private String organization;
    private JsonObject deploymentConfigObject;
    private List<String> apisDeployedInGatewayEnv;
    public static Log logger = LogFactory.getLog(AWSFederatedAPIDiscovery.class);

    @Override
    public void init(Environment environment, List<String> apisDeployedInGatewayEnv, String organization) throws APIManagementException {
        try {
            this.region = environment.getAdditionalProperties().get(AWSConstants.AWS_ENVIRONMENT_REGION);
            this.apisDeployedInGatewayEnv = apisDeployedInGatewayEnv;

            JsonObject deploymentConfigObject = new JsonObject();
            deploymentConfigObject.addProperty(DEPLOYMENT_NAME, environment.getName());
            deploymentConfigObject.addProperty(DEPLOYMENT_VHOST, environment.getVhosts().get(0).getHost());
            deploymentConfigObject.addProperty(DISPLAY_ON_DEVPORTAL_OPTION, true);

            JsonArray deploymentArray = new JsonArray();
            deploymentArray.add(deploymentConfigObject);

            JsonObject deploymentEnvObject = new JsonObject();
            deploymentEnvObject.add(DEPLOYMENT_ENVIRONMENTS, deploymentConfigObject);

            String accessKey = environment.getAdditionalProperties().get(AWSConstants.AWS_ENVIRONMENT_ACCESS_KEY);
            String secretKey = environment.getAdditionalProperties().get(AWSConstants.AWS_ENVIRONMENT_SECRET_KEY);
            this.environment = environment;
            this.organization = organization;

            SdkHttpClient httpClient = ApacheHttpClient.builder().build();
            this.apiGatewayClient = ApiGatewayClient.builder().region(Region.of(region)).httpClient(httpClient).credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKey, secretKey))).build();
            logger.info("----------------------- Initializing AWS Federated Gateway Discovery for region: " + region);
        } catch (Exception e) {
            throw new APIManagementException("Error occurred while initializing AWS Gateway Deployer", e);
        }
    }


    @Override
    public void discoverAPI() {
        List<RestApi> restApis = AWSAPIUtil.getRestApis(apiGatewayClient);
        List<String> retrievedAPIs = new ArrayList<>();
        logger.info("----------------------------- Retrieving APIs from AWS Gateway");

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(organization);
            String adminUsername = APIUtil.getAdminUsername();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(adminUsername);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(APIUtil.getTenantId(adminUsername));

            restApis.forEach(restApi -> {
                try {
                    if (AWSAPIUtil.isAPIExists(restApi, apisDeployedInGatewayEnv, environment)) {
                        logger.info("API " + restApi.name() + " already exists in the environment " + environment.getName());
                        return;
                    }

                    Gson gson = new Gson();

                    String stageName = AWSAPIUtil.getStageNames(apiGatewayClient, restApi.id());
                    if (stageName == null) {
                        return;
                    }
                    String apiDefinition = AWSAPIUtil.getRestApiDefinition(apiGatewayClient, restApi.id(), stageName);

                    APIDTO api = AWSAPIUtil.restAPItoAPI(restApi, apiDefinition, organization, environment);
                    String apiJson = gson.toJson(api);
                    String deploymentEnvString = AWSAPIUtil.createDeploymentYaml(environment);
                    InputStream apiProjectInputStream = AWSAPIUtil.createZipAsInputStream(apiJson, apiDefinition, deploymentEnvString, restApi.name());

                    ImportUtils.importApi(apiProjectInputStream, api, true, true, true, true, false, null, deploymentConfigObject, organization);
                    apisDeployedInGatewayEnv.add(api.getName() + ":" + api.getVersion());
                    retrievedAPIs.add(restApi.name() + ":" + restApi.version());
                    retrievedAPIs.add(restApi.name() + "_" + environment.getName() + ":" + restApi.version());

                    logger.info("Successfully retrieved API definition for" + restApi.id());
                } catch (APIManagementException e) {
                    logger.error("Error occurred while retrieving API definition for " + restApi.name(), e);
                } catch (IllegalArgumentException e) {
                    logger.error("Invalid API definition for " + restApi.name() + ": " + e.getMessage());
                } catch (Throwable t) {
                    logger.error("Unexpected error occurred while retrieving API definition for " + restApi.name(), t);
                }
            });

            for (String apiName : retrievedAPIs) {
                if (!apisDeployedInGatewayEnv.contains(apiName)) {
                    logger.info("API " + apiName + " not found in the environment " + environment.getName());
                }
            }
        } catch (Exception e) {
            logger.error("Error occurred while discovering API definitions", e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }
}

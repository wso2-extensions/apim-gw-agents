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

package org.wso2.aws.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.aws.client.util.AWSAPIUtil;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.FederatedAPIDiscovery;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.Environment;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.apigateway.ApiGatewayClient;
import software.amazon.awssdk.services.apigateway.model.RestApi;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class AWSFederatedAPIDiscovery implements FederatedAPIDiscovery {

    private static final Log log = LogFactory.getLog(AWSFederatedAPIDiscovery.class);

    private Environment environment;
    private ApiGatewayClient apiGatewayClient;
    private String organization;
    private String stage;
    private String region;

    @Override
    public void init(Environment environment, String organization)
            throws APIManagementException {
        if (log.isDebugEnabled()) {
            log.debug("Initializing AWS Gateway for API Discovery in environment " + environment.getName());
        }
        try {
            this.environment = environment;
            this.organization = organization;
            region = environment.getAdditionalProperties().get(AWSConstants.AWS_ENVIRONMENT_REGION);
            this.stage = environment.getAdditionalProperties().get(AWSConstants.AWS_API_STAGE);

            String accessKey = environment.getAdditionalProperties().get(AWSConstants.AWS_ENVIRONMENT_ACCESS_KEY);
            String secretKey = environment.getAdditionalProperties().get(AWSConstants.AWS_ENVIRONMENT_SECRET_KEY);

            if (region == null || accessKey == null || secretKey == null) {
                throw new APIManagementException("Missing required AWS environment configurations");
            }

            SdkHttpClient httpClient = ApacheHttpClient.builder().build();
            this.apiGatewayClient = ApiGatewayClient.builder().region(Region.of(region)).httpClient(httpClient)
                    .credentialsProvider(StaticCredentialsProvider.create(
                            AwsBasicCredentials.create(accessKey, secretKey))).build();
            if (log.isDebugEnabled()) {
                log.debug("AWS Gateway API Discovery environment initialization completed: "
                        + environment.getName());
            }
            log.info("AWS Gateway API Discovery environment " + environment.getName() + " " +
                    "initialized successfully for organization: " + organization);

        } catch (Exception e) {
            throw new APIManagementException("Error occurred during AWS Gateway Discovery initialization: ", e);
        }
    }

    @Override
    public List<API> discoverAPI() {
        List<RestApi> restApis = AWSAPIUtil.getRestApis(apiGatewayClient);
        List<API> retrievedAPIs = new ArrayList<>();
        for (RestApi restApi : restApis) {
            String apiStage = AWSAPIUtil.getStageNames(apiGatewayClient, restApi.id());
            if (!Objects.equals(apiStage, stage)) {
                continue;
            }
            String apiDefinition = AWSAPIUtil.getRestApiDefinition(apiGatewayClient, restApi.id(), stage);
            API api = AWSAPIUtil.restAPItoAPI(restApi, apiDefinition, organization, environment);
            AWSAPIUtil.updateAPIWithEndpoints(api, restApi, environment, region);
            retrievedAPIs.add(api);
        }
        return retrievedAPIs;
    }
}

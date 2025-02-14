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

package org.wso2.aws.client;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.Component;
import org.wso2.aws.client.util.AWSAPIUtil;
import org.wso2.aws.client.util.GatewayUtil;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.Environment;
import org.wso2.carbon.apimgt.api.model.URITemplate;
import org.wso2.carbon.apimgt.impl.deployer.ExternalGatewayDeployer;
import org.wso2.carbon.apimgt.impl.deployer.exceptions.DeployerException;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;


/**
 * This class controls the API artifact deployments on the AWS API Gateway
 */
@Component(
        name = "aws.external.gateway.deployer.component",
        immediate = true,
        service = ExternalGatewayDeployer.class
)
public class AWSGatewayDeployer implements ExternalGatewayDeployer {
    private static final Log log = LogFactory.getLog(AWSAPIUtil.class);

    @Override
    public String deploy(API api, Environment environment, String referenceArtifact) throws DeployerException {
        if (referenceArtifact == null) {
            return AWSAPIUtil.importRestAPI(api, environment);
        } else {
            return AWSAPIUtil.reimportRestAPI(referenceArtifact, api, environment);
        }
    }

    @Override
    public boolean undeploy(String apiID, String apiName, String apiVersion, String apiContext,
                            Environment environment, String referenceArtifact) throws DeployerException {

        return AWSAPIUtil.deleteDeployment(environment, referenceArtifact);
    }

    @Override
    public boolean undeployWhenRetire(API api, Environment environment, String referenceArtifact) throws DeployerException {

        return AWSAPIUtil.deleteDeployment(environment, referenceArtifact);
    }

    @Override
    public List<ConfigurationDto> getConnectionConfigurations() {
        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList
                .add(new ConfigurationDto("access_key", "Access Key", "input", "AWS Access Key for Signature Authentication", "", true,
                        true, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("secret_key", "Secret Key", "input", "AWS Secret Key for Signature Authentication", "",
                        true, true, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("region", "AWS Region", "input", "AWS Region", "", true, false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("oauth2_lambda_arn", "OAuth2 Lambda ARN", "input", "Lambda function to " +
                        "support OAuth2", "", true, false, Collections.emptyList(), false));
        configurationDtoList.add(new ConfigurationDto("stage", "Stage Name", "input", "Default stage name", "", true,
                false,
                Collections.emptyList(), false));

        return configurationDtoList;
    }

    @Override
    public String getType() {
        return AWSConstants.AWS_TYPE;
    }

    @Override
    public JsonObject getGatewayFeatureCatalog() throws DeployerException{
        try (InputStream inputStream = AWSGatewayDeployer.class.getClassLoader()
                .getResourceAsStream("GatewayFeatureCatalog.json")) {

            if (inputStream == null) {
                throw new DeployerException("Gateway Feature Catalog JSON not found");
            }

            InputStreamReader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
            return JsonParser.parseReader(reader).getAsJsonObject();
        } catch (Exception e) {
            throw new DeployerException("Error while getting Gateway Feature Catalog", e);
        }
    }

    @Override
    public List<String> validateApi(API api) throws DeployerException {
        List<String> errorList = new ArrayList<>();
        try {
            // Endpoint validation
            errorList.add(GatewayUtil.validateAWSAPIEndpoint(GatewayUtil.getEndpointURL(api)));
            // Check for wildcard in the resources
            errorList.add(GatewayUtil.validateResourceContexts(api));

            return errorList.stream().filter(Objects::nonNull).collect(Collectors.toList());
        } catch (DeployerException e) {
            throw new DeployerException("Error while validating API with AWS Gateway", e);
        }
    }

    @Override
    public String getAPIExecutionURL(String url, Environment environment, String referenceArtifact)
            throws DeployerException {
        StringBuilder resolvedUrl = new StringBuilder(url);
        String awsAPIId = GatewayUtil.getAWSApiIdFromReferenceArtifact(referenceArtifact);

        //replace {apiId} placeHolder with actual API ID
        int start = resolvedUrl.indexOf("{apiId}");
        if (start != -1) {
            resolvedUrl.replace(start, start + "{apiId}".length(), awsAPIId);
        }

        //replace {region} placeHolder with actual region
        String region = environment.getAdditionalProperties().get("region");
        start = resolvedUrl.indexOf("{region}");
        if (start != -1) {
            resolvedUrl.replace(start, start + "{region}".length(), region);
        }
        return resolvedUrl.toString() + "/" + environment.getAdditionalProperties().get("stage");
    }

    @Override
    public void transformAPI(API api) throws DeployerException {
        // change all /* resources to / in the resources list
        for(URITemplate resource: api.getUriTemplates()) {
            if (resource.getUriTemplate().endsWith("/*")) {
                resource.setUriTemplate(resource.getUriTemplate().replace("/*", "/"));
            }
        }
    }

    @Override
    public String getDefaultHostnameTemplate() {

        return "{apiId}.execute-api.{region}.amazonaws.com";
    }
}

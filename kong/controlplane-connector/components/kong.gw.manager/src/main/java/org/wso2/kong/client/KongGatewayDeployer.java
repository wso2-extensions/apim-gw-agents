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

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.Environment;
import org.wso2.carbon.apimgt.api.model.GatewayAPIValidationResult;
import org.wso2.carbon.apimgt.api.model.GatewayDeployer;
import org.wso2.kong.client.util.KongAPIUtil;

import java.util.Collections;


/**
 * This class controls the API artifact deployments on the Kong Gateway.
 */
public class KongGatewayDeployer implements GatewayDeployer {

    private Environment environment;
    @Override
    public void init(Environment environment) throws APIManagementException {
        this.environment = environment;
    }

    @Override
    public String getType() {
        return KongConstants.KONG_TYPE;
    }

    @Override
    public String deploy(API api, String externalReference) throws APIManagementException {
        if (KongAPIUtil.isKubernetesDeployment(environment)) {
            return KongAPIUtil.buildEndpointConfigJsonForKubernetes(api, environment);
        }
        return null;
    }

    @Override
    public boolean undeploy(String externalReference) throws APIManagementException {
        return true;
    }

    @Override
    public GatewayAPIValidationResult validateApi(API api) throws APIManagementException {
        GatewayAPIValidationResult gatewayAPIValidationResult = new GatewayAPIValidationResult();
        gatewayAPIValidationResult.setValid(true);
        gatewayAPIValidationResult.setErrors(Collections.<String>emptyList());
        return gatewayAPIValidationResult;
    }

    @Override
    public String getAPIExecutionURL(String externalReference) throws APIManagementException {
        if (KongAPIUtil.isKubernetesDeployment(environment)) {
            return KongAPIUtil.getAPIExecutionURLForKubernetes(externalReference, null);
        }
        String vhost = environment.getVhosts() != null && !environment.getVhosts().isEmpty()
                ? environment.getVhosts().get(0).getHost() : "example.com";
        return "https://" + vhost;
    }

    @Override
    public void transformAPI(API api) throws APIManagementException {

    }
}

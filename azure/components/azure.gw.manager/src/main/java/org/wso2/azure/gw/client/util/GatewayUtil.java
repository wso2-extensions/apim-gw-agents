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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;

public class GatewayUtil {

    private static final Pattern VALID_PATH_PATTERN = Pattern.compile("^[a-zA-Z0-9-._~%!$&'()*+,;=:@/]*$");

    public static String getEndpointURL(API api) throws APIManagementException {

        try {
            String endpointConfig = api.getEndpointConfig();
            if (StringUtils.isEmpty(endpointConfig)) {
                return endpointConfig;
            }
            JSONParser parser = new JSONParser();
            JSONObject endpointConfigJson = null;

            endpointConfigJson = (JSONObject) parser.parse(endpointConfig);

            JSONObject prodEndpoints = (JSONObject)endpointConfigJson.get("production_endpoints");
            String productionEndpoint = (String) prodEndpoints.get("url");

            return productionEndpoint.charAt(productionEndpoint.length() - 1) == '/' ?
                    productionEndpoint.substring(0, productionEndpoint.length() - 1) : productionEndpoint;
        } catch (ParseException e) {
            throw new APIManagementException("Error while parsing endpoint configuration", e);
        }
    }

    public static String validateAzureAPIEndpoint(String urlString) {
        try {
            if (StringUtils.isEmpty(urlString)) {
                return null;
            }
            URL url = new URL(urlString);

            // Validate scheme (only http and https are allowed)
            String protocol = url.getProtocol();
            if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
                return "Invalid Endpoint URL";
            }

            // Validate host
            if (url.getHost() == null || url.getHost().isEmpty()
                    || url.getHost().equalsIgnoreCase("localhost")) {
                return "Invalid Endpoint URL";
            }

            // Validate path (no illegal characters)
            if (!VALID_PATH_PATTERN.matcher(url.getPath()).matches()) {
                return "Invalid Endpoint URL";
            }
            return null;
        } catch (MalformedURLException e) {
            return "Invalid Endpoint URL";
        }
    }
}

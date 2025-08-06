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

/**
 * This class contains the constants used in AWS client.
 */
public class AzureConstants {
    public static final String AZURE_TYPE = "Azure";

    public static final String AZURE_API_EXECUTION_URL_TEMPLATE_SERVICE_NAME_PLACEHOLDER = "{service_name}";
    public static final String AZURE_API_EXECUTION_URL_TEMPLATE_CONTEXT_PLACEHOLDER = "{context_version}";
    public static final String AZURE_API_EXECUTION_URL_TEMPLATE =
            AZURE_API_EXECUTION_URL_TEMPLATE_SERVICE_NAME_PLACEHOLDER + ".azure-api.net" +
            AZURE_API_EXECUTION_URL_TEMPLATE_CONTEXT_PLACEHOLDER;
    public static final String AZURE_EXTERNAL_REFERENCE_PATH = "path";
    public static final String AZURE_EXTERNAL_REFERENCE_UUID = "uuid";

    public static final String GATEWAY_FEATURE_CATALOG_FILENAME = "GatewayFeatureCatalog.json";

    // Environment related constants
    public static final String AZURE_ENVIRONMENT_TENANT_ID = "tenant_id";
    public static final String AZURE_ENVIRONMENT_SUBSCRIPTION_ID = "subscription_id";
    public static final String AZURE_ENVIRONMENT_CLIENT_ID = "client_id";
    public static final String AZURE_ENVIRONMENT_CLIENT_SECRET = "client_secret";
    public static final String AZURE_ENVIRONMENT_RESOURCE_GROUP = "resource_group";
    public static final String AZURE_ENVIRONMENT_SERVICE_NAME = "service_name";
}

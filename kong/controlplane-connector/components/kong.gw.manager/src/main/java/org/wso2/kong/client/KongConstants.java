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

/**
 * This class contains the constants used in Kong client.
 */
public class KongConstants {
    public static final String KONG_TYPE = "Kong";
    public static final String KONG_ADMIN_URL = "admin_url";
    public static final String KONG_CONTROL_PLANE_ID = "control_plane_id";
    public static final String KONG_AUTH_TOKEN = "auth_key";

    public static final String KONG_DEPLOYMENT_TYPE = "deployment_type";
    public static final String KONG_STANDALONE_DEPLOYMENT = "Standalone";
    public static final String KONG_KUBERNETES_DEPLOYMENT = "Kubernetes";

    // API endpoint configuration property names
    public static final String KONG_API_UUID = "uuid";
    public static final String KONG_API_CONTEXT = "context";
    public static final String KONG_API_VERSION = "version";
    public static final String KONG_GATEWAY_HOST = "host";
    public static final String KONG_GATEWAY_HTTP_CONTEXT = "httpContext";
    public static final String KONG_GATEWAY_HTTP_PORT = "httpPort";
    public static final String KONG_GATEWAY_HTTPS_PORT = "httpsPort";

    public static final String HTTPS_PROTOCOL = "https";
    public static final String HTTP_PROTOCOL = "http";
    public static final String PROTOCOL_SEPARATOR = "://";
    public static final String HOST_PORT_SEPARATOR = ":";
    public static final String CONTEXT_SEPARATOR = "/";
    public static final int DEFAULT_HTTPS_PORT = 443;
    public static final int DEFAULT_HTTP_PORT = 80;

    // Kong Plugin Types
    public static final String KONG_CORS_PLUGIN_TYPE = "cors";
    public static final String KONG_RATELIMIT_ADVANCED_PLUGIN_TYPE = "rate-limiting-advanced";
    public static final String KONG_RATELIMIT_PLUGIN_TYPE = "rate-limiting";
}

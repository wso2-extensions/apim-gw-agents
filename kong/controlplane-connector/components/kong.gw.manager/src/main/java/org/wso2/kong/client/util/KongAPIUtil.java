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

package org.wso2.kong.client.util;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.Environment;
import org.wso2.kong.client.KongConstants;
import org.wso2.kong.client.model.KongRoute;
import org.wso2.kong.client.model.KongService;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for building OpenAPI Specification (OAS) from Kong routes and services.
 */
public class KongAPIUtil {
    public static String buildOasFromRoutes(KongService svc, List<KongRoute> routes, String vhost) {
        JsonObject root = new JsonObject();
        root.addProperty("openapi", "3.0.3");

        // info
        JsonObject info = new JsonObject();
        info.addProperty("title", svc.getName() != null ? svc.getName() : "kong-service");
        info.addProperty("version", "v1");
        root.add("info", info);

        // servers (public base URL on the gateway/vhost)
        JsonArray servers = new JsonArray();
        JsonObject server0 = new JsonObject();
        server0.addProperty("url", "https://" + vhost);
        servers.add(server0);
        root.add("servers", servers);

        // paths
        JsonObject paths = new JsonObject();

        for (KongRoute r : routes) {
            List<String> routePaths = (r.getPaths() != null) ? r.getPaths() : java.util.Collections.<String>emptyList();
            List<String> methods = (r.getMethods() != null && !r.getMethods().isEmpty())
                    ? r.getMethods()
                    : java.util.Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS");

            for (String kongPath : routePaths) {
                String oasPath = toOasPath(kongPath); // normalize regex → template

                // Ensure we have a path object
                JsonObject pathItem = paths.has(oasPath) ? paths.getAsJsonObject(oasPath) : new JsonObject();

                // For each HTTP method, create a minimal operation
                for (String m : methods) {
                    String http = m.toLowerCase(Locale.ROOT);
                    // Avoid duplicates (if multiple routes map to same path+method, last one wins)
                    JsonObject op = new JsonObject();
                    op.addProperty("operationId", safeOpId(r.getName(), http, oasPath));
                    op.addProperty("summary", r.getName() != null ? r.getName() : "Kong route");

                    // Path params (derive from {param} in the normalized path)
                    JsonArray parameters = buildPathParameters(oasPath);
                    if (parameters.size() > 0) {
                        op.add("parameters", parameters);
                    }

                    // Minimal 200 response
                    JsonObject responses = new JsonObject();
                    JsonObject ok = new JsonObject();
                    ok.addProperty("description", "OK");
                    responses.add("200", ok);
                    op.add("responses", responses);

                    pathItem.add(http, op);
                }

                paths.add(oasPath, pathItem);
            }
        }

        root.add("paths", paths);
        // components left empty for now
        root.add("components", new JsonObject());

        return root.toString();
    }

    /** Convert Kong route path value to an OAS path template. Handles:
     *  - plain prefixes like "/get" (returned as-is)
     *  - regex form starting with "~" and ending with "$"
     *  - named groups like (?<value>[^#?/]+)  →  {value}
     */
    public static String toOasPath(String kongPath) {
        if (kongPath == null || kongPath.isEmpty()) {
            return "/";
        }

        String p = kongPath.trim();

        // Regex-style route (starts with "~")
        if (p.startsWith("~")) {
            // strip leading "~" and trailing "$"
            if (p.endsWith("$")) {
                p = p.substring(1, p.length() - 1);
            } else {
                p = p.substring(1);
            }

            // Remove a leading ^ if present
            if (p.startsWith("^")) {
                p = p.substring(1);
            }

            // Replace named capture groups with {name}
            // (?<name>pattern)  →  {name}
            Pattern named = Pattern.compile("\\(\\?<([A-Za-z_][A-Za-z0-9_-]*)>[^)]+\\)");
            Matcher m = named.matcher(p);
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                m.appendReplacement(sb, "{" + m.group(1) + "}");
            }
            m.appendTail(sb);
            p = sb.toString();

            // Remove remaining regex tokens that aren’t valid in OAS paths
            // (non-named groups, anchors)
            p = p.replaceAll("\\((?:\\?:)?[^)]*\\)", ""); // drop other groups
        }

        // Ensure it starts with "/"
        if (!p.startsWith("/")) {
            p = "/" + p;
        }
        // Collapse any double slashes
        p = p.replaceAll("/{2,}", "/");

        return p;
    }

    /**
     * Build path parameters from a Kong route path.
     * Extracts {param} style placeholders and returns them as OAS path parameters.
     */
    public static JsonArray buildPathParameters(String oasPath) {
        JsonArray params = new JsonArray();
        Matcher m = Pattern.compile("\\{([A-Za-z_][A-Za-z0-9_-]*)\\}").matcher(oasPath);
        while (m.find()) {
            String name = m.group(1);
            JsonObject p = new JsonObject();
            p.addProperty("name", name);
            p.addProperty("in", "path");
            p.addProperty("required", true);

            JsonObject schema = new JsonObject();
            schema.addProperty("type", "string");
            p.add("schema", schema);

            params.add(p);
        }
        return params;
    }

    public static String safeOpId(String routeName, String method, String path) {
        String base = (routeName != null && !routeName.isEmpty()) ? routeName : "op";
        // sanitize path to opId-friendly
        String p = path.replaceAll("[^A-Za-z0-9]+", "_");
        return (base + "_" + method + "_" + p).replaceAll("_+", "_");
    }

    /**
     * Build endpointConfig JSON for APIM/Kong using Gson.
     * Both production and sandbox endpoints are included.
     */
    public static String buildEndpointConfigJson(String productionUrl, String sandboxUrl, boolean failOver) {
        JsonObject endpointConfig = new JsonObject();
        endpointConfig.addProperty("endpoint_type", "http");
        endpointConfig.addProperty("failOver", failOver);

        JsonObject prod = new JsonObject();
        prod.addProperty("template_not_supported", false);
        prod.addProperty("url", productionUrl);

        JsonObject sand = new JsonObject();
        sand.addProperty("template_not_supported", false);
        sand.addProperty("url", sandboxUrl);

        endpointConfig.add("production_endpoints", prod);
        endpointConfig.add("sandbox_endpoints", sand);

        return endpointConfig.toString();
    }

    /**
     * Build endpointConfig JSON for KONG on Kubernetes.
     */
    public static String buildEndpointConfigJsonForKubernetes(API api, Environment environment) {
        JsonObject endpointConfig = new JsonObject();

        endpointConfig.addProperty(KongConstants.KONG_API_UUID, api.getUuid());
        endpointConfig.addProperty(KongConstants.KONG_API_CONTEXT, api.getContext());
        endpointConfig.addProperty(KongConstants.KONG_API_VERSION, api.getId().getVersion());

        endpointConfig.addProperty(KongConstants.KONG_GATEWAY_HOST, environment.getVhosts().get(0).getHost());
        endpointConfig.addProperty(KongConstants.KONG_GATEWAY_HTTP_CONTEXT,
                environment.getVhosts().get(0).getHttpContext());
        endpointConfig.addProperty(KongConstants.KONG_GATEWAY_HTTP_PORT, environment.getVhosts().get(0).getHttpPort());
        endpointConfig.addProperty(KongConstants.KONG_GATEWAY_HTTPS_PORT,
                environment.getVhosts().get(0).getHttpsPort());

        return endpointConfig.toString();
    }

    public static String buildEndpointUrl(String protocol, String host, int port, String path) {
        StringBuilder sb = new StringBuilder();
        sb.append(protocol).append("://").append(host);
        if (port > 0) {
            sb.append(":").append(port);
        }
        if (path != null && !path.isEmpty()) {
            sb.append(path);
        }
        if (sb.charAt(sb.length() - 1) != '/') {
            sb.append('/');
        }
        return sb.toString();
    }

    /**
     * Checks if the environment is configured for Kubernetes deployment.
     *
     * @param environment The environment to check
     * @return true if the environment is configured for Kubernetes deployment, false otherwise
     */
    public static boolean isKubernetesDeployment(Environment environment) {
        return Objects.equals(getEnvironmentProperty(environment, KongConstants.KONG_DEPLOYMENT_TYPE),
                KongConstants.KONG_KUBERNETES_DEPLOYMENT);
    }

    /**
     * Safely gets a property from environment's additional properties.
     *
     * @param environment The environment
     * @param key         The property key
     * @return The property value, or null if not found or environment/properties are null
     */
    public static String getEnvironmentProperty(Environment environment, String key) {
        if (environment == null || environment.getAdditionalProperties() == null || key == null) {
            return null;
        }
        return environment.getAdditionalProperties().get(key);
    }

    /**
     * Builds the API execution URL for Kong on Kubernetes deployment. Parses the external reference JSON to extract the
     * necessary information.
     *
     * @param externalReference JSON string containing Kong API configuration
     * @param protocol          The protocol to use (http or https). If null or empty, defaults to https.
     * @return The API execution URL for Kong on Kubernetes
     * @throws APIManagementException If there is an error while constructing the URL.
     */
    public static String getAPIExecutionURLForKubernetes(String externalReference, String protocol)
            throws APIManagementException {
        try {
            JsonObject config = JsonParser.parseString(externalReference).getAsJsonObject();

            String host = config.get(KongConstants.KONG_GATEWAY_HOST).getAsString();
            String context = config.get(KongConstants.KONG_API_CONTEXT).getAsString();
            String httpContext = config.has(KongConstants.KONG_GATEWAY_HTTP_CONTEXT) ?
                    config.get(KongConstants.KONG_GATEWAY_HTTP_CONTEXT).getAsString() :
                    null;
            int httpsPort = config.has(KongConstants.KONG_GATEWAY_HTTPS_PORT) ?
                    config.get(KongConstants.KONG_GATEWAY_HTTPS_PORT).getAsInt() :
                    KongConstants.DEFAULT_HTTPS_PORT;
            int httpPort = config.has(KongConstants.KONG_GATEWAY_HTTP_PORT) ?
                    config.get(KongConstants.KONG_GATEWAY_HTTP_PORT).getAsInt() :
                    KongConstants.DEFAULT_HTTP_PORT;

            StringBuilder url = new StringBuilder();
            if (protocol == null || protocol.isEmpty()) {
                protocol = KongConstants.HTTPS_PROTOCOL;
            }
            url.append(protocol).append(KongConstants.PROTOCOL_SEPARATOR).append(host);

            if (protocol.equalsIgnoreCase(
                    KongConstants.HTTPS_PROTOCOL) && httpsPort != KongConstants.DEFAULT_HTTPS_PORT) {
                url.append(KongConstants.HOST_PORT_SEPARATOR).append(httpsPort);
            } else if (protocol.equalsIgnoreCase(
                    KongConstants.HTTP_PROTOCOL) && httpPort != KongConstants.DEFAULT_HTTP_PORT) {
                url.append(KongConstants.HOST_PORT_SEPARATOR).append(httpPort);
            }

            if (httpContext != null && !httpContext.trim().isEmpty()) {
                if (!httpContext.startsWith(KongConstants.CONTEXT_SEPARATOR)) {
                    url.append(KongConstants.CONTEXT_SEPARATOR);
                }
                url.append(httpContext);
            }

            if (!context.startsWith(KongConstants.CONTEXT_SEPARATOR)) {
                url.append(KongConstants.CONTEXT_SEPARATOR);
            }
            url.append(context);

            return url.toString();

        } catch (Exception e) {
            throw new APIManagementException("Failed to parse Kong external reference");
        }
    }
    
}

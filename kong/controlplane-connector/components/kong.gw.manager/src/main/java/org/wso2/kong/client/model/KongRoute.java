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

package org.wso2.kong.client.model;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Represents a Kong Route.
 * This class is used to map the JSON response from the Kong API for routes.
 */
public class KongRoute {
    private String id;
    private String name;

    private List<String> hosts;
    private List<String> paths;
    private List<String> methods;
    private List<String> protocols;

    @SerializedName("strip_path") private Boolean stripPath;
    @SerializedName("preserve_host") private Boolean preserveHost;
    @SerializedName("path_handling") private String pathHandling;
    @SerializedName("https_redirect_status_code") private Integer httpsRedirectStatusCode;
    @SerializedName("regex_priority") private Integer regexPriority;
    @SerializedName("request_buffering") private Boolean requestBuffering;
    @SerializedName("response_buffering") private Boolean responseBuffering;
    @SerializedName("created_at") private Long createdAt;
    @SerializedName("updated_at") private Long updatedAt;

    private ServiceRef service;

    /**
     * Represents a reference to a Kong Service.
     * This is used to link the route to its corresponding service.
     */
    public static class ServiceRef {
        private String id;
        public String getId() {
            return id;
        }
        public void setId(String id) {
            this.id = id;
        }
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getHosts() {
        return hosts;
    }

    public void setHosts(List<String> hosts) {
        this.hosts = hosts;
    }

    public List<String> getPaths() {
        return paths;
    }

    public void setPaths(List<String> paths) {
        this.paths = paths;
    }

    public List<String> getMethods() {
        return methods;
    }

    public void setMethods(List<String> methods) {
        this.methods = methods;
    }

    public List<String> getProtocols() {
        return protocols;
    }

    public void setProtocols(List<String> protocols) {
        this.protocols = protocols;
    }

    public Boolean getStripPath() {
        return stripPath;
    }

    public void setStripPath(Boolean stripPath) {
        this.stripPath = stripPath;
    }

    public Boolean getPreserveHost() {
        return preserveHost;
    }

    public void setPreserveHost(Boolean preserveHost) {
        this.preserveHost = preserveHost;
    }

    public String getPathHandling() {
        return pathHandling;
    }

    public void setPathHandling(String pathHandling) {
        this.pathHandling = pathHandling;
    }

    public Integer getHttpsRedirectStatusCode() {
        return httpsRedirectStatusCode;
    }

    public void setHttpsRedirectStatusCode(Integer httpsRedirectStatusCode) {
        this.httpsRedirectStatusCode = httpsRedirectStatusCode;
    }

    public Integer getRegexPriority() {
        return regexPriority;
    }

    public void setRegexPriority(Integer regexPriority) {
        this.regexPriority = regexPriority;
    }

    public Boolean getRequestBuffering() {
        return requestBuffering;
    }

    public void setRequestBuffering(Boolean requestBuffering) {
        this.requestBuffering = requestBuffering;
    }

    public Boolean getResponseBuffering() {
        return responseBuffering;
    }

    public void setResponseBuffering(Boolean responseBuffering) {
        this.responseBuffering = responseBuffering;
    }

    public Long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Long createdAt) {
        this.createdAt = createdAt;
    }

    public Long getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Long updatedAt) {
        this.updatedAt = updatedAt;
    }

    public ServiceRef getService() {
        return service;
    }

    public void setService(ServiceRef service) {
        this.service = service;
    }

}


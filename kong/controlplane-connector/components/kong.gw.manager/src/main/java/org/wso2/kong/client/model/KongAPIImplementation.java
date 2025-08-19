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

/**
 * Represents a Kong API implementation.
 * This class is used to encapsulate the details of an API implementation in Kong.
 */
public class KongAPIImplementation {
    private String id;
    @SerializedName("created_at") private String createdAt;
    @SerializedName("updated_at") private String updatedAt;
    @SerializedName("api_id") private String apiId;
    private ServiceLink service;

    /**
     * Represents a link to a Kong service.
     * This is used to associate an API implementation with a specific service in Kong.
     */
    public static class ServiceLink {
        private String id;
        @SerializedName("control_plane_id") private String controlPlaneId;
        public String getId() {
            return id;
        }
        public void setId(String id) {
            this.id = id;
        }
        public String getControlPlaneId() {
            return controlPlaneId;
        }
        public void setControlPlaneId(String controlPlaneId) {
            this.controlPlaneId = controlPlaneId;
        }
    }

    // getters/setters
    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }
    public String getCreatedAt() {
        return createdAt;
    }
    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }
    public String getUpdatedAt() {
        return updatedAt;
    }
    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }
    public String getApiId() {
        return apiId;
    }
    public void setApiId(String apiId) {
        this.apiId = apiId;
    }
    public ServiceLink getService() {
        return service;
    }
    public void setService(ServiceLink service) {
        this.service = service;
    }
}

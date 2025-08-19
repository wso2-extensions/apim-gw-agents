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
import java.util.Map;

/**
 * Represents a Kong API.
 * This class is used to encapsulate the details of an API in Kong.
 */
public class KongAPI {
    private String id;
    private String name;
    private String version;
    private String description;
    private Map<String, String> labels;
    @SerializedName("created_at") private String createdAt; // ISO8601
    @SerializedName("updated_at") private String updatedAt; // ISO8601
    private String slug;
    @SerializedName("api_spec_ids") private List<String> apiSpecIds;

    // getters/setters
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
    public String getVersion() {
        return version;
    }
    public void setVersion(String version) {
        this.version = version;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public Map<String, String> getLabels() {
        return labels;
    }
    public void setLabels(Map<String, String> labels) {
        this.labels = labels;
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
    public String getSlug() {
        return slug;
    }
    public void setSlug(String slug) {
        this.slug = slug;
    }
    public List<String> getApiSpecIds() {
        return apiSpecIds;
    }
    public void setApiSpecIds(List<String> apiSpecIds) {
        this.apiSpecIds = apiSpecIds;
    }
}

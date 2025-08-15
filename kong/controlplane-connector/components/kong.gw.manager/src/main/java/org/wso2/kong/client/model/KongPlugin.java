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

import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Represents a Kong plugin.
 */
public class KongPlugin {
    private String id;
    private String name;
    private Boolean enabled;
    private List<String> protocols;
    private JsonObject config; // keep config as raw JSON for flexibility

    private RouteRef route;       // optional, present if plugin is bound to a route
    private ServiceRef service;   // optional, present if plugin is bound to a service
    private ConsumerRef consumer; // optional, if plugin is bound to a consumer

    @SerializedName("created_at") private Long createdAt; // epoch seconds
    @SerializedName("updated_at") private Long updatedAt; // epoch seconds

    /**
     * These can be used to bind the plugin to specific entities in Kong.
     */
    public static class RouteRef {
        private String id;
        public String getId() { 
            return id; 
        }
        public void setId(String id) { 
            this.id = id; 
        }
    }
    /**
     * This can be used to bind the plugin to a specific service in Kong.
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
    /**
     * This can be used to bind the plugin to a specific consumer in Kong.
     */
    public static class ConsumerRef {
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
    public Boolean getEnabled() { 
        return enabled; 
    }
    public void setEnabled(Boolean enabled) { 
        this.enabled = enabled; 
    }
    public List<String> getProtocols() { 
        return protocols; 
    }
    public void setProtocols(List<String> protocols) { 
        this.protocols = protocols; 
    }
    public JsonObject getConfig() { 
        return config; 
    }
    public void setConfig(JsonObject config) { 
        this.config = config; 
    }
    public RouteRef getRoute() { 
        return route; 
    }
    public void setRoute(RouteRef route) { 
        this.route = route; 
    }
    public ServiceRef getService() { 
        return service; 
    }
    public void setService(ServiceRef service) { 
        this.service = service; 
    }
    public ConsumerRef getConsumer() { 
        return consumer; 
    }
    public void setConsumer(ConsumerRef consumer) { 
        this.consumer = consumer; 
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
}

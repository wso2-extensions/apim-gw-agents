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

import feign.Headers;
import feign.Param;
import feign.RequestLine;

import org.wso2.kong.client.model.KongAPI;
import org.wso2.kong.client.model.KongAPIImplementation;
import org.wso2.kong.client.model.KongAPISpec;
import org.wso2.kong.client.model.KongListResponse;
import org.wso2.kong.client.model.KongPlugin;
import org.wso2.kong.client.model.KongRoute;
import org.wso2.kong.client.model.KongService;
import org.wso2.kong.client.model.PagedResponse;

/**
 * Kong Konnect API interface for managing services and routes.
 * This interface defines methods to interact with the Kong Konnect API for listing, creating,
 * and managing services and routes.
 */
public interface KongKonnectApi {

  // List APIs
  @RequestLine("GET /v3/apis?size={size}")
  @Headers({"Accept: application/json"})
  KongListResponse<KongAPI> listAPIs(@Param("size") int size);

  // Get one API spec by API ID + Spec ID
  @RequestLine("GET /v3/apis/{apiId}/specifications/{specId}")
  @Headers({"Accept: application/json"})
  KongAPISpec getAPISpec(@Param("apiId") String apiId, @Param("specId") String specId);

  // List API implementations (api_id -> service mapping)
  @RequestLine("GET /v3/api-implementations?size={size}")
  @Headers({"Accept: application/json"})
  KongListResponse<KongAPIImplementation> listAPIImplementations(@Param("size") int size);

  // Services

  // Fetch a single service from a given control plane
  @RequestLine("GET /v2/control-planes/{cpId}/core-entities/services/{serviceId}")
  @Headers({"Accept: application/json"})
  KongService getService(@Param("cpId") String controlPlaneId, @Param("serviceId") String serviceId);

  @RequestLine("GET /v2/control-planes/{cpId}/core-entities/services?size={size}")
  @Headers({"Accept: application/json"})
  PagedResponse<KongService> listServices(@Param("cpId") String controlPlaneId, @Param("size") int size);

  @RequestLine("POST /v2/control-planes/{cpId}/core-entities/services")
  @Headers({"Accept: application/json", "Content-Type: application/json"})
  KongService createService(@Param("cpId") String controlPlaneId, KongService body);

  // GET /v2/control-planes/{cpId}/core-entities/services/{serviceId}/routes?size={size}
  @RequestLine("GET /v2/control-planes/{cpId}/core-entities/services/{serviceId}/routes?size={size}")
  @Headers({"Accept: application/json"})
  PagedResponse<KongRoute> listRoutesByServiceId(@Param("cpId") String controlPlaneId,
                                                 @Param("serviceId") String serviceId,
                                                 @Param("size") int size);

  // (Optional) create a route under a specific service
  @RequestLine("POST /v2/control-planes/{cpId}/core-entities/services/{serviceId}/routes")
  @Headers({"Accept: application/json", "Content-Type: application/json"})
  KongRoute createRouteForService(@Param("cpId") String controlPlaneId,
                                  @Param("serviceId") String serviceId,
                                  KongRoute body);

  // List plugins bound to a specific service
  @RequestLine("GET /v2/control-planes/{cpId}/core-entities/services/{serviceId}/plugins?size={size}")
  @Headers({"Accept: application/json"})
  PagedResponse<KongPlugin> listPluginsByServiceId(@Param("cpId") String controlPlaneId,
                                                   @Param("serviceId") String serviceId,
                                                   @Param("size") int size);

  // (Optional) create a plugin on a service
  @RequestLine("POST /v2/control-planes/{cpId}/core-entities/services/{serviceId}/plugins")
  @Headers({"Accept: application/json", "Content-Type: application/json"})
  KongPlugin createPluginForService(@Param("cpId") String controlPlaneId,
                                    @Param("serviceId") String serviceId,
                                    KongPlugin body);

  // (Optional) update/delete by plugin id
  @RequestLine("PATCH /v2/control-planes/{cpId}/core-entities/plugins/{pluginId}")
  @Headers({"Accept: application/json", "Content-Type: application/json"})
  KongPlugin patchPlugin(@Param("cpId") String controlPlaneId,
                         @Param("pluginId") String pluginId,
                         KongPlugin body);

  @RequestLine("DELETE /v2/control-planes/{cpId}/core-entities/plugins/{pluginId}")
  @Headers({"Accept: application/json"})
  void deletePlugin(@Param("cpId") String controlPlaneId,
                    @Param("pluginId") String pluginId);

  // Routes
  @RequestLine("GET /v2/control-planes/{cpId}/core-entities/routes?size={size}")
  @Headers({"Accept: application/json"})
  PagedResponse<KongRoute> listRoutes(@Param("cpId") String controlPlaneId, @Param("size") int size);

  @RequestLine("POST /v2/control-planes/{cpId}/core-entities/routes")
  @Headers({"Accept: application/json", "Content-Type: application/json"})
  KongRoute createRoute(@Param("cpId") String controlPlaneId, KongRoute body);
}

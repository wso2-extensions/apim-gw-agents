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

package org.wso2.aws.client.util;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.apigateway.ApiGatewayClient;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This class is used to manage the API Gateway clients.
 *
 */
public class ApiGatewayClientManager {
    private static final Map<String, ApiGatewayClient> clients = new ConcurrentHashMap<>();

    public static ApiGatewayClient getClient(String region, String accessKey, String secretKey) {
        String key = region + "|" + accessKey + "|" + secretKey;
        return clients.computeIfAbsent(key, k -> createClient(region, accessKey, secretKey));
    }

    private static ApiGatewayClient createClient(String region, String accessKey, String secretKey) {
        SdkHttpClient httpClient = ApacheHttpClient.builder().build();
        return ApiGatewayClient.builder()
                .region(Region.of(region))
                .httpClient(httpClient)
                .credentialsProvider(StaticCredentialsProvider
                        .create(AwsBasicCredentials.create(accessKey, secretKey)))
                .build();
    }
}


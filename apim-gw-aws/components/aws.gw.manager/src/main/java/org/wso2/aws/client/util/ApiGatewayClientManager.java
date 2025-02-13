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


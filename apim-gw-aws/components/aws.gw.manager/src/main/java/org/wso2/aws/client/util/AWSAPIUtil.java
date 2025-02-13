package org.wso2.aws.client.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.Environment;

import org.wso2.carbon.apimgt.api.model.OperationPolicy;
import org.wso2.carbon.apimgt.api.model.URITemplate;
import org.wso2.carbon.apimgt.impl.deployer.exceptions.DeployerException;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.apigateway.ApiGatewayClient;
import software.amazon.awssdk.services.apigateway.model.Authorizer;
import software.amazon.awssdk.services.apigateway.model.CreateDeploymentRequest;
import software.amazon.awssdk.services.apigateway.model.CreateDeploymentResponse;
import software.amazon.awssdk.services.apigateway.model.DeleteDeploymentRequest;
import software.amazon.awssdk.services.apigateway.model.DeleteStageRequest;
import software.amazon.awssdk.services.apigateway.model.Deployment;
import software.amazon.awssdk.services.apigateway.model.GetAuthorizersRequest;
import software.amazon.awssdk.services.apigateway.model.GetDeploymentsRequest;
import software.amazon.awssdk.services.apigateway.model.GetDeploymentsResponse;
import software.amazon.awssdk.services.apigateway.model.GetResourcesRequest;
import software.amazon.awssdk.services.apigateway.model.GetResourcesResponse;
import software.amazon.awssdk.services.apigateway.model.GetRestApiRequest;
import software.amazon.awssdk.services.apigateway.model.ImportRestApiRequest;
import software.amazon.awssdk.services.apigateway.model.ImportRestApiResponse;
import software.amazon.awssdk.services.apigateway.model.IntegrationType;
import software.amazon.awssdk.services.apigateway.model.Method;
import software.amazon.awssdk.services.apigateway.model.Op;
import software.amazon.awssdk.services.apigateway.model.PatchOperation;
import software.amazon.awssdk.services.apigateway.model.PutIntegrationRequest;
import software.amazon.awssdk.services.apigateway.model.PutIntegrationResponse;
import software.amazon.awssdk.services.apigateway.model.PutIntegrationResponseRequest;
import software.amazon.awssdk.services.apigateway.model.PutMode;
import software.amazon.awssdk.services.apigateway.model.PutRestApiRequest;
import software.amazon.awssdk.services.apigateway.model.PutRestApiResponse;
import software.amazon.awssdk.services.apigateway.model.Resource;
import software.amazon.awssdk.services.apigateway.model.UpdateMethodRequest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AWSAPIUtil {
    private static final Log log = LogFactory.getLog(AWSAPIUtil.class);

    public static String importRestAPI (API api, Environment environment) throws DeployerException {

        String openAPI = api.getSwaggerDefinition();
        ApiGatewayClient apiGatewayClient = null;
        String apiId = null;
        Map<String, String> authorizers = new HashMap<>();
        Map<String, String> pathToArnMapping = new HashMap<>();

        try {
            String region = environment.getAdditionalProperties().get("region");
            String accessKey = environment.getAdditionalProperties().get("access_key");
            String secretAccessKey = environment.getAdditionalProperties().get("secret_key");

            apiGatewayClient = ApiGatewayClientManager.getClient(region, accessKey, secretAccessKey);

            ImportRestApiRequest importApiRequest = ImportRestApiRequest.builder()
                    .body(SdkBytes.fromUtf8String(openAPI))
                    .failOnWarnings(false)
                    .build();

            //import rest API with the openapi definition
            ImportRestApiResponse importApiResponse = apiGatewayClient.importRestApi(importApiRequest);
            apiId = importApiResponse.id();

            //add integrations for each resource
            GetResourcesRequest getResourcesRequest = GetResourcesRequest.builder().restApiId(apiId).build();
            GetResourcesResponse getResourcesResponse = apiGatewayClient.getResources(getResourcesRequest);

            //configure authorizers
            String lambdaArnAPI = null;
            String invokeRoleArn = null;
            List<OperationPolicy> apiPolicies = api.getApiPolicies();
            if (apiPolicies != null) {
                for (OperationPolicy policy : apiPolicies) {
                    if (policy.getPolicyName().equals("awsOAuth2")) {
                        lambdaArnAPI = policy.getParameters().get("lambdaARN").toString();
                        invokeRoleArn = policy.getParameters().get("invokeRoleArn").toString();
                        break;
                    }
                }
            }
            if (lambdaArnAPI != null) {
                pathToArnMapping.put("API", lambdaArnAPI);
                authorizers.put(lambdaArnAPI ,GatewayUtil.getAuthorizer(apiId,
                        lambdaArnAPI.substring(lambdaArnAPI.lastIndexOf(':') + 1),
                        lambdaArnAPI, invokeRoleArn, region,
                        apiGatewayClient).id());
            }

            for (URITemplate resource: api.getUriTemplates()) {
                String resourceLambdaARN = null;
                for (OperationPolicy policy: resource.getOperationPolicies()) {
                    if (policy.getPolicyName().equals("awsOAuth2")) {
                        resourceLambdaARN = policy.getParameters().get("lambdaARN").toString();
                        break;
                    }
                }

                if (resourceLambdaARN != null && !authorizers.containsKey(resourceLambdaARN)) {
                    pathToArnMapping.put(resource.getUriTemplate().toLowerCase()
                                    + "|" + resource.getHTTPVerb().toLowerCase(), resourceLambdaARN);
                    authorizers.put(resourceLambdaARN, GatewayUtil.getAuthorizer(apiId,
                            resourceLambdaARN.substring(resourceLambdaARN.lastIndexOf(':') + 1),
                            resourceLambdaARN, invokeRoleArn, region,
                            apiGatewayClient).id());
                }
            }

            String endpointConfig = api.getEndpointConfig();
            JSONParser parser = new JSONParser();
            JSONObject endpointConfigJson = (JSONObject) parser.parse(endpointConfig);
            JSONObject prodEndpoints = (JSONObject)endpointConfigJson.get("production_endpoints");
            String productionEndpoint = (String) prodEndpoints.get("url");

            productionEndpoint = productionEndpoint.charAt(productionEndpoint.length() - 1) == '/' ?
                    productionEndpoint.substring(0, productionEndpoint.length() - 1) : productionEndpoint;

            List<Resource> resources = getResourcesResponse.items();
            for (Resource resource : resources) {
                Map<String, Method> resourceMethods = resource.resourceMethods();
                if (!resourceMethods.isEmpty()) {
                    //check and configure CORS
                    GatewayUtil.configureOptionsCallForCORS(apiId, resource, apiGatewayClient);

                    for (Map.Entry entry : resourceMethods.entrySet()) {
                        PutIntegrationRequest putIntegrationRequest = PutIntegrationRequest.builder()
                                .httpMethod(entry.getKey().toString())
                                .integrationHttpMethod(entry.getKey().toString())
                                .resourceId(resource.id())
                                .restApiId(apiId)
                                .type(IntegrationType.HTTP)
                                .uri(productionEndpoint + resource.path())
                                .build();
                        PutIntegrationResponse putIntegrationResponse =
                                apiGatewayClient.putIntegration(putIntegrationRequest);
                        String integrationURI = putIntegrationResponse.uri();

                        //Configure default output mapping
                        PutIntegrationResponseRequest putIntegrationResponseRequest =
                                PutIntegrationResponseRequest.builder()
                                .httpMethod(entry.getKey().toString())
                                .resourceId(resource.id())
                                .restApiId(apiId)
                                .statusCode("200")
                                .responseTemplates(Map.of("application/json", ""))
                                .build();
                        apiGatewayClient.putIntegrationResponse(putIntegrationResponseRequest);

                        String key = resource.path().toLowerCase() + "|" + entry.getKey().toString().toLowerCase();
                        if (!authorizers.containsKey(pathToArnMapping.get(key))) {
                            key = "API";
                            if (!authorizers.containsKey(pathToArnMapping.get(key))) {
                                throw new DeployerException("Authorizer not found for the resource: "
                                        + resource.path());
                            }
                        }
                        String authorizerId = authorizers.get(pathToArnMapping.get(key));

                        //configure authorizer
                        UpdateMethodRequest updateMethodRequest = UpdateMethodRequest.builder().restApiId(apiId)
                                .resourceId(resource.id()).httpMethod(entry.getKey().toString())
                                .patchOperations(PatchOperation.builder().op(Op.REPLACE).path("/authorizationType")
                                        .value("CUSTOM").build(),
                                        PatchOperation.builder().op(Op.REPLACE).path("/authorizerId")
                                                .value(authorizerId).build()).build();
                        apiGatewayClient.updateMethod(updateMethodRequest);

                        //configure CORS Headers at request Method level
                        GatewayUtil.configureCORSHeadersAtMethodLevel(apiId, resource, entry.getKey().toString(),
                                apiGatewayClient);
                    }
                }
            }

            String stageName = environment.getAdditionalProperties().get("stage");
            CreateDeploymentRequest createDeploymentRequest = CreateDeploymentRequest.builder().restApiId(apiId)
                    .stageName(stageName).build();
            apiGatewayClient.createDeployment(createDeploymentRequest);
        } catch (Exception e) {
            try {
                GatewayUtil.rollbackDeployment(apiGatewayClient, apiId, api.getUuid(), environment.getUuid());
            } catch (APIManagementException ex) {
                throw new DeployerException("Error occurred while rolling back deployment: " + ex.getMessage());
            }
            throw new DeployerException("Error occurred while importing API: " + e.getMessage());
        }

        GetRestApiRequest getRestApiRequest = GetRestApiRequest.builder().restApiId(apiId).build();

        return apiGatewayClient.getRestApi(getRestApiRequest).toString();
    }

    public static String reimportRestAPI(String referenceArtifact, API api, Environment environment)
            throws DeployerException {
        String awsApiId = GatewayUtil.getAWSApiIdFromReferenceArtifact(referenceArtifact);
        ApiGatewayClient apiGatewayClient = null;
        List<String> currentARNs = new ArrayList<>();
        Map<String, String> authorizers = new HashMap<>();
        Map<String, String> pathToArnMapping = new HashMap<>();
        try {
            String openAPI = api.getSwaggerDefinition();

            String region = environment.getAdditionalProperties().get("region");
            String accessKey = environment.getAdditionalProperties().get("access_key");
            String secretAccessKey = environment.getAdditionalProperties().get("secret_key");
            apiGatewayClient = ApiGatewayClientManager.getClient(region, accessKey, secretAccessKey);
            PutRestApiRequest reimportApiRequest = PutRestApiRequest.builder()
                    .restApiId(awsApiId)
                    .body(SdkBytes.fromUtf8String(openAPI))
                    .failOnWarnings(false)
                    .mode(PutMode.OVERWRITE)
                    .build();
            PutRestApiResponse reimportApiResponse = apiGatewayClient.putRestApi(reimportApiRequest);

            awsApiId = reimportApiResponse.id();

            //configure authorizers
            GetAuthorizersRequest getAuthorizersRequest = GetAuthorizersRequest.builder().restApiId(awsApiId).build();
            List<Authorizer> existingAuthorizers = apiGatewayClient.getAuthorizers(getAuthorizersRequest).items();

            for (Authorizer authorizer : existingAuthorizers) {
                String regex = "arn:aws:apigateway:[^:]+:lambda:path/2015-03-31/functions/([^/]+)/invocations";
                Pattern compiledPattern = Pattern.compile(regex);
                Matcher matcher = compiledPattern.matcher(authorizer.authorizerUri());
                String arn = null;
                if (matcher.find()) {
                    arn = matcher.group(1);
                }
                authorizers.put(arn, authorizer.id());
                currentARNs.add(arn);
            }

            String lambdaArnAPI = null;
            String invokeRoleArn = null;
            List<OperationPolicy> apiPolicies = api.getApiPolicies();
            if (apiPolicies != null) {
                for (OperationPolicy policy : apiPolicies) {
                    if (policy.getPolicyName().equals("awsOAuth2")) {
                        lambdaArnAPI = policy.getParameters().get("lambdaARN").toString();
                        invokeRoleArn = policy.getParameters().get("invokeRoleArn").toString();
                        break;
                    }
                }
            }
            if (lambdaArnAPI != null && !authorizers.containsKey(lambdaArnAPI)) {
                pathToArnMapping.put("API", lambdaArnAPI);
                authorizers.put(lambdaArnAPI ,GatewayUtil.getAuthorizer(awsApiId,
                        lambdaArnAPI.substring(lambdaArnAPI.lastIndexOf(':') + 1),
                        lambdaArnAPI, invokeRoleArn, region,
                        apiGatewayClient).id());
            }

            Set<URITemplate> uriTemplates = api.getUriTemplates();
            if (uriTemplates != null) {
                for (URITemplate resource : uriTemplates) {
                    String resourceLambdaARN = null;
                    List<OperationPolicy> resourcePolicies = resource.getOperationPolicies();
                    if (resourcePolicies != null) {
                        for (OperationPolicy policy : resourcePolicies) {
                            if (policy.getPolicyName().equals("awsOAuth2")) {
                                resourceLambdaARN = policy.getParameters().get("lambdaARN").toString();
                                break;
                            }
                        }
                    }

                    if (resourceLambdaARN != null && !authorizers.containsKey(resourceLambdaARN)) {
                        pathToArnMapping.put(resource.getUriTemplate().toLowerCase()
                                + "|" + resource.getHTTPVerb().toLowerCase(), resourceLambdaARN);
                        authorizers.put(resourceLambdaARN, GatewayUtil.getAuthorizer(awsApiId,
                                resourceLambdaARN.substring(resourceLambdaARN.lastIndexOf(':') + 1),
                                resourceLambdaARN, invokeRoleArn, region,
                                apiGatewayClient).id());
                    }
                }
            }

            //remove unused authorizers
            for (String arn : currentARNs) {
                if (!authorizers.containsKey(arn)) {
                    GatewayUtil.deleteAuthorizer(awsApiId, authorizers.get(arn), apiGatewayClient);
                    authorizers.remove(arn);
                }
            }

            //add integrations for each resource
            GetResourcesRequest getResourcesRequest = GetResourcesRequest.builder()
                    .restApiId(awsApiId)
                    .build();
            GetResourcesResponse getResourcesResponse = apiGatewayClient.getResources(getResourcesRequest);

            String endpointConfig = api.getEndpointConfig();
            JSONParser parser = new JSONParser();
            JSONObject endpointConfigJson = (JSONObject) parser.parse(endpointConfig);
            JSONObject prodEndpoints = (JSONObject)endpointConfigJson.get("production_endpoints");
            String productionEndpoint = (String) prodEndpoints.get("url");

            productionEndpoint = productionEndpoint.charAt(productionEndpoint.length() - 1) == '/' ?
                    productionEndpoint.substring(0, productionEndpoint.length() - 1) : productionEndpoint;

            List<Resource> resources = getResourcesResponse.items();
            for (Resource resource : resources) {
                Map<String, Method> resourceMethods = resource.resourceMethods();
                if (!resourceMethods.isEmpty()) {
                    //check and configure CORS
                    GatewayUtil.configureOptionsCallForCORS(awsApiId, resource, apiGatewayClient);

                    for (Map.Entry entry : resourceMethods.entrySet()) {
                        PutIntegrationRequest putIntegrationRequest = PutIntegrationRequest.builder()
                                .httpMethod(entry.getKey().toString())
                                .integrationHttpMethod(entry.getKey().toString())
                                .resourceId(resource.id())
                                .restApiId(awsApiId)
                                .type(IntegrationType.HTTP)
                                .uri(productionEndpoint + resource.path())
                                .build();
                        apiGatewayClient.putIntegration(putIntegrationRequest);

                        //Configure default output mapping
                        PutIntegrationResponseRequest putIntegrationResponseRequest =
                                PutIntegrationResponseRequest.builder()
                                        .httpMethod(entry.getKey().toString())
                                        .resourceId(resource.id())
                                        .restApiId(awsApiId)
                                        .statusCode("200")
                                        .responseTemplates(Map.of("application/json", ""))
                                        .build();
                        apiGatewayClient.putIntegrationResponse(putIntegrationResponseRequest);

                        String key = resource.path().toLowerCase() + "|" + entry.getKey().toString().toLowerCase();
                        if (!authorizers.containsKey(pathToArnMapping.get(key))) {
                            key = "API";
                            if (!authorizers.containsKey(pathToArnMapping.get(key))) {
                                throw new DeployerException("Authorizer not found for the resource: "
                                        + resource.path());
                            }
                        }
                        String authorizerId = authorizers.get(pathToArnMapping.get(key));

                        UpdateMethodRequest updateMethodRequest = UpdateMethodRequest.builder().restApiId(awsApiId)
                                .resourceId(resource.id()).httpMethod(entry.getKey().toString())
                                .patchOperations(PatchOperation.builder().op(Op.REPLACE).path("/authorizationType")
                                                .value("CUSTOM").build(),
                                        PatchOperation.builder().op(Op.REPLACE).path("/authorizerId")
                                                .value(authorizerId).build()).build();
                        apiGatewayClient.updateMethod(updateMethodRequest);

                        //configure CORS Headers at request Method level
                        GatewayUtil.configureCORSHeadersAtMethodLevel(awsApiId, resource, entry.getKey().toString(),
                                apiGatewayClient);
                    }
                }
            }

            // re-deploy API
            String stageName = environment.getAdditionalProperties().get("stage");
            CreateDeploymentRequest createDeploymentRequest = CreateDeploymentRequest.builder().restApiId(awsApiId)
                    .stageName(stageName).build();
            CreateDeploymentResponse createDeploymentResponse =
                    apiGatewayClient.createDeployment(createDeploymentRequest);
            String deploymentId = createDeploymentResponse.id();

            GetDeploymentsRequest getDeploymentsRequest = GetDeploymentsRequest.builder().restApiId(awsApiId).build();
            GetDeploymentsResponse getDeploymentsResponse = apiGatewayClient.getDeployments(getDeploymentsRequest);
            List<Deployment> deployments = getDeploymentsResponse.items();
            for (Deployment deployment : deployments) {
                if (!deployment.id().equals(deploymentId)) {
                    DeleteDeploymentRequest deleteDeploymentRequest = DeleteDeploymentRequest.builder()
                            .deploymentId(deployment.id())
                            .restApiId(awsApiId)
                            .build();
                    apiGatewayClient.deleteDeployment(deleteDeploymentRequest);
                }
            }

            GetRestApiRequest getRestApiRequest = GetRestApiRequest.builder().restApiId(awsApiId).build();
            return apiGatewayClient.getRestApi(getRestApiRequest).toString();
        } catch (Exception e) {
            throw new DeployerException("Error occurred while re-importing API: " + e.getMessage());
        }
    }

    public static boolean deleteDeployment(String apiId, Environment environment) throws DeployerException {
        try {
            String referenceArtifact = APIUtil.getApiExternalApiMappingReferenceByApiId(apiId, environment.getUuid());
            if (referenceArtifact == null) {
                throw new DeployerException("API ID is not mapped with AWS API ID");
            }
            String awsApiId = GatewayUtil.getAWSApiIdFromReferenceArtifact(referenceArtifact);

            String region = environment.getAdditionalProperties().get("region");
            String accessKey = environment.getAdditionalProperties().get("access_key");
            String secretAccessKey = environment.getAdditionalProperties().get("secret_key");
            ApiGatewayClient apiGatewayClient = ApiGatewayClientManager.getClient(region, accessKey, secretAccessKey);
            String stageName = environment.getAdditionalProperties().get("stage");

            // Delete the stage before deleting the deployment
            DeleteStageRequest deleteStageRequest = DeleteStageRequest.builder()
                    .restApiId(awsApiId)
                    .stageName(stageName)
                    .build();
            apiGatewayClient.deleteStage(deleteStageRequest);

            GetDeploymentsRequest getDeploymentsRequest = GetDeploymentsRequest.builder().restApiId(awsApiId).build();
            GetDeploymentsResponse getDeploymentsResponse = apiGatewayClient.getDeployments(getDeploymentsRequest);
            List<Deployment> deployments = getDeploymentsResponse.items();
            for (Deployment deployment : deployments) {
                DeleteDeploymentRequest deleteDeploymentRequest = DeleteDeploymentRequest.builder()
                        .deploymentId(deployment.id())
                        .restApiId(awsApiId)
                        .build();
                apiGatewayClient.deleteDeployment(deleteDeploymentRequest);
            }
            return true;
        } catch (APIManagementException e) {
            throw new DeployerException("Error occurred while deleting deployment: " + e.getMessage());
        }
    }
}

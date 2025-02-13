package org.wso2.aws.client.util;

import com.amazonaws.DefaultRequest;
import com.amazonaws.Request;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.http.HttpMethodName;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.net.URI;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

public class AuthUtil {
    private static final Log log = LogFactory.getLog(AuthUtil.class);

    public static String generateAWSAuthHeader(String accessKey, String secretKey, String region, String service) {
        String authorizationHeader = null;

        log.info("[CUSTOM WORKFLOW EXECUTOR] Generating AWS Auth Header");

        try {
            BasicAWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
            AWS4Signer signer = new AWS4Signer();
            signer.setServiceName(service);
            signer.setRegionName(region);

            // Define the request parameters
            String method = "GET";
            String path = "/restapis";
            String host = service + "." + region + "." + "amazonaws.com";
            String body = "";

            LocalDateTime currentDateTime = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
            String formattedDateTime = currentDateTime.format(formatter);
            log.info("[CUSTOM WORKFLOW EXECUTOR] Current Date Time: " + formattedDateTime);

            // Creating the HTTP request (excluding signing for now)
            Request<?> request = new DefaultRequest<>(service);
            request.setHttpMethod(HttpMethodName.GET);
            request.setEndpoint(URI.create("https://" + host + path));

            Map<String, String> headers = new HashMap<>();
            headers.put("x-amz-date", formattedDateTime);
            //headers.put("Content-Type", "application/json");
            headers.put("Host", host);
            request.setHeaders(headers);

            // Sign the request
            signer.sign(request, credentials);

            // Extract the Authorization header
            authorizationHeader = request.getHeaders().get("Authorization");
            log.info("[CUSTOM WORKFLOW EXECUTOR] Authorization Header: " + authorizationHeader);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return authorizationHeader;
    }
}

package org.wso2.aws.client;

import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.apimgt.api.model.ConfigurationDto;
import org.wso2.carbon.apimgt.api.model.FederatedGatewayAgentConfiguration;
import org.wso2.carbon.apimgt.impl.APIConstants;

import java.util.*;

@Component(
        name = "aws.configuration.component",
        immediate = true,
        service = FederatedGatewayAgentConfiguration.class
)
public class AWSAgentConfiguration implements FederatedGatewayAgentConfiguration {
    public String getType() {
        return AWSConstants.AWS_TYPE;
    }

    public List<ConfigurationDto> getConnectionConfigurations() {
        List<ConfigurationDto> configurationDtoList = new ArrayList<>();
        configurationDtoList
                .add(new ConfigurationDto("access_key", "Access Key", "input", "AWS Access Key for Signature Authentication", "", true,
                        true, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("secret_key", "Secret Key", "input", "AWS Secret Key for Signature Authentication", "",
                        true, true, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("region", "AWS Region", "input", "AWS Region", "", true, false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("service_name", "AWS Service Name", "input", "AWS Service Name", "", true, false, Collections.emptyList(), false));
        configurationDtoList
                .add(new ConfigurationDto("api_url", "Management API URL", "input", "Management API URL", "", true, false, Collections.emptyList(), false));
        return configurationDtoList;
    }

    public Map<String, Boolean> getFeatureConfigurations() {
        Map<String, Boolean> featureConfigurations = new HashMap<>();

        featureConfigurations.put(APIConstants.FederatedGatewayConstants.CORS_FEATURE, true);
        featureConfigurations.put(APIConstants.FederatedGatewayConstants.SCHEMA_VALIDATION_FEATURE, true);

        return featureConfigurations;
    }

}
package org.wso2.azure.gw.client;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.FederatedAPIDiscovery;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.Environment;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class implements the FederatedAPIDiscovery interface for Azure Gateway.
 */
public class AzureGatewayDiscovery implements FederatedAPIDiscovery {
    @Override
    public void init(Environment environment, String s) throws APIManagementException {

    }

    @Override
    public List<API> discoverAPI() {
        return new ArrayList<>(Collections.emptyList());
    }
}

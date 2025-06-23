# Common Agent - WSO2 APK

The **Common Agent** is a pluggable component that integrates with different API gateways. It handles API deployments by generating and managing Kubernetes resources specific to each gateway.  

## Prerequisites
- **Go 1.23** installed  
- **Helm** installed  
- **Revive 1.3.4** installed  
- **Gradle 8.11** installed (for building the Common Agent)
- **Docker** installed

## 1. Import and Register a Gateway-Specific Agent  
To add a new gateway-specific agent (e.g., APK), update `internal/agent/registry.go` as follows:  

### Import the Gateway Agent
```go
import (
    apkAgent "github.com/wso2/product-apim-tooling/apim-agents/<gateway-agent>"
)
```

### Register the Agent
```go
func init() {
    // Register other agents
    agentReg.RegisterAgent("<gateway-agent-name>", &apkAgent.Agent{})
}
```

## 2. Build the Common Agent
Once the agent integration is ready, navigate to the **Common Agent root directory** and run:  

```sh
./gradlew build
```

This command compiles the Common Agent and prepares it for deployment.

## 3. Deploy the Common Agent using Helm 
To deploy the Common Agent in your Kubernetes cluster using Helm, run:  

```sh
helm install apim-agent . -n apk
```

### Helm Configuration (`values.yaml`)
In the agent **Helm chart**, specify the agent and its configuration:

```yaml
mode: CPtoDP
agent:
  gateway: <gateway-agent-name>

gatewayAgent:
  configFrom:
    - config-map-1
    - config-map-2
  key1: value1
  key2: value2
```

This ensures that the Common Agent runs with **<gateway-agent-name>** as the selected gateway and applies any gateway-specific configurations.

## 4. Verify the Deployment  
After deploying, check if the Common Agent is running successfully:  

```sh
kubectl get pods -n apk
```

To check logs for debugging:  

```sh
kubectl logs -l app=apim-agent -n apk
```

## Conclusion 
This guide covers setting up, building, and deploying the **Common Agent** with **WSO2 APIM**. By following these steps, you can register a new gateway agent, build the Common Agent, and deploy it using Helm.
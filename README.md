# apim-gw-agents
This repo includes gateway agent implementations for Gateway Federation feature in APIM

### Purpose
Introduces multi-gateway support in WSO2 API Manager (WSO2 APIM) by implementing a pluggable agent architecture with:

- Common Agent: A shared base agent that handles common configurations, and gateway-specific agent execution.
- Kong Gateway Integration: Includes a Helm chart, Go-based Kong agent, and Gateway configuration (feature catalog) for APIM CP.
- WSO2 APK Integration: Includes a Helm chart and Go-based APK agent for API management on APK.
- Common Gradle Scripts: Shared Gradle scripts for managing builds and dependencies.

### Goals
- Implement a Common Agent that serves as a base for multiple gateway-specific agents.
- Provide Kong Gateway support with a dedicated Go agent, Helm deployment, and APIM CP feature catalog.
- Provide WSO2 APK support with a Go agent and Helm deployment.
- Enable API migration between gateways.

### Approach

##### Common Agent
- Implements a pluggable agent architecture where the gateway-specific agent is selected at runtime.
- Kong Agent and APK Agent are registered within the Common Agent.
- The Helm chart specifies the gateway under agent.gateway: <gateway-registered-name>, and the Common Agent runs with that gateway agent.
- Handles CP communication, event handling, and other common configurations.

##### Kong Integration
- Helm Chart: Deploys Kong Gateway Agent in Kubernetes.
- Go-based Kong Agent: Converts API Projects into Kong-specific configurations and vice versa.
- Feature Catalog (gw-config): Defines capabilities available for APIs in APIM CP.

##### WSO2 APK Integration
- Helm Chart: Deploys APK Gateway Agent in Kubernetes.
- Go-based APK Agent: Manages API deployment on APK.

##### Common Gradle Scripts
- Standardizes build configurations across the project.

### Documentation
- [Kong Agent Guide](http://github.com/taedmonds/wso2-apim-gw-agents/tree/k8s-gw-agents/kong/gateway-connector)
- [WSO2 APK Agent Guide](https://github.com/taedmonds/wso2-apim-gw-agents/tree/k8s-gw-agents/apk/gateway-connector)
- [Common Agent Guide](https://github.com/taedmonds/wso2-apim-gw-agents/blob/k8s-gw-agents/common-agent/README.md)
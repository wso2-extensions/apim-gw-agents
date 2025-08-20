# Guide to Integrate APK Agent with Common Agent

This guide explains how to integrate the **APK Agent** with the **Common Agent**.

## 1. Import the APK Agent
In the **Common Agent** codebase, modify `internal/agent/registry.go` to import the new agent:

```go
import (
    // ... Import other agents
    apkAgent "github.com/wso2-extensions/apim-gw-connectors/apk/gateway-connector"
)
```

## 2. Register the APK Agent 
Update the `init()` function in `registry.go` to register the APK Agent:

```go
func init() {
    // ... Register other agents
    agentReg.RegisterAgent("apk", &apkAgent.Agent{})
}
```

## 3. Configure the Common Agent via Helm
In the **Common Agent deployment Helm chart**, specify APK as the gateway and define any gateway-specific configurations under the `gatewayAgent` section:

```yaml
agent:
  gateway: apk

gatewayAgent:
  key1: value1
```
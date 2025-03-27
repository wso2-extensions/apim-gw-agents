# Guide to Integrate Kong Agent with Common Agent

This guide explains how to integrate the **Kong Agent** with the **Common Agent**.

## 1. Import the Kong Agent
In the **Common Agent** codebase, modify `internal/agent/registry.go` to import the new agent:

```go
import (
    // ... Import other agents
    kongAgent "github.com/wso2-extensions/apim-gw-agents/kong/agent"
)
```

## 2. Register the Kong Agent
Update the `init()` function in `registry.go` to register the Kong Agent:

```go
func init() {
    // ... Register other agents
    agentReg.RegisterAgent("kong", &kongAgent.Agent{})
}
```

## 3. Configure the Common Agent via Helm
In the **Common Agent deployment Helm chart**, specify Kong as the gateway and define any gateway-specific configurations under the `gatewayAgent` section:

```yaml
agent:
  gateway: kong

gatewayAgent:
  key1: value1
```

## 4. Testing the Integration

### 4.1 Deploying the APIM Control Plane (CP) in Testing Mode
Before running tests, ensure that the **APIM Control Plane** is deployed in testing mode, either **CPtoDP** or **DPtoCP**, with Kong Gateway and Kong Agent.

### 4.2 Setting Up the Key Manager's Certificate
1. Log in to the **Admin Portal** (`am.wso2.com/admin`).
2. Navigate to **Key Managers** -> **Select Resident Key Manager**.
3. In the **Certificates** section, select **PEM**.
4. Upload the **certificate PEM file** and click **Save**.

### 4.3 Running the Tests
To run the tests, navigate to the `kong-agent` directory and execute the following commands based on the test mode:

#### Running CP to DP Test
```sh
cd kong-agent
go run tests/tests_main.go --mode=CPtoDP
```

#### Running DP to CP Test
```sh
cd kong-agent
go run tests/tests_main.go --mode=DPtoCP
```
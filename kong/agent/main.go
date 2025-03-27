package kongAgent

import (
	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/eventhub/types"
	msg "github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/messaging"
	"github.com/wso2-extensions/apim-gw-agents/kong/agent/internal/agent"
	"github.com/wso2-extensions/apim-gw-agents/kong/agent/internal/events"
	"github.com/wso2-extensions/apim-gw-agents/kong/agent/internal/loggers"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Agent defines the pluggable agent structure
type Agent struct{}

// PreRun handles any prerequisites before agent Run
func (a Agent) PreRun(conf *config.Config, scheme *runtime.Scheme) {
	agent.PreRun(conf, scheme)
}

// Run initiates the gateway specific agent
func (a Agent) Run(conf *config.Config, mgr manager.Manager) {
	agent.Run(conf, mgr)
}

// ProcessEvents handles gateway specific functions need to be triggered on event processing
func (a Agent) ProcessEvents(conf *config.Config, client client.Client) {
	// No operation
}

// HandleLifeCycleEvents handles the events of an api through out the life cycle
func (a Agent) HandleLifeCycleEvents(data []byte) {
	loggers.LoggerAgent.Println("Triggered: HandleLifeCycleEvents")
	events.HandleLifeCycleEvents(data)
}

// HandleAPIEvents to process api related data
func (a Agent) HandleAPIEvents(data []byte, eventType string, conf *config.Config, client client.Client) {
	loggers.LoggerAgent.Println("Triggered: HandleAPIEvents")
	events.HandleAPIEvents(data, eventType, conf, client)
}

// HandleApplicationEvents to process application related events
func (a Agent) HandleApplicationEvents(data []byte, eventType string, client client.Client) {
	loggers.LoggerAgent.Println("Triggered: HandleApplicationEvents")
	events.HandleApplicationEvents(data, eventType, client)
}

// HandleSubscriptionEvents to process subscription related events
func (a Agent) HandleSubscriptionEvents(data []byte, eventType string, client client.Client) {
	loggers.LoggerAgent.Println("Triggered: HandleSubscriptionEvents")
	events.HandleSubscriptionEvents(data, eventType, client)
}

// HandlePolicyEvents to process policy related events
func (a Agent) HandlePolicyEvents(data []byte, eventType string, client client.Client) {
	loggers.LoggerAgent.Println("Triggered: HandlePolicyEvents")
	events.HandlePolicyEvents(data, eventType, client)
}

// HandleAIProviderEvents to process AI Provider related events
func (a Agent) HandleAIProviderEvents(data []byte, eventType string, client client.Client) {
	loggers.LoggerAgent.Println("Triggered: HandleAIProviderEvents")
	events.HandleAIProviderEvents(data, eventType, client)
}

// HandleScopeEvents to process scope related events
func (a Agent) HandleScopeEvents(data []byte, eventType string, client client.Client) {
	loggers.LoggerAgent.Infof("Triggered: HandleScopeEvents")
	events.HandleScopeEvents(data, eventType, client)
}

// HandleKMConfiguration to handle Key Manager configurations
func (a Agent) HandleKMConfiguration(keyManager *types.KeyManager, notification msg.EventKeyManagerNotification, client client.Client) {
	loggers.LoggerAgent.Println("Triggered: HandleKMConfiguration")
	events.HandleKMConfiguration(keyManager, notification, client)
}

/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

// Package agent contains the implementation to start the agent
package agent

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	logger "github.com/wso2-extensions/apim-gw-agents/common-agent/internal/loggers"
	logging "github.com/wso2-extensions/apim-gw-agents/common-agent/internal/logging"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/internal/messaging"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/health"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/managementserver"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/metrics"
	"github.com/wso2/apk/common-go-libs/loggers"
	"github.com/wso2/apk/common-go-libs/pkg/discovery/api/wso2/discovery/service/apkmgt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	healthservice "github.com/wso2/apk/adapter/pkg/health/api/wso2/health/service"
)

var (
	debug       bool
	onlyLogging bool

	port    uint
	alsPort uint

	mode string
)

const (
	ads                      = "ads"
	amqpProtocol             = "amqp"
	grpcMaxConcurrentStreams = 1000000
)

func init() {
	flag.BoolVar(&debug, "debug", true, "Use debug logging")
	flag.BoolVar(&onlyLogging, "onlyLogging", false, "Only demo AccessLogging Service")
	flag.UintVar(&port, "port", 18000, "Management server port")
	flag.UintVar(&alsPort, "als", 18090, "Accesslog server port")
	flag.StringVar(&mode, "ads", ads, "Management server type (ads, grpc, rest)")
}

// Run starts the Event listener and gateway agent.
func Run(conf *config.Config) {
	logger.LoggerAgent.Infof("Loading %v agent...", conf.Agent.Gateway)
	agent, err := agentReg.GetAgent(conf.Agent.Gateway)
	if err != nil {
		logger.LoggerAgent.Errorf("Agent loader error: %v. ", err)
		return
	}

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	// TODO: (VirajSalaka) Support the REST API Configuration via flags only if it is a valid requirement
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger.LoggerAgent.Debugf("Run method started with context : %v", ctx)

	// log config watcher
	watcherLogConf, _ := fsnotify.NewWatcher()
	logConfigPath, errC := config.GetLogConfigPath()
	if errC == nil {
		errC = watcherLogConf.Add(logConfigPath)
	}

	if errC != nil {
		logger.LoggerAgent.ErrorC(logging.PrintError(logging.Error1102, logging.CRITICAL, "Error reading the log configs, error: %v", errC.Error()))
	}

	logger.LoggerAgent.Info("Starting apim-agent ....")
	eventHubEnabled := conf.ControlPlane.Enabled

	var probeAddr string
	var scheme = runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(gwapiv1.Install(scheme))

	// run agent specific functions
	logger.LoggerAgent.Info("PreRunning gateway specific agent...")
	agent.PreRun(conf, scheme)
	logger.LoggerAgent.Info("PreRunning complete...")

	options := ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: probeAddr,
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	}

	if conf.Metrics.Enabled {
		options.Metrics.BindAddress = fmt.Sprintf(":%d", conf.Metrics.Port)
		// Register the metrics collector
		if strings.EqualFold(conf.Metrics.Type, metrics.PrometheusMetricType) {
			loggers.LoggerAPKOperator.Info("Registering Prometheus metrics collector.")
			metrics.RegisterPrometheusCollector()
		}
	} else {
		options.Metrics.BindAddress = "0"
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)

	if err != nil {
		logger.LoggerAgent.Error("unable to start kubernetes controller manager", err)
	}

	if eventHubEnabled {
		var connectionURLList = conf.ControlPlane.BrokerConnectionParameters.EventListeningEndpoints
		if strings.Contains(connectionURLList[0], amqpProtocol) {
			go messaging.ProcessEvents(conf, mgr.GetClient(), agent)
		}
	}

	health.NotificationListenerService.SetStatus(true)

	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions, grpc.KeepaliveParams(
		keepalive.ServerParameters{
			Time:    time.Duration(5 * time.Minute),
			Timeout: time.Duration(20 * time.Second),
		}),
		grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams),
	)
	publicKeyLocation, privateKeyLocation, truststoreLocation := config.GetKeyLocations()
	cert, err := config.GetServerCertificate(publicKeyLocation, privateKeyLocation)

	caCertPool := config.GetTrustedCertPool(truststoreLocation)

	if err == nil {
		grpcOptions = append(grpcOptions, grpc.Creds(
			credentials.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    caCertPool,
			}),
		))
	} else {
		logger.LoggerAgent.Warn("failed to initiate the ssl context: ", err)
		panic(err)
	}

	grpcOptions = append(grpcOptions, grpc.KeepaliveParams(
		keepalive.ServerParameters{
			Time:    time.Duration(5 * time.Minute),
			Timeout: time.Duration(20 * time.Second),
		}),
	)
	grpcServer := grpc.NewServer(grpcOptions...)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.LoggerAgent.ErrorC(logging.PrintError(logging.Error1100, logging.BLOCKER, "Failed to listen on port: %v, error: %v", port, err.Error()))
	}
	apkmgt.RegisterEventStreamServiceServer(grpcServer, &managementserver.EventServer{})
	// register health service
	healthservice.RegisterHealthServer(grpcServer, &health.Server{})
	logger.LoggerAgent.Info("port: ", port, " APK agent Listening for gRPC connections")

	go func() {
		logger.LoggerAgent.Info("Starting GRPC server.")
		health.CommonControllerGrpcService.SetStatus(true)
		if err = grpcServer.Serve(lis); err != nil {
			health.CommonControllerGrpcService.SetStatus(false)
			logger.LoggerAgent.ErrorC(logging.PrintError(logging.Error1101, logging.BLOCKER, "Failed to start GRPC server, error: %v", err.Error()))
		}
	}()

	// Start the manager in a goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.LoggerAgent.Info("starting manager")
		if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
			logger.LoggerAgent.Warnf("problem running manager: %v", err)
		}
	}()

	AgentMode := conf.Agent.Mode
	logger.LoggerAgent.Infof("Agent Mode: %v", AgentMode)

	// run agent specific functions
	logger.LoggerAgent.Info("Running gateway specific agent...")
	agent.Run(conf, mgr)
OUTER:
	for {
		select {
		case l := <-watcherLogConf.Events:
			switch l.Op.String() {
			case "WRITE":
				logger.LoggerAgent.Info("Loading updated log config file...")
				config.ClearLogConfigInstance()
				logger.UpdateLoggers()
			}
		case s := <-sig:
			switch s {
			case os.Interrupt:
				logger.LoggerAgent.Info("Shutting down...")
				break OUTER
			}
		}
	}
	logger.LoggerAgent.Info("Bye!")
}

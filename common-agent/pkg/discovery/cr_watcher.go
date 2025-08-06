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

package discovery

import (
	"context"
	"sync"
	"time"

	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/loggers"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/pkg/managementserver"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Define the resources to watch
var (
	configOnce sync.Once
	eventQueue chan managementserver.APICPEvent
	APIMap     map[string]managementserver.API // Maps apiUUID to latest API struct
	APIHashMap map[string]string               // Maps apiUUID to api hash string
	wg         sync.WaitGroup
)

// CRWatcher defines a watcher for Kubernetes Custom Resources with pluggable event handlers
type CRWatcher struct {
	DynamicClient dynamic.Interface
	Namespace     string
	GroupVersions []schema.GroupVersionResource
	AddFunc       func(*unstructured.Unstructured)
	UpdateFunc    func(oldObj, newObj *unstructured.Unstructured)
	DeleteFunc    func(*unstructured.Unstructured)
}

// Watch starts watching the specified resources with the provided handlers
func (cw *CRWatcher) Watch() {
	// Load in-cluster Kubernetes config
	config, err := rest.InClusterConfig()
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to load in-cluster config: %v", err)
		return
	}

	// Create dynamic Kubernetes client
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		loggers.LoggerWatcher.Errorf("Failed to create dynamic client: %v", err)
		return
	}
	cw.DynamicClient = dynamicClient

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start watching each resource
	for _, gvr := range cw.GroupVersions {
		go cw.watchResourceWithRetries(ctx, gvr, cw.Namespace)
	}

	// Keep running
	select {}
}

// watchResourceWithRetries watches a specific GVR in a namespace and retries if it stops unexpectedly
func (cw *CRWatcher) watchResourceWithRetries(ctx context.Context, gvr schema.GroupVersionResource, namespace string) {
	for {
		select {
		case <-ctx.Done():
			loggers.LoggerWatcher.Infof("Stopping watch for %s", gvr.Resource)
			return
		default:
			loggers.LoggerWatcher.Infof("Starting watch for %s in namespace %s", gvr.Resource, namespace)
			err := cw.startInformer(ctx, gvr, namespace)
			if err != nil {
				loggers.LoggerWatcher.Errorf("Error watching %s: %v", gvr.Resource, err)
			}
			loggers.LoggerWatcher.Warnf("Restarting watch for %s after 5 seconds", gvr.Resource)
			time.Sleep(5 * time.Second) // Avoid aggressive restarts
		}
	}
}

// startInformer starts an informer for a specific resource and handles events
func (cw *CRWatcher) startInformer(ctx context.Context, gvr schema.GroupVersionResource, namespace string) error {
	defer func() {
		if r := recover(); r != nil {
			loggers.LoggerWatcher.Errorf("Recovered from panic in watch for %s: %v", gvr.Resource, r)
		}
	}()

	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return cw.DynamicClient.Resource(gvr).Namespace(namespace).List(ctx, options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return cw.DynamicClient.Resource(gvr).Namespace(namespace).Watch(ctx, options)
			},
		},
		&unstructured.Unstructured{},
		time.Minute, // Resync period
		cache.Indexers{},
	)

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			u := obj.(*unstructured.Unstructured)
			if cw.AddFunc != nil {
				cw.AddFunc(u)
			} else {
				loggers.LoggerWatcher.Infof("%s Added: %s/%s", gvr.Resource, u.GetNamespace(), u.GetName())
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldU := oldObj.(*unstructured.Unstructured)
			newU := newObj.(*unstructured.Unstructured)
			if cw.UpdateFunc != nil {
				cw.UpdateFunc(oldU, newU)
			} else {
				loggers.LoggerWatcher.Infof("%s Updated: %s/%s", gvr.Resource, newU.GetNamespace(), newU.GetName())
			}
		},
		DeleteFunc: func(obj interface{}) {
			u := obj.(*unstructured.Unstructured)
			if cw.DeleteFunc != nil {
				cw.DeleteFunc(u)
			} else {
				loggers.LoggerWatcher.Infof("%s Deleted: %s/%s", gvr.Resource, u.GetNamespace(), u.GetName())
			}
		},
	})

	informer.Run(ctx.Done())
	return nil
}

func init() {
	configOnce.Do(func() {
		APIMap = make(map[string]managementserver.API)
		APIHashMap = make(map[string]string)
		eventQueue = make(chan managementserver.APICPEvent, 100)

		wg.Add(1)
		go sendData()
	})
}

// sendData sends data as a POST request to the control plane host.
func sendData() {
	loggers.LoggerWatcher.Infof("A thread assigned to handle event")

	defer wg.Done()

	for event := range eventQueue {
		loggers.LoggerWatcher.Infof("Processing event: %+v", event)

		for {
			if event.Event == managementserver.DeleteEvent {
				managementserver.HandleDeleteEvent(event)
			} else {
				id, revisionID, err := managementserver.HandleCreateOrUpdateEvent(event)
				if err != nil {
					loggers.LoggerWatcher.Errorf("Event create or update error : %+v", err)
				} else if id == "" {
					loggers.LoggerWatcher.Error("Id field not present in response")
					id = "" // Default to empty string if not found
				} else if revisionID == "" {
					loggers.LoggerWatcher.Error("Revision field not present in response")
					revisionID = ""
				}
				loggers.LoggerWatcher.Infof("Adding label update to API Labels: apiUUID: %s, revisionID: %s",
					id, revisionID)
			}
			break
		}
	}
}

// QueueEvent adds an event to the event queue
func QueueEvent(eventType managementserver.EventType, api managementserver.API, crName, crNamespace string) {
	event := managementserver.APICPEvent{
		Event: eventType,
		API:   api,
	}
	select {
	case eventQueue <- event:
		loggers.LoggerWatcher.Infof("Queued %s event for API %s", eventType, api.APIUUID)
	default:
		loggers.LoggerWatcher.Warnf("Event queue full, dropping %s event for API %s", eventType, api.APIUUID)
	}
}

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

// Package k8sclient contains the common implementation methods to invoke k8s APIs in the agent
package k8sclient

import (
	"context"

	v1 "github.com/kong/kubernetes-configuration/api/configuration/v1"
	"github.com/wso2-extensions/apim-gw-agents/common-agent/config"
	"github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/internal/loggers"
	"github.com/wso2-extensions/apim-gw-agents/kong/gateway-connector/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	k8error "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// DeployHTTPRouteCR applies the given HttpRoute struct to the Kubernetes cluster.
func DeployHTTPRouteCR(httpRoute *gwapiv1.HTTPRoute, k8sClient client.Client) {
	loggers.LoggerK8sClient.Debugf("Deploying HTTPRoute CR|Name:%s Namespace:%s\n", httpRoute.Name, httpRoute.ObjectMeta.Namespace)

	crHTTPRoute := &gwapiv1.HTTPRoute{}
	// Retrieve CR from Kubernetes cluster
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: httpRoute.ObjectMeta.Namespace, Name: httpRoute.Name}, crHTTPRoute); err != nil {
		if !k8error.IsNotFound(err) {
			loggers.LoggerK8sClient.Error("Unable to get HTTPRoute CR: " + err.Error())
		}
		if err := k8sClient.Create(context.Background(), httpRoute); err != nil {
			loggers.LoggerK8sClient.Error("Unable to create HTTPRoute CR: " + err.Error())
		} else {
			loggers.LoggerK8sClient.Info("HTTPRoute CR created: " + httpRoute.Name)
		}
	} else {
		crHTTPRoute.Spec = httpRoute.Spec
		if err := k8sClient.Update(context.Background(), crHTTPRoute); err != nil {
			loggers.LoggerK8sClient.Error("Unable to update HTTPRoute CR: " + err.Error())
		} else {
			loggers.LoggerK8sClient.Info("HTTPRoute CR updated: " + crHTTPRoute.Name)
		}
	}
}

// DeployServiceCR applies the given Service struct to the Kubernetes cluster.
func DeployServiceCR(service *corev1.Service, k8sClient client.Client) {
	loggers.LoggerK8sClient.Debugf("Deploying Service CR|Name:%s Namespace:%s\n", service.Name, service.ObjectMeta.Namespace)

	crService := &corev1.Service{}
	// Retrieve CR from Kubernetes cluster
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: service.ObjectMeta.Namespace, Name: service.Name}, crService); err != nil {
		if !k8error.IsNotFound(err) {
			loggers.LoggerK8sClient.Error("Unable to get Service CR: " + err.Error())
		}
		if err := k8sClient.Create(context.Background(), service); err != nil {
			loggers.LoggerK8sClient.Error("Unable to create Service CR: " + err.Error())
		} else {
			loggers.LoggerK8sClient.Info("Service CR created: " + service.Name)
		}
	} else {
		crService.Spec = service.Spec
		if err := k8sClient.Update(context.Background(), crService); err != nil {
			loggers.LoggerK8sClient.Error("Unable to update Service CR: " + err.Error())
		} else {
			loggers.LoggerK8sClient.Info("Service CR updated: " + crService.Name)
		}
	}
}

// DeployKongPluginCR applies the given KongPlugin struct to the Kubernetes cluster.
func DeployKongPluginCR(plugin *v1.KongPlugin, k8sClient client.Client) {
	loggers.LoggerK8sClient.Debugf("Deploying KongPlugin CR|Name:%s Namespace:%s\n", plugin.Name, plugin.ObjectMeta.Namespace)

	crKongPlugin := &v1.KongPlugin{}
	// Retrieve CR from Kubernetes cluster
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: plugin.ObjectMeta.Namespace, Name: plugin.Name}, crKongPlugin); err != nil {
		if !k8error.IsNotFound(err) {
			loggers.LoggerK8sClient.Error("Unable to get KongPlugin CR: " + err.Error())
		}
		if err := k8sClient.Create(context.Background(), plugin); err != nil {
			loggers.LoggerK8sClient.Error("Unable to create KongPlugin CR: " + err.Error())
		} else {
			loggers.LoggerK8sClient.Info("KongPlugin CR created: " + plugin.Name)
		}
	} else {
		crKongPlugin.Config = plugin.Config
		if err := k8sClient.Update(context.Background(), crKongPlugin); err != nil {
			loggers.LoggerK8sClient.Error("Unable to update KongPlugin CR: " + err.Error())
		} else {
			loggers.LoggerK8sClient.Info("KongPlugin CR updated: " + crKongPlugin.Name)
		}
	}
}

// DeployKongConsumerCR applies the given KongConsumer struct to the Kubernetes cluster.
func DeployKongConsumerCR(consumer *v1.KongConsumer, k8sClient client.Client) {
	loggers.LoggerK8sClient.Debugf("Deploying KongConsumer CR|Name:%s Namespace:%s\n", consumer.Name, consumer.ObjectMeta.Namespace)

	crKongConsumer := &v1.KongConsumer{}
	// Retrieve CR from Kubernetes cluster
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: consumer.ObjectMeta.Namespace, Name: consumer.Name}, crKongConsumer); err != nil {
		if !k8error.IsNotFound(err) {
			loggers.LoggerK8sClient.Error("Unable to get KongConsumer CR: " + err.Error())
		}
		if err := k8sClient.Create(context.Background(), consumer); err != nil {
			loggers.LoggerK8sClient.Error("Unable to create KongConsumer CR: " + err.Error())
		} else {
			loggers.LoggerK8sClient.Info("KongConsumer CR created: " + consumer.Name)
		}
	} else {
		crKongConsumer.CustomID = consumer.CustomID
		crKongConsumer.Username = consumer.Username
		if err := k8sClient.Update(context.Background(), crKongConsumer); err != nil {
			loggers.LoggerK8sClient.Error("Unable to update KongConsumer CR: " + err.Error())
		} else {
			loggers.LoggerK8sClient.Info("KongConsumer CR updated: " + crKongConsumer.Name)
		}
	}
}

// DeploySecretCR applies the given Service struct to the Kubernetes cluster.
func DeploySecretCR(k8sSecret *corev1.Secret, k8sClient client.Client) {
	loggers.LoggerK8sClient.Debugf("Deploying Secret CR|Name:%s Namespace:%s\n", k8sSecret.Name, k8sSecret.ObjectMeta.Namespace)

	crSecret := &corev1.Secret{}
	// Retrieve CR from Kubernetes cluster
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: k8sSecret.ObjectMeta.Namespace, Name: k8sSecret.Name}, crSecret); err != nil {
		if !k8error.IsNotFound(err) {
			loggers.LoggerK8sClient.Error("Unable to get Secret CR: " + err.Error())
		}
		if err := k8sClient.Create(context.Background(), k8sSecret); err != nil {
			loggers.LoggerK8sClient.Error("Unable to create Secret CR: " + err.Error())
		} else {
			loggers.LoggerK8sClient.Info("Secret CR created: " + k8sSecret.Name)
		}
	} else {
		crSecret.StringData = k8sSecret.StringData
		if err := k8sClient.Update(context.Background(), crSecret); err != nil {
			loggers.LoggerK8sClient.Error("Unable to update Secret CR: " + err.Error())
		} else {
			loggers.LoggerK8sClient.Info("Secret CR updated: " + crSecret.Name)
		}
	}
}

// UnDeploySecretCR removes the Secret Resources from the Kubernetes cluster based on name.
func UnDeploySecretCR(name string, k8sClient client.Client, conf *config.Config) {
	loggers.LoggerK8sClient.Debugf("Undeploying Secret CR|Name:%s Namespace:%s\n", name, conf.DataPlane.Namespace)

	resource := &corev1.Secret{}
	// Retrieve CR from Kubernetes cluster
	err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: conf.DataPlane.Namespace, Name: name}, resource)
	if err != nil {
		loggers.LoggerK8sClient.Error("Unable to get Secret CR: " + err.Error())
	} else {
		if err := k8sClient.Delete(context.Background(), resource, &client.DeleteOptions{}); err != nil {
			loggers.LoggerK8sClient.Errorf("Unable to delete Secret CR: %v", err)
		} else {
			loggers.LoggerK8sClient.Infof("Deleted Secret CR: %s", resource.Name)
		}
	}
}

// UnDeployKongPluginCR removes the Kong plugin CR Resources from the Kubernetes cluster based on name.
func UnDeployKongPluginCR(name string, k8sClient client.Client, conf *config.Config) {
	loggers.LoggerK8sClient.Debugf("Undeploying KongPlugin CR|Name:%s Namespace:%s\n", name, conf.DataPlane.Namespace)

	resource := &v1.KongPlugin{}
	// Retrieve CR from Kubernetes cluster
	err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: conf.DataPlane.Namespace, Name: name}, resource)
	if err != nil {
		loggers.LoggerK8sClient.Error("Unable to get Kong Plugin CR: " + err.Error())
	} else {
		if err := k8sClient.Delete(context.Background(), resource, &client.DeleteOptions{}); err != nil {
			loggers.LoggerK8sClient.Errorf("Unable to delete Kong Plugin CR: %v", err)
		} else {
			loggers.LoggerK8sClient.Infof("Deleted Kong Plugin CR: %s", resource.Name)
		}
	}
}

// UnDeployKongConsumerCR removes the Kong consumer CR Resources from the Kubernetes cluster based on name.
func UnDeployKongConsumerCR(name string, k8sClient client.Client, conf *config.Config) {
	loggers.LoggerK8sClient.Debugf("Undeploying KongConsumer CR|Name:%s Namespace:%s\n", name, conf.DataPlane.Namespace)

	resource := &v1.KongConsumer{}
	// Retrieve CR from Kubernetes cluster
	if err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: conf.DataPlane.Namespace, Name: name}, resource); err != nil {
		loggers.LoggerK8sClient.Error("Unable to get Kong Consumer CR: " + err.Error())
	} else {
		if err := k8sClient.Delete(context.Background(), resource, &client.DeleteOptions{}); err != nil {
			loggers.LoggerK8sClient.Errorf("Unable to delete Kong Consumer CR: %v", err)
		} else {
			loggers.LoggerK8sClient.Infof("Deleted Kong Consumer CR: %s", resource.Name)
		}
	}
}

// GetKongConsumerCR gets Kong consumer CR Resources from the Kubernetes cluster based on name.
func GetKongConsumerCR(name string, k8sClient client.Client, conf *config.Config) *v1.KongConsumer {
	loggers.LoggerK8sClient.Debugf("Getting KongConsumer CR|Name:%s Namespace:%s\n", name, conf.DataPlane.Namespace)

	resource := &v1.KongConsumer{}
	// Retrieve CR from Kubernetes cluster
	err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: conf.DataPlane.Namespace, Name: name}, resource)
	if err != nil {
		if !k8error.IsNotFound(err) {
			loggers.LoggerK8sClient.Error("Unable to get Kong Consumer CR: " + err.Error())
		}
		return nil
	}
	return resource
}

// GetK8sSecrets gets k8s secret CR Resources from the Kubernetes cluster based on given labels.
func GetK8sSecrets(labelSelectors map[string]string, k8sClient client.Client, conf *config.Config) []corev1.Secret {
	loggers.LoggerK8sClient.Debugf("Getting k8s secrets|Labels:%d Namespace:%s\n", len(labelSelectors), conf.DataPlane.Namespace)

	resourceList := &corev1.SecretList{}
	// Retrieve all CRs from the Kubernetes cluster
	err := k8sClient.List(context.Background(), resourceList, &client.ListOptions{Namespace: conf.DataPlane.Namespace, LabelSelector: labels.SelectorFromSet(labelSelectors)})
	if err != nil {
		loggers.LoggerK8sClient.Errorf("Unable to list K8s Secret CRs: %v", err)
	} else {
		return resourceList.Items
	}
	return nil
}

// GetK8sSecret gets k8s secret resource from the Kubernetes cluster based on given name.
func GetK8sSecret(name string, k8sClient client.Client, conf *config.Config) *corev1.Secret {
	loggers.LoggerK8sClient.Debugf("Getting k8s secret|Name:%s Namespace:%s\n", name, conf.DataPlane.Namespace)

	resource := &corev1.Secret{}
	// Retrieve CR from the Kubernetes cluster
	err := k8sClient.Get(context.Background(), client.ObjectKey{Namespace: conf.DataPlane.Namespace, Name: name}, resource)
	if err != nil {
		loggers.LoggerK8sClient.Errorf("Unable to list K8s Secret CRs: %v", err)
	} else {
		return resource
	}
	return nil
}

// UndeployAPICRs removes the API Custom Resources from the Kubernetes cluster based on API ID label.
func UndeployAPICRs(apiID string, k8sClient client.Client) {
	loggers.LoggerK8sClient.Debugf("Undeploying API CRs|APIID:%s\n", apiID)

	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		loggers.LoggerK8sClient.Errorf("Error reading configurations: %v", errReadConfig)
	}

	undeployHTTPRoutes(apiID, k8sClient, conf)
	undeployServices(apiID, k8sClient, conf)
	undeployKongPlugins(k8sClient, conf, labels.SelectorFromSet(map[string]string{"apiUUID": apiID}))
}

// UndeployAPPCRs removes the APP Custom Resources from the Kubernetes cluster based on Application ID label.
func UndeployAPPCRs(appID string, k8sClient client.Client) {
	loggers.LoggerK8sClient.Debugf("Undeploying APP CRs|AppID:%s\n", appID)

	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		loggers.LoggerK8sClient.Errorf("Error reading configurations: %v", errReadConfig)
	}
	undeployKongConsumers(appID, k8sClient, conf)
	undeployKongPlugins(k8sClient, conf, labels.SelectorFromSet(map[string]string{"applicationUUID": appID}))
	unDeploySecret(appID, k8sClient, conf)
}

// undeployHTTPRoutes removes the HTTPRoute Resources from the Kubernetes cluster based on API ID label.
func undeployHTTPRoutes(apiID string, k8sClient client.Client, conf *config.Config) {
	loggers.LoggerK8sClient.Debugf("Undeploying HTTPRoutes|APIID:%s\n", apiID)

	resourceList := &gwapiv1.HTTPRouteList{}
	// Retrieve all CRs from the Kubernetes cluster
	err := k8sClient.List(context.Background(), resourceList, &client.ListOptions{Namespace: conf.DataPlane.Namespace, LabelSelector: labels.SelectorFromSet(map[string]string{"apiUUID": apiID})})
	if err != nil {
		loggers.LoggerK8sClient.Errorf("Unable to list HTTPRoute CRs: %v", err)
	} else {
		for _, resource := range resourceList.Items {
			err := k8sClient.Delete(context.Background(), &resource, &client.DeleteOptions{})
			if err != nil {
				loggers.LoggerK8sClient.Errorf("Unable to delete HTTPRoute CR: %v", err)
			} else {
				loggers.LoggerK8sClient.Infof("Deleted HTTPRoute CR: %s", resource.Name)
			}
		}
	}
}

// undeployServices removes the Service Resources from the Kubernetes cluster based on API ID label.
func undeployServices(apiID string, k8sClient client.Client, conf *config.Config) {
	loggers.LoggerK8sClient.Debugf("Undeploying Services|APIID:%s\n", apiID)

	resourceList := &corev1.ServiceList{}
	// Retrieve all CRs from the Kubernetes cluster
	err := k8sClient.List(context.Background(), resourceList, &client.ListOptions{Namespace: conf.DataPlane.Namespace, LabelSelector: labels.SelectorFromSet(map[string]string{"apiUUID": apiID})})
	if err != nil {
		loggers.LoggerK8sClient.Errorf("Unable to list Service CRs: %v", err)
	} else {
		for _, resource := range resourceList.Items {
			err := k8sClient.Delete(context.Background(), &resource, &client.DeleteOptions{})
			if err != nil {
				loggers.LoggerK8sClient.Errorf("Unable to delete Service CR: %v", err)
			} else {
				loggers.LoggerK8sClient.Infof("Deleted Service CR: %s", resource.Name)
			}
		}
	}
}

// undeployKongPlugins removes the KongPlugin Resources from the Kubernetes cluster based on label selector.
func undeployKongPlugins(k8sClient client.Client, conf *config.Config, labelSelector labels.Selector) {
	loggers.LoggerK8sClient.Debugf("Undeploying KongPlugins|LabelSelector:%s\n", labelSelector.String())

	resourceList := &v1.KongPluginList{}
	// Retrieve all CRs from the Kubernetes cluster
	err := k8sClient.List(context.Background(), resourceList, &client.ListOptions{Namespace: conf.DataPlane.Namespace, LabelSelector: labelSelector})
	if err != nil {
		loggers.LoggerK8sClient.Errorf("Unable to list KongPlugin CRs: %v", err)
	} else {
		for _, resource := range resourceList.Items {
			err := k8sClient.Delete(context.Background(), &resource, &client.DeleteOptions{})
			if err != nil {
				loggers.LoggerK8sClient.Errorf("Unable to delete KongPlugin CR: %v", err)
			} else {
				loggers.LoggerK8sClient.Infof("Deleted KongPlugin CR: %s", resource.Name)
			}
		}
	}
}

// undeployKongConsumers removes the KongConsumer Resources from the Kubernetes cluster based on application ID label.
func undeployKongConsumers(appID string, k8sClient client.Client, conf *config.Config) {
	loggers.LoggerK8sClient.Debugf("Undeploying KongConsumers|AppID:%s\n", appID)

	resourceList := &v1.KongConsumerList{}
	// Retrieve all CRs from the Kubernetes cluster
	err := k8sClient.List(context.Background(), resourceList, &client.ListOptions{Namespace: conf.DataPlane.Namespace, LabelSelector: labels.SelectorFromSet(map[string]string{"applicationUUID": appID})})
	if err != nil {
		loggers.LoggerK8sClient.Errorf("Unable to list KongConsumer CRs: %v", err)
	} else {
		for _, resource := range resourceList.Items {
			err := k8sClient.Delete(context.Background(), &resource, &client.DeleteOptions{})
			if err != nil {
				loggers.LoggerK8sClient.Errorf("Unable to delete KongConsumer CR: %v", err)
			} else {
				loggers.LoggerK8sClient.Infof("Deleted KongConsumer CR: %s", resource.Name)
			}
		}
	}
}

// unDeploySecret removes the Secret Resources from the Kubernetes cluster based on application ID label.
func unDeploySecret(appID string, k8sClient client.Client, conf *config.Config) {
	loggers.LoggerK8sClient.Debugf("Undeploying Secrets|AppID:%s\n", appID)

	resourceList := &corev1.SecretList{}
	// Retrieve all CRs from the Kubernetes cluster
	err := k8sClient.List(context.Background(), resourceList, &client.ListOptions{Namespace: conf.DataPlane.Namespace, LabelSelector: labels.SelectorFromSet(map[string]string{"applicationUUID": appID})})
	if err != nil {
		loggers.LoggerK8sClient.Errorf("Unable to list Secret CRs: %v", err)
	} else {
		for _, resource := range resourceList.Items {
			err := k8sClient.Delete(context.Background(), &resource, &client.DeleteOptions{})
			if err != nil {
				loggers.LoggerK8sClient.Errorf("Unable to delete Secret CR: %v", err)
			} else {
				loggers.LoggerK8sClient.Infof("Deleted Secret CR: %s", resource.Name)
			}
		}
	}
}

// UpdateKongConsumerCredential updates credentials in KongConsumer Resources from the Kubernetes cluster based on application ID and environment label.
func UpdateKongConsumerCredential(appID string, env string, k8sClient client.Client, conf *config.Config, addCredentials []string, removeCredentials []string) {
	loggers.LoggerK8sClient.Debugf("Updating KongConsumer credentials|AppID:%s Env:%s Add:%d Remove:%d\n", appID, env, len(addCredentials), len(removeCredentials))

	resourceList := &v1.KongConsumerList{}
	labelSelectors := map[string]string{"applicationUUID": appID}
	if env != "" {
		labelSelectors["environment"] = env
	}

	// Retrieve all CRs from the Kubernetes cluster
	err := k8sClient.List(context.Background(), resourceList, &client.ListOptions{Namespace: conf.DataPlane.Namespace, LabelSelector: labels.SelectorFromSet(labelSelectors)})
	if err != nil {
		loggers.LoggerK8sClient.Errorf("Unable to list KongConsumer CRs: %v", err)
	} else {
		for _, resource := range resourceList.Items {
			// update plugin credentials
			resource.Credentials = utils.PrepareCredentials(resource.Credentials, addCredentials, removeCredentials)
			err := k8sClient.Update(context.Background(), &resource, &client.UpdateOptions{})
			if err != nil {
				loggers.LoggerK8sClient.Errorf("Unable to update KongConsumer CR: %v", err)
			} else {
				loggers.LoggerK8sClient.Infof("Updated KongConsumer CR: %s", resource.Name)
			}
		}
	}
}

// UpdateKongConsumerPluginAnnotation updates plugin annotation to Kong Consumer based on application and environment label.
func UpdateKongConsumerPluginAnnotation(appID string, env string, k8sClient client.Client, conf *config.Config, addAnnotations []string, removeAnnotations []string) {
	loggers.LoggerK8sClient.Debugf("Updating KongConsumer annotations|AppID:%s Env:%s Add:%d Remove:%d\n", appID, env, len(addAnnotations), len(removeAnnotations))

	resourceList := &v1.KongConsumerList{}
	labelSelectors := map[string]string{"applicationUUID": appID}
	if env != "" {
		labelSelectors["environment"] = env
	}

	// Retrieve all CRs from the Kubernetes cluster
	err := k8sClient.List(context.Background(), resourceList, &client.ListOptions{Namespace: conf.DataPlane.Namespace, LabelSelector: labels.SelectorFromSet(labelSelectors)})
	if err != nil {
		loggers.LoggerK8sClient.Errorf("Unable to list KongConsumer CRs: %v", err)
	} else {
		for _, resource := range resourceList.Items {
			// update plugin annotations
			resource.Annotations["konghq.com/plugins"] = utils.PrepareAnnotations(resource.Annotations["konghq.com/plugins"], addAnnotations, removeAnnotations)
			err := k8sClient.Update(context.Background(), &resource, &client.UpdateOptions{})
			if err != nil {
				loggers.LoggerK8sClient.Errorf("Unable to add KongConsumer CR annotations: %v", err)
			} else {
				loggers.LoggerK8sClient.Infof("Updated KongConsumer CR annotations: %s", resource.Name)
			}
		}
	}
}

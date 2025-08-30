/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package managementserver

// APIImportCallback defines a callback interface for gateway connectors to receive
// notification when an API has been successfully imported to the control plane
type APIImportCallback interface {
	OnAPIImportSuccess(apiUUID, apiID, revisionID, crName, crNamespace, agentName string)
}

// apiImportCallback holds the registered callback implementation
var apiImportCallback APIImportCallback

// RegisterAPIImportCallback registers a callback to be invoked when an API is successfully imported
func RegisterAPIImportCallback(callback APIImportCallback) {
	apiImportCallback = callback
}

// GetAPIImportCallback returns the registered callback if any
func GetAPIImportCallback() APIImportCallback {
	return apiImportCallback
}

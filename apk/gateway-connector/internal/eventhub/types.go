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

package eventhub

// Application for struct application
type Application struct {
	UUID         string            `json:"uuid"`
	ID           int32             `json:"id" json:"applicationId"`
	Name         string            `json:"name" json:"applicationName"`
	SubName      string            `json:"subName" json:"subscriber"`
	Policy       string            `json:"policy" json:"applicationPolicy"`
	TokenType    string            `json:"tokenType"`
	Attributes   map[string]string `json:"attributes"`
	TenantID     int32             `json:"tenanId,omitempty"`
	Organization string            `json:"organization,omitempty"`
	TimeStamp    int64             `json:"timeStamp,omitempty"`
}

// ApplicationList for struct list of application
type ApplicationList struct {
	List []Application `json:"list"`
}

// ApplicationKeyMapping for struct applicationKeyMapping
type ApplicationKeyMapping struct {
	ApplicationID   int32  `json:"applicationId"`
	ApplicationUUID string `json:"applicationUUID"`
	ConsumerKey     string `json:"consumerKey"`
	KeyType         string `json:"keyType"`
	KeyManager      string `json:"keyManager"`
	TenantID        int32  `json:"tenanId,omitempty"`
	TenantDomain    string `json:"tenanDomain,omitempty"`
	TimeStamp       int64  `json:"timeStamp,omitempty"`
}

// ApplicationKeyMappingList for struct list of applicationKeyMapping
type ApplicationKeyMappingList struct {
	List []ApplicationKeyMapping `json:"list"`
}

// ApplicationPolicy for struct ApplicationPolicy
type ApplicationPolicy struct {
	ID        int32  `json:"id"`
	TenantID  int32  `json:"tenantId"`
	Name      string `json:"name"`
	QuotaType string `json:"quotaType"`
}

// ApplicationPolicyList for struct list of ApplicationPolicy
type ApplicationPolicyList struct {
	List []ApplicationPolicy `json:"list"`
}

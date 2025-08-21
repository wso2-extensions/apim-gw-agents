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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddSubscription(t *testing.T) {
	testSub := Subscription{
		UUID:         "c8d8fb750ece-0a5b1039-9836-4b05-baa8-e06c",
		SubStatus:    "active",
		Organization: "Org1",
		SubscribedAPI: &SubscribedAPI{
			Name:    "Test API",
			Version: "v1.0.0",
		},
		TimeStamp: 123456789,
	}
	AddSubscription(testSub)
	if _, ok := subscriptionMap[testSub.UUID]; !ok {
		t.Errorf("Subscription not added to the map")
	}
}

func TestGetAllSubscriptions(t *testing.T) {
	subscription1 := Subscription{UUID: "sub1", SubStatus: "Active", Organization: "Org1"}
	subscription2 := Subscription{UUID: "sub2", SubStatus: "Inactive", Organization: "Org2"}
	subscriptionMap = map[string]Subscription{
		"sub1": subscription1,
		"sub2": subscription2,
	}
	subscriptions := GetAllSubscriptions()
	assert.Len(t, subscriptions, 2)
	for _, sub := range subscriptions {
		expSub := subscriptionMap[sub.UUID]
		assert.Equal(t, sub.UUID, expSub.UUID)
		assert.Equal(t, sub.SubStatus, expSub.SubStatus)
		assert.Equal(t, sub.Organization, expSub.Organization)
	}
}

func TestGetSubscription(t *testing.T) {
	subscription := Subscription{UUID: "sub1", SubStatus: "Active", Organization: "Org1"}
	subscriptionMap = map[string]Subscription{
		"sub1": subscription,
	}
	result := GetSubscription("sub1")
	assert.Equal(t, result, subscription)
}

func TestDeleteSubscription(t *testing.T) {
	subscriptionMap = map[string]Subscription{"sub1": {UUID: "sub1", Organization: "Org1"}}
	DeleteSubscription("sub1")
	assert.Empty(t, subscriptionMap)
}

func TestUpdateSubscription(t *testing.T) {
	uuid := "sub1"
	subscription := Subscription{UUID: "uuid", SubStatus: "Active", Organization: "Org1", SubscribedAPI: &SubscribedAPI{Name: "Test API", Version: "v1"}}
	UpdateSubscription(uuid, subscription)
	assert.Equal(t, subscriptionMap[uuid], subscription)
}

func TestDeleteAllSubscriptions(t *testing.T) {
	DeleteAllSubscriptions()
	assert.Empty(t, subscriptionMap)
}

func TestAddAllSubscriptions(t *testing.T) {
	subscriptionMapTemp := map[string]Subscription{
		"sub1": {UUID: "sub1", SubStatus: "Active", Organization: "Org1"},
		"sub2": {UUID: "sub2", SubStatus: "Inactive", Organization: "Org2"},
	}
	AddAllSubscriptions(subscriptionMapTemp)
	assert.Equal(t, subscriptionMapTemp, subscriptionMap)
}

func TestDeleteAllSubscriptionsByApplicationsUUID(t *testing.T) {
	uuid := "Org1"
	DeleteAllSubscriptionsByApplicationsUUID(uuid)
	for _, sub := range subscriptionMap {
		assert.NotEqual(t, uuid, sub.Organization)
	}
}

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

package utils

import (
	"slices"
	"strings"

	"github.com/wso2-extensions/apim-gw-connectors/kong/gateway-connector/constants"
)

// FilterItems filter items
func FilterItems(items []string, filterItems []string) []string {
	result := []string{}
	for _, item := range items {
		if !slices.Contains(filterItems, item) {
			result = append(result, item)
		}
	}
	return TrimSpaces(result)
}

// AddItems adds items to given string separated ","
func AddItems(items []string, addItems []string) []string {
	for _, item := range addItems {
		if !slices.Contains(items, item) {
			items = append(items, item)
		}
	}
	return TrimSpaces(items)
}

// TrimSpaces removes empty strings from string array
func TrimSpaces(items []string) []string {
	return slices.DeleteFunc(items, func(e string) bool {
		return e == constants.EmptyString
	})
}

// PrepareCredentials adds/removes listed credentials from given list of credentials
func PrepareCredentials(credentials []string, addItems []string, removeItems []string) []string {
	if removeItems != nil {
		credentials = FilterItems(credentials, removeItems)
	}
	if addItems != nil {
		credentials = AddItems(credentials, addItems)
	}
	return credentials
}

// PrepareAnnotations adds/removes listed annotations from given list of annotations
func PrepareAnnotations(annotations string, addItems []string, removeItems []string) string {
	result := strings.Split(annotations, constants.CommaString)
	if removeItems != nil {
		result = FilterItems(result, removeItems)
	}
	if addItems != nil {
		result = AddItems(result, addItems)
	}
	return strings.Join(result, constants.CommaString)
}

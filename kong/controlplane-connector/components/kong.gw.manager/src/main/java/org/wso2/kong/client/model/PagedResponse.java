/*
 * Copyright (c) 2025 WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.kong.client.model;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * Represents a paginated response from the Kong API.
 * This class is used to encapsulate the data returned from the Kong API when fetching
 * resources that support pagination.
 *
 * @param <T> The type of data contained in the response.
 */
public class PagedResponse<T> {
    private List<T> data;

    // Optional fields you might get back from Konnect
    @SerializedName("next")   private String next;
    @SerializedName("offset") private String offset;

    public List<T> getData() {
        return data;
    }

    public void setData(List<T> data) {
        this.data = data;
    }

    public String getNext() {
        return next;
    }

    public void setNext(String next) {
        this.next = next;
    }

    public String getOffset() {
        return offset;
    }

    public void setOffset(String offset) {
        this.offset = offset;
    }

}


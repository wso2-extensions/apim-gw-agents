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

import java.util.List;

/**
 * Represents a generic response from the Kong API that contains a list of items and metadata.
 * This is used for paginated responses from Kong endpoints.
 *
 * @param <T> The type of items in the response data list.
 */
public class KongListResponse<T> {
    private List<T> data;
    private Meta meta;

    /**
     * Metadata about the pagination of the response.
     * This includes information like total items, page size, and current page number.
     */
    public static class Meta {
        private Page page;
        public Page getPage() {
            return page;
        }
        public void setPage(Page page) {
            this.page = page;
        }
    }
    /**
     * Represents pagination details such as total items, page size, and current page number.
     */
    public static class Page {
        private int total;
        private int size;
        private int number;
        public int getTotal() {
            return total;
        }
        public void setTotal(int total) {
            this.total = total;
        }
        public int getSize() {
            return size;
        }
        public void setSize(int size) {
            this.size = size;
        }
        public int getNumber() {
            return number;
        }
        public void setNumber(int number) {
            this.number = number;
        }
    }

    public List<T> getData() {
        return data;
    }
    public void setData(List<T> data) {
        this.data = data;
    }
    public Meta getMeta() {
        return meta;
    }
    public void setMeta(Meta meta) {
        this.meta = meta;
    }
}

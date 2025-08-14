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

package org.wso2.azure.gw.client.model;

/**
 * Represents the envelope for exporting API details from Azure API Management.
 * Contains the API ID, type, name, and properties including the export format and link.
 */
public final class ExportEnvelope {
    public String id;
    public String type;
    public String name;
    public Properties properties;

    public String getLink() {
        return properties != null && properties.value != null ? properties.value.link : null;
    }

    /**
     * Represents the properties of the export envelope, including the format and export value.
     */
    public static final class Properties {
        public String format;
        public ExportValue value;
    }

    /**
     * Represents the export value containing the link to the exported API definition.
     */
    public static final class ExportValue {
        public String link;
    }
}

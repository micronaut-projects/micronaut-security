/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.scim.core;

import io.micronaut.core.annotation.Experimental;

/**
 * Schema URIs registered by RFC 7643.
 *
 * @since 5.4.0
 */
@Experimental
public final class SchemaUris {
    /** The core User schema URI. */
    public static final String USER = "urn:ietf:params:scim:schemas:core:2.0:User";
    /** The core Group schema URI. */
    public static final String GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
    /** The enterprise User extension schema URI. */
    public static final String ENTERPRISE_USER = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    /** The ServiceProviderConfig schema URI. */
    public static final String SERVICE_PROVIDER_CONFIG =
        "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
    /** The ResourceType schema URI. */
    public static final String RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
    /** The Schema resource schema URI. */
    public static final String SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema";

    private SchemaUris() {
    }
}

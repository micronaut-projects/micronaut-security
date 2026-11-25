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
package io.micronaut.security.scim.server.protocol;

import io.micronaut.core.annotation.Experimental;

/**
 * Schema URIs identifying the protocol messages defined by RFC 7644.
 *
 * @since 5.4.0
 */
@Experimental
public final class ScimMessageSchemas {
    /** List response schema URI. */
    public static final String LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    /** Search request schema URI. */
    public static final String SEARCH_REQUEST = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
    /** PATCH request schema URI. */
    public static final String PATCH_OPERATION = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    /** Bulk request schema URI. */
    public static final String BULK_REQUEST = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
    /** Bulk response schema URI. */
    public static final String BULK_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
    /** Error response schema URI. */
    public static final String ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";

    private ScimMessageSchemas() {
    }
}

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

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;

import java.util.List;

/**
 * RFC 7644 bulk response.
 *
 * @param schemas Message schema URIs
 * @param operations Operation results
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record ScimBulkResponse(
    List<String> schemas,
    @JsonProperty("Operations") List<ScimBulkResponseOperation> operations
) {
    /**
     * Creates an immutable bulk response.
     *
     * @since 5.4.0
     */
    public ScimBulkResponse {
        schemas = List.copyOf(schemas);
        operations = List.copyOf(operations);
    }

    /**
     * Creates a bulk response with the RFC 7644 response schema URI.
     *
     * @param operations Operation results
     * @return Bulk response
     * @since 5.4.0
     */
    public static ScimBulkResponse of(List<ScimBulkResponseOperation> operations) {
        return new ScimBulkResponse(List.of(ScimMessageSchemas.BULK_RESPONSE), operations);
    }
}

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
import io.micronaut.security.scim.server.model.ScimPage;

import java.util.List;

/**
 * RFC 7644 ListResponse message.
 *
 * @param schemas Message schema URIs
 * @param totalResults Total matching resources
 * @param resources Resources in the current page
 * @param startIndex One-based index of the first current-page resource
 * @param itemsPerPage Number of resources in the current page
 * @param <T> Resource type
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record ScimListResponse<T>(
    List<String> schemas,
    long totalResults,
    @JsonProperty("Resources") List<T> resources,
    int startIndex,
    int itemsPerPage
) {
    /**
     * Creates an immutable list response.
     *
     * @since 5.4.0
     */
    public ScimListResponse {
        schemas = List.copyOf(schemas);
        resources = List.copyOf(resources);
    }

    /**
     * Creates an RFC 7644 response from an application result page.
     *
     * @param page Application result page
     * @param <T> Resource type
     * @return List response
     * @since 5.4.0
     */
    public static <T> ScimListResponse<T> fromPage(ScimPage<T> page) {
        return new ScimListResponse<>(List.of(ScimMessageSchemas.LIST_RESPONSE), page.totalResults(),
            page.resources(), page.startIndex(), page.resources().size());
    }
}

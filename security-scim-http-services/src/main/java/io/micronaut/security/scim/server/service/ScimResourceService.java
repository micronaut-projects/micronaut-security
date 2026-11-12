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
package io.micronaut.security.scim.server.service;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.security.scim.core.ScimResource;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.model.ScimPage;
import io.micronaut.security.scim.server.model.ScimQuery;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import io.micronaut.security.scim.server.model.ScimResourceResponse;
import io.micronaut.security.scim.server.protocol.ScimPatchRequest;

import java.util.Optional;

/**
 * Persistence and policy operations that a SCIM application implements for a resource type.
 * Implementations must enforce schema mutability, uniqueness, authorization, PATCH atomicity,
 * and conditional request semantics appropriate for their persistence technology.
 *
 * @param <T> Resource type
 * @since 5.4.0
 */
@Experimental
public interface ScimResourceService<T extends ScimResource> {
    /**
     * Persists a new resource and assigns its server-controlled attributes.
     *
     * @param resource Client representation
     * @param context Request context
     * @return The persisted representation
     * @since 5.4.0
     */
    ScimResourceResponse<T> create(T resource, ScimRequestContext context);

    /**
     * Retrieves a resource by its service-provider identifier.
     *
     * @param id Resource identifier
     * @param context Request context
     * @return The resource response, or empty when absent
     * @since 5.4.0
     */
    Optional<ScimResourceResponse<T>> get(String id, ScimRequestContext context);

    /**
     * Applies filtering, sorting, pagination, and attribute selection to a resource query.
     *
     * @param query Parsed query
     * @param context Request context
     * @return The result page
     * @since 5.4.0
     */
    ScimPage<T> search(ScimQuery query, ScimRequestContext context);

    /**
     * Replaces writable attributes of an existing resource.
     *
     * @param id Resource identifier
     * @param resource Replacement representation
     * @param context Request context, including any {@code If-Match} value
     * @return The persisted representation, or empty when absent
     * @since 5.4.0
     */
    Optional<ScimResourceResponse<T>> replace(String id, T resource, ScimRequestContext context);

    /**
     * Atomically applies all PATCH operations to an existing resource.
     *
     * @param id Resource identifier
     * @param patch PATCH message
     * @param context Request context, including any {@code If-Match} value
     * @return The persisted representation, or empty when absent
     * @since 5.4.0
     */
    Optional<ScimResourceResponse<T>> patch(String id, ScimPatchRequest patch, ScimRequestContext context);

    /**
     * Deletes an existing resource.
     *
     * @param id Resource identifier
     * @param context Request context, including any {@code If-Match} value
     * @throws ScimException When the resource is absent or cannot be deleted
     * @since 5.4.0
     */
    void delete(String id, ScimRequestContext context);
}

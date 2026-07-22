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
import io.micronaut.security.scim.server.model.ScimRequestContext;
import io.micronaut.security.scim.server.protocol.ScimBulkRequest;
import io.micronaut.security.scim.server.protocol.ScimBulkResponse;
import org.reactivestreams.Publisher;

/**
 * Optional application contract for RFC 7644 bulk operations. The implementation owns transaction
 * boundaries, {@code bulkId} resolution, circular-reference detection, and fail-on-error behavior.
 *
 * @since 5.4.0
 */
@Experimental
public interface ScimBulkService {
    /**
     * Executes the validated operations in a bulk request.
     *
     * @param request Bulk request
     * @param context Request context
     * @return The bulk response; must emit exactly one result
     * @since 5.4.0
     */
    Publisher<ScimBulkResponse> execute(ScimBulkRequest request, ScimRequestContext context);
}

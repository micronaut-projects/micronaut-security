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
import io.micronaut.serde.annotation.Serdeable;
import org.jspecify.annotations.Nullable;

/**
 * One result in an RFC 7644 bulk response.
 *
 * @param method HTTP method
 * @param bulkId Request-local identifier
 * @param version Resulting resource version
 * @param location Resulting resource location
 * @param response Response body, required for failures
 * @param status HTTP status as a JSON string
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record ScimBulkResponseOperation(
    @Nullable ScimBulkMethod method,
    @Nullable String bulkId,
    @Nullable String version,
    @Nullable String location,
    @Nullable Object response,
    String status
) {
}

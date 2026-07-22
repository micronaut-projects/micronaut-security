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
 * One operation in an RFC 7644 bulk request.
 *
 * @param method HTTP method
 * @param bulkId Request-local identifier required for POST
 * @param version Conditional resource version
 * @param path Path relative to the SCIM service root
 * @param data POST, PUT, or PATCH request body
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record ScimBulkRequestOperation(
    @Nullable ScimBulkMethod method,
    @Nullable String bulkId,
    @Nullable String version,
    @Nullable String path,
    @Nullable Object data
) {
}

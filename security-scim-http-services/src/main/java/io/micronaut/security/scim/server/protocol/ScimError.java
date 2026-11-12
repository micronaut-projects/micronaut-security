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

import java.util.List;

/**
 * RFC 7644 error response body.
 *
 * @param schemas Message schema URIs
 * @param status HTTP status code represented as a decimal string
 * @param scimType Optional SCIM error keyword
 * @param detail Human-readable error description
 * @since 5.4.0
 */
@Serdeable
@Experimental
public record ScimError(
    List<String> schemas,
    String status,
    @Nullable ScimErrorType scimType,
    @Nullable String detail
) {
    /**
     * Creates an immutable SCIM error.
     *
     * @since 5.4.0
     */
    public ScimError {
        schemas = List.copyOf(schemas);
    }

    /**
     * Creates an error carrying the RFC 7644 error schema URI.
     *
     * @param status HTTP status code
     * @param scimType Optional SCIM error keyword
     * @param detail Human-readable error description
     * @return SCIM error
     * @since 5.4.0
     */
    public static ScimError of(int status, @Nullable ScimErrorType scimType, @Nullable String detail) {
        return new ScimError(List.of(ScimMessageSchemas.ERROR), Integer.toString(status), scimType, detail);
    }
}

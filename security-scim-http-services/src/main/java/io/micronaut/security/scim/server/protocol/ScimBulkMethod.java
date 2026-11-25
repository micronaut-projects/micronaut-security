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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;

import java.util.Arrays;

/**
 * HTTP methods allowed within an RFC 7644 bulk request.
 *
 * @since 5.4.0
 */
@Serdeable
@Experimental
public enum ScimBulkMethod {
    /** Create. */
    POST,
    /** Replace. */
    PUT,
    /** Partial update. */
    PATCH,
    /** Delete. */
    DELETE;

    /**
     * @return Uppercase HTTP method
     * @since 5.4.0
     */
    @JsonValue
    public String getValue() {
        return name();
    }

    /**
     * @param value HTTP method
     * @return The corresponding bulk method
     * @since 5.4.0
     */
    @JsonCreator
    public static ScimBulkMethod fromValue(String value) {
        return Arrays.stream(values())
            .filter(method -> method.name().equalsIgnoreCase(value))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Unsupported SCIM bulk method: " + value));
    }
}

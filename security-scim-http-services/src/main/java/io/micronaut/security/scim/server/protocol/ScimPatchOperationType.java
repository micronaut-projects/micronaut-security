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
 * RFC 7644 PATCH operation type.
 *
 * @since 5.4.0
 */
@Serdeable
@Experimental
public enum ScimPatchOperationType {
    /** Add a value. */
    ADD("add"),
    /** Remove a value. */
    REMOVE("remove"),
    /** Replace a value. */
    REPLACE("replace");

    private final String value;

    ScimPatchOperationType(String value) {
        this.value = value;
    }

    /**
     * @return The RFC wire value
     * @since 5.4.0
     */
    @JsonValue
    public String getValue() {
        return value;
    }

    /**
     * @param value The RFC wire value
     * @return The corresponding operation type
     * @since 5.4.0
     */
    @JsonCreator
    public static ScimPatchOperationType fromValue(String value) {
        return Arrays.stream(values())
            .filter(operation -> operation.value.equalsIgnoreCase(value))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Unknown SCIM PATCH operation: " + value));
    }
}

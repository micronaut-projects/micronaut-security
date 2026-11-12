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
package io.micronaut.security.scim.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.serde.annotation.Serdeable;

import java.util.Arrays;

/**
 * SCIM attribute data types.
 *
 * @since 5.4.0
 */
@Serdeable
@Experimental
public enum AttributeType {
    /** A Unicode string. */
    STRING("string"),
    /** A Boolean. */
    BOOLEAN("boolean"),
    /** A decimal JSON number. */
    DECIMAL("decimal"),
    /** An integer JSON number. */
    INTEGER("integer"),
    /** An xsd:dateTime string. */
    DATE_TIME("dateTime"),
    /** Base64-encoded binary data. */
    BINARY("binary"),
    /** A resource URI. */
    REFERENCE("reference"),
    /** An object composed of sub-attributes. */
    COMPLEX("complex");

    private final String value;

    AttributeType(String value) {
        this.value = value;
    }

    /**
     * Returns the described SCIM value.
     *
     * @return The RFC 7643 wire value
     * @since 5.4.0
     */
    @JsonValue
    public String getValue() {
        return value;
    }

    /**
     * Resolves an RFC 7643 wire value.
     *
     * @param value The wire value
     * @return The corresponding type
     * @since 5.4.0
     */
    @JsonCreator
    public static AttributeType fromValue(String value) {
        return Arrays.stream(values())
            .filter(type -> type.value.equals(value))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Unknown SCIM attribute type: " + value));
    }
}

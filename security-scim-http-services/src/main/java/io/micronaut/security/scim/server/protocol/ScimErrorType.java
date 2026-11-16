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
 * RFC 7644 SCIM error keywords.
 *
 * @since 5.4.0
 */
@Serdeable
@Experimental
public enum ScimErrorType {
    /** The specified filter syntax is invalid or the filter is unknown. */
    INVALID_FILTER("invalidFilter"),
    /** The requested result set is too large. */
    TOO_MANY("tooMany"),
    /** An attribute value violates a uniqueness constraint. */
    UNIQUENESS("uniqueness"),
    /** The request attempts to change an attribute whose mutability forbids the change. */
    MUTABILITY("mutability"),
    /** The request body is syntactically invalid. */
    INVALID_SYNTAX("invalidSyntax"),
    /** A PATCH path is invalid or unsupported. */
    INVALID_PATH("invalidPath"),
    /** A PATCH path did not select a target. */
    NO_TARGET("noTarget"),
    /** An attribute value is invalid. */
    INVALID_VALUE("invalidValue"),
    /** The requested protocol or schema version is unsupported. */
    INVALID_VERSION("invalidVers"),
    /** The requested attribute is sensitive and cannot be returned. */
    SENSITIVE("sensitive");

    private final String value;

    ScimErrorType(String value) {
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
     * @return The corresponding error type
     * @since 5.4.0
     */
    @JsonCreator
    public static ScimErrorType fromValue(String value) {
        return Arrays.stream(values())
            .filter(type -> type.value.equals(value))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Unknown SCIM error type: " + value));
    }
}

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
 * Circumstances under which a SCIM attribute may be defined or changed.
 *
 * @since 5.4.0
 */
@Serdeable
@Experimental
public enum Mutability {
    /** The attribute cannot be modified. */
    READ_ONLY("readOnly"),
    /** The attribute can be read and updated. */
    READ_WRITE("readWrite"),
    /** The attribute can be set on creation or replacement but cannot later be updated. */
    IMMUTABLE("immutable"),
    /** The attribute can be updated but cannot be returned. */
    WRITE_ONLY("writeOnly");

    private final String value;

    Mutability(String value) {
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
     * @return The corresponding mutability
     * @since 5.4.0
     */
    @JsonCreator
    public static Mutability fromValue(String value) {
        return Arrays.stream(values())
            .filter(mutability -> mutability.value.equals(value))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Unknown SCIM mutability: " + value));
    }
}

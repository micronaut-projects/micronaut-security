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
package io.micronaut.security.ojdbc.extensions;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.Internal;
import oracle.sql.json.OracleJsonException;
import oracle.sql.json.OracleJsonObject;
import oracle.sql.json.OracleJsonValue;

/**
 * Utility methods for validating Oracle JSON values used by OJDBC provider configuration.
 */
@Experimental
@Internal
final class JsonUtils {

    private JsonUtils() {
    }

    /**
     * Requires an Oracle JSON value to be a JSON object.
     *
     * <p>This method does not parse or convert arbitrary JSON values. It only
     * verifies that the supplied Oracle JSON value is present and has the
     * {@link OracleJsonValue.OracleJsonType#OBJECT} type. Arrays, scalar values,
     * and JSON null values are rejected.
     *
     * @param name name used to identify the value in exception messages
     * @param value Oracle JSON value to validate
     *
     * @return the value as an {@link OracleJsonObject}
     *
     * @throws IllegalArgumentException if {@code value} is {@code null}
     * @throws OracleJsonException if {@code value} is not a JSON object
     */
    static OracleJsonObject requireJsonObject(String name, OracleJsonValue value) {
        if (value == null) {
            throw new IllegalArgumentException("Value of \"" + name + "\" is null");
        }
        if (value.getOracleJsonType() != OracleJsonValue.OracleJsonType.OBJECT) {
            throw new OracleJsonException("Value of " + name + " is a " + value.getOracleJsonType() + ". A JSON object is required.");
        }
        return value.asJsonObject();
    }
}

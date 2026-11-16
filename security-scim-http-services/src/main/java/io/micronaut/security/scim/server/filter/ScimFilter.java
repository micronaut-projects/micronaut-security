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
package io.micronaut.security.scim.server.filter;

import io.micronaut.core.annotation.Experimental;

import java.util.Arrays;

/**
 * Parsed RFC 7644 filter expression. Applications can translate this syntax tree into
 * persistence-native predicates without depending on a particular database technology.
 *
 * @since 5.4.0
 */
@Experimental
public sealed interface ScimFilter permits ScimFilter.Comparison, ScimFilter.Presence,
    ScimFilter.Logical, ScimFilter.Not, ScimFilter.ValuePath {

    /**
     * Attribute comparison.
     *
     * @param attributePath Attribute path
     * @param operator Comparison operator
     * @param value Comparison value
     * @since 5.4.0
     */
    @Experimental
    record Comparison(String attributePath, ComparisonOperator operator, Value value) implements ScimFilter {
    }

    /**
     * Attribute presence expression.
     *
     * @param attributePath Attribute path
     * @since 5.4.0
     */
    @Experimental
    record Presence(String attributePath) implements ScimFilter {
    }

    /**
     * Binary logical expression.
     *
     * @param left Left expression
     * @param operator Logical operator
     * @param right Right expression
     * @since 5.4.0
     */
    @Experimental
    record Logical(ScimFilter left, LogicalOperator operator, ScimFilter right) implements ScimFilter {
    }

    /**
     * Negated expression.
     *
     * @param filter Negated filter
     * @since 5.4.0
     */
    @Experimental
    record Not(ScimFilter filter) implements ScimFilter {
    }

    /**
     * Filter applied to the values of a multi-valued attribute.
     *
     * @param attributePath Multi-valued attribute path
     * @param filter Filter evaluated against each value
     * @since 5.4.0
     */
    @Experimental
    record ValuePath(String attributePath, ScimFilter filter) implements ScimFilter {
    }

    /**
     * RFC 7644 comparison operators.
     *
     * @since 5.4.0
     */
    @Experimental
    enum ComparisonOperator {
        /** Equal. */
        EQUAL("eq"),
        /** Not equal. */
        NOT_EQUAL("ne"),
        /** Contains. */
        CONTAINS("co"),
        /** Starts with. */
        STARTS_WITH("sw"),
        /** Ends with. */
        ENDS_WITH("ew"),
        /** Greater than. */
        GREATER_THAN("gt"),
        /** Greater than or equal. */
        GREATER_THAN_OR_EQUAL("ge"),
        /** Less than. */
        LESS_THAN("lt"),
        /** Less than or equal. */
        LESS_THAN_OR_EQUAL("le");

        private final String value;

        ComparisonOperator(String value) {
            this.value = value;
        }

        /**
         * @return The RFC wire value
         * @since 5.4.0
         */
        public String getValue() {
            return value;
        }

        static ComparisonOperator fromValue(String value) {
            return Arrays.stream(values())
                .filter(operator -> operator.value.equalsIgnoreCase(value))
                .findFirst()
                .orElseThrow(() -> new ScimFilterException("Unknown comparison operator: " + value));
        }
    }

    /**
     * RFC 7644 logical operators.
     *
     * @since 5.4.0
     */
    @Experimental
    enum LogicalOperator {
        /** Both operands must match. */
        AND,
        /** Either operand may match. */
        OR
    }

    /**
     * Filter comparison value.
     *
     * @param type JSON-compatible value type
     * @param value Decoded lexical value; {@code null} for the JSON null literal
     * @since 5.4.0
     */
    @Experimental
    record Value(ValueType type, @org.jspecify.annotations.Nullable String value) {
    }

    /**
     * JSON-compatible types allowed in an RFC 7644 filter.
     *
     * @since 5.4.0
     */
    @Experimental
    enum ValueType {
        /** JSON string. */
        STRING,
        /** JSON number. */
        NUMBER,
        /** JSON boolean. */
        BOOLEAN,
        /** JSON null. */
        NULL
    }
}

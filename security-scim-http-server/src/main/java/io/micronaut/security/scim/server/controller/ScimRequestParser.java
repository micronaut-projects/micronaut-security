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
package io.micronaut.security.scim.server.controller;

import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.security.scim.server.configuration.ScimServerConfiguration;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.filter.ScimFilter;
import io.micronaut.security.scim.server.filter.ScimFilterException;
import io.micronaut.security.scim.server.filter.ScimFilterParser;
import io.micronaut.security.scim.server.model.ScimAttributeSelection;
import io.micronaut.security.scim.server.model.ScimQuery;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import io.micronaut.security.scim.server.protocol.ScimBulkMethod;
import io.micronaut.security.scim.server.protocol.ScimBulkRequest;
import io.micronaut.security.scim.server.protocol.ScimBulkRequestOperation;
import io.micronaut.security.scim.server.protocol.ScimErrorType;
import io.micronaut.security.scim.server.protocol.ScimMessageSchemas;
import io.micronaut.security.scim.server.protocol.ScimPatchOperation;
import io.micronaut.security.scim.server.protocol.ScimPatchOperationType;
import io.micronaut.security.scim.server.protocol.ScimPatchRequest;
import io.micronaut.security.scim.server.protocol.ScimSearchRequest;
import io.micronaut.security.scim.server.protocol.ScimSortOrder;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

@Internal
@Singleton
final class ScimRequestParser {
    private final ScimFilterParser filterParser;
    private final ScimServerConfiguration configuration;

    ScimRequestParser(ScimFilterParser filterParser, ScimServerConfiguration configuration) {
        this.filterParser = filterParser;
        this.configuration = configuration;
    }

    ScimQuery query(
        @Nullable String attributes,
        @Nullable String excludedAttributes,
        @Nullable String filter,
        @Nullable String sortBy,
        @Nullable ScimSortOrder sortOrder,
        @Nullable Integer startIndex,
        @Nullable Integer count
    ) {
        return query(selection(attributes, excludedAttributes), filter, sortBy, sortOrder, startIndex, count);
    }

    ScimQuery query(ScimSearchRequest request) {
        requireSchema(request.schemas(), ScimMessageSchemas.SEARCH_REQUEST, "search request");
        return query(
            selection(copy(request.attributes()), copy(request.excludedAttributes())),
            request.filter(),
            request.sortBy(),
            request.sortOrder(),
            request.startIndex(),
            request.count()
        );
    }

    ScimAttributeSelection selection(@Nullable String attributes, @Nullable String excludedAttributes) {
        return selection(split(attributes), split(excludedAttributes));
    }

    ScimRequestContext context(HttpRequest<?> request, ScimAttributeSelection selection) {
        return new ScimRequestContext(request, selection, request.getHeaders().get(HttpHeaders.IF_MATCH));
    }

    void validate(ScimPatchRequest request) {
        requireSchema(request.schemas(), ScimMessageSchemas.PATCH_OPERATION, "PATCH request");
        List<ScimPatchOperation> operations = request.operations();
        if (operations == null || operations.isEmpty()) {
            throw invalidSyntax("A PATCH request must contain at least one operation");
        }
        for (ScimPatchOperation operation : operations) {
            if (operation == null || operation.op() == null) {
                throw invalidSyntax("Every PATCH operation must specify op");
            }
            if (operation.path() != null && operation.path().isBlank()) {
                throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_PATH,
                    "A PATCH path must not be blank");
            }
            if (operation.op() == ScimPatchOperationType.REMOVE && operation.path() == null) {
                throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.NO_TARGET,
                    "A remove operation must specify path");
            }
            if (operation.op() != ScimPatchOperationType.REMOVE && operation.value() == null) {
                throw invalidValue("An add or replace operation must specify value");
            }
        }
    }

    void validate(ScimBulkRequest request) {
        requireSchema(request.schemas(), ScimMessageSchemas.BULK_REQUEST, "bulk request");
        if (request.failOnErrors() != null && request.failOnErrors() < 0) {
            throw invalidValue("failOnErrors must not be negative");
        }
        List<ScimBulkRequestOperation> operations = request.operations();
        if (operations == null || operations.isEmpty()) {
            throw invalidSyntax("A bulk request must contain at least one operation");
        }
        Set<String> bulkIds = new HashSet<>();
        for (ScimBulkRequestOperation operation : operations) {
            if (operation == null || operation.method() == null) {
                throw invalidSyntax("Every bulk operation must specify method");
            }
            if (operation.path() == null || operation.path().isBlank()) {
                throw invalidValue("Every bulk operation must specify path");
            }
            if (operation.method() == ScimBulkMethod.POST) {
                if (operation.bulkId() == null || operation.bulkId().isBlank()) {
                    throw invalidValue("Every POST bulk operation must specify bulkId");
                }
                if (!bulkIds.add(operation.bulkId())) {
                    throw invalidValue("POST bulkId values must be unique within a request");
                }
            }
            if (operation.method() != ScimBulkMethod.DELETE && operation.data() == null) {
                throw invalidValue("POST, PUT, and PATCH bulk operations must specify data");
            }
        }
    }

    private ScimQuery query(
        ScimAttributeSelection selection,
        @Nullable String filter,
        @Nullable String sortBy,
        @Nullable ScimSortOrder sortOrder,
        @Nullable Integer startIndex,
        @Nullable Integer count
    ) {
        int normalizedStartIndex = startIndex == null || startIndex < 1 ? 1 : startIndex;
        int normalizedCount = count == null ? configuration.getDefaultPageSize() : count;
        if (normalizedCount < 0) {
            normalizedCount = 0;
        }
        normalizedCount = Math.min(normalizedCount, configuration.getMaxPageSize());
        String normalizedFilter = normalize(filter);
        String normalizedSortBy = normalize(sortBy);
        ScimFilter parsedFilter = null;
        if (normalizedFilter != null) {
            try {
                parsedFilter = filterParser.parse(normalizedFilter);
            } catch (ScimFilterException exception) {
                throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_FILTER,
                    exception.getMessage());
            }
        }
        return new ScimQuery(selection, parsedFilter, normalizedFilter, normalizedSortBy,
            sortOrder == null ? ScimSortOrder.ASCENDING : sortOrder,
            normalizedStartIndex, normalizedCount);
    }

    private static ScimAttributeSelection selection(List<String> attributes, List<String> excludedAttributes) {
        if (!attributes.isEmpty() && !excludedAttributes.isEmpty()) {
            throw invalidValue("attributes and excludedAttributes are mutually exclusive");
        }
        return new ScimAttributeSelection(attributes, excludedAttributes);
    }

    private static List<String> split(@Nullable String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split(","))
            .map(String::trim)
            .filter(part -> !part.isEmpty())
            .distinct()
            .toList();
    }

    private static List<String> copy(@Nullable List<String> values) {
        if (values == null) {
            return List.of();
        }
        return values.stream()
            .filter(Objects::nonNull)
            .map(String::trim)
            .filter(value -> !value.isEmpty())
            .distinct()
            .toList();
    }

    private static void requireSchema(@Nullable List<String> schemas, String schema, String messageName) {
        if (schemas == null || !schemas.contains(schema)) {
            throw invalidSyntax("The " + messageName + " schemas attribute must contain " + schema);
        }
    }

    @Nullable
    private static String normalize(@Nullable String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static ScimException invalidSyntax(String detail) {
        return new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_SYNTAX, detail);
    }

    private static ScimException invalidValue(String detail) {
        return new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_VALUE, detail);
    }
}

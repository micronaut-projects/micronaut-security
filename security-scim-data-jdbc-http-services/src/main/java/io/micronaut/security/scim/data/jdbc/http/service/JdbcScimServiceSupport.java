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
package io.micronaut.security.scim.data.jdbc.http.service;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpStatus;
import io.micronaut.json.JsonMapper;
import io.micronaut.security.scim.core.Meta;
import io.micronaut.security.scim.core.SchemaUris;
import io.micronaut.security.scim.core.ScimResource;
import io.micronaut.security.scim.core.User;
import io.micronaut.security.scim.data.entities.ScimResourceExtensionEntity;
import io.micronaut.security.scim.data.entities.ScimResourceType;
import io.micronaut.security.scim.data.jdbc.repositories.ScimResourceExtensionJdbcRepository;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.filter.ScimFilter;
import io.micronaut.security.scim.server.filter.ScimFilterException;
import io.micronaut.security.scim.server.filter.ScimFilterParser;
import io.micronaut.security.scim.server.model.ScimRequestContext;
import io.micronaut.security.scim.server.model.ScimResourceResponse;
import io.micronaut.security.scim.server.protocol.ScimErrorType;
import io.micronaut.security.scim.server.protocol.ScimPatchOperation;
import io.micronaut.security.scim.server.protocol.ScimPatchOperationType;
import io.micronaut.security.scim.server.protocol.ScimPatchRequest;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Internal
final class JdbcScimServiceSupport {
    private static final Argument<Map<String, Object>> MAP_ARGUMENT = Argument.mapOf(String.class, Object.class);

    private JdbcScimServiceSupport() {
    }

    static <T extends ScimResource> ScimResourceResponse<T> response(
        T resource,
        String resourceType,
        @Nullable Instant created,
        @Nullable Instant lastModified,
        @Nullable Long version,
        String collection,
        ScimRequestContext context
    ) {
        URI location = location(context, collection, requiredId(resource));
        String etag = etag(version);
        resource.setMeta(new Meta(
            resourceType,
            created == null ? null : created.toString(),
            lastModified == null ? null : lastModified.toString(),
            location.toString(),
            etag
        ));
        return new ScimResourceResponse<>(resource, location, etag);
    }

    static void verifyIfMatch(@Nullable String ifMatch, @Nullable Long version) {
        if (ifMatch == null) {
            return;
        }
        String current = etag(version);
        if ("*".equals(ifMatch.trim()) || current != null && anyTagMatches(ifMatch, current)) {
            return;
        }
        throw new ScimException(HttpStatus.PRECONDITION_FAILED, "The supplied If-Match value is stale");
    }

    static void storeExtensions(
        ScimResource resource,
        ScimResourceType resourceType,
        String resourceId,
        ScimResourceExtensionJdbcRepository repository,
        JsonMapper jsonMapper
    ) {
        repository.deleteByResourceTypeAndResourceId(resourceType, resourceId);
        for (Map.Entry<String, Object> entry : resource.getExtensions().entrySet()) {
            try {
                repository.save(new ScimResourceExtensionEntity(
                    null,
                    resourceType,
                    resourceId,
                    entry.getKey(),
                    jsonMapper.writeValueAsString(entry.getValue())
                ));
            } catch (IOException e) {
                throw invalidValue("Cannot serialize extension " + entry.getKey(), e);
            }
        }
    }

    static void loadExtensions(
        ScimResource resource,
        ScimResourceType resourceType,
        String resourceId,
        ScimResourceExtensionJdbcRepository repository,
        JsonMapper jsonMapper
    ) {
        for (ScimResourceExtensionEntity extension :
            repository.findAllByResourceTypeAndResourceId(resourceType, resourceId)) {
            try {
                resource.setExtension(extension.schemaUri(), jsonMapper.readValue(extension.extensionJson(), Object.class));
            } catch (IOException e) {
                throw invalidValue("Cannot deserialize extension " + extension.schemaUri(), e);
            }
        }
    }

    static <T extends ScimResource> T applyPatch(
        T current,
        ScimPatchRequest request,
        Argument<T> resourceType,
        JsonMapper jsonMapper,
        ScimFilterParser filterParser
    ) {
        try {
            Map<String, Object> document = jsonMapper.readValue(jsonMapper.writeValueAsBytes(current), MAP_ARGUMENT);
            if (request.operations() == null) {
                throw invalidValue("A PATCH request must contain operations");
            }
            for (ScimPatchOperation operation : request.operations()) {
                applyOperation(document, operation, current instanceof User, filterParser);
            }
            T patched = jsonMapper.readValue(jsonMapper.writeValueAsBytes(document), resourceType);
            patched.setId(current.getId());
            patched.setMeta(current.getMeta());
            if (patched instanceof User patchedUser && current instanceof User currentUser) {
                patchedUser.setGroups(currentUser.getGroups());
            }
            normalizeSchemas(patched);
            return patched;
        } catch (IOException e) {
            throw invalidValue("Cannot apply the PATCH request", e);
        }
    }

    private static void applyOperation(
        Map<String, Object> document,
        ScimPatchOperation operation,
        boolean userResource,
        ScimFilterParser filterParser
    ) {
        if (operation.op() == null) {
            throw invalidValue("Every PATCH operation must specify op");
        }
        if (operation.path() == null) {
            if (operation.op() == ScimPatchOperationType.REMOVE || !(operation.value() instanceof Map<?, ?> values)) {
                throw invalidPath("A path-less add or replace operation must contain an object value");
            }
            for (Map.Entry<?, ?> entry : values.entrySet()) {
                if (!(entry.getKey() instanceof String key)) {
                    throw invalidValue("PATCH object attribute names must be strings");
                }
                applyOperation(document,
                    new ScimPatchOperation(operation.op(), key, entry.getValue()),
                    userResource,
                    filterParser);
            }
            return;
        }
        PatchPath path = resolvePath(document, operation.path(), filterParser);
        verifyMutable(path.attribute(), userResource);
        ScimPatchOperation normalizedOperation = normalizeManagerOperation(path, operation, userResource);
        if (path.filter() != null) {
            applyFiltered(document, path, normalizedOperation);
            return;
        }
        if (path.subAttribute() == null) {
            applyToMap(document, path.attribute(), normalizedOperation);
            return;
        }
        Object value = getCaseInsensitive(document, path.attribute());
        if (value instanceof List<?>) {
            throw invalidPath("A multi-valued sub-attribute PATCH path requires a value filter: "
                + operation.path());
        }
        if (!(value instanceof Map<?, ?> existing)) {
            if (normalizedOperation.op() == ScimPatchOperationType.REMOVE) {
                throw noTarget(operation.path());
            }
            Map<String, Object> nested = new LinkedHashMap<>();
            putCaseInsensitive(document, path.attribute(), nested);
            applyToMap(nested, path.subAttribute(), normalizedOperation);
            return;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> nested = (Map<String, Object>) existing;
        applyToMap(nested, path.subAttribute(), normalizedOperation);
    }

    private static void applyFiltered(
        Map<String, Object> document,
        PatchPath path,
        ScimPatchOperation operation
    ) {
        Object target = getCaseInsensitive(document, path.attribute());
        List<?> values;
        if (target == null) {
            values = List.of();
        } else if (target instanceof List<?> list) {
            values = list;
        } else {
            throw invalidPath("A PATCH value-selection filter requires a multi-valued attribute: "
                + operation.path());
        }

        List<Object> updated = new ArrayList<>(values.size() + 1);
        boolean matched = false;
        for (Object value : values) {
            if (!JdbcScimQueryProcessor.matches(value, path.filter())) {
                updated.add(value);
                continue;
            }
            matched = true;
            if (operation.op() == ScimPatchOperationType.REMOVE) {
                continue;
            }
            if (path.subAttribute() != null) {
                if (!(value instanceof Map<?, ?> mapValue)) {
                    throw invalidPath("The PATCH path selects a non-complex value: " + operation.path());
                }
                Map<String, Object> mutableValue = mutableMap(mapValue);
                applyToMap(mutableValue, path.subAttribute(), operation);
                updated.add(mutableValue);
            } else if (operation.op() == ScimPatchOperationType.ADD
                && value instanceof Map<?, ?> mapValue
                && operation.value() instanceof Map<?, ?> additions) {
                Map<String, Object> mutableValue = mutableMap(mapValue);
                additions.forEach((key, addition) ->
                    putCaseInsensitive(mutableValue, String.valueOf(key), addition));
                updated.add(mutableValue);
            } else {
                updated.add(operation.value());
            }
        }

        if (!matched) {
            if (operation.op() == ScimPatchOperationType.REMOVE) {
                return;
            }
            if (operation.op() == ScimPatchOperationType.REPLACE) {
                throw noTarget(operation.path());
            }
            updated.add(createFilteredValue(path, operation));
        }
        putCaseInsensitive(document, path.attribute(), updated);
    }

    private static Object createFilteredValue(PatchPath path, ScimPatchOperation operation) {
        Map<String, Object> value = new LinkedHashMap<>();
        if (!seedFromFilter(value, path.filter())) {
            throw invalidPath("Cannot add a value for PATCH filter " + operation.path()
                + "; creation requires equality conditions");
        }
        if (path.subAttribute() != null) {
            applyToMap(value, path.subAttribute(), operation);
            return value;
        }
        if (operation.value() instanceof Map<?, ?> additions) {
            additions.forEach((key, addition) -> putCaseInsensitive(value, String.valueOf(key), addition));
            return value;
        }
        return operation.value();
    }

    private static boolean seedFromFilter(Map<String, Object> target, ScimFilter filter) {
        if (filter instanceof ScimFilter.Comparison comparison
            && comparison.operator() == ScimFilter.ComparisonOperator.EQUAL) {
            putPath(target, comparison.attributePath(), filterValue(comparison.value()));
            return true;
        }
        if (filter instanceof ScimFilter.Logical logical
            && logical.operator() == ScimFilter.LogicalOperator.AND) {
            return seedFromFilter(target, logical.left()) && seedFromFilter(target, logical.right());
        }
        return false;
    }

    private static void putPath(Map<String, Object> target, String path, @Nullable Object value) {
        String[] segments = path.split("\\.");
        Map<String, Object> current = target;
        for (int index = 0; index < segments.length - 1; index++) {
            Object existing = getCaseInsensitive(current, segments[index]);
            if (existing instanceof Map<?, ?> existingMap) {
                Map<String, Object> mutable = mutableMap(existingMap);
                putCaseInsensitive(current, segments[index], mutable);
                current = mutable;
            } else {
                Map<String, Object> nested = new LinkedHashMap<>();
                putCaseInsensitive(current, segments[index], nested);
                current = nested;
            }
        }
        putCaseInsensitive(current, segments[segments.length - 1], value);
    }

    @Nullable
    private static Object filterValue(ScimFilter.Value value) {
        return switch (value.type()) {
            case STRING -> value.value();
            case BOOLEAN -> Boolean.valueOf(value.value());
            case NUMBER -> value.value() == null ? null : new BigDecimal(value.value());
            case NULL -> null;
        };
    }

    private static Map<String, Object> mutableMap(Map<?, ?> source) {
        Map<String, Object> result = new LinkedHashMap<>();
        source.forEach((key, value) -> result.put(String.valueOf(key), value));
        return result;
    }

    private static void applyToMap(Map<String, Object> target, String key, ScimPatchOperation operation) {
        String existingKey = findKey(target, key);
        if (operation.op() == ScimPatchOperationType.REMOVE) {
            if (existingKey == null) {
                throw noTarget(key);
            }
            target.remove(existingKey);
            return;
        }
        Object current = existingKey == null ? null : target.get(existingKey);
        if (operation.op() == ScimPatchOperationType.ADD && current instanceof List<?> values) {
            List<Object> appended = new ArrayList<>(values);
            if (operation.value() instanceof List<?> additions) {
                appended.addAll(additions);
            } else {
                appended.add(operation.value());
            }
            putCaseInsensitive(target, key, appended);
        } else if (operation.op() == ScimPatchOperationType.ADD
            && current instanceof Map<?, ?> currentMap
            && operation.value() instanceof Map<?, ?> additions) {
            Map<String, Object> merged = new LinkedHashMap<>();
            currentMap.forEach((mapKey, mapValue) -> merged.put(String.valueOf(mapKey), mapValue));
            additions.forEach((mapKey, mapValue) -> putCaseInsensitive(merged, String.valueOf(mapKey), mapValue));
            putCaseInsensitive(target, key, merged);
        } else {
            putCaseInsensitive(target, key, operation.value());
        }
    }

    private static PatchPath resolvePath(
        Map<String, Object> document,
        String requestedPath,
        ScimFilterParser filterParser
    ) {
        String path = requestedPath.trim();
        if (path.isEmpty()) {
            throw invalidPath("A PATCH path must not be empty");
        }
        int filterStart = path.indexOf('[');
        if (filterStart < 0) {
            return resolveUnfilteredPath(document, path);
        }
        int filterEnd = findFilterEnd(path, filterStart);
        if (filterEnd < 0) {
            throw invalidPath("The PATCH path has an unterminated value-selection filter: " + requestedPath);
        }
        PatchPath attribute = resolveUnfilteredPath(document, path.substring(0, filterStart).trim());
        if (attribute.subAttribute() != null) {
            throw invalidPath("A value-selection filter must immediately follow a multi-valued attribute: "
                + requestedPath);
        }
        String suffix = path.substring(filterEnd + 1).trim();
        String subAttribute = null;
        if (!suffix.isEmpty()) {
            if (suffix.charAt(0) != '.' || suffix.length() == 1 || suffix.indexOf('.', 1) >= 0
                || suffix.indexOf('[', 1) >= 0 || suffix.indexOf(']', 1) >= 0) {
                throw invalidPath("Invalid sub-attribute after PATCH value-selection filter: " + requestedPath);
            }
            subAttribute = suffix.substring(1);
        }
        try {
            ScimFilter filter = filterParser.parse(path.substring(filterStart + 1, filterEnd));
            return new PatchPath(attribute.attribute(), filter, subAttribute);
        } catch (ScimFilterException e) {
            throw invalidPath("Invalid PATCH value-selection filter in path " + requestedPath, e);
        }
    }

    private static PatchPath resolveUnfilteredPath(Map<String, Object> document, String path) {
        if (path.isBlank()) {
            throw invalidPath("A PATCH path must name an attribute");
        }
        for (String key : document.keySet()) {
            if (path.equalsIgnoreCase(key)) {
                return new PatchPath(key, null, null);
            }
            String prefix = key + ':';
            if (path.regionMatches(true, 0, prefix, 0, prefix.length())) {
                String remainder = path.substring(prefix.length());
                return new PatchPath(key, null, remainder.isBlank() ? null : remainder);
            }
        }
        String userPrefix = SchemaUris.USER + ':';
        if (path.regionMatches(true, 0, userPrefix, 0, userPrefix.length())) {
            return resolveUnfilteredPath(document, path.substring(userPrefix.length()));
        }
        String groupPrefix = SchemaUris.GROUP + ':';
        if (path.regionMatches(true, 0, groupPrefix, 0, groupPrefix.length())) {
            return resolveUnfilteredPath(document, path.substring(groupPrefix.length()));
        }
        int schemaSeparator = path.lastIndexOf(':');
        if (schemaSeparator > 0) {
            String schema = path.substring(0, schemaSeparator);
            try {
                if (new URI(schema).isAbsolute()) {
                    return new PatchPath(schema, null, path.substring(schemaSeparator + 1));
                }
            } catch (URISyntaxException ignored) {
                // The path is handled as an unqualified attribute below.
            }
        }
        int dot = path.indexOf('.');
        if (dot > 0) {
            return new PatchPath(path.substring(0, dot), null, path.substring(dot + 1));
        }
        return new PatchPath(path, null, null);
    }

    private static int findFilterEnd(String path, int filterStart) {
        int depth = 0;
        boolean quoted = false;
        boolean escaped = false;
        for (int index = filterStart; index < path.length(); index++) {
            char character = path.charAt(index);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (quoted && character == '\\') {
                escaped = true;
                continue;
            }
            if (character == '"') {
                quoted = !quoted;
                continue;
            }
            if (quoted) {
                continue;
            }
            if (character == '[') {
                depth++;
            } else if (character == ']' && --depth == 0) {
                return index;
            }
        }
        return -1;
    }

    private static ScimPatchOperation normalizeManagerOperation(
        PatchPath path,
        ScimPatchOperation operation,
        boolean userResource
    ) {
        if (!userResource || !path.attribute().equalsIgnoreCase(SchemaUris.ENTERPRISE_USER)
            || path.subAttribute() == null || !path.subAttribute().equalsIgnoreCase("manager")
            || !(operation.value() instanceof String managerValue)) {
            return operation;
        }
        if (managerValue.isBlank()) {
            return new ScimPatchOperation(ScimPatchOperationType.REMOVE, operation.path(), null);
        }
        return new ScimPatchOperation(operation.op(), operation.path(), Map.of("value", managerValue));
    }

    private static void verifyMutable(String attribute, boolean userResource) {
        String normalized = attribute.toLowerCase(Locale.ROOT);
        if (normalized.equals("id") || normalized.equals("meta") || normalized.equals("schemas")
            || userResource && normalized.equals("groups")) {
            throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.MUTABILITY,
                "The " + attribute + " attribute is read-only");
        }
        if (userResource && normalized.equals("password")) {
            throw new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.SENSITIVE,
                "The JDBC adapter does not persist passwords; provide an application ScimUserService to handle them");
        }
    }

    private static void normalizeSchemas(ScimResource resource) {
        for (String schema : List.copyOf(resource.getSchemas())) {
            if (schema.equals(SchemaUris.USER) || schema.equals(SchemaUris.GROUP)) {
                continue;
            }
            if (schema.equals(SchemaUris.ENTERPRISE_USER)) {
                if (resource instanceof User user && user.getEnterpriseUser() == null) {
                    resource.removeSchema(schema);
                }
            } else if (!resource.getExtensions().containsKey(schema)) {
                resource.removeSchema(schema);
            }
        }
    }

    static URI location(ScimRequestContext context, String collection, String id) {
        URI requestUri = context.request().getUri();
        String path = requestUri.getPath();
        String collectionPath = '/' + collection;
        int marker = path.lastIndexOf(collectionPath);
        String base = marker < 0 ? path : path.substring(0, marker + collectionPath.length());
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        try {
            return new URI(requestUri.getScheme(), requestUri.getAuthority(), base + '/' + id, null, null);
        } catch (URISyntaxException e) {
            throw new ScimException(HttpStatus.INTERNAL_SERVER_ERROR, "Cannot construct the SCIM resource location");
        }
    }

    @Nullable
    private static String etag(@Nullable Long version) {
        return version == null ? null : "W/\"" + version + "\"";
    }

    private static boolean anyTagMatches(String supplied, String current) {
        String normalizedCurrent = weakValue(current);
        for (String candidate : supplied.split(",")) {
            if (weakValue(candidate.trim()).equals(normalizedCurrent)) {
                return true;
            }
        }
        return false;
    }

    private static String weakValue(String value) {
        return value.startsWith("W/") ? value.substring(2) : value;
    }

    private static String requiredId(ScimResource resource) {
        if (resource.getId() == null) {
            throw new ScimException(HttpStatus.INTERNAL_SERVER_ERROR, "A persisted SCIM resource has no id");
        }
        return resource.getId();
    }

    @Nullable
    private static Object getCaseInsensitive(Map<String, Object> values, String key) {
        String existing = findKey(values, key);
        return existing == null ? null : values.get(existing);
    }

    private static void putCaseInsensitive(Map<String, Object> values, String key, @Nullable Object value) {
        String existing = findKey(values, key);
        values.put(existing == null ? key : existing, value);
    }

    @Nullable
    private static String findKey(Map<String, Object> values, String key) {
        return values.keySet().stream().filter(candidate -> candidate.equalsIgnoreCase(key)).findFirst().orElse(null);
    }

    private static ScimException invalidPath(String detail) {
        return new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_PATH, detail);
    }

    private static ScimException invalidPath(String detail, RuntimeException cause) {
        ScimException exception = invalidPath(detail);
        exception.initCause(cause);
        return exception;
    }

    private static ScimException noTarget(String path) {
        return new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.NO_TARGET,
            "The PATCH path did not select a value: " + path);
    }

    private static ScimException invalidValue(String detail) {
        return new ScimException(HttpStatus.BAD_REQUEST, ScimErrorType.INVALID_VALUE, detail);
    }

    private static ScimException invalidValue(String detail, IOException cause) {
        ScimException exception = invalidValue(detail);
        exception.initCause(cause);
        return exception;
    }

    private record PatchPath(
        String attribute,
        @Nullable ScimFilter filter,
        @Nullable String subAttribute
    ) {
    }
}

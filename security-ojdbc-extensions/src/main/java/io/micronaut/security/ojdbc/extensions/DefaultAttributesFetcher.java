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
import io.micronaut.security.authentication.Authentication;
import oracle.jdbc.EndUserSecurityContext;
import oracle.jdbc.spi.OracleResourceProvider;
import oracle.sql.json.OracleJsonArray;
import oracle.sql.json.OracleJsonException;
import oracle.sql.json.OracleJsonFactory;
import oracle.sql.json.OracleJsonObject;
import oracle.sql.json.OracleJsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.io.StringReader;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.ATTRIBUTE_NAMES_PARAMETER;
import static io.micronaut.security.ojdbc.extensions.MicronautEndUserSecurityContextProvider.END_USER_CONTEXT_ATTRIBUTE_PARAMETER;

/**
 * Default {@link AttributesFetcher} implementation.
 *
 * @since 5.1.0
 */
@Experimental
@Internal
public class DefaultAttributesFetcher implements AttributesFetcher {
    private final OracleJsonFactory oracleJsonFactory;

    /**
     * @param oracleJsonFactory Oracle JSON factory
     * @since 5.1.0
     */
    DefaultAttributesFetcher(OracleJsonFactory oracleJsonFactory) {
        this.oracleJsonFactory = oracleJsonFactory;
    }

    @Override
    public @Nullable Map<String, OracleJsonObject> fetchAttributes(@NonNull Map<OracleResourceProvider.Parameter, CharSequence> parameters,
                                                            @NonNull Authentication authentication) {
        return fetchAttributes(getFixedAttributes(parameters), getAuthenticationNamedAttributes(parameters, authentication));
    }

    /**
     * If multiple maps contain the same key, then attributes in the map at the highest array index
     * overwrite those in maps of lower indices.
     * @param attributesMaps Attributes to add, not null, may not contain null.
     * @return merged attributes
     */
    @SafeVarargs
    private @Nullable Map<String, OracleJsonObject> fetchAttributes(Map<String, OracleJsonObject>... attributesMaps) {
        Map<String, OracleJsonObject> merged = null;

        for (Map<String, OracleJsonObject> attributes : attributesMaps) {
            merged = merge(merged, attributes);
        }
        return merged;
    }

    /**
     * Returns END USER CONTEXT attributes configured by the
     * {@link MicronautEndUserSecurityContextProvider#END_USER_CONTEXT_ATTRIBUTE_PARAMETER}.
     *
     * @param parameters Parameters that configure this provider. Not null, may
     * not contain null.
     *
     * @return Map of END USER CONTEXT attributes to set. Not null, may not
     * contain null.
     */
    private Map<String, OracleJsonObject> getFixedAttributes(Map<OracleResourceProvider.Parameter, CharSequence> parameters) {
        CharSequence fixedAttributes = parameters.get(END_USER_CONTEXT_ATTRIBUTE_PARAMETER);
        if (fixedAttributes == null || fixedAttributes.length() == 0) {
            return Collections.emptyMap();
        }
        return parseAttributes("attributes configured by the " + END_USER_CONTEXT_ATTRIBUTE_PARAMETER.name() + " parameter",
                fixedAttributes.toString());
    }

    /**
     * Parses a JSON string as a Map of END USER CONTEXT attributes which can be
     * passed to {@link EndUserSecurityContext#withAttributes(Map)}. The structure
     * of the JSON object passed to this method should contain END USER CONTEXT
     * names associated to JSON objects that contain attributes values, as in:
     * <pre>
     *   {
     *     "schema.context_name" : {
     *       "string_attribute" : "value",
     *       "integer_attribute" : 1,
     *     },
     *     "scott.user_info" : {
     *       "first_name" : "George",
     *       "last_name" : "Washington"
     *     }
     *   }
     * </pre>
     *
     * @param name Name to use in error messages if the jsonString cannot be
     * parsed. Not null.
     *
     * @param jsonString String to parse. May be null.
     *
     * @return Map of END USER CONTEXT attributes, not null.
     */
    private Map<String, OracleJsonObject> parseAttributes(String name, String jsonString) {
        if (jsonString == null || jsonString.isEmpty()) {
            return Collections.emptyMap();
        }
        return parseAttributes(name, parseJsonObject(name, jsonString));
    }

    private Map<String, OracleJsonObject> parseAttributes(String name, OracleJsonObject jsonObject) {
        HashMap<String, OracleJsonObject> attributes = new HashMap<>(jsonObject.size());
        for (Map.Entry<String, OracleJsonValue> entry : jsonObject.entrySet()) {
            String contextName = entry.getKey();
            OracleJsonObject attributeValues = JsonUtils.requireJsonObject(contextName + " within " + name, entry.getValue());
            attributes.put(contextName, attributeValues);
        }
        return attributes;
    }

    private OracleJsonObject parseJsonObject(String name, String jsonString) {
        final OracleJsonValue jsonValue;
        try {
            jsonValue = oracleJsonFactory.createJsonTextValue(new StringReader(jsonString));
        } catch (OracleJsonException oracleJsonException) {
            throw new IllegalArgumentException("Failed to parse JSON from " + name, oracleJsonException);
        }
        return JsonUtils.requireJsonObject(name, jsonValue);
    }

    /**
     * Merges JSON objects contained with maps.
     * <pre>{@code
     *   Map<String, OracleJsonObject> merged = merge(
     *     Map.of("key", toJSON("{\"a\" : 0, \"b\" : 0}")),
     *     Map.of("key", toJSON("{\"b\" : 1, \"c\" : 1}")));
     *
     *   // This is true:
     *   merged.equals(
     *     Map.of("key", toJSON("{\"a\" : 0, \"b\" : 1, \"c\" : 1}")));
     * }</pre>
     *
     * @param existing Map that contains JSON values which can be overwritten by
     * the current map. May be null, but may not contain null.
     *
     * @param current Map that contains JSON values which can overwrite those in
     * the existing map. May be null, but may not contain null.
     *
     * @return Map that contains all values in the existing map, plus those in
     * the current Map. Not null, may not contain null.
     */
    private static Map<String, OracleJsonObject> merge(
            Map<String, OracleJsonObject> existing,
            Map<String, OracleJsonObject> current) {

        if (existing == null || existing.isEmpty()) {
            return current == null
                    ? Collections.emptyMap()
                    : current;
        }
        if (current == null || current.isEmpty()) {
            return existing;
        }

        HashMap<String, OracleJsonObject> merged = new HashMap<>(existing);

        for (Map.Entry<String, OracleJsonObject> entry : current.entrySet()) {
            merged.merge(
                    entry.getKey(), entry.getValue(), (existingJson, currentJson) -> {
                        existingJson.putAll(currentJson);
                        return existingJson;
                    });
        }

        return merged;
    }

    /**
     * Returns END USER CONTEXT attributes derived from authentication attributes
     * whose names are configured by
     * {@link MicronautEndUserSecurityContextProvider#ATTRIBUTE_NAMES_PARAMETER}.
     *
     * @param parameters Parameters that configure this provider. Not null, may
     * not contain null.
     *
     * @return Map of END USER CONTEXT attributes to set. Not null, may not
     * contain null.
     */
    private Map<String, OracleJsonObject> getAuthenticationNamedAttributes(
            Map<OracleResourceProvider.Parameter, CharSequence> parameters,
            Authentication authentication) {

        CharSequence authenticationAttributeNames = parameters.get(ATTRIBUTE_NAMES_PARAMETER);
        if (authenticationAttributeNames == null || authenticationAttributeNames.length() == 0) {
            return Collections.emptyMap();
        }
        Map<String, Object> authenticationAttributes = authentication.getAttributes();
        Map<String, OracleJsonObject> attributes = null;
        for (String attributeName : Arrays.stream(authenticationAttributeNames.toString().split(","))
                .map(String::trim)
                .filter(name -> !name.isEmpty())
                .toList()) {
            if (!authenticationAttributes.containsKey(attributeName)) {
                continue;
            }
            attributes = merge(attributes, toAttributes(
                    "authentication attribute " + attributeName + " configured by the " + ATTRIBUTE_NAMES_PARAMETER.name() + " parameter",
                    authenticationAttributes.get(attributeName)));
        }
        return attributes == null ? Collections.emptyMap() : attributes;
    }

    private Map<String, OracleJsonObject> toAttributes(String name, @Nullable Object value) {
        if (value == null) {
            throw new IllegalArgumentException("Value of " + name + " is null. A JSON object is required.");
        }
        if (value instanceof OracleJsonObject jsonObject) {
            return parseAttributes(name, jsonObject);
        }
        if (value instanceof OracleJsonValue jsonValue) {
            return parseAttributes(name, JsonUtils.requireJsonObject(name, jsonValue));
        }
        if (value instanceof CharSequence charSequence) {
            return parseAttributes(name, charSequence.toString());
        }
        if (value instanceof Map<?, ?> map) {
            return toAttributes(name, map);
        }
        throw new IllegalArgumentException("Value of " + name + " is a " + value.getClass().getName() + ". A JSON object is required.");
    }

    private Map<String, OracleJsonObject> toAttributes(String name, Map<?, ?> map) {
        Map<String, OracleJsonObject> attributes = new HashMap<>(map.size());
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            Object key = entry.getKey();
            if (key == null) {
                throw new IllegalArgumentException("Key of " + name + " is null. A String is required.");
            }
            if (!(key instanceof String contextName)) {
                throw new IllegalArgumentException("Key of " + name + " is a " + key.getClass().getName() + ". A String is required.");
            }
            attributes.put(contextName, toAttributeValues(contextName + " within " + name, entry.getValue()));
        }
        return attributes;
    }

    private OracleJsonObject toAttributeValues(String name, @Nullable Object value) {
        if (value == null) {
            throw new IllegalArgumentException("Value of " + name + " is null. A JSON object is required.");
        }
        if (value instanceof OracleJsonObject jsonObject) {
            return jsonObject;
        }
        if (value instanceof OracleJsonValue jsonValue) {
            return JsonUtils.requireJsonObject(name, jsonValue);
        }
        if (value instanceof CharSequence charSequence) {
            return parseJsonObject(name, charSequence.toString());
        }
        if (value instanceof Map<?, ?> map) {
            return toJsonObject(name, map);
        }
        throw new IllegalArgumentException("Value of " + name + " is a " + value.getClass().getName() + ". A JSON object is required.");
    }

    private OracleJsonObject toJsonObject(String name, Map<?, ?> map) {
        OracleJsonObject jsonObject = oracleJsonFactory.createObject();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            Object key = entry.getKey();
            if (key == null) {
                throw new IllegalArgumentException("Key of " + name + " is null. A String is required.");
            }
            if (!(key instanceof String attributeName)) {
                throw new IllegalArgumentException("Key of " + name + " is a " + key.getClass().getName() + ". A String is required.");
            }
            jsonObject.put(attributeName, toJsonValue(attributeName + " within " + name, entry.getValue()));
        }
        return jsonObject;
    }

    private OracleJsonArray toJsonArray(String name, Collection<?> collection) {
        OracleJsonArray jsonArray = oracleJsonFactory.createArray();
        for (Object value : collection) {
            jsonArray.add(toJsonValue(name, value));
        }
        return jsonArray;
    }

    private OracleJsonValue toJsonValue(String name, @Nullable Object value) {
        if (value == null) {
            return oracleJsonFactory.createNull();
        }
        if (value instanceof OracleJsonValue jsonValue) {
            return jsonValue;
        }
        if (value instanceof CharSequence charSequence) {
            return oracleJsonFactory.createString(charSequence.toString());
        }
        if (value instanceof Integer integer) {
            return oracleJsonFactory.createDecimal(integer);
        }
        if (value instanceof Short shortValue) {
            return oracleJsonFactory.createDecimal(shortValue.intValue());
        }
        if (value instanceof Byte byteValue) {
            return oracleJsonFactory.createDecimal(byteValue.intValue());
        }
        if (value instanceof Long longValue) {
            return oracleJsonFactory.createDecimal(longValue);
        }
        if (value instanceof BigInteger bigInteger) {
            return oracleJsonFactory.createDecimal(new BigDecimal(bigInteger));
        }
        if (value instanceof BigDecimal bigDecimal) {
            return oracleJsonFactory.createDecimal(bigDecimal);
        }
        if (value instanceof Float floatValue) {
            return oracleJsonFactory.createFloat(floatValue);
        }
        if (value instanceof Double doubleValue) {
            return oracleJsonFactory.createDouble(doubleValue);
        }
        if (value instanceof Boolean booleanValue) {
            return oracleJsonFactory.createBoolean(booleanValue);
        }
        if (value instanceof LocalDateTime localDateTime) {
            return oracleJsonFactory.createTimestamp(localDateTime);
        }
        if (value instanceof OffsetDateTime offsetDateTime) {
            return oracleJsonFactory.createTimestampTZ(offsetDateTime);
        }
        if (value instanceof byte[] bytes) {
            return oracleJsonFactory.createBinary(bytes);
        }
        if (value instanceof Map<?, ?> map) {
            return toJsonObject(name, map);
        }
        if (value instanceof Collection<?> collection) {
            return toJsonArray(name, collection);
        }
        throw new IllegalArgumentException("Value of " + name + " is a " + value.getClass().getName() + ". A supported JSON value is required.");
    }
}
